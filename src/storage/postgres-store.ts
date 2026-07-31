import pg from 'pg';

import type { OttoLicenseCapability } from '../contracts/license.js';
import type {
  DeploymentTelemetrySummary,
  OttoTelemetryEvent,
  OttoTelemetryReceipt,
} from '../contracts/telemetry.js';
import { conflict } from '../errors.js';
import type {
  AuditEventInput,
  ControlStore,
  CreateLicenseRecordInput,
  CreateUpdateReleaseRecordInput,
  CustomerRecord,
  DeploymentUpdateAssignmentRecord,
  DeploymentRecord,
  LicenseRecord,
  RecordStatus,
  UpdateDistributionRecord,
  UpdateReleaseRecord,
  UpdateReleaseTransition,
} from './control-store.js';
import type { UpdateChannel, UpdateReleaseState } from '../contracts/update-policy.js';
import { runMigrations } from './migrations.js';

const { Pool } = pg;

interface PostgresStoreOptions {
  connectionString: string;
  ssl: boolean;
}

interface CustomerRow {
  id: string;
  name: string;
  status: RecordStatus;
  created_at: Date;
  updated_at: Date;
}

interface DeploymentRow {
  id: string;
  customer_id: string;
  customer_name: string;
  organization_id: string;
  machine_fingerprint: string;
  name: string;
  status: RecordStatus;
  created_at: Date;
  updated_at: Date;
}

interface LicenseRow {
  id: string;
  deployment_id: string;
  customer_name: string;
  organization_id: string;
  machine_fingerprint: string;
  plan: string;
  issued_at_ms: string;
  expires_at_ms: string;
  seat_limit: number;
  modules: OttoLicenseCapability[];
  offline: boolean;
  telemetry_allowed: boolean;
  lease_endpoint: string | null;
  token_version: number;
  signature: string;
  signing_key_id: string;
  revoked_at_ms: string | null;
  created_at: Date;
  updated_at: Date;
}

interface TelemetryCountRow {
  event_type: string;
  count: number;
}

interface LatestTelemetryRow {
  source_created_at_ms: string;
  received_at: Date;
  payload: Record<string, unknown>;
}

interface UpdateDistributionRow {
  id: string;
  name: string;
  status: RecordStatus;
  created_at: Date;
  updated_at: Date;
}

interface UpdateReleaseRow {
  id: string;
  distribution_id: string;
  version: string;
  source_commit: string;
  channel: UpdateChannel;
  rollout_percent: number;
  state: UpdateReleaseState;
  notes: string;
  full_manifest_url: string | null;
  full_manifest_sha256: string | null;
  incremental_manifest_url: string | null;
  incremental_manifest_sha256: string | null;
  previous_release_id: string | null;
  published_at: Date | null;
  created_at: Date;
  updated_at: Date;
}

interface DeploymentUpdateAssignmentRow {
  deployment_id: string;
  distribution_id: string;
  updated_at: Date;
}

function postgresCode(error: unknown): string | null {
  return error && typeof error === 'object' && 'code' in error
    ? String(error.code)
    : null;
}

function customerFromRow(row: CustomerRow): CustomerRecord {
  return {
    id: row.id,
    name: row.name,
    status: row.status,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function deploymentFromRow(row: DeploymentRow): DeploymentRecord {
  return {
    id: row.id,
    customerId: row.customer_id,
    customerName: row.customer_name,
    organizationId: row.organization_id,
    machineFingerprint: row.machine_fingerprint,
    name: row.name,
    status: row.status,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function licenseFromRow(row: LicenseRow): LicenseRecord {
  return {
    id: row.id,
    deploymentId: row.deployment_id,
    customerName: row.customer_name,
    organizationId: row.organization_id,
    machineFingerprint: row.machine_fingerprint,
    plan: row.plan,
    issuedAtMs: Number(row.issued_at_ms),
    expiresAtMs: Number(row.expires_at_ms),
    seatLimit: row.seat_limit,
    modules: row.modules,
    offline: row.offline,
    telemetryAllowed: row.telemetry_allowed,
    leaseEndpoint: row.lease_endpoint,
    tokenVersion: row.token_version,
    signature: row.signature,
    signingKeyId: row.signing_key_id,
    revokedAtMs: row.revoked_at_ms === null ? null : Number(row.revoked_at_ms),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function updateDistributionFromRow(row: UpdateDistributionRow): UpdateDistributionRecord {
  return {
    id: row.id,
    name: row.name,
    status: row.status,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function updateReleaseFromRow(row: UpdateReleaseRow): UpdateReleaseRecord {
  return {
    id: row.id,
    distributionId: row.distribution_id,
    version: row.version,
    sourceCommit: row.source_commit,
    channel: row.channel,
    rolloutPercent: row.rollout_percent,
    state: row.state,
    notes: row.notes,
    fullManifestUrl: row.full_manifest_url,
    fullManifestSha256: row.full_manifest_sha256,
    incrementalManifestUrl: row.incremental_manifest_url,
    incrementalManifestSha256: row.incremental_manifest_sha256,
    previousReleaseId: row.previous_release_id,
    publishedAt: row.published_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export class PostgresControlStore implements ControlStore {
  readonly #pool: InstanceType<typeof Pool>;

  private constructor(pool: InstanceType<typeof Pool>) {
    this.#pool = pool;
  }

  static async connect(options: PostgresStoreOptions): Promise<PostgresControlStore> {
    const pool = new Pool({
      connectionString: options.connectionString,
      max: 10,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 10_000,
      ssl: options.ssl ? { rejectUnauthorized: true } : false,
    });
    const client = await pool.connect();
    let migrationError: unknown;
    try {
      await runMigrations(client);
    } catch (error) {
      migrationError = error;
    } finally {
      client.release();
    }
    if (migrationError) {
      await pool.end();
      throw migrationError;
    }
    return new PostgresControlStore(pool);
  }

  async ping(): Promise<void> {
    await this.#pool.query('SELECT 1');
  }

  async close(): Promise<void> {
    await this.#pool.end();
  }

  async createCustomer(input: { id: string; name: string }): Promise<CustomerRecord> {
    try {
      const result = await this.#pool.query<CustomerRow>(
        `INSERT INTO control_customers (id, name)
         VALUES ($1, $2)
         RETURNING *`,
        [input.id, input.name],
      );
      return customerFromRow(result.rows[0]!);
    } catch (error) {
      if (postgresCode(error) === '23505') throw conflict('customer already exists');
      throw error;
    }
  }

  async createDeployment(input: {
    id: string;
    customerId: string;
    organizationId: string;
    machineFingerprint: string;
    name: string;
  }): Promise<DeploymentRecord> {
    try {
      const result = await this.#pool.query<DeploymentRow>(
        `WITH inserted AS (
           INSERT INTO control_deployments
             (id, customer_id, organization_id, machine_fingerprint, name)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING *
         )
         SELECT inserted.*, customers.name AS customer_name
         FROM inserted
         JOIN control_customers customers ON customers.id = inserted.customer_id`,
        [
          input.id,
          input.customerId,
          input.organizationId,
          input.machineFingerprint,
          input.name,
        ],
      );
      return deploymentFromRow(result.rows[0]!);
    } catch (error) {
      if (postgresCode(error) === '23503') throw conflict('customer does not exist');
      if (postgresCode(error) === '23505') throw conflict('deployment already exists');
      throw error;
    }
  }

  async getDeployment(id: string): Promise<DeploymentRecord | null> {
    const result = await this.#pool.query<DeploymentRow>(
      `SELECT deployments.*, customers.name AS customer_name
       FROM control_deployments deployments
       JOIN control_customers customers ON customers.id = deployments.customer_id
       WHERE deployments.id = $1`,
      [id],
    );
    return result.rows[0] ? deploymentFromRow(result.rows[0]) : null;
  }

  async createLicense(input: CreateLicenseRecordInput): Promise<LicenseRecord> {
    try {
      const result = await this.#pool.query<LicenseRow>(
        `INSERT INTO control_licenses
          (id, deployment_id, customer_name, organization_id, machine_fingerprint,
           plan, issued_at_ms, expires_at_ms, seat_limit, modules, offline,
           telemetry_allowed, lease_endpoint, token_version, signature, signing_key_id,
           revoked_at_ms)
         VALUES
          ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11, $12,
           $13, $14, $15, $16, $17)
         RETURNING *`,
        [
          input.id,
          input.deploymentId,
          input.customerName,
          input.organizationId,
          input.machineFingerprint,
          input.plan,
          input.issuedAtMs,
          input.expiresAtMs,
          input.seatLimit,
          JSON.stringify(input.modules),
          input.offline,
          input.telemetryAllowed,
          input.leaseEndpoint,
          input.tokenVersion,
          input.signature,
          input.signingKeyId,
          input.revokedAtMs,
        ],
      );
      return licenseFromRow(result.rows[0]!);
    } catch (error) {
      if (postgresCode(error) === '23505') throw conflict('license already exists');
      throw error;
    }
  }

  async getLicense(id: string): Promise<LicenseRecord | null> {
    const result = await this.#pool.query<LicenseRow>(
      'SELECT * FROM control_licenses WHERE id = $1',
      [id],
    );
    return result.rows[0] ? licenseFromRow(result.rows[0]) : null;
  }

  async revokeLicense(id: string, revokedAtMs: number): Promise<LicenseRecord | null> {
    const result = await this.#pool.query<LicenseRow>(
      `UPDATE control_licenses
       SET revoked_at_ms = COALESCE(revoked_at_ms, $2), updated_at = now()
       WHERE id = $1
       RETURNING *`,
      [id, revokedAtMs],
    );
    return result.rows[0] ? licenseFromRow(result.rows[0]) : null;
  }

  async consumeLeaseNonce(input: {
    deploymentId: string;
    nonce: string;
    expiresAtMs: number;
  }): Promise<boolean> {
    const client = await this.#pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('DELETE FROM control_lease_nonces WHERE expires_at_ms < $1', [Date.now()]);
      const result = await client.query(
        `INSERT INTO control_lease_nonces (deployment_id, nonce, expires_at_ms)
         VALUES ($1, $2, $3)
         ON CONFLICT DO NOTHING
         RETURNING nonce`,
        [input.deploymentId, input.nonce, input.expiresAtMs],
      );
      await client.query('COMMIT');
      return result.rowCount === 1;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async ingestTelemetryBatch(input: {
    deploymentId: string;
    licenseId: string;
    nonce: string;
    nonceExpiresAtMs: number;
    retentionBeforeMs: number;
    receivedAtMs: number;
    events: OttoTelemetryEvent[];
  }): Promise<OttoTelemetryReceipt | null> {
    const client = await this.#pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(
        'DELETE FROM control_telemetry_nonces WHERE expires_at_ms < $1',
        [input.receivedAtMs],
      );
      const nonce = await client.query(
        `INSERT INTO control_telemetry_nonces (deployment_id, nonce, expires_at_ms)
         VALUES ($1, $2, $3)
         ON CONFLICT DO NOTHING
         RETURNING nonce`,
        [input.deploymentId, input.nonce, input.nonceExpiresAtMs],
      );
      if (nonce.rowCount !== 1) {
        await client.query('ROLLBACK');
        return null;
      }
      await client.query(
        'DELETE FROM control_telemetry_events WHERE received_at < to_timestamp($1 / 1000.0)',
        [input.retentionBeforeMs],
      );
      let accepted = 0;
      let duplicates = 0;
      for (const event of input.events) {
        const result = await client.query(
          `INSERT INTO control_telemetry_events
            (deployment_id, event_id, license_id, organization_id, event_type,
             payload, integrity, source_created_at_ms, received_at)
           VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, to_timestamp($9 / 1000.0))
           ON CONFLICT (deployment_id, event_id) DO NOTHING
           RETURNING event_id`,
          [
            input.deploymentId,
            event.id,
            input.licenseId,
            event.organizationId,
            event.eventType,
            JSON.stringify(event.payload),
            event.integrity,
            event.createdAtMs,
            input.receivedAtMs,
          ],
        );
        if (result.rowCount === 1) accepted += 1;
        else duplicates += 1;
      }
      await client.query('COMMIT');
      return { accepted, duplicates };
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async getDeploymentTelemetrySummary(input: {
    deploymentId: string;
    sinceMs: number;
  }): Promise<DeploymentTelemetrySummary> {
    const counts = await this.#pool.query<TelemetryCountRow>(
      `SELECT event_type, COUNT(*)::integer AS count
       FROM control_telemetry_events
       WHERE deployment_id = $1 AND received_at >= to_timestamp($2 / 1000.0)
       GROUP BY event_type
       ORDER BY event_type`,
      [input.deploymentId, input.sinceMs],
    );
    const latest = await this.#pool.query<LatestTelemetryRow>(
      `SELECT source_created_at_ms, received_at, payload
       FROM control_telemetry_events
       WHERE deployment_id = $1 AND event_type = 'runtime_health'
       ORDER BY source_created_at_ms DESC
       LIMIT 1`,
      [input.deploymentId],
    );
    const lastSeen = await this.#pool.query<{ received_at: Date | null }>(
      `SELECT MAX(received_at) AS received_at
       FROM control_telemetry_events
       WHERE deployment_id = $1`,
      [input.deploymentId],
    );
    const eventCounts = Object.fromEntries(
      counts.rows.map((row) => [row.event_type, row.count]),
    );
    const latestHealth = latest.rows[0];
    return {
      deploymentId: input.deploymentId,
      since: new Date(input.sinceMs).toISOString(),
      totalEvents: counts.rows.reduce((total, row) => total + row.count, 0),
      lastSeenAt: lastSeen.rows[0]?.received_at?.toISOString() ?? null,
      eventCounts,
      latestRuntimeHealth: latestHealth
        ? {
            createdAt: new Date(Number(latestHealth.source_created_at_ms)).toISOString(),
            receivedAt: latestHealth.received_at.toISOString(),
            payload: latestHealth.payload,
          }
        : null,
    };
  }

  async createUpdateDistribution(input: {
    id: string;
    name: string;
  }): Promise<UpdateDistributionRecord> {
    try {
      const result = await this.#pool.query<UpdateDistributionRow>(
        `INSERT INTO control_update_distributions (id, name)
         VALUES ($1, $2)
         RETURNING *`,
        [input.id, input.name],
      );
      return updateDistributionFromRow(result.rows[0]!);
    } catch (error) {
      if (postgresCode(error) === '23505') throw conflict('update distribution already exists');
      throw error;
    }
  }

  async getUpdateDistribution(id: string): Promise<UpdateDistributionRecord | null> {
    const result = await this.#pool.query<UpdateDistributionRow>(
      'SELECT * FROM control_update_distributions WHERE id = $1',
      [id],
    );
    return result.rows[0] ? updateDistributionFromRow(result.rows[0]) : null;
  }

  async assignDeploymentUpdateDistribution(input: {
    deploymentId: string;
    distributionId: string;
    updatedAt: Date;
  }): Promise<DeploymentUpdateAssignmentRecord> {
    try {
      const result = await this.#pool.query<DeploymentUpdateAssignmentRow>(
        `INSERT INTO control_deployment_update_assignments
          (deployment_id, distribution_id, updated_at)
         VALUES ($1, $2, $3)
         ON CONFLICT (deployment_id) DO UPDATE
         SET distribution_id = EXCLUDED.distribution_id, updated_at = EXCLUDED.updated_at
         RETURNING *`,
        [input.deploymentId, input.distributionId, input.updatedAt],
      );
      const row = result.rows[0]!;
      return {
        deploymentId: row.deployment_id,
        distributionId: row.distribution_id,
        updatedAt: row.updated_at,
      };
    } catch (error) {
      if (postgresCode(error) === '23503') {
        throw conflict('deployment or update distribution does not exist');
      }
      throw error;
    }
  }

  async getDeploymentUpdateAssignment(
    deploymentId: string,
  ): Promise<DeploymentUpdateAssignmentRecord | null> {
    const result = await this.#pool.query<DeploymentUpdateAssignmentRow>(
      'SELECT * FROM control_deployment_update_assignments WHERE deployment_id = $1',
      [deploymentId],
    );
    const row = result.rows[0];
    return row ? {
      deploymentId: row.deployment_id,
      distributionId: row.distribution_id,
      updatedAt: row.updated_at,
    } : null;
  }

  async createUpdateRelease(input: CreateUpdateReleaseRecordInput): Promise<UpdateReleaseRecord> {
    try {
      const result = await this.#pool.query<UpdateReleaseRow>(
        `INSERT INTO control_update_releases
          (id, distribution_id, version, source_commit, channel, rollout_percent, notes,
           full_manifest_url, full_manifest_sha256, incremental_manifest_url,
           incremental_manifest_sha256)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         RETURNING *`,
        [
          input.id,
          input.distributionId,
          input.version,
          input.sourceCommit,
          input.channel,
          input.rolloutPercent,
          input.notes,
          input.fullManifestUrl,
          input.fullManifestSha256,
          input.incrementalManifestUrl,
          input.incrementalManifestSha256,
        ],
      );
      return updateReleaseFromRow(result.rows[0]!);
    } catch (error) {
      if (postgresCode(error) === '23503') throw conflict('update distribution does not exist');
      if (postgresCode(error) === '23505') throw conflict('update release already exists');
      throw error;
    }
  }

  async getUpdateRelease(id: string): Promise<UpdateReleaseRecord | null> {
    const result = await this.#pool.query<UpdateReleaseRow>(
      'SELECT * FROM control_update_releases WHERE id = $1',
      [id],
    );
    return result.rows[0] ? updateReleaseFromRow(result.rows[0]) : null;
  }

  async listUpdateReleases(distributionId: string): Promise<UpdateReleaseRecord[]> {
    const result = await this.#pool.query<UpdateReleaseRow>(
      `SELECT * FROM control_update_releases
       WHERE distribution_id = $1
       ORDER BY created_at DESC`,
      [distributionId],
    );
    return result.rows.map(updateReleaseFromRow);
  }

  async activateUpdateRelease(
    id: string,
    publishedAt: Date,
  ): Promise<UpdateReleaseTransition | null> {
    const client = await this.#pool.connect();
    try {
      await client.query('BEGIN');
      const selected = await client.query<UpdateReleaseRow>(
        'SELECT * FROM control_update_releases WHERE id = $1 FOR UPDATE',
        [id],
      );
      const candidate = selected.rows[0];
      if (!candidate) {
        await client.query('ROLLBACK');
        return null;
      }
      if (candidate.state === 'active') throw conflict('update release is already active');
      if (candidate.state === 'rolled_back') {
        throw conflict('rolled-back release cannot be reactivated');
      }
      await client.query(
        'SELECT id FROM control_update_distributions WHERE id = $1 FOR UPDATE',
        [candidate.distribution_id],
      );
      const previous = await client.query<UpdateReleaseRow>(
        `SELECT * FROM control_update_releases
         WHERE distribution_id = $1 AND channel = $2 AND state = 'active' AND id <> $3
         FOR UPDATE`,
        [candidate.distribution_id, candidate.channel, id],
      );
      if (previous.rows[0]) {
        await client.query(
          `UPDATE control_update_releases
           SET state = 'paused', updated_at = $2
           WHERE id = $1`,
          [previous.rows[0].id, publishedAt],
        );
      }
      const activated = await client.query<UpdateReleaseRow>(
        `UPDATE control_update_releases
         SET state = 'active', previous_release_id = $2,
             published_at = COALESCE(published_at, $3), updated_at = $3
         WHERE id = $1
         RETURNING *`,
        [id, previous.rows[0]?.id ?? null, publishedAt],
      );
      await client.query('COMMIT');
      return {
        release: updateReleaseFromRow(activated.rows[0]!),
        fallback: previous.rows[0] ? updateReleaseFromRow(previous.rows[0]) : null,
      };
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async pauseUpdateRelease(id: string, updatedAt: Date): Promise<UpdateReleaseRecord | null> {
    const result = await this.#pool.query<UpdateReleaseRow>(
      `UPDATE control_update_releases
       SET state = 'paused', updated_at = $2
       WHERE id = $1 AND state = 'active'
       RETURNING *`,
      [id, updatedAt],
    );
    return result.rows[0] ? updateReleaseFromRow(result.rows[0]) : null;
  }

  async rollbackUpdateRelease(
    id: string,
    updatedAt: Date,
  ): Promise<UpdateReleaseTransition | null> {
    const client = await this.#pool.connect();
    try {
      await client.query('BEGIN');
      const selected = await client.query<UpdateReleaseRow>(
        'SELECT * FROM control_update_releases WHERE id = $1 FOR UPDATE',
        [id],
      );
      const target = selected.rows[0];
      if (!target) {
        await client.query('ROLLBACK');
        return null;
      }
      if (target.state !== 'active' && target.state !== 'paused') {
        throw conflict('only an active or paused update release can be rolled back');
      }
      await client.query(
        'SELECT id FROM control_update_distributions WHERE id = $1 FOR UPDATE',
        [target.distribution_id],
      );
      await client.query(
        `UPDATE control_update_releases
         SET state = 'rolled_back', updated_at = $2
         WHERE id = $1`,
        [id, updatedAt],
      );
      let fallback: UpdateReleaseRow | undefined;
      if (target.previous_release_id) {
        const previous = await client.query<UpdateReleaseRow>(
          `SELECT * FROM control_update_releases
           WHERE id = $1 AND distribution_id = $2 AND channel = $3
           FOR UPDATE`,
          [target.previous_release_id, target.distribution_id, target.channel],
        );
        fallback = previous.rows[0];
        if (fallback) {
          await client.query(
            `UPDATE control_update_releases
             SET state = 'paused', updated_at = $3
             WHERE distribution_id = $1 AND channel = $2 AND state = 'active'`,
            [target.distribution_id, target.channel, updatedAt],
          );
          const restored = await client.query<UpdateReleaseRow>(
            `UPDATE control_update_releases
             SET state = 'active', updated_at = $2
             WHERE id = $1
             RETURNING *`,
            [fallback.id, updatedAt],
          );
          fallback = restored.rows[0];
        }
      }
      const rolledBack = await client.query<UpdateReleaseRow>(
        'SELECT * FROM control_update_releases WHERE id = $1',
        [id],
      );
      await client.query('COMMIT');
      return {
        release: updateReleaseFromRow(rolledBack.rows[0]!),
        fallback: fallback ? updateReleaseFromRow(fallback) : null,
      };
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async getActiveUpdateReleases(distributionId: string): Promise<UpdateReleaseRecord[]> {
    const result = await this.#pool.query<UpdateReleaseRow>(
      `SELECT * FROM control_update_releases
       WHERE distribution_id = $1 AND state = 'active'
       ORDER BY CASE channel WHEN 'required' THEN 1 WHEN 'stable' THEN 2 ELSE 3 END`,
      [distributionId],
    );
    return result.rows.map(updateReleaseFromRow);
  }

  async consumeUpdatePolicyNonce(input: {
    deploymentId: string;
    nonce: string;
    expiresAtMs: number;
  }): Promise<boolean> {
    const client = await this.#pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(
        'DELETE FROM control_update_policy_nonces WHERE expires_at_ms < $1',
        [Date.now()],
      );
      const result = await client.query(
        `INSERT INTO control_update_policy_nonces (deployment_id, nonce, expires_at_ms)
         VALUES ($1, $2, $3)
         ON CONFLICT DO NOTHING
         RETURNING nonce`,
        [input.deploymentId, input.nonce, input.expiresAtMs],
      );
      await client.query('COMMIT');
      return result.rowCount === 1;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async appendAuditEvent(input: AuditEventInput): Promise<void> {
    await this.#pool.query(
      `INSERT INTO control_audit_events
       (actor_id, action, target_type, target_id, detail)
       VALUES ($1, $2, $3, $4, $5::jsonb)`,
      [input.actorId, input.action, input.targetType, input.targetId, JSON.stringify(input.detail)],
    );
  }
}

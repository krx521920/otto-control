import pg from 'pg';

import type {
  OttoLicenseCapability,
  OttoSeatEnforcement,
  OttoSeatStatus,
} from '../contracts/license.js';
import type {
  AdminAccountRecord,
  AdminApprovalRecord,
  AdminApprovalStatus,
  AdminPermission,
  AdminPrincipal,
  AdminRoleRecord,
  AdminSessionRecord,
} from '../contracts/admin-identity.js';
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
  LicenseLifecycleEventRecord,
  LicenseRecord,
  LicenseSeatUsageRecord,
  RecordStatus,
  SigningKeyProvider,
  SigningKeyRecord,
  SigningKeyState,
  SigningKeyTransition,
  UpdateDistributionRecord,
  UpdateLicenseRecordInput,
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
  revision: number;
  deployment_id: string;
  customer_name: string;
  organization_id: string;
  machine_fingerprint: string;
  plan: string;
  issued_at_ms: string;
  expires_at_ms: string;
  seat_limit: number;
  grace_period_ms: string;
  seat_enforcement: OttoSeatEnforcement;
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

interface LicenseLifecycleEventRow {
  id: string;
  license_id: string;
  revision: number;
  change_type: LicenseLifecycleEventRecord['changeType'];
  actor_id: string;
  detail: Record<string, unknown>;
  created_at: Date;
}

interface LicenseSeatUsageRow {
  license_id: string;
  deployment_id: string;
  active_seats: number;
  seat_limit: number;
  status: OttoSeatStatus;
  overage_started_at_ms: string | null;
  grace_expires_at_ms: string | null;
  last_reported_at_ms: string;
}

interface SigningKeyRow {
  key_id: string;
  algorithm: 'ed25519';
  public_key_pem: string;
  provider: SigningKeyProvider;
  state: SigningKeyState;
  created_at: Date;
  activated_at: Date | null;
  retired_at: Date | null;
  revoked_at: Date | null;
  revocation_reason: string | null;
  updated_at: Date;
}

interface AdminAccountRow {
  id: string;
  username: string;
  display_name: string;
  password_hash: string;
  mfa_secret_ciphertext: string;
  status: AdminAccountRecord['status'];
  failed_login_count: number;
  locked_until: Date | null;
  mfa_confirmed_at: Date | null;
  created_at: Date;
  updated_at: Date;
  roles?: string[];
}

interface AdminSessionRow {
  id: string;
  account_id: string;
  username: string;
  display_name: string;
  token_hash: string;
  expires_at: Date;
  last_seen_at: Date;
  mfa_verified_at: Date;
  revoked_at: Date | null;
  created_at: Date;
}

interface AdminApprovalRow {
  id: string;
  requester_account_id: string;
  operation: string;
  target_type: string;
  target_id: string;
  request_hash: string;
  status: AdminApprovalStatus;
  required_approvals: number;
  approval_count: number | string;
  expires_at: Date;
  executed_at: Date | null;
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
    revision: row.revision,
    deploymentId: row.deployment_id,
    customerName: row.customer_name,
    organizationId: row.organization_id,
    machineFingerprint: row.machine_fingerprint,
    plan: row.plan,
    issuedAtMs: Number(row.issued_at_ms),
    expiresAtMs: Number(row.expires_at_ms),
    seatLimit: row.seat_limit,
    gracePeriodMs: Number(row.grace_period_ms),
    seatEnforcement: row.seat_enforcement,
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

function lifecycleEventFromRow(row: LicenseLifecycleEventRow): LicenseLifecycleEventRecord {
  return {
    id: Number(row.id),
    licenseId: row.license_id,
    revision: row.revision,
    changeType: row.change_type,
    actorId: row.actor_id,
    detail: row.detail,
    createdAt: row.created_at,
  };
}

function seatUsageFromRow(row: LicenseSeatUsageRow): LicenseSeatUsageRecord {
  return {
    licenseId: row.license_id,
    deploymentId: row.deployment_id,
    activeSeats: row.active_seats,
    seatLimit: row.seat_limit,
    status: row.status,
    overageStartedAtMs: row.overage_started_at_ms === null
      ? null
      : Number(row.overage_started_at_ms),
    graceExpiresAtMs: row.grace_expires_at_ms === null
      ? null
      : Number(row.grace_expires_at_ms),
    lastReportedAtMs: Number(row.last_reported_at_ms),
  };
}

function signingKeyFromRow(row: SigningKeyRow): SigningKeyRecord {
  return {
    keyId: row.key_id,
    algorithm: row.algorithm,
    publicKeyPem: row.public_key_pem,
    provider: row.provider,
    state: row.state,
    createdAt: row.created_at,
    activatedAt: row.activated_at,
    retiredAt: row.retired_at,
    revokedAt: row.revoked_at,
    revocationReason: row.revocation_reason,
    updatedAt: row.updated_at,
  };
}

function adminAccountFromRow(row: AdminAccountRow): AdminAccountRecord {
  return {
    id: row.id,
    username: row.username,
    displayName: row.display_name,
    passwordHash: row.password_hash,
    mfaSecretCiphertext: row.mfa_secret_ciphertext,
    status: row.status,
    failedLoginCount: row.failed_login_count,
    lockedUntil: row.locked_until,
    mfaConfirmedAt: row.mfa_confirmed_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function adminSessionFromRow(row: AdminSessionRow): AdminSessionRecord {
  return {
    id: row.id,
    accountId: row.account_id,
    username: row.username,
    displayName: row.display_name,
    tokenHash: row.token_hash,
    expiresAt: row.expires_at,
    lastSeenAt: row.last_seen_at,
    mfaVerifiedAt: row.mfa_verified_at,
    revokedAt: row.revoked_at,
    createdAt: row.created_at,
  };
}

function adminApprovalFromRow(row: AdminApprovalRow): AdminApprovalRecord {
  return {
    id: row.id,
    requesterAccountId: row.requester_account_id,
    operation: row.operation,
    targetType: row.target_type,
    targetId: row.target_id,
    requestHash: row.request_hash,
    status: row.status,
    requiredApprovals: row.required_approvals,
    approvalCount: Number(row.approval_count),
    expiresAt: row.expires_at,
    executedAt: row.executed_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

const ADMIN_APPROVAL_SELECT = `SELECT approvals.*,
  COUNT(decisions.account_id) FILTER (WHERE decisions.decision = 'approve') AS approval_count
  FROM control_admin_approvals approvals
  LEFT JOIN control_admin_approval_decisions decisions ON decisions.approval_id = approvals.id`;

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
          (id, revision, deployment_id, customer_name, organization_id, machine_fingerprint,
           plan, issued_at_ms, expires_at_ms, seat_limit, grace_period_ms, seat_enforcement,
           modules, offline,
           telemetry_allowed, lease_endpoint, token_version, signature, signing_key_id,
           revoked_at_ms)
         VALUES
          ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
           $13::jsonb, $14, $15, $16, $17, $18, $19, $20)
         RETURNING *`,
        [
          input.id,
          input.revision,
          input.deploymentId,
          input.customerName,
          input.organizationId,
          input.machineFingerprint,
          input.plan,
          input.issuedAtMs,
          input.expiresAtMs,
          input.seatLimit,
          input.gracePeriodMs,
          input.seatEnforcement,
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

  async updateLicense(input: UpdateLicenseRecordInput): Promise<LicenseRecord | null> {
    const client = await this.#pool.connect();
    try {
      await client.query('BEGIN');
      const current = await client.query<LicenseRow>(
        'SELECT * FROM control_licenses WHERE id = $1 FOR UPDATE',
        [input.id],
      );
      if (!current.rows[0] || current.rows[0].revision !== input.expectedRevision) {
        await client.query('ROLLBACK');
        return null;
      }
      if (input.deploymentMachineFingerprint) {
        const binding = input.deploymentMachineFingerprint;
        const deployment = await client.query<DeploymentRow>(
          'SELECT * FROM control_deployments WHERE id = $1 FOR UPDATE',
          [binding.deploymentId],
        );
        if (
          !deployment.rows[0] ||
          deployment.rows[0].machine_fingerprint !== binding.expectedFingerprint
        ) {
          await client.query('ROLLBACK');
          return null;
        }
        await client.query(
          `UPDATE control_deployments
           SET machine_fingerprint = $2, updated_at = now()
           WHERE id = $1`,
          [binding.deploymentId, binding.newFingerprint],
        );
      }
      const updated = await client.query<LicenseRow>(
        `UPDATE control_licenses
         SET revision = $2, deployment_id = $3, customer_name = $4,
             organization_id = $5, machine_fingerprint = $6, plan = $7,
             issued_at_ms = $8, expires_at_ms = $9, seat_limit = $10,
             grace_period_ms = $11, seat_enforcement = $12, modules = $13::jsonb,
             offline = $14, telemetry_allowed = $15, lease_endpoint = $16,
             token_version = $17, signature = $18, signing_key_id = $19,
             revoked_at_ms = $20, updated_at = now()
         WHERE id = $1
         RETURNING *`,
        [
          input.id,
          input.revision,
          input.deploymentId,
          input.customerName,
          input.organizationId,
          input.machineFingerprint,
          input.plan,
          input.issuedAtMs,
          input.expiresAtMs,
          input.seatLimit,
          input.gracePeriodMs,
          input.seatEnforcement,
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
      if (input.resetSeatUsage) {
        await client.query(
          'DELETE FROM control_license_seat_usage WHERE license_id = $1',
          [input.id],
        );
      }
      await client.query(
        `INSERT INTO control_license_lifecycle_events
          (license_id, revision, change_type, actor_id, detail)
         VALUES ($1, $2, $3, $4, $5::jsonb)`,
        [
          input.id,
          input.revision,
          input.changeType,
          input.actorId,
          JSON.stringify(input.changeDetail),
        ],
      );
      await client.query('COMMIT');
      return licenseFromRow(updated.rows[0]!);
    } catch (error) {
      await client.query('ROLLBACK');
      if (postgresCode(error) === '23505') {
        throw conflict('License lifecycle change conflicts with an existing binding');
      }
      throw error;
    } finally {
      client.release();
    }
  }

  async listLicenseLifecycleEvents(
    licenseId: string,
    limit: number,
  ): Promise<LicenseLifecycleEventRecord[]> {
    const result = await this.#pool.query<LicenseLifecycleEventRow>(
      `SELECT * FROM control_license_lifecycle_events
       WHERE license_id = $1
       ORDER BY revision DESC
       LIMIT $2`,
      [licenseId, limit],
    );
    return result.rows.map(lifecycleEventFromRow);
  }

  async getLicenseSeatUsage(licenseId: string): Promise<LicenseSeatUsageRecord | null> {
    const result = await this.#pool.query<LicenseSeatUsageRow>(
      'SELECT * FROM control_license_seat_usage WHERE license_id = $1',
      [licenseId],
    );
    return result.rows[0] ? seatUsageFromRow(result.rows[0]) : null;
  }

  async recordLicenseSeatUsage(input: {
    licenseId: string;
    deploymentId: string;
    activeSeats: number;
    seatLimit: number;
    gracePeriodMs: number;
    enforcement: OttoSeatEnforcement;
    reportedAtMs: number;
  }): Promise<LicenseSeatUsageRecord> {
    const client = await this.#pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(
        'SELECT id FROM control_licenses WHERE id = $1 FOR UPDATE',
        [input.licenseId],
      );
      const existing = await client.query<LicenseSeatUsageRow>(
        'SELECT * FROM control_license_seat_usage WHERE license_id = $1 FOR UPDATE',
        [input.licenseId],
      );
      const previous = existing.rows[0] ? seatUsageFromRow(existing.rows[0]) : null;
      const overLimit = input.activeSeats > input.seatLimit;
      const overageStartedAtMs = overLimit && input.enforcement === 'enforce'
        ? previous?.overageStartedAtMs ?? input.reportedAtMs
        : null;
      const graceExpiresAtMs = overageStartedAtMs === null
        ? null
        : overageStartedAtMs + input.gracePeriodMs;
      const status: OttoSeatStatus = !overLimit
        ? 'within_limit'
        : input.enforcement === 'monitor'
          ? 'over_limit_monitor'
          : input.reportedAtMs >= graceExpiresAtMs!
            ? 'blocked'
            : 'overage_grace';
      const result = await client.query<LicenseSeatUsageRow>(
        `INSERT INTO control_license_seat_usage
          (license_id, deployment_id, active_seats, seat_limit, status,
           overage_started_at_ms, grace_expires_at_ms, last_reported_at_ms)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (license_id) DO UPDATE SET
           deployment_id = EXCLUDED.deployment_id,
           active_seats = EXCLUDED.active_seats,
           seat_limit = EXCLUDED.seat_limit,
           status = EXCLUDED.status,
           overage_started_at_ms = EXCLUDED.overage_started_at_ms,
           grace_expires_at_ms = EXCLUDED.grace_expires_at_ms,
           last_reported_at_ms = EXCLUDED.last_reported_at_ms,
           updated_at = now()
         RETURNING *`,
        [
          input.licenseId,
          input.deploymentId,
          input.activeSeats,
          input.seatLimit,
          status,
          overageStartedAtMs,
          graceExpiresAtMs,
          input.reportedAtMs,
        ],
      );
      await client.query('COMMIT');
      return seatUsageFromRow(result.rows[0]!);
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async registerSigningKey(input: {
    keyId: string;
    publicKeyPem: string;
    provider: SigningKeyProvider;
  }): Promise<SigningKeyRecord> {
    const result = await this.#pool.query<SigningKeyRow>(
      `INSERT INTO control_signing_keys (key_id, public_key_pem, provider)
       VALUES ($1, $2, $3)
       ON CONFLICT (key_id) DO NOTHING
       RETURNING *`,
      [input.keyId, input.publicKeyPem, input.provider],
    );
    const row = result.rows[0] ?? (await this.#pool.query<SigningKeyRow>(
      'SELECT * FROM control_signing_keys WHERE key_id = $1',
      [input.keyId],
    )).rows[0];
    if (!row) throw new Error('signing key registration did not persist');
    const record = signingKeyFromRow(row);
    if (record.publicKeyPem !== input.publicKeyPem || record.provider !== input.provider) {
      throw conflict('signing key id is already bound to another provider or public key');
    }
    return record;
  }

  async getSigningKey(keyId: string): Promise<SigningKeyRecord | null> {
    const result = await this.#pool.query<SigningKeyRow>(
      'SELECT * FROM control_signing_keys WHERE key_id = $1',
      [keyId],
    );
    return result.rows[0] ? signingKeyFromRow(result.rows[0]) : null;
  }

  async listSigningKeys(): Promise<SigningKeyRecord[]> {
    const result = await this.#pool.query<SigningKeyRow>(
      `SELECT * FROM control_signing_keys
       ORDER BY
         CASE state WHEN 'active' THEN 0 WHEN 'standby' THEN 1
           WHEN 'retired' THEN 2 ELSE 3 END,
         created_at DESC`,
    );
    return result.rows.map(signingKeyFromRow);
  }

  async activateSigningKey(
    keyId: string,
    changedAt: Date,
  ): Promise<SigningKeyTransition | null> {
    const client = await this.#pool.connect();
    try {
      await client.query('BEGIN');
      await client.query("SELECT pg_advisory_xact_lock(hashtext('otto_control_signing_keys'))");
      const targetResult = await client.query<SigningKeyRow>(
        'SELECT * FROM control_signing_keys WHERE key_id = $1 FOR UPDATE',
        [keyId],
      );
      const target = targetResult.rows[0];
      if (!target) {
        await client.query('ROLLBACK');
        return null;
      }
      if (target.state === 'revoked') throw conflict('revoked signing key cannot be activated');
      const previousResult = await client.query<SigningKeyRow>(
        "SELECT * FROM control_signing_keys WHERE state = 'active' AND key_id <> $1 FOR UPDATE",
        [keyId],
      );
      const previous = previousResult.rows[0] ?? null;
      if (previous) {
        await client.query(
          `UPDATE control_signing_keys
           SET state = 'retired', retired_at = $2, updated_at = $2
           WHERE key_id = $1`,
          [previous.key_id, changedAt],
        );
      }
      const activeResult = await client.query<SigningKeyRow>(
        `UPDATE control_signing_keys
         SET state = 'active', activated_at = COALESCE(activated_at, $2),
             retired_at = NULL, updated_at = $2
         WHERE key_id = $1
         RETURNING *`,
        [keyId, changedAt],
      );
      await client.query('COMMIT');
      return {
        key: signingKeyFromRow(activeResult.rows[0]!),
        activeKey: signingKeyFromRow(activeResult.rows[0]!),
        previousActiveKey: previous ? signingKeyFromRow(previous) : null,
      };
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async retireSigningKey(
    keyId: string,
    changedAt: Date,
  ): Promise<SigningKeyTransition | null> {
    const result = await this.#pool.query<SigningKeyRow>(
      `UPDATE control_signing_keys
       SET state = 'retired', retired_at = COALESCE(retired_at, $2), updated_at = $2
       WHERE key_id = $1 AND state IN ('standby', 'retired')
       RETURNING *`,
      [keyId, changedAt],
    );
    if (!result.rows[0]) {
      const existing = await this.getSigningKey(keyId);
      if (!existing) return null;
      if (existing.state === 'active') throw conflict('activate a replacement before retiring the active key');
      throw conflict('revoked signing key cannot be retired');
    }
    const activeResult = await this.#pool.query<SigningKeyRow>(
      "SELECT * FROM control_signing_keys WHERE state = 'active'",
    );
    return {
      key: signingKeyFromRow(result.rows[0]),
      activeKey: activeResult.rows[0] ? signingKeyFromRow(activeResult.rows[0]) : null,
      previousActiveKey: null,
    };
  }

  async revokeSigningKey(input: {
    keyId: string;
    replacementKeyId: string | null;
    reason: string;
    changedAt: Date;
  }): Promise<SigningKeyTransition | null> {
    const client = await this.#pool.connect();
    try {
      await client.query('BEGIN');
      await client.query("SELECT pg_advisory_xact_lock(hashtext('otto_control_signing_keys'))");
      const targetResult = await client.query<SigningKeyRow>(
        'SELECT * FROM control_signing_keys WHERE key_id = $1 FOR UPDATE',
        [input.keyId],
      );
      const target = targetResult.rows[0];
      if (!target) {
        await client.query('ROLLBACK');
        return null;
      }
      if (target.state === 'revoked') {
        const activeResult = await client.query<SigningKeyRow>(
          "SELECT * FROM control_signing_keys WHERE state = 'active'",
        );
        await client.query('COMMIT');
        return {
          key: signingKeyFromRow(target),
          activeKey: activeResult.rows[0] ? signingKeyFromRow(activeResult.rows[0]) : null,
          previousActiveKey: null,
        };
      }
      let replacement: SigningKeyRow | null = null;
      if (target.state === 'active') {
        if (!input.replacementKeyId || input.replacementKeyId === input.keyId) {
          throw conflict('revoking the active key requires a different replacement key');
        }
        const replacementResult = await client.query<SigningKeyRow>(
          'SELECT * FROM control_signing_keys WHERE key_id = $1 FOR UPDATE',
          [input.replacementKeyId],
        );
        replacement = replacementResult.rows[0] ?? null;
        if (!replacement) throw conflict('replacement signing key does not exist');
        if (replacement.state === 'revoked') {
          throw conflict('revoked signing key cannot be used as a replacement');
        }
      }
      const revokedResult = await client.query<SigningKeyRow>(
        `UPDATE control_signing_keys
         SET state = 'revoked', revoked_at = $2, revocation_reason = $3,
             retired_at = COALESCE(retired_at, $2), updated_at = $2
         WHERE key_id = $1
         RETURNING *`,
        [input.keyId, input.changedAt, input.reason],
      );
      let activeKey: SigningKeyRecord | null = null;
      if (replacement) {
        const activeResult = await client.query<SigningKeyRow>(
          `UPDATE control_signing_keys
           SET state = 'active', activated_at = COALESCE(activated_at, $2),
               retired_at = NULL, updated_at = $2
           WHERE key_id = $1
           RETURNING *`,
          [replacement.key_id, input.changedAt],
        );
        activeKey = signingKeyFromRow(activeResult.rows[0]!);
      } else {
        const activeResult = await client.query<SigningKeyRow>(
          "SELECT * FROM control_signing_keys WHERE state = 'active'",
        );
        activeKey = activeResult.rows[0] ? signingKeyFromRow(activeResult.rows[0]) : null;
      }
      await client.query('COMMIT');
      return {
        key: signingKeyFromRow(revokedResult.rows[0]!),
        activeKey,
        previousActiveKey: target.state === 'active' ? signingKeyFromRow(target) : null,
      };
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async countAdminAccounts(): Promise<number> {
    const result = await this.#pool.query<{ count: string }>(
      'SELECT COUNT(*) AS count FROM control_admin_accounts',
    );
    return Number(result.rows[0]?.count ?? 0);
  }

  async createAdminAccount(input: {
    id: string;
    username: string;
    displayName: string;
    passwordHash: string;
    mfaSecretCiphertext: string;
    enrollmentTokenHash: string;
    enrollmentExpiresAt: Date;
    roleIds: string[];
  }): Promise<AdminAccountRecord> {
    const client = await this.#pool.connect();
    try {
      await client.query('BEGIN');
      const roles = await client.query<{ id: string }>(
        'SELECT id FROM control_admin_roles WHERE id = ANY($1::text[])',
        [input.roleIds],
      );
      if (roles.rowCount !== input.roleIds.length) throw conflict('administrator role does not exist');
      const result = await client.query<AdminAccountRow>(
        `INSERT INTO control_admin_accounts
          (id, username, display_name, password_hash, mfa_secret_ciphertext)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING *`,
        [
          input.id,
          input.username,
          input.displayName,
          input.passwordHash,
          input.mfaSecretCiphertext,
        ],
      );
      await client.query(
        `INSERT INTO control_admin_enrollments (account_id, token_hash, expires_at)
         VALUES ($1, $2, $3)`,
        [input.id, input.enrollmentTokenHash, input.enrollmentExpiresAt],
      );
      for (const roleId of input.roleIds) {
        await client.query(
          `INSERT INTO control_admin_account_roles (account_id, role_id)
           VALUES ($1, $2)`,
          [input.id, roleId],
        );
      }
      await client.query('COMMIT');
      return adminAccountFromRow(result.rows[0]!);
    } catch (error) {
      await client.query('ROLLBACK');
      if (postgresCode(error) === '23505') throw conflict('administrator account already exists');
      throw error;
    } finally {
      client.release();
    }
  }

  async getAdminAccountById(id: string): Promise<AdminAccountRecord | null> {
    const result = await this.#pool.query<AdminAccountRow>(
      'SELECT * FROM control_admin_accounts WHERE id = $1',
      [id],
    );
    return result.rows[0] ? adminAccountFromRow(result.rows[0]) : null;
  }

  async getAdminAccountByUsername(username: string): Promise<AdminAccountRecord | null> {
    const result = await this.#pool.query<AdminAccountRow>(
      'SELECT * FROM control_admin_accounts WHERE username = $1',
      [username],
    );
    return result.rows[0] ? adminAccountFromRow(result.rows[0]) : null;
  }

  async listAdminAccounts(): Promise<Array<AdminAccountRecord & { roles: string[] }>> {
    const result = await this.#pool.query<AdminAccountRow>(
      `SELECT accounts.*,
         COALESCE(array_agg(account_roles.role_id ORDER BY account_roles.role_id)
           FILTER (WHERE account_roles.role_id IS NOT NULL), ARRAY[]::text[]) AS roles
       FROM control_admin_accounts accounts
       LEFT JOIN control_admin_account_roles account_roles ON account_roles.account_id = accounts.id
       GROUP BY accounts.id
       ORDER BY accounts.created_at`,
    );
    return result.rows.map((row) => ({ ...adminAccountFromRow(row), roles: row.roles ?? [] }));
  }

  async listAdminRoles(): Promise<AdminRoleRecord[]> {
    const result = await this.#pool.query<{
      id: string;
      name: string;
      system: boolean;
      permissions: AdminPermission[];
    }>(
      `SELECT roles.id, roles.name, roles.system,
         COALESCE(array_agg(role_permissions.permission_id ORDER BY role_permissions.permission_id)
           FILTER (WHERE role_permissions.permission_id IS NOT NULL), ARRAY[]::text[]) AS permissions
       FROM control_admin_roles roles
       LEFT JOIN control_admin_role_permissions role_permissions
         ON role_permissions.role_id = roles.id
       GROUP BY roles.id
       ORDER BY roles.id`,
    );
    return result.rows.map((row) => ({
      id: row.id,
      name: row.name,
      system: row.system,
      permissions: row.permissions,
    }));
  }

  async replaceAdminAccountRoles(accountId: string, roleIds: string[]): Promise<string[] | null> {
    const client = await this.#pool.connect();
    try {
      await client.query('BEGIN');
      await client.query("SELECT pg_advisory_xact_lock(hashtext('otto_control_admin_super_guard'))");
      const account = await client.query<{ id: string; status: AdminAccountRecord['status'] }>(
        'SELECT id, status FROM control_admin_accounts WHERE id = $1 FOR UPDATE',
        [accountId],
      );
      if (!account.rowCount) {
        await client.query('ROLLBACK');
        return null;
      }
      const roles = await client.query<{ id: string }>(
        'SELECT id FROM control_admin_roles WHERE id = ANY($1::text[])',
        [roleIds],
      );
      if (roles.rowCount !== roleIds.length) throw conflict('administrator role does not exist');
      const hadSuperRole = await client.query(
        `SELECT 1 FROM control_admin_account_roles
         WHERE account_id = $1 AND role_id = 'super_admin'`,
        [accountId],
      );
      if (
        account.rows[0]?.status === 'active'
        && hadSuperRole.rowCount === 1
        && !roleIds.includes('super_admin')
      ) {
        const alternatives = await client.query(
          `SELECT 1 FROM control_admin_accounts accounts
           JOIN control_admin_account_roles roles ON roles.account_id = accounts.id
           WHERE accounts.id <> $1 AND accounts.status = 'active'
             AND roles.role_id = 'super_admin' LIMIT 1`,
          [accountId],
        );
        if (!alternatives.rowCount) throw conflict('the last active super administrator must be preserved');
      }
      await client.query('DELETE FROM control_admin_account_roles WHERE account_id = $1', [accountId]);
      for (const roleId of roleIds) {
        await client.query(
          'INSERT INTO control_admin_account_roles (account_id, role_id) VALUES ($1, $2)',
          [accountId, roleId],
        );
      }
      await client.query('UPDATE control_admin_accounts SET updated_at = now() WHERE id = $1', [accountId]);
      await client.query('COMMIT');
      return roleIds;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async setAdminAccountStatus(
    accountId: string,
    status: AdminAccountRecord['status'],
    changedAt: Date,
  ): Promise<AdminAccountRecord | null> {
    const client = await this.#pool.connect();
    try {
      await client.query('BEGIN');
      await client.query("SELECT pg_advisory_xact_lock(hashtext('otto_control_admin_super_guard'))");
      const account = await client.query<AdminAccountRow>(
        'SELECT * FROM control_admin_accounts WHERE id = $1 FOR UPDATE',
        [accountId],
      );
      const current = account.rows[0];
      if (!current) {
        await client.query('ROLLBACK');
        return null;
      }
      if (current.status === 'active' && status !== 'active') {
        const superRole = await client.query(
          `SELECT 1 FROM control_admin_account_roles
           WHERE account_id = $1 AND role_id = 'super_admin'`,
          [accountId],
        );
        if (superRole.rowCount === 1) {
          const alternatives = await client.query(
            `SELECT 1 FROM control_admin_accounts accounts
             JOIN control_admin_account_roles roles ON roles.account_id = accounts.id
             WHERE accounts.id <> $1 AND accounts.status = 'active'
               AND roles.role_id = 'super_admin' LIMIT 1`,
            [accountId],
          );
          if (!alternatives.rowCount) throw conflict('the last active super administrator must be preserved');
        }
      }
      const result = await client.query<AdminAccountRow>(
        `UPDATE control_admin_accounts SET status = $2, updated_at = $3
         WHERE id = $1 RETURNING *`,
        [accountId, status, changedAt],
      );
      await client.query('COMMIT');
      return adminAccountFromRow(result.rows[0]!);
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async confirmAdminEnrollment(input: {
    accountId: string;
    enrollmentTokenHash: string;
    recoveryCodeHashes: string[];
    confirmedAt: Date;
  }): Promise<AdminAccountRecord | null> {
    const client = await this.#pool.connect();
    try {
      await client.query('BEGIN');
      const enrollment = await client.query<{ account_id: string }>(
        `SELECT account_id FROM control_admin_enrollments
         WHERE account_id = $1 AND token_hash = $2 AND expires_at > $3
         FOR UPDATE`,
        [input.accountId, input.enrollmentTokenHash, input.confirmedAt],
      );
      if (!enrollment.rows[0]) {
        await client.query('ROLLBACK');
        return null;
      }
      const result = await client.query<AdminAccountRow>(
        `UPDATE control_admin_accounts
         SET status = 'active', mfa_confirmed_at = $2, updated_at = $2
         WHERE id = $1 AND status = 'pending'
         RETURNING *`,
        [input.accountId, input.confirmedAt],
      );
      if (!result.rows[0]) {
        await client.query('ROLLBACK');
        return null;
      }
      for (const codeHash of input.recoveryCodeHashes) {
        await client.query(
          `INSERT INTO control_admin_recovery_codes (account_id, code_hash)
           VALUES ($1, $2)`,
          [input.accountId, codeHash],
        );
      }
      await client.query('DELETE FROM control_admin_enrollments WHERE account_id = $1', [input.accountId]);
      await client.query('COMMIT');
      return adminAccountFromRow(result.rows[0]);
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async recordAdminLoginFailure(input: {
    accountId: string;
    failedLoginCount: number;
    lockedUntil: Date | null;
    changedAt: Date;
  }): Promise<void> {
    await this.#pool.query(
      `UPDATE control_admin_accounts
       SET failed_login_count = $2, locked_until = $3, updated_at = $4
       WHERE id = $1`,
      [input.accountId, input.failedLoginCount, input.lockedUntil, input.changedAt],
    );
  }

  async clearAdminLoginFailures(accountId: string, changedAt: Date): Promise<void> {
    await this.#pool.query(
      `UPDATE control_admin_accounts
       SET failed_login_count = 0, locked_until = NULL, updated_at = $2
       WHERE id = $1`,
      [accountId, changedAt],
    );
  }

  async consumeAdminRecoveryCode(
    accountId: string,
    codeHash: string,
    usedAt: Date,
  ): Promise<boolean> {
    const result = await this.#pool.query(
      `UPDATE control_admin_recovery_codes SET used_at = $3
       WHERE account_id = $1 AND code_hash = $2 AND used_at IS NULL
       RETURNING code_hash`,
      [accountId, codeHash, usedAt],
    );
    return result.rowCount === 1;
  }

  async createAdminSession(input: {
    id: string;
    accountId: string;
    tokenHash: string;
    expiresAt: Date;
    mfaVerifiedAt: Date;
    createdAt: Date;
  }): Promise<AdminSessionRecord> {
    const result = await this.#pool.query<AdminSessionRow>(
      `WITH inserted AS (
         INSERT INTO control_admin_sessions
           (id, account_id, token_hash, expires_at, last_seen_at, mfa_verified_at, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $5)
         RETURNING *
       )
       SELECT inserted.*, accounts.username, accounts.display_name
       FROM inserted JOIN control_admin_accounts accounts ON accounts.id = inserted.account_id`,
      [
        input.id,
        input.accountId,
        input.tokenHash,
        input.expiresAt,
        input.createdAt,
        input.mfaVerifiedAt,
      ],
    );
    return adminSessionFromRow(result.rows[0]!);
  }

  async getAdminPrincipalBySessionTokenHash(input: {
    tokenHash: string;
    now: Date;
    idleCutoff: Date;
  }): Promise<AdminPrincipal | null> {
    const result = await this.#pool.query<{
      account_id: string;
      session_id: string;
      username: string;
      display_name: string;
      mfa_verified_at: Date;
      roles: string[];
      permissions: AdminPermission[];
    }>(
      `SELECT accounts.id AS account_id, sessions.id AS session_id, accounts.username,
         accounts.display_name, sessions.mfa_verified_at,
         COALESCE(array_agg(DISTINCT account_roles.role_id)
           FILTER (WHERE account_roles.role_id IS NOT NULL), ARRAY[]::text[]) AS roles,
         COALESCE(array_agg(DISTINCT role_permissions.permission_id)
           FILTER (WHERE role_permissions.permission_id IS NOT NULL), ARRAY[]::text[]) AS permissions
       FROM control_admin_sessions sessions
       JOIN control_admin_accounts accounts ON accounts.id = sessions.account_id
       LEFT JOIN control_admin_account_roles account_roles ON account_roles.account_id = accounts.id
       LEFT JOIN control_admin_role_permissions role_permissions
         ON role_permissions.role_id = account_roles.role_id
       WHERE sessions.token_hash = $1 AND sessions.revoked_at IS NULL
         AND sessions.expires_at > $2 AND sessions.last_seen_at > $3
         AND accounts.status = 'active' AND accounts.mfa_confirmed_at IS NOT NULL
       GROUP BY accounts.id, sessions.id`,
      [input.tokenHash, input.now, input.idleCutoff],
    );
    const row = result.rows[0];
    return row ? {
      accountId: row.account_id,
      sessionId: row.session_id,
      username: row.username,
      displayName: row.display_name,
      roles: row.roles,
      permissions: row.permissions,
      mfaVerifiedAt: row.mfa_verified_at,
    } : null;
  }

  async touchAdminSession(sessionId: string, seenAt: Date): Promise<void> {
    await this.#pool.query(
      'UPDATE control_admin_sessions SET last_seen_at = $2 WHERE id = $1 AND revoked_at IS NULL',
      [sessionId, seenAt],
    );
  }

  async revokeAdminSession(sessionId: string, revokedAt: Date): Promise<void> {
    await this.#pool.query(
      `UPDATE control_admin_sessions SET revoked_at = COALESCE(revoked_at, $2)
       WHERE id = $1`,
      [sessionId, revokedAt],
    );
  }

  async revokeAdminAccountSessions(accountId: string, revokedAt: Date): Promise<void> {
    await this.#pool.query(
      `UPDATE control_admin_sessions SET revoked_at = COALESCE(revoked_at, $2)
       WHERE account_id = $1`,
      [accountId, revokedAt],
    );
  }

  async createAdminApproval(input: {
    id: string;
    requesterAccountId: string;
    operation: string;
    targetType: string;
    targetId: string;
    requestHash: string;
    requiredApprovals: number;
    expiresAt: Date;
    createdAt: Date;
  }): Promise<AdminApprovalRecord> {
    const result = await this.#pool.query<AdminApprovalRow>(
      `WITH inserted AS (
         INSERT INTO control_admin_approvals
           (id, requester_account_id, operation, target_type, target_id, request_hash,
            required_approvals, expires_at, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9)
         RETURNING *
       )
       SELECT inserted.*, 0 AS approval_count FROM inserted`,
      [
        input.id,
        input.requesterAccountId,
        input.operation,
        input.targetType,
        input.targetId,
        input.requestHash,
        input.requiredApprovals,
        input.expiresAt,
        input.createdAt,
      ],
    );
    return adminApprovalFromRow(result.rows[0]!);
  }

  async getAdminApproval(id: string): Promise<AdminApprovalRecord | null> {
    await this.#pool.query(
      `UPDATE control_admin_approvals SET status = 'expired', updated_at = now()
       WHERE id = $1 AND status IN ('pending', 'approved') AND expires_at <= now()`,
      [id],
    );
    const result = await this.#pool.query<AdminApprovalRow>(
      `${ADMIN_APPROVAL_SELECT} WHERE approvals.id = $1 GROUP BY approvals.id`,
      [id],
    );
    return result.rows[0] ? adminApprovalFromRow(result.rows[0]) : null;
  }

  async listAdminApprovals(limit: number): Promise<AdminApprovalRecord[]> {
    await this.#pool.query(
      `UPDATE control_admin_approvals SET status = 'expired', updated_at = now()
       WHERE status IN ('pending', 'approved') AND expires_at <= now()`,
    );
    const result = await this.#pool.query<AdminApprovalRow>(
      `${ADMIN_APPROVAL_SELECT} GROUP BY approvals.id
       ORDER BY approvals.created_at DESC LIMIT $1`,
      [limit],
    );
    return result.rows.map(adminApprovalFromRow);
  }

  async decideAdminApproval(input: {
    approvalId: string;
    accountId: string;
    decision: 'approve' | 'reject';
    reason: string | null;
    decidedAt: Date;
  }): Promise<AdminApprovalRecord | null> {
    const client = await this.#pool.connect();
    try {
      await client.query('BEGIN');
      const approvalResult = await client.query<AdminApprovalRow>(
        'SELECT *, 0 AS approval_count FROM control_admin_approvals WHERE id = $1 FOR UPDATE',
        [input.approvalId],
      );
      const approval = approvalResult.rows[0];
      if (!approval) {
        await client.query('ROLLBACK');
        return null;
      }
      if (approval.requester_account_id === input.accountId) {
        throw conflict('approval requester cannot approve their own operation');
      }
      if (approval.expires_at <= input.decidedAt) {
        await client.query(
          "UPDATE control_admin_approvals SET status = 'expired', updated_at = $2 WHERE id = $1",
          [input.approvalId, input.decidedAt],
        );
        await client.query('COMMIT');
        return this.getAdminApproval(input.approvalId);
      }
      if (approval.status !== 'pending') throw conflict('approval is no longer pending');
      try {
        await client.query(
          `INSERT INTO control_admin_approval_decisions
            (approval_id, account_id, decision, reason, decided_at)
           VALUES ($1, $2, $3, $4, $5)`,
          [input.approvalId, input.accountId, input.decision, input.reason, input.decidedAt],
        );
      } catch (error) {
        if (postgresCode(error) === '23505') throw conflict('administrator has already decided this approval');
        throw error;
      }
      const countResult = await client.query<{ count: string }>(
        `SELECT COUNT(*) AS count FROM control_admin_approval_decisions
         WHERE approval_id = $1 AND decision = 'approve'`,
        [input.approvalId],
      );
      const approvalCount = Number(countResult.rows[0]?.count ?? 0);
      const status = input.decision === 'reject'
        ? 'rejected'
        : approvalCount >= approval.required_approvals ? 'approved' : 'pending';
      await client.query(
        'UPDATE control_admin_approvals SET status = $2, updated_at = $3 WHERE id = $1',
        [input.approvalId, status, input.decidedAt],
      );
      await client.query('COMMIT');
      return this.getAdminApproval(input.approvalId);
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async consumeAdminApproval(input: {
    approvalId: string;
    requesterAccountId: string;
    operation: string;
    targetType: string;
    targetId: string;
    requestHash: string;
    executedAt: Date;
  }): Promise<AdminApprovalRecord | null> {
    const result = await this.#pool.query<AdminApprovalRow>(
      `WITH consumed AS (
         UPDATE control_admin_approvals
         SET status = 'executed', executed_at = $8, updated_at = $8
         WHERE id = $1 AND requester_account_id = $2 AND operation = $3
           AND target_type = $4 AND target_id = $5 AND request_hash = $6
           AND status = 'approved' AND expires_at > $7
         RETURNING *
       )
       SELECT consumed.*,
         (SELECT COUNT(*) FROM control_admin_approval_decisions decisions
          WHERE decisions.approval_id = consumed.id AND decisions.decision = 'approve') AS approval_count
       FROM consumed`,
      [
        input.approvalId,
        input.requesterAccountId,
        input.operation,
        input.targetType,
        input.targetId,
        input.requestHash,
        input.executedAt,
        input.executedAt,
      ],
    );
    return result.rows[0] ? adminApprovalFromRow(result.rows[0]) : null;
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
         ON CONFLICT (deployment_id, distribution_id) DO UPDATE
         SET updated_at = EXCLUDED.updated_at
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

  async hasDeploymentUpdateAssignment(
    deploymentId: string,
    distributionId: string,
  ): Promise<boolean> {
    const result = await this.#pool.query(
      `SELECT 1 FROM control_deployment_update_assignments
       WHERE deployment_id = $1 AND distribution_id = $2`,
      [deploymentId, distributionId],
    );
    return result.rowCount === 1;
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

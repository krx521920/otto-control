import pg from 'pg';

import type { OttoLicenseCapability } from '../contracts/license.js';
import { conflict } from '../errors.js';
import type {
  AuditEventInput,
  ControlStore,
  CreateLicenseRecordInput,
  CustomerRecord,
  DeploymentRecord,
  LicenseRecord,
  RecordStatus,
} from './control-store.js';
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

  async appendAuditEvent(input: AuditEventInput): Promise<void> {
    await this.#pool.query(
      `INSERT INTO control_audit_events
       (actor_id, action, target_type, target_id, detail)
       VALUES ($1, $2, $3, $4, $5::jsonb)`,
      [input.actorId, input.action, input.targetType, input.targetId, JSON.stringify(input.detail)],
    );
  }
}

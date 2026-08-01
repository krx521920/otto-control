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
  CommercialInventorySnapshot,
  ControlStore,
  CreateLicenseRecordInput,
  CreateReleaseArtifactRecordInput,
  CreateUpdateReleaseRecordInput,
  CustomerRecord,
  DeploymentUpdateAssignmentRecord,
  DeploymentRecord,
  LicenseLifecycleEventRecord,
  LicenseRecord,
  LicenseSeatUsageRecord,
  RecordStatus,
  ReleaseArtifactRecord,
  ReleaseArtifactRevocationResult,
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
import type {
  ReleaseArtifactKind,
  ReleaseArtifactPlatform,
  ReleaseArtifactState,
} from '../contracts/release-artifact.js';
import type {
  BillingRateRecord,
  CreditAccountRecord,
  CreditHoldMutationResult,
  CreditHoldRecord,
  CreditMutationResult,
  CreditStatement,
  CreditTransactionRecord,
  CreditTransactionType,
  OttoBillingModule,
} from '../contracts/billing.js';
import type {
  AlertDeliveryPayload,
  AlertDeliveryRecord,
  AlertDeliveryStatus,
  AlertSeverity,
} from '../contracts/alert-delivery.js';
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

interface CreditAccountRow {
  customer_id: string;
  available_balance: string;
  frozen_balance: string;
  total_topped_up: string;
  total_consumed: string;
  total_refunded: string;
  version: number;
  created_at: Date;
  updated_at: Date;
}

interface BillingRateRow {
  customer_id: string;
  module: OttoBillingModule;
  unit_size: string;
  credits_per_unit: string;
  updated_by: string;
  created_at: Date;
  updated_at: Date;
}

interface CreditHoldRow {
  id: string;
  customer_id: string;
  organization_id: string;
  deployment_id: string;
  module: OttoBillingModule;
  amount: string;
  status: CreditHoldRecord['status'];
  idempotency_key: string;
  expires_at: Date;
  created_at: Date;
  updated_at: Date;
}

interface CreditTransactionRow {
  id: string;
  customer_id: string;
  organization_id: string | null;
  deployment_id: string | null;
  module: OttoBillingModule | null;
  type: CreditTransactionType;
  available_delta: string;
  frozen_delta: string;
  billed_amount: string;
  available_after: string;
  frozen_after: string;
  idempotency_key: string;
  reference_id: string | null;
  related_transaction_id: string | null;
  description: string;
  metadata: Record<string, unknown>;
  occurred_at: Date;
  created_at: Date;
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

interface ReleaseArtifactRow {
  id: string;
  release_id: string;
  distribution_id: string;
  release_version: string;
  source_commit: string;
  kind: ReleaseArtifactKind;
  platform: ReleaseArtifactPlatform;
  url: string;
  sha256: string;
  size_bytes: string;
  signing_key_id: string;
  signature: string;
  state: ReleaseArtifactState;
  revoked_at: Date | null;
  revoked_by: string | null;
  revocation_reason: string | null;
  created_at: Date;
  updated_at: Date;
}

interface AlertDeliveryRow {
  id: string;
  source: AlertDeliveryRecord['source'];
  event_type: AlertDeliveryRecord['eventType'];
  fingerprint: string;
  severity: AlertSeverity;
  payload: AlertDeliveryPayload;
  status: AlertDeliveryStatus;
  attempts: number;
  next_attempt_at: Date;
  lease_until: Date | null;
  last_error: string | null;
  delivered_at: Date | null;
  created_at: Date;
  updated_at: Date;
}

interface CommercialInventoryCountRow {
  customer_total: string;
  customer_active: string;
  customer_suspended: string;
  deployment_total: string;
  deployment_active: string;
  deployment_suspended: string;
  license_total: string;
  license_active: string;
  license_expiring_soon: string;
  license_grace: string;
  license_expired: string;
  license_revoked: string;
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

function releaseArtifactFromRow(row: ReleaseArtifactRow): ReleaseArtifactRecord {
  return {
    id: row.id,
    releaseId: row.release_id,
    distributionId: row.distribution_id,
    releaseVersion: row.release_version,
    sourceCommit: row.source_commit,
    kind: row.kind,
    platform: row.platform,
    url: row.url,
    sha256: row.sha256,
    sizeBytes: Number(row.size_bytes),
    signingKeyId: row.signing_key_id,
    signature: row.signature,
    state: row.state,
    revokedAt: row.revoked_at,
    revokedBy: row.revoked_by,
    revocationReason: row.revocation_reason,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function alertDeliveryFromRow(row: AlertDeliveryRow): AlertDeliveryRecord {
  return {
    id: row.id,
    source: row.source,
    eventType: row.event_type,
    fingerprint: row.fingerprint,
    severity: row.severity,
    payload: row.payload,
    status: row.status,
    attempts: row.attempts,
    nextAttemptAt: row.next_attempt_at,
    leaseUntil: row.lease_until,
    lastError: row.last_error,
    deliveredAt: row.delivered_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function creditAccountFromRow(row: CreditAccountRow): CreditAccountRecord {
  return {
    customerId: row.customer_id,
    availableBalance: Number(row.available_balance),
    frozenBalance: Number(row.frozen_balance),
    totalToppedUp: Number(row.total_topped_up),
    totalConsumed: Number(row.total_consumed),
    totalRefunded: Number(row.total_refunded),
    version: row.version,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function billingRateFromRow(row: BillingRateRow): BillingRateRecord {
  return {
    customerId: row.customer_id,
    module: row.module,
    unitSize: Number(row.unit_size),
    creditsPerUnit: Number(row.credits_per_unit),
    updatedBy: row.updated_by,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function creditHoldFromRow(row: CreditHoldRow): CreditHoldRecord {
  return {
    id: row.id,
    customerId: row.customer_id,
    organizationId: row.organization_id,
    deploymentId: row.deployment_id,
    module: row.module,
    amount: Number(row.amount),
    status: row.status,
    idempotencyKey: row.idempotency_key,
    expiresAt: row.expires_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function creditTransactionFromRow(row: CreditTransactionRow): CreditTransactionRecord {
  return {
    id: row.id,
    customerId: row.customer_id,
    organizationId: row.organization_id,
    deploymentId: row.deployment_id,
    module: row.module,
    type: row.type,
    availableDelta: Number(row.available_delta),
    frozenDelta: Number(row.frozen_delta),
    billedAmount: Number(row.billed_amount),
    availableAfter: Number(row.available_after),
    frozenAfter: Number(row.frozen_after),
    idempotencyKey: row.idempotency_key,
    referenceId: row.reference_id,
    relatedTransactionId: row.related_transaction_id,
    description: row.description,
    metadata: row.metadata,
    occurredAt: row.occurred_at,
    createdAt: row.created_at,
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

  async getCommercialInventory(input: {
    nowMs: number;
    expiringWithinMs: number;
    recentLimit: number;
  }): Promise<CommercialInventorySnapshot> {
    const client = await this.#pool.connect();
    try {
      await client.query('BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY');
      const countResult = await client.query<CommercialInventoryCountRow>(
        `SELECT
          (SELECT COUNT(*)::text FROM control_customers) AS customer_total,
          (SELECT COUNT(*)::text FROM control_customers WHERE status = 'active')
            AS customer_active,
          (SELECT COUNT(*)::text FROM control_customers WHERE status = 'suspended')
            AS customer_suspended,
          (SELECT COUNT(*)::text FROM control_deployments) AS deployment_total,
          (SELECT COUNT(*)::text FROM control_deployments WHERE status = 'active')
            AS deployment_active,
          (SELECT COUNT(*)::text FROM control_deployments WHERE status = 'suspended')
            AS deployment_suspended,
          (SELECT COUNT(*)::text FROM control_licenses) AS license_total,
          (SELECT COUNT(*)::text FROM control_licenses
           WHERE revoked_at_ms IS NULL AND expires_at_ms > $1::bigint) AS license_active,
          (SELECT COUNT(*)::text FROM control_licenses
           WHERE revoked_at_ms IS NULL AND expires_at_ms > $1::bigint
             AND expires_at_ms <= ($1::bigint + $2::bigint)) AS license_expiring_soon,
          (SELECT COUNT(*)::text FROM control_licenses
           WHERE revoked_at_ms IS NULL AND expires_at_ms <= $1::bigint
             AND expires_at_ms + grace_period_ms > $1::bigint) AS license_grace,
          (SELECT COUNT(*)::text FROM control_licenses
           WHERE revoked_at_ms IS NULL
             AND expires_at_ms + grace_period_ms <= $1::bigint) AS license_expired,
          (SELECT COUNT(*)::text FROM control_licenses WHERE revoked_at_ms IS NOT NULL)
            AS license_revoked`,
        [input.nowMs, input.expiringWithinMs],
      );
      const customers = await client.query<CustomerRow>(
        `SELECT * FROM control_customers
         ORDER BY updated_at DESC, id DESC LIMIT $1`,
        [input.recentLimit],
      );
      const deployments = await client.query<DeploymentRow>(
        `SELECT deployments.*, customers.name AS customer_name
         FROM control_deployments deployments
         JOIN control_customers customers ON customers.id = deployments.customer_id
         ORDER BY deployments.updated_at DESC, deployments.id DESC LIMIT $1`,
        [input.recentLimit],
      );
      const licenses = await client.query<LicenseRow>(
        `SELECT * FROM control_licenses
         ORDER BY updated_at DESC, id DESC LIMIT $1`,
        [input.recentLimit],
      );
      await client.query('COMMIT');
      const counts = countResult.rows[0]!;
      return {
        generatedAt: new Date(input.nowMs),
        counts: {
          customers: {
            total: Number(counts.customer_total),
            active: Number(counts.customer_active),
            suspended: Number(counts.customer_suspended),
          },
          deployments: {
            total: Number(counts.deployment_total),
            active: Number(counts.deployment_active),
            suspended: Number(counts.deployment_suspended),
          },
          licenses: {
            total: Number(counts.license_total),
            active: Number(counts.license_active),
            expiringSoon: Number(counts.license_expiring_soon),
            grace: Number(counts.license_grace),
            expired: Number(counts.license_expired),
            revoked: Number(counts.license_revoked),
          },
        },
        recentCustomers: customers.rows.map(customerFromRow),
        recentDeployments: deployments.rows.map(deploymentFromRow),
        recentLicenses: licenses.rows.map(licenseFromRow),
      };
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
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

  async createReleaseArtifact(
    input: CreateReleaseArtifactRecordInput,
  ): Promise<ReleaseArtifactRecord> {
    try {
      const result = await this.#pool.query<ReleaseArtifactRow>(
        `INSERT INTO control_release_artifacts
          (id, release_id, distribution_id, release_version, source_commit, kind, platform,
           url, sha256, size_bytes, signing_key_id, signature, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $13)
         RETURNING *`,
        [
          input.id,
          input.releaseId,
          input.distributionId,
          input.releaseVersion,
          input.sourceCommit,
          input.kind,
          input.platform,
          input.url,
          input.sha256,
          input.sizeBytes,
          input.signingKeyId,
          input.signature,
          input.createdAt,
        ],
      );
      return releaseArtifactFromRow(result.rows[0]!);
    } catch (error) {
      if (postgresCode(error) === '23503') {
        throw conflict('release, distribution, or signing key does not exist');
      }
      if (postgresCode(error) === '23505') {
        throw conflict('release artifact already exists for this kind and platform');
      }
      throw error;
    }
  }

  async getReleaseArtifact(id: string): Promise<ReleaseArtifactRecord | null> {
    const result = await this.#pool.query<ReleaseArtifactRow>(
      'SELECT * FROM control_release_artifacts WHERE id = $1',
      [id],
    );
    return result.rows[0] ? releaseArtifactFromRow(result.rows[0]) : null;
  }

  async listReleaseArtifacts(releaseId: string): Promise<ReleaseArtifactRecord[]> {
    const result = await this.#pool.query<ReleaseArtifactRow>(
      `SELECT * FROM control_release_artifacts
       WHERE release_id = $1
       ORDER BY created_at ASC, id ASC`,
      [releaseId],
    );
    return result.rows.map(releaseArtifactFromRow);
  }

  async revokeReleaseArtifact(input: {
    id: string;
    actorId: string;
    reason: string;
    revokedAt: Date;
  }): Promise<ReleaseArtifactRevocationResult | null> {
    const client = await this.#pool.connect();
    try {
      await client.query('BEGIN');
      const selected = await client.query<ReleaseArtifactRow>(
        'SELECT * FROM control_release_artifacts WHERE id = $1 FOR UPDATE',
        [input.id],
      );
      const current = selected.rows[0];
      if (!current || current.state !== 'active') {
        await client.query('ROLLBACK');
        return null;
      }
      const revoked = await client.query<ReleaseArtifactRow>(
        `UPDATE control_release_artifacts
         SET state = 'revoked', revoked_at = $2, revoked_by = $3,
             revocation_reason = $4, updated_at = $2
         WHERE id = $1
         RETURNING *`,
        [input.id, input.revokedAt, input.actorId, input.reason],
      );
      const paused = await client.query(
        `UPDATE control_update_releases
         SET state = 'paused', updated_at = $2
         WHERE id = $1 AND state = 'active'`,
        [current.release_id, input.revokedAt],
      );
      await client.query('COMMIT');
      return {
        artifact: releaseArtifactFromRow(revoked.rows[0]!),
        releasePaused: paused.rowCount === 1,
      };
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
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

  async getCreditAccount(customerId: string): Promise<CreditAccountRecord | null> {
    const result = await this.#pool.query<CreditAccountRow>(
      'SELECT * FROM control_credit_accounts WHERE customer_id = $1',
      [customerId],
    );
    return result.rows[0] ? creditAccountFromRow(result.rows[0]) : null;
  }

  async setBillingRate(input: {
    customerId: string;
    module: OttoBillingModule;
    unitSize: number;
    creditsPerUnit: number;
    actorId: string;
    changedAt: Date;
  }): Promise<BillingRateRecord> {
    try {
      const result = await this.#pool.query<BillingRateRow>(
        `INSERT INTO control_billing_rates
          (customer_id, module, unit_size, credits_per_unit, updated_by, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $6)
         ON CONFLICT (customer_id, module) DO UPDATE SET
           unit_size = EXCLUDED.unit_size,
           credits_per_unit = EXCLUDED.credits_per_unit,
           updated_by = EXCLUDED.updated_by,
           updated_at = EXCLUDED.updated_at
         RETURNING *`,
        [
          input.customerId,
          input.module,
          input.unitSize,
          input.creditsPerUnit,
          input.actorId,
          input.changedAt,
        ],
      );
      return billingRateFromRow(result.rows[0]!);
    } catch (error) {
      if (postgresCode(error) === '23503') throw conflict('customer does not exist');
      throw error;
    }
  }

  async getBillingRate(
    customerId: string,
    module: OttoBillingModule,
  ): Promise<BillingRateRecord | null> {
    const result = await this.#pool.query<BillingRateRow>(
      'SELECT * FROM control_billing_rates WHERE customer_id = $1 AND module = $2',
      [customerId, module],
    );
    return result.rows[0] ? billingRateFromRow(result.rows[0]) : null;
  }

  async listBillingRates(customerId: string): Promise<BillingRateRecord[]> {
    const result = await this.#pool.query<BillingRateRow>(
      'SELECT * FROM control_billing_rates WHERE customer_id = $1 ORDER BY module',
      [customerId],
    );
    return result.rows.map(billingRateFromRow);
  }

  async topUpCredits(input: {
    transactionId: string;
    customerId: string;
    amount: number;
    idempotencyKey: string;
    referenceId: string;
    description: string;
    metadata: Record<string, unknown>;
    occurredAt: Date;
  }): Promise<CreditMutationResult> {
    const client = await this.#pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(
        `INSERT INTO control_credit_accounts (customer_id)
         VALUES ($1) ON CONFLICT DO NOTHING`,
        [input.customerId],
      );
      const accountResult = await client.query<CreditAccountRow>(
        'SELECT * FROM control_credit_accounts WHERE customer_id = $1 FOR UPDATE',
        [input.customerId],
      );
      const current = accountResult.rows[0];
      if (!current) throw conflict('customer does not exist');
      const existing = await client.query<CreditTransactionRow>(
        `SELECT * FROM control_credit_transactions
         WHERE customer_id = $1 AND idempotency_key = $2`,
        [input.customerId, input.idempotencyKey],
      );
      if (existing.rows[0]) {
        const transaction = creditTransactionFromRow(existing.rows[0]);
        if (
          transaction.type !== 'topup' ||
          transaction.availableDelta !== input.amount ||
          transaction.referenceId !== input.referenceId
        ) throw conflict('idempotency key was already used for a different operation');
        await client.query('COMMIT');
        return { account: creditAccountFromRow(current), transaction, replayed: true };
      }
      const updated = await client.query<CreditAccountRow>(
        `UPDATE control_credit_accounts SET
           available_balance = available_balance + $2,
           total_topped_up = total_topped_up + $2,
           version = version + 1,
           updated_at = $3
         WHERE customer_id = $1 RETURNING *`,
        [input.customerId, input.amount, input.occurredAt],
      );
      const account = creditAccountFromRow(updated.rows[0]!);
      const inserted = await client.query<CreditTransactionRow>(
        `INSERT INTO control_credit_transactions
          (id, customer_id, type, available_delta, frozen_delta, billed_amount,
           available_after, frozen_after, idempotency_key, reference_id,
           description, metadata, occurred_at)
         VALUES ($1, $2, 'topup', $3, 0, 0, $4, $5, $6, $7, $8, $9::jsonb, $10)
         RETURNING *`,
        [input.transactionId, input.customerId, input.amount, account.availableBalance,
          account.frozenBalance, input.idempotencyKey, input.referenceId,
          input.description, JSON.stringify(input.metadata), input.occurredAt],
      );
      await client.query('COMMIT');
      return {
        account,
        transaction: creditTransactionFromRow(inserted.rows[0]!),
        replayed: false,
      };
    } catch (error) {
      await client.query('ROLLBACK');
      if (postgresCode(error) === '23503') throw conflict('customer does not exist');
      if (postgresCode(error) === '23514') throw conflict('credit ledger limit exceeded');
      throw error;
    } finally {
      client.release();
    }
  }

  async createCreditHold(input: {
    holdId: string;
    transactionId: string;
    customerId: string;
    organizationId: string;
    deploymentId: string;
    module: OttoBillingModule;
    amount: number;
    idempotencyKey: string;
    expiresAt: Date;
    occurredAt: Date;
  }): Promise<CreditHoldMutationResult> {
    const client = await this.#pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(
        'INSERT INTO control_credit_accounts (customer_id) VALUES ($1) ON CONFLICT DO NOTHING',
        [input.customerId],
      );
      const accountResult = await client.query<CreditAccountRow>(
        'SELECT * FROM control_credit_accounts WHERE customer_id = $1 FOR UPDATE',
        [input.customerId],
      );
      const current = accountResult.rows[0];
      if (!current) throw conflict('customer does not exist');
      const existingHold = await client.query<CreditHoldRow>(
        `SELECT * FROM control_credit_holds
         WHERE customer_id = $1 AND idempotency_key = $2`,
        [input.customerId, input.idempotencyKey],
      );
      if (existingHold.rows[0]) {
        const hold = creditHoldFromRow(existingHold.rows[0]);
        if (
          hold.organizationId !== input.organizationId ||
          hold.deploymentId !== input.deploymentId ||
          hold.module !== input.module ||
          hold.amount !== input.amount
        ) throw conflict('idempotency key was already used for a different hold');
        const transactionResult = await client.query<CreditTransactionRow>(
          `SELECT * FROM control_credit_transactions
           WHERE customer_id = $1 AND idempotency_key = $2`,
          [input.customerId, input.idempotencyKey],
        );
        await client.query('COMMIT');
        return {
          account: creditAccountFromRow(current),
          hold,
          transaction: creditTransactionFromRow(transactionResult.rows[0]!),
          replayed: true,
        };
      }
      if (Number(current.available_balance) < input.amount) {
        throw conflict('insufficient available credits');
      }
      const updated = await client.query<CreditAccountRow>(
        `UPDATE control_credit_accounts SET
           available_balance = available_balance - $2,
           frozen_balance = frozen_balance + $2,
           version = version + 1,
           updated_at = $3
         WHERE customer_id = $1 RETURNING *`,
        [input.customerId, input.amount, input.occurredAt],
      );
      const account = creditAccountFromRow(updated.rows[0]!);
      const holdResult = await client.query<CreditHoldRow>(
        `INSERT INTO control_credit_holds
          (id, customer_id, organization_id, deployment_id, module, amount, status,
           idempotency_key, expires_at, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, 'active', $7, $8, $9, $9)
         RETURNING *`,
        [input.holdId, input.customerId, input.organizationId, input.deploymentId,
          input.module, input.amount, input.idempotencyKey, input.expiresAt, input.occurredAt],
      );
      const transactionResult = await client.query<CreditTransactionRow>(
        `INSERT INTO control_credit_transactions
          (id, customer_id, organization_id, deployment_id, module, type,
           available_delta, frozen_delta, billed_amount, available_after, frozen_after,
           idempotency_key, reference_id, description, occurred_at)
         VALUES ($1, $2, $3, $4, $5, 'freeze', $6, $7, 0, $8, $9, $10, $11, $12, $13)
         RETURNING *`,
        [input.transactionId, input.customerId, input.organizationId, input.deploymentId,
          input.module, -input.amount, input.amount, account.availableBalance,
          account.frozenBalance, input.idempotencyKey, input.holdId,
          'Credit hold created', input.occurredAt],
      );
      await client.query('COMMIT');
      return {
        account,
        hold: creditHoldFromRow(holdResult.rows[0]!),
        transaction: creditTransactionFromRow(transactionResult.rows[0]!),
        replayed: false,
      };
    } catch (error) {
      await client.query('ROLLBACK');
      if (postgresCode(error) === '23503') throw conflict('customer does not exist');
      throw error;
    } finally {
      client.release();
    }
  }

  async getCreditHold(id: string): Promise<CreditHoldRecord | null> {
    const result = await this.#pool.query<CreditHoldRow>(
      'SELECT * FROM control_credit_holds WHERE id = $1',
      [id],
    );
    return result.rows[0] ? creditHoldFromRow(result.rows[0]) : null;
  }

  async listExpiredCreditHolds(input: {
    customerId: string;
    expiredBefore: Date;
    limit: number;
  }): Promise<CreditHoldRecord[]> {
    const result = await this.#pool.query<CreditHoldRow>(
      `SELECT * FROM control_credit_holds
       WHERE customer_id = $1 AND status = 'active' AND expires_at <= $2
       ORDER BY expires_at, id LIMIT $3`,
      [input.customerId, input.expiredBefore, input.limit],
    );
    return result.rows.map(creditHoldFromRow);
  }

  async captureCreditHold(input: {
    transactionId: string;
    holdId: string;
    customerId: string;
    amount: number;
    idempotencyKey: string;
    referenceId: string;
    description: string;
    occurredAt: Date;
  }): Promise<CreditHoldMutationResult | null> {
    const client = await this.#pool.connect();
    try {
      await client.query('BEGIN');
      const accountResult = await client.query<CreditAccountRow>(
        'SELECT * FROM control_credit_accounts WHERE customer_id = $1 FOR UPDATE',
        [input.customerId],
      );
      const current = accountResult.rows[0];
      if (!current) {
        await client.query('ROLLBACK');
        return null;
      }
      const existing = await client.query<CreditTransactionRow>(
        `SELECT * FROM control_credit_transactions
         WHERE customer_id = $1 AND idempotency_key = $2`,
        [input.customerId, input.idempotencyKey],
      );
      if (existing.rows[0]) {
        const transaction = creditTransactionFromRow(existing.rows[0]);
        if (
          transaction.type !== 'capture' || transaction.referenceId !== input.referenceId ||
          transaction.metadata.holdId !== input.holdId || transaction.billedAmount !== input.amount
        ) throw conflict('idempotency key was already used for a different operation');
        const holdResult = await client.query<CreditHoldRow>(
          'SELECT * FROM control_credit_holds WHERE id = $1', [input.holdId],
        );
        await client.query('COMMIT');
        return {
          account: creditAccountFromRow(current),
          hold: creditHoldFromRow(holdResult.rows[0]!),
          transaction,
          replayed: true,
        };
      }
      const holdResult = await client.query<CreditHoldRow>(
        `SELECT * FROM control_credit_holds
         WHERE id = $1 AND customer_id = $2 FOR UPDATE`,
        [input.holdId, input.customerId],
      );
      const holdRow = holdResult.rows[0];
      if (!holdRow) {
        await client.query('ROLLBACK');
        return null;
      }
      if (holdRow.status !== 'active') throw conflict('credit hold is no longer active');
      if (holdRow.expires_at.getTime() <= input.occurredAt.getTime()) {
        throw conflict('credit hold has expired');
      }
      const heldAmount = Number(holdRow.amount);
      const availableDelta = heldAmount - input.amount;
      if (Number(current.available_balance) + availableDelta < 0) {
        throw conflict('insufficient available credits for capture');
      }
      const updated = await client.query<CreditAccountRow>(
        `UPDATE control_credit_accounts SET
           available_balance = available_balance + $2,
           frozen_balance = frozen_balance - $3,
           total_consumed = total_consumed + $4,
           version = version + 1,
           updated_at = $5
         WHERE customer_id = $1 RETURNING *`,
        [input.customerId, availableDelta, heldAmount, input.amount, input.occurredAt],
      );
      const account = creditAccountFromRow(updated.rows[0]!);
      const updatedHold = await client.query<CreditHoldRow>(
        `UPDATE control_credit_holds SET status = 'captured', updated_at = $2
         WHERE id = $1 RETURNING *`,
        [input.holdId, input.occurredAt],
      );
      const transactionResult = await client.query<CreditTransactionRow>(
        `INSERT INTO control_credit_transactions
          (id, customer_id, organization_id, deployment_id, module, type,
           available_delta, frozen_delta, billed_amount, available_after, frozen_after,
           idempotency_key, reference_id, description, metadata, occurred_at)
         VALUES ($1, $2, $3, $4, $5, 'capture', $6, $7, $8, $9, $10,
                 $11, $12, $13, $14::jsonb, $15)
         RETURNING *`,
        [input.transactionId, input.customerId, holdRow.organization_id, holdRow.deployment_id,
          holdRow.module, availableDelta, -heldAmount, input.amount, account.availableBalance,
          account.frozenBalance, input.idempotencyKey, input.referenceId,
          input.description, JSON.stringify({ holdId: input.holdId }), input.occurredAt],
      );
      await client.query('COMMIT');
      return {
        account,
        hold: creditHoldFromRow(updatedHold.rows[0]!),
        transaction: creditTransactionFromRow(transactionResult.rows[0]!),
        replayed: false,
      };
    } catch (error) {
      await client.query('ROLLBACK');
      if (postgresCode(error) === '23514') throw conflict('credit ledger limit exceeded');
      throw error;
    } finally {
      client.release();
    }
  }

  async releaseCreditHold(input: {
    transactionId: string;
    holdId: string;
    customerId: string;
    idempotencyKey: string;
    reason: 'released' | 'expired';
    description: string;
    occurredAt: Date;
  }): Promise<CreditHoldMutationResult | null> {
    const client = await this.#pool.connect();
    try {
      await client.query('BEGIN');
      const accountResult = await client.query<CreditAccountRow>(
        'SELECT * FROM control_credit_accounts WHERE customer_id = $1 FOR UPDATE',
        [input.customerId],
      );
      const current = accountResult.rows[0];
      if (!current) {
        await client.query('ROLLBACK');
        return null;
      }
      const existing = await client.query<CreditTransactionRow>(
        `SELECT * FROM control_credit_transactions
         WHERE customer_id = $1 AND idempotency_key = $2`,
        [input.customerId, input.idempotencyKey],
      );
      if (existing.rows[0]) {
        const transaction = creditTransactionFromRow(existing.rows[0]);
        if (transaction.type !== 'release' || transaction.referenceId !== input.holdId) {
          throw conflict('idempotency key was already used for a different operation');
        }
        const holdResult = await client.query<CreditHoldRow>(
          'SELECT * FROM control_credit_holds WHERE id = $1', [input.holdId],
        );
        await client.query('COMMIT');
        return {
          account: creditAccountFromRow(current),
          hold: creditHoldFromRow(holdResult.rows[0]!),
          transaction,
          replayed: true,
        };
      }
      const holdResult = await client.query<CreditHoldRow>(
        `SELECT * FROM control_credit_holds
         WHERE id = $1 AND customer_id = $2 FOR UPDATE`,
        [input.holdId, input.customerId],
      );
      const holdRow = holdResult.rows[0];
      if (!holdRow) {
        await client.query('ROLLBACK');
        return null;
      }
      if (holdRow.status !== 'active') throw conflict('credit hold is no longer active');
      const amount = Number(holdRow.amount);
      const updated = await client.query<CreditAccountRow>(
        `UPDATE control_credit_accounts SET
           available_balance = available_balance + $2,
           frozen_balance = frozen_balance - $2,
           version = version + 1,
           updated_at = $3
         WHERE customer_id = $1 RETURNING *`,
        [input.customerId, amount, input.occurredAt],
      );
      const account = creditAccountFromRow(updated.rows[0]!);
      const updatedHold = await client.query<CreditHoldRow>(
        `UPDATE control_credit_holds SET status = $2, updated_at = $3
         WHERE id = $1 RETURNING *`,
        [input.holdId, input.reason, input.occurredAt],
      );
      const transactionResult = await client.query<CreditTransactionRow>(
        `INSERT INTO control_credit_transactions
          (id, customer_id, organization_id, deployment_id, module, type,
           available_delta, frozen_delta, billed_amount, available_after, frozen_after,
           idempotency_key, reference_id, description, occurred_at)
         VALUES ($1, $2, $3, $4, $5, 'release', $6, $7, 0, $8, $9,
                 $10, $11, $12, $13)
         RETURNING *`,
        [input.transactionId, input.customerId, holdRow.organization_id, holdRow.deployment_id,
          holdRow.module, amount, -amount, account.availableBalance, account.frozenBalance,
          input.idempotencyKey, input.holdId, input.description, input.occurredAt],
      );
      await client.query('COMMIT');
      return {
        account,
        hold: creditHoldFromRow(updatedHold.rows[0]!),
        transaction: creditTransactionFromRow(transactionResult.rows[0]!),
        replayed: false,
      };
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async consumeCredits(input: {
    transactionId: string;
    customerId: string;
    organizationId: string;
    deploymentId: string;
    module: OttoBillingModule;
    amount: number;
    idempotencyKey: string;
    referenceId: string;
    description: string;
    metadata: Record<string, unknown>;
    occurredAt: Date;
  }): Promise<CreditMutationResult> {
    const client = await this.#pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(
        'INSERT INTO control_credit_accounts (customer_id) VALUES ($1) ON CONFLICT DO NOTHING',
        [input.customerId],
      );
      const accountResult = await client.query<CreditAccountRow>(
        'SELECT * FROM control_credit_accounts WHERE customer_id = $1 FOR UPDATE',
        [input.customerId],
      );
      const current = accountResult.rows[0];
      if (!current) throw conflict('customer does not exist');
      const existing = await client.query<CreditTransactionRow>(
        `SELECT * FROM control_credit_transactions
         WHERE customer_id = $1 AND idempotency_key = $2`,
        [input.customerId, input.idempotencyKey],
      );
      if (existing.rows[0]) {
        const transaction = creditTransactionFromRow(existing.rows[0]);
        if (
          transaction.type !== 'consume' || transaction.billedAmount !== input.amount ||
          transaction.organizationId !== input.organizationId ||
          transaction.deploymentId !== input.deploymentId || transaction.module !== input.module ||
          transaction.referenceId !== input.referenceId
        ) throw conflict('idempotency key was already used for a different operation');
        await client.query('COMMIT');
        return { account: creditAccountFromRow(current), transaction, replayed: true };
      }
      if (Number(current.available_balance) < input.amount) {
        throw conflict('insufficient available credits');
      }
      const updated = await client.query<CreditAccountRow>(
        `UPDATE control_credit_accounts SET
           available_balance = available_balance - $2,
           total_consumed = total_consumed + $2,
           version = version + 1,
           updated_at = $3
         WHERE customer_id = $1 RETURNING *`,
        [input.customerId, input.amount, input.occurredAt],
      );
      const account = creditAccountFromRow(updated.rows[0]!);
      const transactionResult = await client.query<CreditTransactionRow>(
        `INSERT INTO control_credit_transactions
          (id, customer_id, organization_id, deployment_id, module, type,
           available_delta, frozen_delta, billed_amount, available_after, frozen_after,
           idempotency_key, reference_id, description, metadata, occurred_at)
         VALUES ($1, $2, $3, $4, $5, 'consume', $6, 0, $7, $8, $9,
                 $10, $11, $12, $13::jsonb, $14)
         RETURNING *`,
        [input.transactionId, input.customerId, input.organizationId, input.deploymentId,
          input.module, -input.amount, input.amount, account.availableBalance,
          account.frozenBalance, input.idempotencyKey, input.referenceId,
          input.description, JSON.stringify(input.metadata), input.occurredAt],
      );
      await client.query('COMMIT');
      return {
        account,
        transaction: creditTransactionFromRow(transactionResult.rows[0]!),
        replayed: false,
      };
    } catch (error) {
      await client.query('ROLLBACK');
      if (postgresCode(error) === '23503') throw conflict('customer does not exist');
      if (postgresCode(error) === '23514') throw conflict('credit ledger limit exceeded');
      throw error;
    } finally {
      client.release();
    }
  }

  async refundCredits(input: {
    transactionId: string;
    customerId: string;
    relatedTransactionId: string;
    amount: number;
    idempotencyKey: string;
    referenceId: string;
    description: string;
    metadata: Record<string, unknown>;
    occurredAt: Date;
  }): Promise<CreditMutationResult | null> {
    const client = await this.#pool.connect();
    try {
      await client.query('BEGIN');
      const accountResult = await client.query<CreditAccountRow>(
        'SELECT * FROM control_credit_accounts WHERE customer_id = $1 FOR UPDATE',
        [input.customerId],
      );
      const current = accountResult.rows[0];
      if (!current) {
        await client.query('ROLLBACK');
        return null;
      }
      const existing = await client.query<CreditTransactionRow>(
        `SELECT * FROM control_credit_transactions
         WHERE customer_id = $1 AND idempotency_key = $2`,
        [input.customerId, input.idempotencyKey],
      );
      if (existing.rows[0]) {
        const transaction = creditTransactionFromRow(existing.rows[0]);
        if (
          transaction.type !== 'refund' || transaction.billedAmount !== input.amount ||
          transaction.relatedTransactionId !== input.relatedTransactionId ||
          transaction.referenceId !== input.referenceId
        ) throw conflict('idempotency key was already used for a different operation');
        await client.query('COMMIT');
        return { account: creditAccountFromRow(current), transaction, replayed: true };
      }
      const originalResult = await client.query<CreditTransactionRow>(
        `SELECT * FROM control_credit_transactions
         WHERE id = $1 AND customer_id = $2 FOR UPDATE`,
        [input.relatedTransactionId, input.customerId],
      );
      const original = originalResult.rows[0];
      if (!original || !['consume', 'capture'].includes(original.type)) {
        await client.query('ROLLBACK');
        return null;
      }
      const refundedResult = await client.query<{ total: string }>(
        `SELECT COALESCE(SUM(billed_amount), 0)::text AS total
         FROM control_credit_transactions
         WHERE related_transaction_id = $1 AND type = 'refund'`,
        [input.relatedTransactionId],
      );
      if (Number(refundedResult.rows[0]!.total) + input.amount > Number(original.billed_amount)) {
        throw conflict('refund exceeds the remaining refundable amount');
      }
      const updated = await client.query<CreditAccountRow>(
        `UPDATE control_credit_accounts SET
           available_balance = available_balance + $2,
           total_refunded = total_refunded + $2,
           version = version + 1,
           updated_at = $3
         WHERE customer_id = $1 RETURNING *`,
        [input.customerId, input.amount, input.occurredAt],
      );
      const account = creditAccountFromRow(updated.rows[0]!);
      const transactionResult = await client.query<CreditTransactionRow>(
        `INSERT INTO control_credit_transactions
          (id, customer_id, organization_id, deployment_id, module, type,
           available_delta, frozen_delta, billed_amount, available_after, frozen_after,
           idempotency_key, reference_id, related_transaction_id, description, metadata,
           occurred_at)
         VALUES ($1, $2, $3, $4, $5, 'refund', $6, 0, $6, $7, $8,
                 $9, $10, $11, $12, $13::jsonb, $14)
         RETURNING *`,
        [input.transactionId, input.customerId, original.organization_id,
          original.deployment_id, original.module, input.amount, account.availableBalance,
          account.frozenBalance, input.idempotencyKey, input.referenceId,
          input.relatedTransactionId, input.description, JSON.stringify(input.metadata),
          input.occurredAt],
      );
      await client.query('COMMIT');
      return {
        account,
        transaction: creditTransactionFromRow(transactionResult.rows[0]!),
        replayed: false,
      };
    } catch (error) {
      await client.query('ROLLBACK');
      if (postgresCode(error) === '23514') throw conflict('credit ledger limit exceeded');
      throw error;
    } finally {
      client.release();
    }
  }

  async listCreditTransactions(input: {
    customerId: string;
    from: Date;
    to: Date;
    organizationId?: string;
    module?: OttoBillingModule;
    limit: number;
  }): Promise<CreditTransactionRecord[]> {
    const values: unknown[] = [input.customerId, input.from, input.to];
    const conditions = [
      'customer_id = $1',
      'occurred_at >= $2',
      'occurred_at < $3',
    ];
    if (input.organizationId) {
      values.push(input.organizationId);
      conditions.push(`organization_id = $${values.length}`);
    }
    if (input.module) {
      values.push(input.module);
      conditions.push(`module = $${values.length}`);
    }
    values.push(input.limit);
    const result = await this.#pool.query<CreditTransactionRow>(
      `SELECT * FROM control_credit_transactions
       WHERE ${conditions.join(' AND ')}
       ORDER BY occurred_at DESC, id DESC
       LIMIT $${values.length}`,
      values,
    );
    return result.rows.map(creditTransactionFromRow);
  }

  async getCreditStatement(input: {
    customerId: string;
    from: Date;
    to: Date;
  }): Promise<CreditStatement | null> {
    const account = await this.getCreditAccount(input.customerId);
    if (!account) return null;
    const totals = await this.#pool.query<{
      opening_balance: string;
      period_delta: string;
      topped_up: string;
      consumed: string;
      refunded: string;
    }>(
      `SELECT
         COALESCE(SUM(available_delta + frozen_delta)
           FILTER (WHERE occurred_at < $2), 0)::text AS opening_balance,
         COALESCE(SUM(available_delta + frozen_delta)
           FILTER (WHERE occurred_at >= $2 AND occurred_at < $3), 0)::text AS period_delta,
         COALESCE(SUM(available_delta)
           FILTER (WHERE type = 'topup' AND occurred_at >= $2 AND occurred_at < $3), 0)::text
           AS topped_up,
         COALESCE(SUM(billed_amount)
           FILTER (WHERE type IN ('consume', 'capture') AND occurred_at >= $2 AND occurred_at < $3), 0)::text
           AS consumed,
         COALESCE(SUM(billed_amount)
           FILTER (WHERE type = 'refund' AND occurred_at >= $2 AND occurred_at < $3), 0)::text
           AS refunded
       FROM control_credit_transactions WHERE customer_id = $1`,
      [input.customerId, input.from, input.to],
    );
    const lines = await this.#pool.query<{
      organization_id: string;
      module: OttoBillingModule;
      consumed: string;
      refunded: string;
      transaction_count: string;
    }>(
      `SELECT organization_id, module,
         COALESCE(SUM(billed_amount) FILTER (WHERE type IN ('consume', 'capture')), 0)::text
           AS consumed,
         COALESCE(SUM(billed_amount) FILTER (WHERE type = 'refund'), 0)::text AS refunded,
         COUNT(*)::text AS transaction_count
       FROM control_credit_transactions
       WHERE customer_id = $1 AND occurred_at >= $2 AND occurred_at < $3
         AND organization_id IS NOT NULL AND module IS NOT NULL
         AND type IN ('consume', 'capture', 'refund')
       GROUP BY organization_id, module
       ORDER BY organization_id, module`,
      [input.customerId, input.from, input.to],
    );
    const summary = totals.rows[0]!;
    const openingBalance = Number(summary.opening_balance);
    return {
      customerId: input.customerId,
      from: input.from,
      to: input.to,
      openingBalance,
      closingBalance: openingBalance + Number(summary.period_delta),
      totalToppedUp: Number(summary.topped_up),
      totalConsumed: Number(summary.consumed),
      totalRefunded: Number(summary.refunded),
      lines: lines.rows.map((line) => ({
        organizationId: line.organization_id,
        module: line.module,
        consumedCredits: Number(line.consumed),
        refundedCredits: Number(line.refunded),
        netCredits: Number(line.consumed) - Number(line.refunded),
        transactionCount: Number(line.transaction_count),
      })),
    };
  }

  async enqueueAlertDelivery(input: {
    id: string;
    source: AlertDeliveryRecord['source'];
    eventType: AlertDeliveryRecord['eventType'];
    fingerprint: string;
    severity: AlertSeverity;
    payload: AlertDeliveryPayload;
    createdAt: Date;
    audit: AuditEventInput;
  }): Promise<{ record: AlertDeliveryRecord; created: boolean }> {
    const client = await this.#pool.connect();
    try {
      await client.query('BEGIN');
      const inserted = await client.query<AlertDeliveryRow>(
        `INSERT INTO control_alert_deliveries
          (id, source, event_type, fingerprint, severity, payload, status, attempts,
           next_attempt_at, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6::jsonb, 'pending', 0, $7, $7, $7)
         ON CONFLICT (fingerprint) DO NOTHING
         RETURNING *`,
        [
          input.id,
          input.source,
          input.eventType,
          input.fingerprint,
          input.severity,
          JSON.stringify(input.payload),
          input.createdAt,
        ],
      );
      if (inserted.rows[0]) {
        await client.query(
          `INSERT INTO control_audit_events
           (actor_id, action, target_type, target_id, detail)
           VALUES ($1, $2, $3, $4, $5::jsonb)`,
          [
            input.audit.actorId,
            input.audit.action,
            input.audit.targetType,
            input.audit.targetId,
            JSON.stringify(input.audit.detail),
          ],
        );
        await client.query('COMMIT');
        return { record: alertDeliveryFromRow(inserted.rows[0]), created: true };
      }
      const existing = await client.query<AlertDeliveryRow>(
        'SELECT * FROM control_alert_deliveries WHERE fingerprint = $1',
        [input.fingerprint],
      );
      if (!existing.rows[0]) throw new Error('alert delivery conflict could not be resolved');
      await client.query('COMMIT');
      return { record: alertDeliveryFromRow(existing.rows[0]), created: false };
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async claimAlertDelivery(input: {
    now: Date;
    leaseUntil: Date;
  }): Promise<AlertDeliveryRecord | null> {
    const result = await this.#pool.query<AlertDeliveryRow>(
      `WITH candidate AS (
         SELECT id FROM control_alert_deliveries
         WHERE ((status IN ('pending', 'retrying') AND next_attempt_at <= $1)
           OR (status = 'delivering' AND lease_until <= $1))
         ORDER BY next_attempt_at ASC, created_at ASC, id ASC
         FOR UPDATE SKIP LOCKED
         LIMIT 1
       )
       UPDATE control_alert_deliveries AS delivery
       SET status = 'delivering', attempts = delivery.attempts + 1,
           lease_until = $2, updated_at = $1
       FROM candidate
       WHERE delivery.id = candidate.id
       RETURNING delivery.*`,
      [input.now, input.leaseUntil],
    );
    return result.rows[0] ? alertDeliveryFromRow(result.rows[0]) : null;
  }

  async finishAlertDelivery(input: {
    id: string;
    expectedLeaseUntil: Date;
    status: Extract<AlertDeliveryStatus, 'delivered' | 'retrying' | 'failed'>;
    nextAttemptAt: Date;
    lastError: string | null;
    deliveredAt: Date | null;
    updatedAt: Date;
    audit: AuditEventInput | null;
  }): Promise<AlertDeliveryRecord | null> {
    const client = await this.#pool.connect();
    try {
      await client.query('BEGIN');
      const result = await client.query<AlertDeliveryRow>(
        `UPDATE control_alert_deliveries
         SET status = $2, next_attempt_at = $3, lease_until = NULL, last_error = $4,
             delivered_at = $5, updated_at = $6
         WHERE id = $1 AND status = 'delivering' AND lease_until = $7
         RETURNING *`,
        [
          input.id,
          input.status,
          input.nextAttemptAt,
          input.lastError,
          input.deliveredAt,
          input.updatedAt,
          input.expectedLeaseUntil,
        ],
      );
      if (result.rows[0] && input.audit) {
        await client.query(
          `INSERT INTO control_audit_events
           (actor_id, action, target_type, target_id, detail)
           VALUES ($1, $2, $3, $4, $5::jsonb)`,
          [
            input.audit.actorId,
            input.audit.action,
            input.audit.targetType,
            input.audit.targetId,
            JSON.stringify(input.audit.detail),
          ],
        );
      }
      await client.query('COMMIT');
      return result.rows[0] ? alertDeliveryFromRow(result.rows[0]) : null;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async listAlertDeliveries(limit: number): Promise<AlertDeliveryRecord[]> {
    const result = await this.#pool.query<AlertDeliveryRow>(
      `SELECT * FROM control_alert_deliveries
       ORDER BY created_at DESC, id DESC
       LIMIT $1`,
      [limit],
    );
    return result.rows.map(alertDeliveryFromRow);
  }

  async getAlertDelivery(id: string): Promise<AlertDeliveryRecord | null> {
    const result = await this.#pool.query<AlertDeliveryRow>(
      'SELECT * FROM control_alert_deliveries WHERE id = $1',
      [id],
    );
    return result.rows[0] ? alertDeliveryFromRow(result.rows[0]) : null;
  }

  async retryAlertDelivery(input: {
    id: string;
    retriedAt: Date;
    audit: AuditEventInput;
  }): Promise<AlertDeliveryRecord | null> {
    const client = await this.#pool.connect();
    try {
      await client.query('BEGIN');
      const result = await client.query<AlertDeliveryRow>(
        `UPDATE control_alert_deliveries
         SET status = 'pending', attempts = 0, next_attempt_at = $2,
             lease_until = NULL, last_error = NULL, delivered_at = NULL, updated_at = $2
         WHERE id = $1 AND status = 'failed'
         RETURNING *`,
        [input.id, input.retriedAt],
      );
      if (result.rows[0]) {
        await client.query(
          `INSERT INTO control_audit_events
           (actor_id, action, target_type, target_id, detail)
           VALUES ($1, $2, $3, $4, $5::jsonb)`,
          [
            input.audit.actorId,
            input.audit.action,
            input.audit.targetType,
            input.audit.targetId,
            JSON.stringify(input.audit.detail),
          ],
        );
      }
      await client.query('COMMIT');
      return result.rows[0] ? alertDeliveryFromRow(result.rows[0]) : null;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async pruneAlertDeliveries(before: Date): Promise<number> {
    const result = await this.#pool.query(
      `DELETE FROM control_alert_deliveries
       WHERE status IN ('delivered', 'failed') AND updated_at < $1`,
      [before],
    );
    return result.rowCount ?? 0;
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

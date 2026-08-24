import { createHash } from 'node:crypto';

import pg, { type PoolClient } from 'pg';

import type { EdgeModelUsageV1 } from '../contracts/edge-gateway.js';
import { canonicalJson } from '../crypto/signed-envelope.js';
import type {
  EdgeBillingOutboxAction,
  PreparedEdgeBillingDelivery,
} from './billing-coordinator.js';
import {
  assertEdgeRequestBinding,
  assertEdgeRequestRecord,
  EdgeRequestLedgerConflictError,
  EdgeRequestLedgerCorruptionError,
  EdgeRequestLedgerEngine,
  normalizeEdgeRequestId,
  type EdgeRequestAdmission,
  type EdgeRequestAdmissionResult,
  type EdgeRequestBinding,
  type EdgeRequestLedger,
  type EdgeRequestRecord,
  type EdgeRequestTerminalCommit,
} from './request-ledger.js';

const { Pool } = pg;
const LOCK_NAMESPACE = 'otto_edge_request_ledger:';
const OWNER_IDENTIFIER = /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,159}$/u;
const DEFAULT_LEASE_DURATION_MS = 30_000;
const MAX_LEASE_DURATION_MS = 24 * 60 * 60 * 1_000;
const OUTBOX_STATE = ['pending', 'prepared', 'delivered', 'dead_letter'] as const;
const OUTBOX_ERROR_CODE = /^[A-Z][A-Z0-9_]{0,127}$/u;
const SEQUENCE_SCOPE = /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,159}$/u;
const MAX_OUTBOX_BATCH = 100;
const DEFAULT_OUTBOX_RETRY_BASE_MS = 1_000;
const DEFAULT_OUTBOX_RETRY_MAX_MS = 5 * 60 * 1_000;
const MAX_PREPARED_DELIVERY_BYTES = 1024 * 1024;
export interface PostgresEdgeRequestLedgerOptions {
  connectionString?: string;
  pool?: pg.Pool;
  ssl?: boolean;
  ownerId: string;
  leaseDurationMs?: number;
  now?: () => number;
  manageSchema?: boolean;
  onPoolError?: (error: Error) => void;
}

export interface PostgresEdgeRequestLease {
  ownerId: string;
  leaseUntilMs: number;
  fencingEpoch: number;
  record: EdgeRequestRecord;
}
export type { PreparedEdgeBillingDelivery } from './billing-coordinator.js';

export interface PrepareEdgeBillingDeliveryInput {
  request: EdgeRequestRecord;
  action: EdgeBillingOutboxAction;
  sequenceScope: string;
  sequence: number;
}

export interface ClaimEdgeBillingOutboxOptions {
  sequenceScope: string;
  limit?: number;
  leaseDurationMs?: number;
  prepare(
    input: PrepareEdgeBillingDeliveryInput,
  ): PreparedEdgeBillingDelivery | Promise<PreparedEdgeBillingDelivery>;
}

export interface ClaimedEdgeBillingDelivery {
  requestId: string;
  action: EdgeBillingOutboxAction;
  actionHash: string;
  preparedDelivery: PreparedEdgeBillingDelivery;
  preparedHash: string;
  sequenceScope: string;
  sequence: number;
  claimOwner: string;
  claimUntilMs: number;
  claimEpoch: number;
  attempts: number;
}

export interface EdgeBillingOutboxFence {
  requestId: string;
  claimEpoch: number;
}

export interface RetryEdgeBillingOutboxInput extends EdgeBillingOutboxFence {
  errorCode: string;
  baseDelayMs?: number;
  maxDelayMs?: number;
}

export interface RetriedEdgeBillingDelivery {
  requestId: string;
  attempts: number;
  nextAttemptAtMs: number;
}

export class EdgeBillingOutboxCorruptionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EdgeBillingOutboxCorruptionError';
  }
}

type LedgerAccess = 'admit' | 'lookup' | 'write' | 'renew' | 'finalize';

interface EdgeRequestLedgerRow {
  request_id: string;
  record_json: unknown;
  record_hash: string;
  owner_id: string | null;
  lease_until_ms: string | number | null;
  fencing_epoch: string | number;
}
interface EdgeBillingOutboxRow {
  request_id: string;
  action_kind: string;
  action_json: unknown;
  action_hash: string;
  state: string;
  sequence_scope: string | null;
  delivery_sequence: string | number | null;
  prepared_json: unknown | null;
  prepared_hash: string | null;
  claim_owner: string | null;
  claim_until_ms: string | number | null;
  claim_epoch: string | number;
  attempts: string | number;
  next_attempt_at_ms: string | number;
  last_error_code: string | null;
}

interface JoinedEdgeBillingOutboxRow extends EdgeBillingOutboxRow {
  record_json: unknown;
  record_hash: string;
  request_owner_id: string | null;
  request_lease_until_ms: string | number | null;
  request_fencing_epoch: string | number;
}

type EdgeBillingOutboxState = (typeof OUTBOX_STATE)[number];

interface ParsedEdgeBillingOutbox {
  requestId: string;
  action: EdgeBillingOutboxAction;
  actionHash: string;
  state: EdgeBillingOutboxState;
  sequenceScope: string | null;
  sequence: number | null;
  preparedDelivery: PreparedEdgeBillingDelivery | null;
  preparedHash: string | null;
  claimOwner: string | null;
  claimUntilMs: number | null;
  claimEpoch: number;
  attempts: number;
  nextAttemptAtMs: number;
  lastErrorCode: string | null;
}

interface StoredRequest {
  record: EdgeRequestRecord;
  ownerId: string | null;
  leaseUntilMs: number | null;
  fencingEpoch: number;
}

interface LeaseFence {
  ownerId: string;
  leaseUntilMs: number;
  fencingEpoch: number;
}

function normalizeOwnerId(value: string): string {
  const ownerId = value?.trim();
  if (!OWNER_IDENTIFIER.test(ownerId)) {
    throw new TypeError('PostgreSQL edge request owner ID is invalid');
  }
  return ownerId;
}

function normalizeLeaseDuration(value: number | undefined): number {
  const duration = value ?? DEFAULT_LEASE_DURATION_MS;
  if (!Number.isSafeInteger(duration) || duration < 1 || duration > MAX_LEASE_DURATION_MS) {
    throw new TypeError('PostgreSQL edge request lease duration is invalid');
  }
  return duration;
}

function recordDigest(record: EdgeRequestRecord): string {
  return createHash('sha256')
    .update(canonicalJson(record), 'utf8')
    .digest('hex');
}

function parseStoredInteger(value: string | number, field: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new EdgeRequestLedgerCorruptionError(
      `PostgreSQL edge request ${field} is invalid`,
    );
  }
  return parsed;
}

function recordFromRow(row: EdgeRequestLedgerRow): StoredRequest {
  let value = row.record_json;
  if (typeof value === 'string') {
    try {
      value = JSON.parse(value) as unknown;
    } catch {
      throw new EdgeRequestLedgerCorruptionError(
        'PostgreSQL edge request record JSON is invalid',
      );
    }
  }
  const record = assertEdgeRequestRecord(value);
  if (record.requestId !== row.request_id || recordDigest(record) !== row.record_hash) {
    throw new EdgeRequestLedgerCorruptionError(
      'PostgreSQL edge request record integrity check failed',
    );
  }
  let ownerId: string | null = null;
  if (row.owner_id !== null) {
    try {
      ownerId = normalizeOwnerId(row.owner_id);
    } catch {
      throw new EdgeRequestLedgerCorruptionError(
        'PostgreSQL edge request owner ID is invalid',
      );
    }
  }
  const leaseUntilMs = row.lease_until_ms === null
    ? null
    : parseStoredInteger(row.lease_until_ms, 'lease deadline');
  const fencingEpoch = parseStoredInteger(row.fencing_epoch, 'fencing epoch');
  if ((ownerId === null) !== (leaseUntilMs === null)
    || (ownerId !== null && fencingEpoch < 1)
    || (ownerId === null && fencingEpoch !== 0)) {
    throw new EdgeRequestLedgerCorruptionError(
      'PostgreSQL edge request lease metadata is inconsistent',
    );
  }
  return { record, ownerId, leaseUntilMs, fencingEpoch };
}

function jsonDigest(value: unknown): string {
  return createHash('sha256')
    .update(canonicalJson(value), 'utf8')
    .digest('hex');
}

function normalizeJsonObject(
  value: unknown,
  label: string,
  maximumBytes = Number.POSITIVE_INFINITY,
): Record<string, unknown> {
  try {
    const serialized = canonicalJson(value);
    if (Buffer.byteLength(serialized, 'utf8') > maximumBytes) {
      throw new Error(`${label} is too large`);
    }
    const parsed = JSON.parse(serialized) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error(`${label} must be an object`);
    }
    return parsed as Record<string, unknown>;
  } catch (error) {
    if (error instanceof EdgeBillingOutboxCorruptionError) throw error;
    throw new EdgeBillingOutboxCorruptionError(
      `${label} is not canonical JSON`,
    );
  }
}

function exactKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
  label: string,
): void {
  if (Object.keys(value).some((key) => !allowed.includes(key))) {
    throw new EdgeBillingOutboxCorruptionError(`${label} contains forbidden fields`);
  }
}

function requiredText(value: unknown, label: string, maximum = 512): string {
  if (typeof value !== 'string' || value.length < 1 || value.length > maximum
    || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new EdgeBillingOutboxCorruptionError(`${label} is invalid`);
  }
  return value;
}

function safeUnsignedInteger(value: unknown, label: string): number {
  const result = Number(value);
  if (!Number.isSafeInteger(result) || result < 0) {
    throw new EdgeBillingOutboxCorruptionError(`${label} is invalid`);
  }
  return result;
}

function normalizeSequenceScope(value: string): string {
  const scope = value?.trim();
  if (!SEQUENCE_SCOPE.test(scope)) {
    throw new TypeError('edge billing sequence scope is invalid');
  }
  return scope;
}

function normalizeOutboxLimit(value: number | undefined): number {
  const limit = value ?? 10;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_OUTBOX_BATCH) {
    throw new TypeError('edge billing outbox claim limit is invalid');
  }
  return limit;
}

function normalizeRetryDelay(value: number | undefined, fallback: number): number {
  const delay = value ?? fallback;
  if (!Number.isSafeInteger(delay) || delay < 1 || delay > MAX_LEASE_DURATION_MS) {
    throw new TypeError('edge billing outbox retry delay is invalid');
  }
  return delay;
}

function sameUsage(left: EdgeModelUsageV1, right: EdgeModelUsageV1): boolean {
  return left.inputTokens === right.inputTokens
    && left.outputTokens === right.outputTokens
    && left.totalTokens === right.totalTokens;
}

function parseEdgeBillingAction(
  value: unknown,
  requestRecord: EdgeRequestRecord,
): EdgeBillingOutboxAction {
  const action = normalizeJsonObject(value, 'edge billing outbox action');
  exactKeys(action, ['type', 'request'], 'edge billing outbox action');
  const type = action.type;
  if (type !== 'settle' && type !== 'release' && type !== 'uncertain') {
    throw new EdgeBillingOutboxCorruptionError('edge billing outbox action type is invalid');
  }
  const request = normalizeJsonObject(action.request, 'edge billing outbox request');
  const commonKeys = [
    'requestId', 'tokenId', 'deploymentId', 'organizationId', 'subjectId',
    'endpoint', 'publicModel', 'policyVersion', 'reservation', 'occurredAtMs',
  ];
  const typeKeys = type === 'settle'
    ? ['routeId', 'usage']
    : type === 'release' ? ['reason'] : ['routeId', 'reason'];
  exactKeys(request, [...commonKeys, ...typeKeys], 'edge billing outbox request');
  if (requiredText(request.requestId, 'edge billing request ID', 128)
      !== requestRecord.requestId
    || requiredText(request.deploymentId, 'edge billing deployment ID', 160)
      !== requestRecord.tenant.deploymentId
    || requiredText(request.organizationId, 'edge billing organization ID', 160)
      !== requestRecord.tenant.organizationId
    || requiredText(request.subjectId, 'edge billing subject ID', 160)
      !== requestRecord.tenant.subjectId) {
    throw new EdgeBillingOutboxCorruptionError(
      'edge billing action is bound to another request or tenant',
    );
  }
  requiredText(request.tokenId, 'edge billing token ID', 160);
  requiredText(request.publicModel, 'edge billing public model');
  requiredText(request.policyVersion, 'edge billing policy version', 160);
  if (request.endpoint !== 'chat_completions' && request.endpoint !== 'responses') {
    throw new EdgeBillingOutboxCorruptionError('edge billing endpoint is invalid');
  }
  const reservation = normalizeJsonObject(
    request.reservation,
    'edge billing reservation',
  );
  exactKeys(reservation, ['reservationId'], 'edge billing reservation');
  requiredText(reservation.reservationId, 'edge billing reservation ID');
  const occurredAtMs = safeUnsignedInteger(
    request.occurredAtMs,
    'edge billing occurrence time',
  );
  if (occurredAtMs < requestRecord.createdAtMs) {
    throw new EdgeBillingOutboxCorruptionError(
      'edge billing occurrence predates the admitted request',
    );
  }

  if (requestRecord.state === 'completed') {
    if (type === 'uncertain') {
      throw new EdgeBillingOutboxCorruptionError(
        'completed requests may only settle or release billing',
      );
    }
  } else if (requestRecord.state === 'not_sent') {
    if (type !== 'release') {
      throw new EdgeBillingOutboxCorruptionError(
        'not-sent requests may only release billing',
      );
    }
  } else if (requestRecord.state === 'unknown_outcome') {
    if (type !== 'uncertain') {
      throw new EdgeBillingOutboxCorruptionError(
        'unknown requests may only preserve uncertain billing',
      );
    }
  } else {
    throw new EdgeBillingOutboxCorruptionError(
      'billing action requires a terminal request state',
    );
  }

  if (type === 'settle') {
    if (!requestRecord.actualUsage || requestRecord.routeId === null
      || request.routeId !== requestRecord.routeId) {
      throw new EdgeBillingOutboxCorruptionError(
        'billing settlement route does not match the completed request',
      );
    }
    const usage = normalizeJsonObject(request.usage, 'edge billing usage');
    exactKeys(usage, ['inputTokens', 'outputTokens', 'totalTokens'], 'edge billing usage');
    const normalizedUsage: EdgeModelUsageV1 = {
      inputTokens: safeUnsignedInteger(usage.inputTokens, 'billing input tokens'),
      outputTokens: safeUnsignedInteger(usage.outputTokens, 'billing output tokens'),
      totalTokens: safeUnsignedInteger(usage.totalTokens, 'billing total tokens'),
    };
    if (normalizedUsage.totalTokens
        < normalizedUsage.inputTokens + normalizedUsage.outputTokens
      || !sameUsage(normalizedUsage, requestRecord.actualUsage)) {
      throw new EdgeBillingOutboxCorruptionError(
        'billing settlement usage does not match the completed request',
      );
    }
  } else if (type === 'release') {
    if (!['no_usable_route', 'unmetered_route', 'upstream_rejected', 'zero_usage']
      .includes(String(request.reason))) {
      throw new EdgeBillingOutboxCorruptionError('edge billing release reason is invalid');
    }
  } else {
    if (requestRecord.routeId === null || request.routeId !== requestRecord.routeId) {
      throw new EdgeBillingOutboxCorruptionError(
        'uncertain billing route does not match the request',
      );
    }
    if (![
      'client_cancelled', 'provider_error', 'response_limit_exceeded',
      'stream_timed_out', 'usage_unavailable',
    ].includes(String(request.reason))) {
      throw new EdgeBillingOutboxCorruptionError('edge billing uncertainty reason is invalid');
    }
  }
  return action as unknown as EdgeBillingOutboxAction;
}

function parsePreparedDelivery(value: unknown): PreparedEdgeBillingDelivery {
  return normalizeJsonObject(
    value,
    'prepared edge billing delivery',
    MAX_PREPARED_DELIVERY_BYTES,
  ) as unknown as PreparedEdgeBillingDelivery;
}

function parseOutboxRow(
  row: EdgeBillingOutboxRow,
  requestRecord: EdgeRequestRecord,
): ParsedEdgeBillingOutbox {
  const action = parseEdgeBillingAction(row.action_json, requestRecord);
  const actionHash = requiredText(row.action_hash, 'edge billing action hash', 64);
  if (!/^[a-f0-9]{64}$/u.test(actionHash)
    || actionHash !== jsonDigest(action)
    || row.action_kind !== action.type) {
    throw new EdgeBillingOutboxCorruptionError(
      'edge billing action integrity check failed',
    );
  }
  if (!OUTBOX_STATE.includes(row.state as EdgeBillingOutboxState)) {
    throw new EdgeBillingOutboxCorruptionError('edge billing outbox state is invalid');
  }
  const sequenceScope = row.sequence_scope === null
    ? null
    : normalizeSequenceScope(row.sequence_scope);
  const sequence = row.delivery_sequence === null
    ? null
    : safeUnsignedInteger(row.delivery_sequence, 'edge billing sequence');
  const preparedDelivery = row.prepared_json === null
    ? null
    : parsePreparedDelivery(row.prepared_json);
  const preparedHash = row.prepared_hash === null
    ? null
    : requiredText(row.prepared_hash, 'prepared edge billing hash', 64);
  if ((sequenceScope === null) !== (sequence === null)
    || (sequence === null) !== (preparedDelivery === null)
    || (preparedDelivery === null) !== (preparedHash === null)
    || (preparedDelivery !== null
      && (!/^[a-f0-9]{64}$/u.test(preparedHash!)
        || jsonDigest(preparedDelivery) !== preparedHash))) {
    throw new EdgeBillingOutboxCorruptionError(
      'prepared edge billing delivery integrity check failed',
    );
  }
  const claimOwner = row.claim_owner === null ? null : normalizeOwnerId(row.claim_owner);
  const claimUntilMs = row.claim_until_ms === null
    ? null
    : safeUnsignedInteger(row.claim_until_ms, 'edge billing claim deadline');
  const claimEpoch = safeUnsignedInteger(row.claim_epoch, 'edge billing claim epoch');
  const attempts = safeUnsignedInteger(row.attempts, 'edge billing attempts');
  const nextAttemptAtMs = safeUnsignedInteger(
    row.next_attempt_at_ms,
    'edge billing next attempt time',
  );
  if ((claimOwner === null) !== (claimUntilMs === null)
    || (claimOwner !== null && claimEpoch < 1)
    || ((row.state === 'prepared' || row.state === 'delivered')
      && preparedDelivery === null)
    || (row.state === 'pending' && preparedDelivery !== null)
    || (row.state === 'delivered' && claimOwner !== null)
    || (row.last_error_code !== null && !OUTBOX_ERROR_CODE.test(row.last_error_code))) {
    throw new EdgeBillingOutboxCorruptionError(
      'edge billing outbox metadata is inconsistent',
    );
  }
  return {
    requestId: normalizeEdgeRequestId(row.request_id),
    action,
    actionHash,
    state: row.state as EdgeBillingOutboxState,
    sequenceScope,
    sequence,
    preparedDelivery,
    preparedHash,
    claimOwner,
    claimUntilMs,
    claimEpoch,
    attempts,
    nextAttemptAtMs,
    lastErrorCode: row.last_error_code,
  };
}
async function initializeSchema(pool: pg.Pool): Promise<void> {
  const client = await pool.connect();
  let transactionStarted = false;
  try {
    await client.query('BEGIN');
    transactionStarted = true;
    await client.query(
      "SELECT pg_advisory_xact_lock(hashtext('otto_edge_request_ledger_schema'))",
    );
    await client.query(`
      CREATE TABLE IF NOT EXISTS control_edge_request_ledger (
        request_id VARCHAR(128) PRIMARY KEY,
        record_json JSONB NOT NULL,
        record_hash CHAR(64) NOT NULL
          CHECK (record_hash ~ '^[a-f0-9]{64}$'),
        owner_id VARCHAR(160),
        lease_until_ms BIGINT,
        fencing_epoch BIGINT NOT NULL DEFAULT 0 CHECK (fencing_epoch >= 0),
        revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
        created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
      )
    `);
    await client.query(`
      ALTER TABLE control_edge_request_ledger
        ADD COLUMN IF NOT EXISTS owner_id VARCHAR(160),
        ADD COLUMN IF NOT EXISTS lease_until_ms BIGINT,
        ADD COLUMN IF NOT EXISTS fencing_epoch BIGINT NOT NULL DEFAULT 0
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS control_edge_billing_sequences (
        sequence_scope VARCHAR(160) PRIMARY KEY,
        last_sequence BIGINT NOT NULL CHECK (last_sequence > 0),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS control_edge_billing_outbox (
        request_id VARCHAR(128) PRIMARY KEY
          REFERENCES control_edge_request_ledger(request_id) ON DELETE RESTRICT,
        action_kind VARCHAR(16) NOT NULL
          CHECK (action_kind IN ('settle', 'release', 'uncertain')),
        action_json JSONB NOT NULL,
        action_hash CHAR(64) NOT NULL
          CHECK (action_hash ~ '^[a-f0-9]{64}$'),
        state VARCHAR(16) NOT NULL DEFAULT 'pending'
          CHECK (state IN ('pending', 'prepared', 'delivered', 'dead_letter')),
        sequence_scope VARCHAR(160),
        delivery_sequence BIGINT CHECK (delivery_sequence > 0),
        prepared_json JSONB,
        prepared_hash CHAR(64)
          CHECK (prepared_hash IS NULL OR prepared_hash ~ '^[a-f0-9]{64}$'),
        claim_owner VARCHAR(160),
        claim_until_ms BIGINT,
        claim_epoch BIGINT NOT NULL DEFAULT 0 CHECK (claim_epoch >= 0),
        attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
        next_attempt_at_ms BIGINT NOT NULL DEFAULT 0 CHECK (next_attempt_at_ms >= 0),
        last_error_code VARCHAR(128),
        delivered_at_ms BIGINT CHECK (delivered_at_ms >= 0),
        created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
        CHECK ((claim_owner IS NULL) = (claim_until_ms IS NULL)),
        CHECK (
          (sequence_scope IS NULL AND delivery_sequence IS NULL
            AND prepared_json IS NULL AND prepared_hash IS NULL)
          OR
          (sequence_scope IS NOT NULL AND delivery_sequence IS NOT NULL
            AND prepared_json IS NOT NULL AND prepared_hash IS NOT NULL)
        ),
        CHECK (state NOT IN ('prepared', 'delivered') OR prepared_json IS NOT NULL)
      )
    `);
    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS control_edge_billing_outbox_sequence_uq
      ON control_edge_billing_outbox(sequence_scope, delivery_sequence)
      WHERE sequence_scope IS NOT NULL
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS control_edge_billing_outbox_due_idx
      ON control_edge_billing_outbox(state, next_attempt_at_ms, created_at)
      WHERE state IN ('pending', 'prepared')
    `);    await client.query('COMMIT');
  } catch (error) {
    if (transactionStarted) await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

async function verifySchema(pool: pg.Pool): Promise<void> {
  await pool.query(`
    SELECT request_id, record_json, record_hash,
           owner_id, lease_until_ms, fencing_epoch, revision,
           created_at, updated_at
    FROM control_edge_request_ledger
    WHERE false
  `);  await pool.query(`
    SELECT request_id, action_kind, action_json, action_hash, state,
           sequence_scope, delivery_sequence, prepared_json, prepared_hash,
           claim_owner, claim_until_ms, claim_epoch, attempts,
           next_attempt_at_ms, last_error_code, delivered_at_ms,
           created_at, updated_at
    FROM control_edge_billing_outbox
    WHERE false
  `);
  await pool.query(`
    SELECT sequence_scope, last_sequence, updated_at
    FROM control_edge_billing_sequences
    WHERE false
  `);
}

function activeState(record: EdgeRequestRecord): boolean {
  return record.state === 'received' || record.state === 'executing';
}

function fencingConflict(message: string): EdgeRequestLedgerConflictError {
  return new EdgeRequestLedgerConflictError('EDGE_REQUEST_FENCING_CONFLICT', message);
}

export class PostgresEdgeRequestLedger implements EdgeRequestLedger {
  readonly #pool: pg.Pool;
  readonly #ownsPool: boolean;
  readonly #ownerId: string;
  readonly #leaseDurationMs: number;
  readonly #nowOverride?: () => number;
  readonly #poolErrorListener: (error: Error) => void;
  readonly #fencingEpochs = new Map<string, number>();
  #closed = false;

  private constructor(
    pool: pg.Pool,
    ownsPool: boolean,
    ownerId: string,
    leaseDurationMs: number,
    nowOverride: (() => number) | undefined,
    poolErrorListener: (error: Error) => void,
  ) {
    this.#pool = pool;
    this.#ownsPool = ownsPool;
    this.#ownerId = ownerId;
    this.#leaseDurationMs = leaseDurationMs;
    this.#nowOverride = nowOverride;
    this.#poolErrorListener = poolErrorListener;
  }

  static async connect(
    options: PostgresEdgeRequestLedgerOptions,
  ): Promise<PostgresEdgeRequestLedger> {
    const connectionString = options.connectionString?.trim() ?? '';
    if (Boolean(options.pool) === Boolean(connectionString)) {
      throw new TypeError('provide exactly one PostgreSQL pool or connection string');
    }
    const ownerId = normalizeOwnerId(options.ownerId);
    const leaseDurationMs = normalizeLeaseDuration(options.leaseDurationMs);
    const ownsPool = !options.pool;
    const pool = options.pool ?? new Pool({
      connectionString,
      ssl: options.ssl ? { rejectUnauthorized: true } : undefined,
      max: 20,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 10_000,
      statement_timeout: 30_000,
      application_name: 'otto-edge-request-ledger',
    });
    const poolErrorListener = (error: Error): void => {
      options.onPoolError?.(error);
    };
    pool.on('error', poolErrorListener);
    try {
      if (options.manageSchema ?? true) await initializeSchema(pool);
      else await verifySchema(pool);
    } catch (error) {
      pool.off('error', poolErrorListener);
      if (ownsPool) await pool.end();
      throw error;
    }
    return new PostgresEdgeRequestLedger(
      pool,
      ownsPool,
      ownerId,
      leaseDurationMs,
      options.now,
      poolErrorListener,
    );
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    this.#fencingEpochs.clear();
    if (this.#ownsPool) await this.#pool.end();
    this.#pool.off('error', this.#poolErrorListener);
  }

  async healthCheck(): Promise<void> {
    if (this.#closed) throw new Error('PostgreSQL edge request ledger is closed');
    await this.#pool.query('SELECT 1');
  }

  admit(input: EdgeRequestAdmission): Promise<EdgeRequestAdmissionResult> {
    return this.#transaction(
      input.requestId,
      'admit',
      input,
      (engine) => engine.admit(input),
    );
  }

  lookup(
    input: Omit<EdgeRequestBinding, 'requestHash'>,
  ): Promise<EdgeRequestRecord | null> {
    return this.#transaction(
      input.requestId,
      'lookup',
      null,
      (engine) => engine.lookup(input),
    );
  }

  beginAttempt(
    input: EdgeRequestBinding & { routeId: string },
  ): Promise<EdgeRequestRecord> {
    return this.#transaction(
      input.requestId,
      'write',
      input,
      (engine) => engine.beginAttempt(input),
    );
  }

  recordProviderRequestId(
    input: EdgeRequestBinding & { providerRequestId: string },
  ): Promise<EdgeRequestRecord> {
    return this.#transaction(
      input.requestId,
      'write',
      input,
      (engine) => engine.recordProviderRequestId(input),
    );
  }

  markNotSent(input: EdgeRequestBinding): Promise<EdgeRequestRecord> {
    return this.#transaction(
      input.requestId,
      'write',
      input,
      (engine) => engine.markNotSent(input),
    );
  }

  markUnknownOutcome(input: EdgeRequestBinding): Promise<EdgeRequestRecord> {
    return this.#transaction(
      input.requestId,
      'write',
      input,
      (engine) => engine.markUnknownOutcome(input),
    );
  }

  confirmFailover(input: EdgeRequestBinding): Promise<EdgeRequestRecord> {
    return this.#transaction(
      input.requestId,
      'write',
      input,
      (engine) => engine.confirmFailover(input),
    );
  }

  complete(
    input: EdgeRequestBinding & {
      actualUsage: EdgeModelUsageV1;
      providerRequestId?: string;
    },
  ): Promise<EdgeRequestRecord> {
    return this.#transaction(
      input.requestId,
      'write',
      input,
      (engine) => engine.complete(input),
    );
  }

  finalizeWithBillingAction(
    input: EdgeRequestTerminalCommit,
  ): Promise<EdgeRequestRecord> {
    return this.#transaction(
      input.requestId,
      'finalize',
      input,
      async (engine, _lease, client) => {
        const current = engine.lookup({
          requestId: input.requestId,
          tenant: input.tenant,
        });
        if (!current) {
          throw new EdgeRequestLedgerConflictError(
            'EDGE_REQUEST_STATE_CONFLICT',
            'edge request has not been admitted',
          );
        }
        let terminal: EdgeRequestRecord;
        if (current.state === input.state) {
          if (input.state === 'completed') {
            if (!current.actualUsage || !sameUsage(current.actualUsage, input.actualUsage)
              || (input.providerRequestId !== undefined
                && current.providerRequestId !== input.providerRequestId)) {
              throw new EdgeRequestLedgerConflictError(
                'EDGE_REQUEST_STATE_CONFLICT',
                'completed request evidence conflicts with the stored terminal state',
              );
            }
          }
          terminal = current;
        } else if (input.state === 'completed') {
          terminal = await engine.complete(input);
        } else if (input.state === 'not_sent') {
          terminal = await engine.markNotSent(input);
        } else {
          terminal = await engine.markUnknownOutcome(input);
        }
        const action = parseEdgeBillingAction(input.billingAction, terminal);
        await this.#enqueueRawBillingAction(client, terminal, action);
        return terminal;
      },
    );
  }

  async claimBillingActions(
    options: ClaimEdgeBillingOutboxOptions,
  ): Promise<ClaimedEdgeBillingDelivery[]> {
    if (this.#closed) throw new Error('PostgreSQL edge request ledger is closed');
    const sequenceScope = normalizeSequenceScope(options.sequenceScope);
    const limit = normalizeOutboxLimit(options.limit);
    const leaseDurationMs = normalizeLeaseDuration(
      options.leaseDurationMs ?? this.#leaseDurationMs,
    );
    if (typeof options.prepare !== 'function') {
      throw new TypeError('edge billing delivery prepare callback is required');
    }
    const claimed: ClaimedEdgeBillingDelivery[] = [];
    let quarantined = 0;
    while (claimed.length < limit && quarantined <= limit) {
      const result = await this.#claimOneBillingAction(
        sequenceScope,
        leaseDurationMs,
        options.prepare,
      );
      if (result === null) break;
      if (result === false) {
        quarantined += 1;
        continue;
      }
      claimed.push(result);
    }
    return claimed;
  }

  async ackBillingAction(input: EdgeBillingOutboxFence): Promise<void> {
    const requestId = normalizeEdgeRequestId(input.requestId);
    const claimEpoch = this.#normalizeClaimEpoch(input.claimEpoch);
    await this.#mutateClaimedBillingAction(
      requestId,
      claimEpoch,
      async (client, _outbox, now) => {
        const acknowledged = await client.query(
          `UPDATE control_edge_billing_outbox
           SET state = 'delivered',
               claim_owner = NULL,
               claim_until_ms = NULL,
               delivered_at_ms = $4,
               last_error_code = NULL,
               updated_at = clock_timestamp()
           WHERE request_id = $1
             AND state = 'prepared'
             AND claim_owner = $2
             AND claim_epoch = $3
           RETURNING request_id`,
          [requestId, this.#ownerId, claimEpoch, now],
        );
        if (acknowledged.rowCount !== 1) {
          throw fencingConflict('edge billing acknowledgement lost its fencing race');
        }
      },
    );
  }

  async retryBillingAction(
    input: RetryEdgeBillingOutboxInput,
  ): Promise<RetriedEdgeBillingDelivery> {
    const requestId = normalizeEdgeRequestId(input.requestId);
    const claimEpoch = this.#normalizeClaimEpoch(input.claimEpoch);
    const errorCode = input.errorCode?.trim();
    if (!OUTBOX_ERROR_CODE.test(errorCode)) {
      throw new TypeError('edge billing retry error code is invalid');
    }
    const baseDelayMs = normalizeRetryDelay(
      input.baseDelayMs,
      DEFAULT_OUTBOX_RETRY_BASE_MS,
    );
    const maxDelayMs = normalizeRetryDelay(
      input.maxDelayMs,
      DEFAULT_OUTBOX_RETRY_MAX_MS,
    );
    if (maxDelayMs < baseDelayMs) {
      throw new TypeError('edge billing retry maximum is below its base delay');
    }
    return this.#mutateClaimedBillingAction(
      requestId,
      claimEpoch,
      async (client, outbox, now) => {
        const exponent = Math.min(Math.max(outbox.attempts - 1, 0), 30);
        const delay = Math.min(maxDelayMs, baseDelayMs * (2 ** exponent));
        const nextAttemptAtMs = now + delay;
        if (!Number.isSafeInteger(nextAttemptAtMs)) {
          throw new TypeError('edge billing retry deadline is invalid');
        }
        const retried = await client.query(
          `UPDATE control_edge_billing_outbox
           SET claim_owner = NULL,
               claim_until_ms = NULL,
               next_attempt_at_ms = $4,
               last_error_code = $5,
               updated_at = clock_timestamp()
           WHERE request_id = $1
             AND state = 'prepared'
             AND claim_owner = $2
             AND claim_epoch = $3
           RETURNING request_id`,
          [requestId, this.#ownerId, claimEpoch, nextAttemptAtMs, errorCode],
        );
        if (retried.rowCount !== 1) {
          throw fencingConflict('edge billing retry lost its fencing race');
        }
        return { requestId, attempts: outbox.attempts, nextAttemptAtMs };
      },
    );
  }
  renewLease(input: EdgeRequestBinding): Promise<PostgresEdgeRequestLease> {
    return this.#transaction(
      input.requestId,
      'renew',
      input,
      (engine, lease) => {
        const record = engine.lookup({ requestId: input.requestId, tenant: input.tenant });
        if (!record) {
          throw new EdgeRequestLedgerConflictError(
            'EDGE_REQUEST_STATE_CONFLICT',
            'edge request has not been admitted',
          );
        }
        if (!activeState(record)) {
          throw new EdgeRequestLedgerConflictError(
            'EDGE_REQUEST_STATE_CONFLICT',
            `lease renewal is not allowed while request is ${record.state}`,
          );
        }
        if (!lease) throw fencingConflict('edge request lease is not owned by this instance');
        return { ...lease, record };
      },
    );
  }

  async #enqueueRawBillingAction(
    client: PoolClient,
    record: EdgeRequestRecord,
    action: EdgeBillingOutboxAction,
  ): Promise<void> {
    const actionHash = jsonDigest(action);
    const existing = await client.query<EdgeBillingOutboxRow>(
      `SELECT request_id, action_kind, action_json, action_hash, state,
              sequence_scope, delivery_sequence, prepared_json, prepared_hash,
              claim_owner, claim_until_ms, claim_epoch, attempts,
              next_attempt_at_ms, last_error_code
       FROM control_edge_billing_outbox
       WHERE request_id = $1
       FOR UPDATE`,
      [record.requestId],
    );
    const row = existing.rows[0];
    if (row) {
      const stored = parseOutboxRow(row, record);
      if (stored.actionHash !== actionHash) {
        throw new EdgeRequestLedgerConflictError(
          'EDGE_REQUEST_RESERVATION_CONFLICT',
          'request already has a different billing reservation or action',
        );
      }
      return;
    }
    const inserted = await client.query(
      `INSERT INTO control_edge_billing_outbox (
         request_id, action_kind, action_json, action_hash
       ) VALUES ($1, $2, $3::jsonb, $4)
       ON CONFLICT (request_id) DO NOTHING
       RETURNING request_id`,
      [record.requestId, action.type, JSON.stringify(action), actionHash],
    );
    if (inserted.rowCount !== 1) {
      throw fencingConflict('edge billing action insert lost its transaction fence');
    }
  }

  async #claimOneBillingAction(
    sequenceScope: string,
    leaseDurationMs: number,
    prepare: ClaimEdgeBillingOutboxOptions['prepare'],
  ): Promise<ClaimedEdgeBillingDelivery | false | null> {
    const client = await this.#pool.connect();
    let transactionStarted = false;
    try {
      await client.query('BEGIN');
      transactionStarted = true;
      const now = await this.#databaseClock(client);
      const selected = await client.query<JoinedEdgeBillingOutboxRow>(
        `SELECT o.request_id, o.action_kind, o.action_json, o.action_hash, o.state,
                o.sequence_scope, o.delivery_sequence, o.prepared_json,
                o.prepared_hash, o.claim_owner, o.claim_until_ms, o.claim_epoch,
                o.attempts, o.next_attempt_at_ms, o.last_error_code,
                r.record_json, r.record_hash,
                r.owner_id AS request_owner_id,
                r.lease_until_ms AS request_lease_until_ms,
                r.fencing_epoch AS request_fencing_epoch
         FROM control_edge_billing_outbox o
         JOIN control_edge_request_ledger r ON r.request_id = o.request_id
         WHERE o.state IN ('pending', 'prepared')
           AND o.next_attempt_at_ms <= $1
           AND (o.claim_owner IS NULL OR o.claim_until_ms <= $1)
           AND (o.sequence_scope IS NULL OR o.sequence_scope = $2)
         ORDER BY o.created_at, o.request_id
         FOR UPDATE OF o SKIP LOCKED
         LIMIT 1`,
        [now, sequenceScope],
      );
      const row = selected.rows[0];
      if (!row) {
        await client.query('COMMIT');
        transactionStarted = false;
        return null;
      }
      let requestRecord: EdgeRequestRecord;
      let outbox: ParsedEdgeBillingOutbox;
      try {
        requestRecord = recordFromRow({
          request_id: row.request_id,
          record_json: row.record_json,
          record_hash: row.record_hash,
          owner_id: row.request_owner_id,
          lease_until_ms: row.request_lease_until_ms,
          fencing_epoch: row.request_fencing_epoch,
        }).record;
        outbox = parseOutboxRow(row, requestRecord);
      } catch (error) {
        if (!(error instanceof EdgeBillingOutboxCorruptionError)
          && !(error instanceof EdgeRequestLedgerCorruptionError)) throw error;
        await client.query(
          `UPDATE control_edge_billing_outbox
           SET state = 'dead_letter',
               claim_owner = NULL,
               claim_until_ms = NULL,
               last_error_code = 'OUTBOX_CORRUPTED',
               updated_at = clock_timestamp()
           WHERE request_id = $1`,
          [row.request_id],
        );
        await client.query('COMMIT');
        transactionStarted = false;
        return false;
      }

      let preparedDelivery = outbox.preparedDelivery;
      let preparedHash = outbox.preparedHash;
      let sequence = outbox.sequence;
      if (outbox.state === 'pending') {
        const allocated = await client.query<{ last_sequence: string | number }>(
          `INSERT INTO control_edge_billing_sequences (
             sequence_scope, last_sequence
           ) VALUES ($1, 1)
           ON CONFLICT (sequence_scope) DO UPDATE
           SET last_sequence = control_edge_billing_sequences.last_sequence + 1,
               updated_at = clock_timestamp()
           WHERE control_edge_billing_sequences.last_sequence < 9007199254740991
           RETURNING last_sequence`,
          [sequenceScope],
        );
        if (allocated.rowCount !== 1 || allocated.rows[0] === undefined) {
          throw new EdgeBillingOutboxCorruptionError(
            'edge billing sequence space is exhausted',
          );
        }
        sequence = safeUnsignedInteger(
          allocated.rows[0].last_sequence,
          'edge billing sequence',
        );
        if (sequence < 1) {
          throw new EdgeBillingOutboxCorruptionError('edge billing sequence is invalid');
        }
        preparedDelivery = parsePreparedDelivery(await prepare({
          request: requestRecord,
          action: outbox.action,
          sequenceScope,
          sequence,
        }));
        preparedHash = jsonDigest(preparedDelivery);
      }
      if (!preparedDelivery || !preparedHash || sequence === null) {
        throw new EdgeBillingOutboxCorruptionError(
          'prepared edge billing delivery is missing',
        );
      }
      const claimUntilMs = now + leaseDurationMs;
      if (!Number.isSafeInteger(claimUntilMs)) {
        throw new TypeError('edge billing claim deadline is invalid');
      }
      const claimed = await client.query<{
        claim_epoch: string | number;
        attempts: string | number;
      }>(
        `UPDATE control_edge_billing_outbox
         SET state = 'prepared',
             sequence_scope = $2,
             delivery_sequence = $3,
             prepared_json = $4::jsonb,
             prepared_hash = $5,
             claim_owner = $6,
             claim_until_ms = $7,
             claim_epoch = claim_epoch + 1,
             attempts = attempts + 1,
             last_error_code = NULL,
             updated_at = clock_timestamp()
         WHERE request_id = $1
           AND state IN ('pending', 'prepared')
           AND (claim_owner IS NULL OR claim_until_ms <= $8)
         RETURNING claim_epoch, attempts`,
        [
          outbox.requestId,
          sequenceScope,
          sequence,
          JSON.stringify(preparedDelivery),
          preparedHash,
          this.#ownerId,
          claimUntilMs,
          now,
        ],
      );
      if (claimed.rowCount !== 1 || claimed.rows[0] === undefined) {
        throw fencingConflict('edge billing claim lost its fencing race');
      }
      const claimEpoch = safeUnsignedInteger(
        claimed.rows[0].claim_epoch,
        'edge billing claim epoch',
      );
      const attempts = safeUnsignedInteger(
        claimed.rows[0].attempts,
        'edge billing attempts',
      );
      await client.query('COMMIT');
      transactionStarted = false;
      return {
        requestId: outbox.requestId,
        action: outbox.action,
        actionHash: outbox.actionHash,
        preparedDelivery,
        preparedHash,
        sequenceScope,
        sequence,
        claimOwner: this.#ownerId,
        claimUntilMs,
        claimEpoch,
        attempts,
      };
    } catch (error) {
      if (transactionStarted) await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async #mutateClaimedBillingAction<T>(
    requestId: string,
    claimEpoch: number,
    operation: (
      client: PoolClient,
      outbox: ParsedEdgeBillingOutbox,
      now: number,
    ) => Promise<T>,
  ): Promise<T> {
    if (this.#closed) throw new Error('PostgreSQL edge request ledger is closed');
    const client = await this.#pool.connect();
    let transactionStarted = false;
    try {
      await client.query('BEGIN');
      transactionStarted = true;
      const now = await this.#databaseClock(client);
      const selected = await client.query<JoinedEdgeBillingOutboxRow>(
        `SELECT o.request_id, o.action_kind, o.action_json, o.action_hash, o.state,
                o.sequence_scope, o.delivery_sequence, o.prepared_json,
                o.prepared_hash, o.claim_owner, o.claim_until_ms, o.claim_epoch,
                o.attempts, o.next_attempt_at_ms, o.last_error_code,
                r.record_json, r.record_hash,
                r.owner_id AS request_owner_id,
                r.lease_until_ms AS request_lease_until_ms,
                r.fencing_epoch AS request_fencing_epoch
         FROM control_edge_billing_outbox o
         JOIN control_edge_request_ledger r ON r.request_id = o.request_id
         WHERE o.request_id = $1
         FOR UPDATE OF o`,
        [requestId],
      );
      const row = selected.rows[0];
      if (!row) {
        throw new EdgeRequestLedgerConflictError(
          'EDGE_REQUEST_STATE_CONFLICT',
          'edge billing action does not exist',
        );
      }
      let outbox: ParsedEdgeBillingOutbox;
      try {
        const requestRecord = recordFromRow({
          request_id: row.request_id,
          record_json: row.record_json,
          record_hash: row.record_hash,
          owner_id: row.request_owner_id,
          lease_until_ms: row.request_lease_until_ms,
          fencing_epoch: row.request_fencing_epoch,
        }).record;
        outbox = parseOutboxRow(row, requestRecord);
      } catch (error) {
        if (!(error instanceof EdgeBillingOutboxCorruptionError)
          && !(error instanceof EdgeRequestLedgerCorruptionError)) throw error;
        await client.query(
          `UPDATE control_edge_billing_outbox
           SET state = 'dead_letter',
               claim_owner = NULL,
               claim_until_ms = NULL,
               last_error_code = 'OUTBOX_CORRUPTED',
               updated_at = clock_timestamp()
           WHERE request_id = $1`,
          [requestId],
        );
        await client.query('COMMIT');
        transactionStarted = false;
        throw error;
      }
      if (outbox.state !== 'prepared'
        || outbox.claimOwner !== this.#ownerId
        || outbox.claimEpoch !== claimEpoch) {
        throw fencingConflict('edge billing claim has been superseded');
      }
      const result = await operation(client, outbox, now);
      await client.query('COMMIT');
      transactionStarted = false;
      return result;
    } catch (error) {
      if (transactionStarted) await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  #normalizeClaimEpoch(value: number): number {
    if (!Number.isSafeInteger(value) || value < 1) {
      throw new TypeError('edge billing claim epoch is invalid');
    }
    return value;
  }
  async #transaction<T>(
    requestIdInput: string,
    access: LedgerAccess,
    binding: EdgeRequestBinding | null,
    operation: (
      engine: EdgeRequestLedgerEngine,
      lease: LeaseFence | null,
      client: PoolClient,
      now: number,
    ) => Promise<T> | T,
  ): Promise<T> {
    if (this.#closed) throw new Error('PostgreSQL edge request ledger is closed');
    const requestId = normalizeEdgeRequestId(requestIdInput);
    const client = await this.#pool.connect();
    let transactionStarted = false;
    let fencingEpochToRemember: number | null = null;
    try {
      await client.query('BEGIN');
      transactionStarted = true;
      await client.query(
        'SELECT pg_advisory_xact_lock(hashtextextended($1, 0))',
        [`${LOCK_NAMESPACE}${requestId}`],
      );
      const now = await this.#clock(client);
      const result = await client.query<EdgeRequestLedgerRow>(
        `SELECT request_id, record_json, record_hash,
                owner_id, lease_until_ms, fencing_epoch
         FROM control_edge_request_ledger
         WHERE request_id = $1
         FOR UPDATE`,
        [requestId],
      );
      const row = result.rows[0];
      const stored = row ? recordFromRow(row) : null;
      let expectedHash = stored ? row!.record_hash : null;
      let lease: LeaseFence | null = null;
      const engine = new EdgeRequestLedgerEngine(() => now, async (record) => {
        expectedHash = await this.#persist(client, record, expectedHash, lease);
      });
      if (stored) {
        const storedHash = row!.record_hash;
        engine.load(stored.record);
        if (binding) assertEdgeRequestBinding(stored.record, binding);
        const localEpoch = this.#fencingEpochs.get(requestId);
        const ownsFence = stored.ownerId === this.#ownerId
          && localEpoch !== undefined
          && localEpoch === stored.fencingEpoch;
        if (access !== 'lookup'
          && localEpoch !== undefined
          && !ownsFence) {
          throw fencingConflict('edge request fencing epoch has been superseded');
        }
        if (access !== 'lookup' && ownsFence
          && (activeState(stored.record)
            || access === 'write'
            || access === 'renew'
            || (access === 'admit' && stored.record.state === 'not_sent'))) {
          lease = await this.#renew(client, requestId, storedHash, stored.fencingEpoch, now);
          fencingEpochToRemember = lease.fencingEpoch;
        } else if (access !== 'lookup' && activeState(stored.record)) {
          const expired = stored.leaseUntilMs === null || stored.leaseUntilMs <= now;
          if (access === 'admit' && expired) {
            lease = await this.#claim(
              client,
              requestId,
              storedHash,
              stored.fencingEpoch,
              now,
            );
            fencingEpochToRemember = lease.fencingEpoch;
            await engine.recover();
          } else if (access !== 'admit') {
            throw fencingConflict('edge request is leased by another instance');
          }
        } else if (access !== 'lookup'
          && (access === 'finalize' || stored.record.state !== 'completed')
          && !(access === 'admit' && stored.record.state === 'unknown_outcome')) {
          lease = await this.#claim(
            client,
            requestId,
            storedHash,
            stored.fencingEpoch,
            now,
          );
          fencingEpochToRemember = lease.fencingEpoch;
        }
      } else if (access === 'admit') {
        lease = {
          ownerId: this.#ownerId,
          leaseUntilMs: this.#deadline(now),
          fencingEpoch: 1,
        };
        fencingEpochToRemember = 1;
      }
      const value = await operation(engine, lease, client, now);
      await client.query('COMMIT');
      if (fencingEpochToRemember !== null) {
        this.#fencingEpochs.set(requestId, fencingEpochToRemember);
      }
      return value;
    } catch (error) {
      if (transactionStarted) {
        try {
          await client.query('ROLLBACK');
        } catch (rollbackError) {
          throw new AggregateError(
            [error, rollbackError],
            'PostgreSQL edge request transaction and rollback both failed',
          );
        }
      }
      throw error;
    } finally {
      client.release();
    }
  }

  async #claim(
    client: PoolClient,
    requestId: string,
    expectedHash: string,
    expectedEpoch: number,
    now: number,
  ): Promise<LeaseFence> {
    const leaseUntilMs = this.#deadline(now);
    const claimed = await client.query<{ fencing_epoch: string | number }>(
      `UPDATE control_edge_request_ledger
       SET owner_id = $2,
           lease_until_ms = $3,
           fencing_epoch = fencing_epoch + 1,
           revision = revision + 1,
           updated_at = clock_timestamp()
       WHERE request_id = $1
         AND record_hash = $4
         AND fencing_epoch = $5
       RETURNING fencing_epoch`,
      [requestId, this.#ownerId, leaseUntilMs, expectedHash, expectedEpoch],
    );
    if (claimed.rowCount !== 1 || claimed.rows[0] === undefined) {
      throw fencingConflict('edge request lease claim lost its fencing race');
    }
    return {
      ownerId: this.#ownerId,
      leaseUntilMs,
      fencingEpoch: parseStoredInteger(claimed.rows[0].fencing_epoch, 'fencing epoch'),
    };
  }

  async #renew(
    client: PoolClient,
    requestId: string,
    expectedHash: string,
    expectedEpoch: number,
    now: number,
  ): Promise<LeaseFence> {
    const leaseUntilMs = this.#deadline(now);
    const renewed = await client.query(
      `UPDATE control_edge_request_ledger
       SET lease_until_ms = $4,
           updated_at = clock_timestamp()
       WHERE request_id = $1
         AND record_hash = $2
         AND owner_id = $3
         AND fencing_epoch = $5
       RETURNING request_id`,
      [requestId, expectedHash, this.#ownerId, leaseUntilMs, expectedEpoch],
    );
    if (renewed.rowCount !== 1) {
      throw fencingConflict('edge request lease renewal lost its fencing race');
    }
    return {
      ownerId: this.#ownerId,
      leaseUntilMs,
      fencingEpoch: expectedEpoch,
    };
  }

  async #persist(
    client: PoolClient,
    record: EdgeRequestRecord,
    expectedHash: string | null,
    lease: LeaseFence | null,
  ): Promise<string> {
    const validated = assertEdgeRequestRecord(record);
    const nextHash = recordDigest(validated);
    if (!lease) {
      throw fencingConflict('edge request write has no valid lease fence');
    }
    if (expectedHash === null) {
      const inserted = await client.query(
        `INSERT INTO control_edge_request_ledger (
           request_id, record_json, record_hash,
           owner_id, lease_until_ms, fencing_epoch
         ) VALUES ($1, $2::jsonb, $3, $4, $5, $6)
         ON CONFLICT (request_id) DO NOTHING
         RETURNING request_id`,
        [
          validated.requestId,
          JSON.stringify(validated),
          nextHash,
          lease.ownerId,
          lease.leaseUntilMs,
          lease.fencingEpoch,
        ],
      );
      if (inserted.rowCount !== 1) {
        throw fencingConflict('edge request insert lost its advisory lock fence');
      }
      return nextHash;
    }
    const updated = await client.query(
      `UPDATE control_edge_request_ledger
       SET record_json = $2::jsonb,
           record_hash = $3,
           revision = revision + 1,
           updated_at = clock_timestamp()
       WHERE request_id = $1
         AND record_hash = $4
         AND owner_id = $5
         AND fencing_epoch = $6
       RETURNING request_id`,
      [
        validated.requestId,
        JSON.stringify(validated),
        nextHash,
        expectedHash,
        lease.ownerId,
        lease.fencingEpoch,
      ],
    );
    if (updated.rowCount !== 1) {
      throw fencingConflict('edge request update lost its fencing race');
    }
    return nextHash;
  }

  async #databaseClock(client: PoolClient): Promise<number> {
    const now = Number((await client.query<{ now_ms: string | number }>(
      `SELECT floor(extract(epoch from clock_timestamp()) * 1000)::bigint AS now_ms`,
    )).rows[0]?.now_ms);
    if (!Number.isSafeInteger(now) || now < 0) {
      throw new TypeError('PostgreSQL edge request clock is invalid');
    }
    return now;
  }

  async #clock(client: PoolClient): Promise<number> {
    const now = this.#nowOverride
      ? this.#nowOverride()
      : await this.#databaseClock(client);
    if (!Number.isSafeInteger(now) || now < 0) {
      throw new TypeError('PostgreSQL edge request clock is invalid');
    }
    return now;
  }

  #deadline(now: number): number {
    const deadline = now + this.#leaseDurationMs;
    if (!Number.isSafeInteger(deadline)) {
      throw new TypeError('PostgreSQL edge request lease deadline is invalid');
    }
    return deadline;
  }
}

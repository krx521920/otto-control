import { createHash } from 'node:crypto';

import pg, { type PoolClient } from 'pg';

import type { EdgeModelUsageV1 } from '../contracts/edge-gateway.js';
import { canonicalJson } from '../crypto/signed-envelope.js';
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
} from './request-ledger.js';

const { Pool } = pg;
const LOCK_NAMESPACE = 'otto_edge_request_ledger:';
const OWNER_IDENTIFIER = /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,159}$/u;
const DEFAULT_LEASE_DURATION_MS = 30_000;
const MAX_LEASE_DURATION_MS = 24 * 60 * 60 * 1_000;

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

type LedgerAccess = 'admit' | 'lookup' | 'write' | 'renew';

interface EdgeRequestLedgerRow {
  request_id: string;
  record_json: unknown;
  record_hash: string;
  owner_id: string | null;
  lease_until_ms: string | number | null;
  fencing_epoch: string | number;
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
    await client.query('COMMIT');
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

  async #transaction<T>(
    requestIdInput: string,
    access: LedgerAccess,
    binding: EdgeRequestBinding | null,
    operation: (
      engine: EdgeRequestLedgerEngine,
      lease: LeaseFence | null,
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
          && stored.record.state !== 'completed'
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
      const value = await operation(engine, lease);
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

  async #clock(client: PoolClient): Promise<number> {
    const now = this.#nowOverride
      ? this.#nowOverride()
      : Number((await client.query<{ now_ms: string | number }>(
          `SELECT floor(extract(epoch from clock_timestamp()) * 1000)::bigint AS now_ms`,
        )).rows[0]?.now_ms);
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

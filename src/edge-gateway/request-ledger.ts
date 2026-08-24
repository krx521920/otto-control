import { createHash } from 'node:crypto';
import { lstat, mkdir, open, readFile } from 'node:fs/promises';
import { dirname } from 'node:path';

import type { EdgeModelUsageV1 } from '../contracts/edge-gateway.js';
import { canonicalJson } from '../crypto/signed-envelope.js';

const REQUEST_ID = /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$/u;
const TENANT_IDENTIFIER = /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,159}$/u;
const ROUTE_IDENTIFIER = /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,159}$/u;
const PROVIDER_REQUEST_ID = /^[\x21-\x7e]{1,512}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const MAX_UNITS = 9_000_000_000_000;

export type EdgeRequestState =
  | 'not_sent'
  | 'received'
  | 'executing'
  | 'completed'
  | 'unknown_outcome';

export interface EdgeRequestTenantIdentity {
  deploymentId: string;
  organizationId: string;
  subjectId: string;
}

export interface EdgeRequestBinding {
  requestId: string;
  tenant: EdgeRequestTenantIdentity;
  requestHash: string;
}

export interface EdgeRequestAdmission extends EdgeRequestBinding {
  reservedUnits: number;
}

export type EdgeRequestAttemptOutcome =
  | 'not_sent'
  | 'completed'
  | 'unknown_outcome';

export interface EdgeRequestAttempt {
  attempt: number;
  routeId: string;
  providerRequestId: string | null;
  startedAtMs: number;
  endedAtMs: number | null;
  outcome: EdgeRequestAttemptOutcome | null;
}

export interface EdgeRequestRecord extends EdgeRequestBinding {
  state: EdgeRequestState;
  reservedUnits: number;
  actualUsage: EdgeModelUsageV1 | null;
  attempts: EdgeRequestAttempt[];
  routeId: string | null;
  providerRequestId: string | null;
  failoverConfirmedAt: number | null;
  createdAtMs: number;
  updatedAtMs: number;
  completedAtMs: number | null;
}

export interface EdgeRequestAdmissionResult {
  created: boolean;
  recoveredNotSentRequest: boolean;
  record: EdgeRequestRecord;
}

export interface EdgeRequestLedger {
  admit(input: EdgeRequestAdmission): Promise<EdgeRequestAdmissionResult>;
  lookup(input: Omit<EdgeRequestBinding, 'requestHash'>): Promise<EdgeRequestRecord | null>;
  beginAttempt(input: EdgeRequestBinding & { routeId: string }): Promise<EdgeRequestRecord>;
  recordProviderRequestId(
    input: EdgeRequestBinding & { providerRequestId: string },
  ): Promise<EdgeRequestRecord>;
  markNotSent(input: EdgeRequestBinding): Promise<EdgeRequestRecord>;
  markUnknownOutcome(input: EdgeRequestBinding): Promise<EdgeRequestRecord>;
  confirmFailover(input: EdgeRequestBinding): Promise<EdgeRequestRecord>;
  complete(
    input: EdgeRequestBinding & {
      actualUsage: EdgeModelUsageV1;
      providerRequestId?: string;
    },
  ): Promise<EdgeRequestRecord>;
}

export type EdgeRequestLedgerConflictCode =
  | 'EDGE_REQUEST_TENANT_CONFLICT'
  | 'EDGE_REQUEST_HASH_CONFLICT'
  | 'EDGE_REQUEST_RESERVATION_CONFLICT'
  | 'EDGE_REQUEST_STATE_CONFLICT'
  | 'EDGE_REQUEST_PROVIDER_ID_CONFLICT'
  | 'EDGE_REQUEST_FENCING_CONFLICT';

export class EdgeRequestLedgerConflictError extends Error {
  constructor(
    readonly code: EdgeRequestLedgerConflictCode,
    message: string,
  ) {
    super(message);
    this.name = 'EdgeRequestLedgerConflictError';
  }
}

export class EdgeRequestLedgerCorruptionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EdgeRequestLedgerCorruptionError';
  }
}

export interface FileEdgeRequestLedgerOptions {
  journalFile: string;
  now?: () => number;
}

interface LedgerJournalPayload {
  version: 1;
  index: number;
  previousHash: string | null;
  record: EdgeRequestRecord;
}

type LedgerJournalRecord = LedgerJournalPayload & { hash: string };

function digest(value: unknown): string {
  return createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex');
}

export function hashEdgeRequest(value: string | Uint8Array): string {
  return createHash('sha256').update(value).digest('hex');
}

function cloneTenant(tenant: EdgeRequestTenantIdentity): EdgeRequestTenantIdentity {
  return { ...tenant };
}

function cloneRecord(record: EdgeRequestRecord): EdgeRequestRecord {
  return {
    ...record,
    tenant: cloneTenant(record.tenant),
    actualUsage: record.actualUsage ? { ...record.actualUsage } : null,
    attempts: record.attempts.map((attempt) => ({ ...attempt })),
  };
}

function validTimestamp(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0;
}

function validUnits(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0 && value <= MAX_UNITS;
}

function normalizeTenant(tenant: EdgeRequestTenantIdentity): EdgeRequestTenantIdentity {
  const result = {
    deploymentId: tenant.deploymentId?.trim(),
    organizationId: tenant.organizationId?.trim(),
    subjectId: tenant.subjectId?.trim(),
  };
  if (!TENANT_IDENTIFIER.test(result.deploymentId)
    || !TENANT_IDENTIFIER.test(result.organizationId)
    || !TENANT_IDENTIFIER.test(result.subjectId)) {
    throw new TypeError('edge request tenant identity is invalid');
  }
  return result;
}

export function normalizeEdgeRequestId(value: string): string {
  const requestId = value?.trim();
  if (!REQUEST_ID.test(requestId)) throw new TypeError('edge request ID is invalid');
  return requestId;
}

function normalizeBinding(input: EdgeRequestBinding): EdgeRequestBinding {
  const requestId = normalizeEdgeRequestId(input.requestId);
  const requestHash = input.requestHash?.trim().toLowerCase();
  if (!SHA256.test(requestHash)) {
    throw new TypeError('edge request binding is invalid');
  }
  return { requestId, requestHash, tenant: normalizeTenant(input.tenant) };
}

function normalizeRouteId(value: string): string {
  const routeId = value?.trim();
  if (!ROUTE_IDENTIFIER.test(routeId)) throw new TypeError('edge route ID is invalid');
  return routeId;
}

function normalizeProviderRequestId(value: string): string {
  const providerRequestId = value?.trim();
  if (!PROVIDER_REQUEST_ID.test(providerRequestId)) {
    throw new TypeError('provider request ID is invalid');
  }
  return providerRequestId;
}

function normalizeUsage(value: EdgeModelUsageV1): EdgeModelUsageV1 {
  const usage = {
    inputTokens: value.inputTokens,
    outputTokens: value.outputTokens,
    totalTokens: value.totalTokens,
  };
  if (!validUnits(usage.inputTokens) || !validUnits(usage.outputTokens)
    || !validUnits(usage.totalTokens)
    || usage.totalTokens < usage.inputTokens + usage.outputTokens) {
    throw new TypeError('edge request actual usage is invalid');
  }
  return usage;
}

function sameTenant(
  left: EdgeRequestTenantIdentity,
  right: EdgeRequestTenantIdentity,
): boolean {
  return left.deploymentId === right.deploymentId
    && left.organizationId === right.organizationId
    && left.subjectId === right.subjectId;
}

export function assertEdgeRequestBinding(
  record: EdgeRequestRecord,
  input: EdgeRequestBinding,
): void {
  const binding = normalizeBinding(input);
  if (!sameTenant(record.tenant, binding.tenant)) {
    throw new EdgeRequestLedgerConflictError(
      'EDGE_REQUEST_TENANT_CONFLICT',
      'request ID is already bound to another tenant identity',
    );
  }
  if (record.requestHash !== binding.requestHash) {
    throw new EdgeRequestLedgerConflictError(
      'EDGE_REQUEST_HASH_CONFLICT',
      'request ID is already bound to different request bytes',
    );
  }
}

function assertState(
  record: EdgeRequestRecord,
  allowed: readonly EdgeRequestState[],
  operation: string,
): void {
  if (!allowed.includes(record.state)) {
    throw new EdgeRequestLedgerConflictError(
      'EDGE_REQUEST_STATE_CONFLICT',
      `${operation} is not allowed while request is ${record.state}`,
    );
  }
}

export function assertEdgeRequestRecord(value: unknown): EdgeRequestRecord {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new EdgeRequestLedgerCorruptionError('edge request journal record is invalid');
  }
  const body = value as Record<string, unknown>;
  const binding = normalizeBinding({
    requestId: String(body.requestId ?? ''),
    requestHash: String(body.requestHash ?? ''),
    tenant: body.tenant as EdgeRequestTenantIdentity,
  });
  if (!['not_sent', 'received', 'executing', 'completed', 'unknown_outcome']
    .includes(String(body.state))
    || !validUnits(Number(body.reservedUnits))
    || !validTimestamp(Number(body.createdAtMs))
    || !validTimestamp(Number(body.updatedAtMs))
    || Number(body.updatedAtMs) < Number(body.createdAtMs)
    || (body.completedAtMs !== null && !validTimestamp(Number(body.completedAtMs)))
    || (body.failoverConfirmedAt !== null
      && !validTimestamp(Number(body.failoverConfirmedAt)))) {
    throw new EdgeRequestLedgerCorruptionError('edge request journal state is invalid');
  }
  if (!Array.isArray(body.attempts)) {
    throw new EdgeRequestLedgerCorruptionError('edge request journal attempts are invalid');
  }
  const attempts = body.attempts.map((raw, index): EdgeRequestAttempt => {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      throw new EdgeRequestLedgerCorruptionError('edge request journal attempt is invalid');
    }
    const attempt = raw as Record<string, unknown>;
    const providerRequestId = attempt.providerRequestId === null
      ? null
      : normalizeProviderRequestId(String(attempt.providerRequestId ?? ''));
    const outcome = attempt.outcome;
    if (attempt.attempt !== index + 1
      || !validTimestamp(Number(attempt.startedAtMs))
      || (attempt.endedAtMs !== null && !validTimestamp(Number(attempt.endedAtMs)))
      || (outcome !== null
        && !['not_sent', 'completed', 'unknown_outcome'].includes(String(outcome)))) {
      throw new EdgeRequestLedgerCorruptionError('edge request journal attempt is invalid');
    }
    return {
      attempt: index + 1,
      routeId: normalizeRouteId(String(attempt.routeId ?? '')),
      providerRequestId,
      startedAtMs: Number(attempt.startedAtMs),
      endedAtMs: attempt.endedAtMs === null ? null : Number(attempt.endedAtMs),
      outcome: outcome as EdgeRequestAttemptOutcome | null,
    };
  });
  const state = body.state as EdgeRequestState;
  const activeAttempts = attempts.filter((attempt) => attempt.outcome === null);
  if ((state === 'executing' && activeAttempts.length !== 1)
    || (state !== 'executing' && activeAttempts.length !== 0)
    || (state === 'completed' && body.actualUsage === null)
    || (state !== 'completed' && body.actualUsage !== null)
    || (state === 'completed' && body.completedAtMs === null)
    || (state !== 'completed' && body.completedAtMs !== null)) {
    throw new EdgeRequestLedgerCorruptionError('edge request journal lifecycle is invalid');
  }
  const routeId = body.routeId === null ? null : normalizeRouteId(String(body.routeId ?? ''));
  const providerRequestId = body.providerRequestId === null
    ? null
    : normalizeProviderRequestId(String(body.providerRequestId ?? ''));
  const actualUsage = body.actualUsage === null
    ? null
    : normalizeUsage(body.actualUsage as EdgeModelUsageV1);
  return {
    ...binding,
    state,
    reservedUnits: Number(body.reservedUnits),
    actualUsage,
    attempts,
    routeId,
    providerRequestId,
    failoverConfirmedAt: body.failoverConfirmedAt === null
      ? null
      : Number(body.failoverConfirmedAt),
    createdAtMs: Number(body.createdAtMs),
    updatedAtMs: Number(body.updatedAtMs),
    completedAtMs: body.completedAtMs === null ? null : Number(body.completedAtMs),
  };
}

function assertReplay(previous: EdgeRequestRecord | undefined, next: EdgeRequestRecord): void {
  if (!previous) return;
  assertEdgeRequestBinding(previous, next);
  if (previous.reservedUnits !== next.reservedUnits) {
    throw new EdgeRequestLedgerCorruptionError('edge request reservation changed in journal');
  }
  if (next.attempts.length < previous.attempts.length) {
    throw new EdgeRequestLedgerCorruptionError('edge request attempts moved backwards');
  }
  for (const [index, attempt] of previous.attempts.entries()) {
    const replayed = next.attempts[index];
    if (!replayed || replayed.attempt !== attempt.attempt
      || replayed.routeId !== attempt.routeId
      || (attempt.providerRequestId !== null
        && replayed.providerRequestId !== attempt.providerRequestId)
      || (attempt.outcome !== null && replayed.outcome !== attempt.outcome)) {
      throw new EdgeRequestLedgerCorruptionError('edge request attempt history was rewritten');
    }
  }
}

export type PersistEdgeRequestRecord = (record: EdgeRequestRecord) => Promise<void>;

export class EdgeRequestLedgerEngine {
  readonly #records = new Map<string, EdgeRequestRecord>();
  readonly #now: () => number;
  #persist: PersistEdgeRequestRecord;

  constructor(now: () => number, persist: PersistEdgeRequestRecord) {
    this.#now = now;
    this.#persist = persist;
  }

  setPersist(persist: PersistEdgeRequestRecord): void {
    this.#persist = persist;
  }

  load(record: EdgeRequestRecord): void {
    const previous = this.#records.get(record.requestId);
    assertReplay(previous, record);
    this.#records.set(record.requestId, cloneRecord(record));
  }

  records(): EdgeRequestRecord[] {
    return [...this.#records.values()].map(cloneRecord);
  }

  async admit(input: EdgeRequestAdmission): Promise<EdgeRequestAdmissionResult> {
    const binding = normalizeBinding(input);
    if (!validUnits(input.reservedUnits)) {
      throw new TypeError('edge request reserved units are invalid');
    }
    const existing = this.#records.get(binding.requestId);
    if (existing) {
      assertEdgeRequestBinding(existing, binding);
      if (existing.reservedUnits !== input.reservedUnits) {
        throw new EdgeRequestLedgerConflictError(
          'EDGE_REQUEST_RESERVATION_CONFLICT',
          'request ID is already bound to another reservation',
        );
      }
      if (existing.state === 'not_sent') {
        const received = { ...cloneRecord(existing), state: 'received' as const,
          updatedAtMs: this.#now() };
        await this.#store(received);
        return { created: true, recoveredNotSentRequest: true, record: cloneRecord(received) };
      }
      return { created: false, recoveredNotSentRequest: false, record: cloneRecord(existing) };
    }
    const now = this.#now();
    if (!validTimestamp(now)) throw new TypeError('edge request clock is invalid');
    const record: EdgeRequestRecord = {
      ...binding,
      state: 'received',
      reservedUnits: input.reservedUnits,
      actualUsage: null,
      attempts: [],
      routeId: null,
      providerRequestId: null,
      failoverConfirmedAt: null,
      createdAtMs: now,
      updatedAtMs: now,
      completedAtMs: null,
    };
    await this.#store(record);
    return { created: true, recoveredNotSentRequest: false, record: cloneRecord(record) };
  }

  lookup(input: Omit<EdgeRequestBinding, 'requestHash'>): EdgeRequestRecord | null {
    const requestId = normalizeEdgeRequestId(input.requestId);
    const tenant = normalizeTenant(input.tenant);
    const existing = this.#records.get(requestId);
    if (!existing) return null;
    if (!sameTenant(existing.tenant, tenant)) {
      throw new EdgeRequestLedgerConflictError(
        'EDGE_REQUEST_TENANT_CONFLICT',
        'request ID is already bound to another tenant identity',
      );
    }
    return cloneRecord(existing);
  }

  async beginAttempt(
    input: EdgeRequestBinding & { routeId: string },
  ): Promise<EdgeRequestRecord> {
    const record = this.#required(input);
    const routeId = normalizeRouteId(input.routeId);
    assertState(record, ['received'], 'begin attempt');
    const now = this.#now();
    const next = cloneRecord(record);
    next.state = 'executing';
    next.routeId = routeId;
    next.providerRequestId = null;
    next.updatedAtMs = now;
    next.attempts.push({
      attempt: next.attempts.length + 1,
      routeId,
      providerRequestId: null,
      startedAtMs: now,
      endedAtMs: null,
      outcome: null,
    });
    await this.#store(next);
    return cloneRecord(next);
  }

  async recordProviderRequestId(
    input: EdgeRequestBinding & { providerRequestId: string },
  ): Promise<EdgeRequestRecord> {
    const record = this.#required(input);
    assertState(record, ['executing'], 'record provider request ID');
    const providerRequestId = normalizeProviderRequestId(input.providerRequestId);
    if (record.providerRequestId && record.providerRequestId !== providerRequestId) {
      throw new EdgeRequestLedgerConflictError(
        'EDGE_REQUEST_PROVIDER_ID_CONFLICT',
        'attempt is already bound to another provider request ID',
      );
    }
    if (record.providerRequestId === providerRequestId) return cloneRecord(record);
    const next = cloneRecord(record);
    next.providerRequestId = providerRequestId;
    next.updatedAtMs = this.#now();
    const active = next.attempts.at(-1);
    if (!active || active.outcome !== null) {
      throw new EdgeRequestLedgerCorruptionError('active edge request attempt is missing');
    }
    active.providerRequestId = providerRequestId;
    await this.#store(next);
    return cloneRecord(next);
  }

  async markNotSent(input: EdgeRequestBinding): Promise<EdgeRequestRecord> {
    const record = this.#required(input);
    if (record.providerRequestId !== null) {
      throw new EdgeRequestLedgerConflictError(
        'EDGE_REQUEST_STATE_CONFLICT',
        'a provider-acknowledged request cannot be marked as not sent',
      );
    }
    if (record.state === 'received') {
      const next = cloneRecord(record);
      next.state = 'not_sent';
      next.updatedAtMs = this.#now();
      await this.#store(next);
      return cloneRecord(next);
    }
    return this.#finishAttempt(input, 'not_sent', 'not_sent');
  }

  async markUnknownOutcome(input: EdgeRequestBinding): Promise<EdgeRequestRecord> {
    return this.#finishAttempt(input, 'unknown_outcome', 'unknown_outcome');
  }

  async confirmFailover(input: EdgeRequestBinding): Promise<EdgeRequestRecord> {
    const record = this.#required(input);
    const previousAttempt = record.attempts.at(-1);
    const confirmedNotSentRetry = record.state === 'received'
      && previousAttempt?.outcome === 'not_sent';
    if (record.state !== 'unknown_outcome' && !confirmedNotSentRetry) {
      throw new EdgeRequestLedgerConflictError(
        'EDGE_REQUEST_STATE_CONFLICT',
        'provider failover can only be confirmed after a finished attempt',
      );
    }
    if (!previousAttempt || previousAttempt.endedAtMs === null) {
      throw new EdgeRequestLedgerCorruptionError('finished edge request attempt is missing');
    }
    if (record.failoverConfirmedAt !== null
      && record.failoverConfirmedAt >= previousAttempt.endedAtMs) return cloneRecord(record);
    const next = cloneRecord(record);
    next.failoverConfirmedAt = this.#now();
    next.updatedAtMs = next.failoverConfirmedAt;
    await this.#store(next);
    return cloneRecord(next);
  }

  async complete(
    input: EdgeRequestBinding & {
      actualUsage: EdgeModelUsageV1;
      providerRequestId?: string;
    },
  ): Promise<EdgeRequestRecord> {
    let record = this.#required(input);
    assertState(record, ['executing'], 'complete request');
    if (input.providerRequestId) {
      record = await this.recordProviderRequestId({
        ...input,
        providerRequestId: input.providerRequestId,
      });
    }
    const now = this.#now();
    const next = cloneRecord(record);
    const active = next.attempts.at(-1);
    if (!active || active.outcome !== null) {
      throw new EdgeRequestLedgerCorruptionError('active edge request attempt is missing');
    }
    active.outcome = 'completed';
    active.endedAtMs = now;
    next.state = 'completed';
    next.actualUsage = normalizeUsage(input.actualUsage);
    next.completedAtMs = now;
    next.updatedAtMs = now;
    await this.#store(next);
    return cloneRecord(next);
  }

  async recover(): Promise<void> {
    for (const record of this.records()) {
      if (record.state === 'received') {
        const next = { ...cloneRecord(record), state: 'not_sent' as const,
          updatedAtMs: this.#now() };
        await this.#store(next);
      } else if (record.state === 'executing') {
        await this.markUnknownOutcome(record);
      }
    }
  }

  async #finishAttempt(
    input: EdgeRequestBinding,
    state: Extract<EdgeRequestState, 'not_sent' | 'unknown_outcome'>,
    outcome: Extract<EdgeRequestAttemptOutcome, 'not_sent' | 'unknown_outcome'>,
  ): Promise<EdgeRequestRecord> {
    const record = this.#required(input);
    assertState(record, ['executing'], `mark ${state}`);
    const next = cloneRecord(record);
    const active = next.attempts.at(-1);
    if (!active || active.outcome !== null) {
      throw new EdgeRequestLedgerCorruptionError('active edge request attempt is missing');
    }
    const now = this.#now();
    active.outcome = outcome;
    active.endedAtMs = now;
    next.state = state;
    next.updatedAtMs = now;
    await this.#store(next);
    return cloneRecord(next);
  }

  #required(input: EdgeRequestBinding): EdgeRequestRecord {
    const binding = normalizeBinding(input);
    const record = this.#records.get(binding.requestId);
    if (!record) {
      throw new EdgeRequestLedgerConflictError(
        'EDGE_REQUEST_STATE_CONFLICT',
        'edge request has not been admitted',
      );
    }
    assertEdgeRequestBinding(record, binding);
    return cloneRecord(record);
  }

  async #store(record: EdgeRequestRecord): Promise<void> {
    const validated = assertEdgeRequestRecord(record);
    const previous = this.#records.get(validated.requestId);
    assertReplay(previous, validated);
    await this.#persist(validated);
    this.#records.set(validated.requestId, cloneRecord(validated));
  }
}

abstract class QueuedEdgeRequestLedger implements EdgeRequestLedger {
  readonly #engine: EdgeRequestLedgerEngine;
  #queue: Promise<void> = Promise.resolve();

  protected constructor(
    now: () => number,
    persist: PersistEdgeRequestRecord = async () => undefined,
  ) {
    this.#engine = new EdgeRequestLedgerEngine(now, persist);
  }

  protected engine(): EdgeRequestLedgerEngine {
    return this.#engine;
  }

  protected setPersist(persist: PersistEdgeRequestRecord): void {
    this.#engine.setPersist(persist);
  }

  protected run<T>(operation: (engine: EdgeRequestLedgerEngine) => Promise<T> | T): Promise<T> {
    const task = this.#queue.then(
      () => operation(this.#engine),
      () => operation(this.#engine),
    );
    this.#queue = task.then(() => undefined, () => undefined);
    return task;
  }

  admit(input: EdgeRequestAdmission): Promise<EdgeRequestAdmissionResult> {
    return this.run((engine) => engine.admit(input));
  }

  lookup(input: Omit<EdgeRequestBinding, 'requestHash'>): Promise<EdgeRequestRecord | null> {
    return this.run((engine) => engine.lookup(input));
  }

  beginAttempt(input: EdgeRequestBinding & { routeId: string }): Promise<EdgeRequestRecord> {
    return this.run((engine) => engine.beginAttempt(input));
  }

  recordProviderRequestId(
    input: EdgeRequestBinding & { providerRequestId: string },
  ): Promise<EdgeRequestRecord> {
    return this.run((engine) => engine.recordProviderRequestId(input));
  }

  markNotSent(input: EdgeRequestBinding): Promise<EdgeRequestRecord> {
    return this.run((engine) => engine.markNotSent(input));
  }

  markUnknownOutcome(input: EdgeRequestBinding): Promise<EdgeRequestRecord> {
    return this.run((engine) => engine.markUnknownOutcome(input));
  }

  confirmFailover(input: EdgeRequestBinding): Promise<EdgeRequestRecord> {
    return this.run((engine) => engine.confirmFailover(input));
  }

  complete(
    input: EdgeRequestBinding & {
      actualUsage: EdgeModelUsageV1;
      providerRequestId?: string;
    },
  ): Promise<EdgeRequestRecord> {
    return this.run((engine) => engine.complete(input));
  }
}

export class MemoryEdgeRequestLedger extends QueuedEdgeRequestLedger {
  constructor(options: { now?: () => number } = {}) {
    super(options.now ?? Date.now);
  }
}

export class FileEdgeRequestLedger extends QueuedEdgeRequestLedger {
  readonly #journalFile: string;
  #journalIndex = 0;
  #lastJournalHash: string | null = null;

  private constructor(options: FileEdgeRequestLedgerOptions) {
    let journalFile = '';
    if (typeof options.journalFile === 'string') journalFile = options.journalFile.trim();
    if (!journalFile) throw new TypeError('edge request journal path is required');
    super(options.now ?? Date.now);
    this.#journalFile = journalFile;
    this.setPersist((record) => this.#append(record));
  }

  static async create(options: FileEdgeRequestLedgerOptions): Promise<FileEdgeRequestLedger> {
    const ledger = new FileEdgeRequestLedger(options);
    await ledger.#load();
    await ledger.run((engine) => engine.recover());
    return ledger;
  }

  async #load(): Promise<void> {
    await mkdir(dirname(this.#journalFile), { recursive: true, mode: 0o700 });
    let journalExisted = false;
    try {
      const info = await lstat(this.#journalFile);
      journalExisted = true;
      if (!info.isFile() || info.isSymbolicLink()) {
        throw new EdgeRequestLedgerCorruptionError(
          'edge request journal must be a regular file',
        );
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
    let content = '';
    try {
      content = await readFile(this.#journalFile, 'utf8');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
    if (!content) {
      if (journalExisted) {
        throw new EdgeRequestLedgerCorruptionError('edge request journal is empty or truncated');
      }
      return;
    }
    if (!content.endsWith('\n')) {
      throw new EdgeRequestLedgerCorruptionError('edge request journal is truncated');
    }
    for (const line of content.split('\n').filter(Boolean)) {
      let raw: unknown;
      try {
        raw = JSON.parse(line) as unknown;
      } catch {
        throw new EdgeRequestLedgerCorruptionError('edge request journal JSON is invalid');
      }
      if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
        throw new EdgeRequestLedgerCorruptionError('edge request journal entry is invalid');
      }
      const body = raw as Record<string, unknown>;
      if (body.version !== 1 || body.index !== this.#journalIndex + 1
        || body.previousHash !== this.#lastJournalHash || typeof body.hash !== 'string') {
        throw new EdgeRequestLedgerCorruptionError('edge request journal hash chain is invalid');
      }
      const payload: LedgerJournalPayload = {
        version: 1,
        index: Number(body.index),
        previousHash: body.previousHash as string | null,
        record: assertEdgeRequestRecord(body.record),
      };
      if (!SHA256.test(body.hash) || digest(payload) !== body.hash) {
        throw new EdgeRequestLedgerCorruptionError('edge request journal hash chain is invalid');
      }
      this.#journalIndex = payload.index;
      this.#lastJournalHash = body.hash;
      this.engine().load(payload.record);
    }
  }

  async #append(record: EdgeRequestRecord): Promise<void> {
    const payload: LedgerJournalPayload = {
      version: 1,
      index: this.#journalIndex + 1,
      previousHash: this.#lastJournalHash,
      record: cloneRecord(record),
    };
    const journalRecord: LedgerJournalRecord = { ...payload, hash: digest(payload) };
    const file = await open(this.#journalFile, 'a', 0o600);
    try {
      const info = await file.stat();
      if (!info.isFile()) {
        throw new EdgeRequestLedgerCorruptionError(
          'edge request journal must be a regular file',
        );
      }
      await file.appendFile(`${JSON.stringify(journalRecord)}\n`, 'utf8');
      await file.sync();
    } finally {
      await file.close();
    }
    this.#journalIndex = payload.index;
    this.#lastJournalHash = journalRecord.hash;
  }
}

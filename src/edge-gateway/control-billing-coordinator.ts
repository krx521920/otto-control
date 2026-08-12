import { createHash, randomBytes } from 'node:crypto';
import { mkdir, open, readFile } from 'node:fs/promises';
import { dirname } from 'node:path';

import type {
  ExecutionReceiptV2Payload,
  SignedExecutionReceiptV2,
} from '../contracts/billing.js';
import { canonicalJson, type PayloadSigner } from '../crypto/signed-envelope.js';
import {
  EdgeBillingAdmissionError,
  type EdgeBillingCoordinator,
  type EdgeBillingReleaseRequest,
  type EdgeBillingRequestIdentity,
  type EdgeBillingOperationalStatus,
  type EdgeBillingReservation,
  type EdgeBillingReservationRequest,
  type EdgeBillingSettlementRequest,
  type EdgeBillingUncertainRequest,
} from './billing-coordinator.js';
import {
  type EdgeControlPolicyBinding,
  normalizeEdgeControlBaseUrl,
  normalizeEdgeControlBinding,
  readEdgeControlResponseJson,
} from './control-policy-source.js';

const IDENTIFIER = /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,159}$/u;
const HOLD_ID = /^hold_[a-f0-9]{32}$/u;
const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_RETRY_MS = 10_000;
const RECEIPT_LIFETIME_MS = 518_400_000;
const RECEIPT_KEY_LIFETIME_MS = 31_536_000_000;
const MAX_UNITS = 9_000_000_000_000;

type ReservationStatus = 'active' | 'released' | 'settled' | 'uncertain';

interface ReservationState {
  reservationId: string;
  status: ReservationStatus;
}

interface PendingSettlement {
  requestId: string;
  reservationId: string;
  envelope: SignedExecutionReceiptV2;
}

interface PendingRelease {
  requestId: string;
  reservationId: string;
  idempotencyKey: string;
}

type JournalPayload =
  | {
      version: 1;
      index: number;
      previousHash: string | null;
      type: 'reserved';
      requestId: string;
      reservationId: string;
    }
  | {
      version: 1;
      index: number;
      previousHash: string | null;
      type: 'settlement_pending';
      requestId: string;
      reservationId: string;
      envelope: SignedExecutionReceiptV2;
    }
  | {
      version: 1;
      index: number;
      previousHash: string | null;
      type: 'settled';
      requestId: string;
    }
  | {
      version: 1;
      index: number;
      previousHash: string | null;
      type: 'release_pending';
      requestId: string;
      reservationId: string;
      idempotencyKey: string;
      reason: EdgeBillingReleaseRequest['reason'];
    }
  | {
      version: 1;
      index: number;
      previousHash: string | null;
      type: 'released';
      requestId: string;
    }
  | {
      version: 1;
      index: number;
      previousHash: string | null;
      type: 'uncertain';
      requestId: string;
      routeId: string;
      reason: EdgeBillingUncertainRequest['reason'];
      occurredAtMs: number;
    };

type JournalRecord = JournalPayload & { hash: string };
type JournalEvent<T> = T extends unknown
  ? Omit<T, 'version' | 'index' | 'previousHash'>
  : never;

export interface ControlEdgeBillingCoordinatorOptions {
  controlBaseUrl: string;
  binding: EdgeControlPolicyBinding;
  leaseToken: string;
  signer: PayloadSigner;
  journalFile: string;
  fetch?: typeof fetch;
  now?: () => number;
  randomHex?: () => string;
  requestTimeoutMs?: number;
  retryIntervalMs?: number;
  bootstrapReceiptKey?: boolean;
}

class ControlBillingRequestError extends Error {
  constructor(readonly status: number, readonly code: string | null) {
    super('Control billing request failed');
    this.name = 'ControlBillingRequestError';
  }
}

function responseErrorCode(value: unknown): string | null {
  const code = (value as { error?: { code?: unknown } } | null)?.error?.code;
  return typeof code === 'string' ? code : null;
}

function configurationError(message: string): never {
  throw new Error(`Edge billing configuration is invalid: ${message}`);
}

function boundedInteger(
  value: number | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
  name: string,
): number {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result < minimum || result > maximum) {
    configurationError(name);
  }
  return result;
}

function digest(value: unknown): string {
  return createHash('sha256').update(canonicalJson(value)).digest('hex');
}

function stableId(prefix: string, value: string): string {
  return `${prefix}${createHash('sha256').update(value).digest('hex').slice(0, 32)}`;
}

function reservationId(value: unknown): string {
  const id = (value as { hold?: { id?: unknown } } | null)?.hold?.id;
  if (typeof id !== 'string' || !HOLD_ID.test(id)) {
    throw new Error('Control hold response is invalid');
  }
  return id;
}

function assertIdentity(
  binding: EdgeControlPolicyBinding,
  request: EdgeBillingRequestIdentity,
): void {
  if (request.deploymentId !== binding.deploymentId
    || request.organizationId !== binding.organizationId) {
    throw new Error('Edge billing request does not match the configured deployment');
  }
  if (!IDENTIFIER.test(request.requestId) || !IDENTIFIER.test(request.tokenId)
    || !IDENTIFIER.test(request.subjectId) || !IDENTIFIER.test(request.policyVersion)
    || !request.publicModel.trim() || request.publicModel.trim().length > 160) {
    throw new Error('Edge billing request identity is invalid');
  }
}

function validUnits(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 1 && value <= MAX_UNITS;
}

function validTokenCount(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0 && value <= MAX_UNITS;
}

function journalPayload(value: unknown, expectedIndex: number, previousHash: string | null): JournalPayload {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    configurationError('billing journal record');
  }
  const body = value as Record<string, unknown>;
  if (body.version !== 1 || body.index !== expectedIndex || body.previousHash !== previousHash
    || typeof body.type !== 'string' || typeof body.requestId !== 'string'
    || !IDENTIFIER.test(body.requestId)) configurationError('billing journal record');
  const common = {
    version: 1 as const,
    index: expectedIndex,
    previousHash,
    requestId: body.requestId,
  };
  if (body.type === 'reserved') {
    if (typeof body.reservationId !== 'string' || !HOLD_ID.test(body.reservationId)) {
      configurationError('billing journal reservation');
    }
    return { ...common, type: 'reserved', reservationId: body.reservationId };
  }
  if (body.type === 'settlement_pending') {
    if (typeof body.reservationId !== 'string' || !HOLD_ID.test(body.reservationId)
      || !body.envelope || typeof body.envelope !== 'object' || Array.isArray(body.envelope)) {
      configurationError('billing journal settlement');
    }
    return {
      ...common,
      type: 'settlement_pending',
      reservationId: body.reservationId,
      envelope: body.envelope as unknown as SignedExecutionReceiptV2,
    };
  }
  if (body.type === 'release_pending') {
    if (typeof body.reservationId !== 'string' || !HOLD_ID.test(body.reservationId)
      || typeof body.idempotencyKey !== 'string' || !IDENTIFIER.test(body.idempotencyKey)
      || !['no_usable_route', 'unmetered_route', 'zero_usage'].includes(String(body.reason))) {
      configurationError('billing journal release');
    }
    return {
      ...common,
      type: 'release_pending',
      reservationId: body.reservationId,
      idempotencyKey: body.idempotencyKey,
      reason: body.reason as EdgeBillingReleaseRequest['reason'],
    };
  }
  if (body.type === 'uncertain') {
    if (typeof body.routeId !== 'string' || !IDENTIFIER.test(body.routeId)
      || !['client_cancelled', 'provider_error', 'stream_timed_out', 'usage_unavailable']
        .includes(String(body.reason))
      || !Number.isSafeInteger(body.occurredAtMs) || Number(body.occurredAtMs) < 1) {
      configurationError('billing journal uncertain event');
    }
    return {
      ...common,
      type: 'uncertain',
      routeId: body.routeId,
      reason: body.reason as EdgeBillingUncertainRequest['reason'],
      occurredAtMs: Number(body.occurredAtMs),
    };
  }
  if (body.type === 'settled' || body.type === 'released') {
    return { ...common, type: body.type };
  }
  configurationError('billing journal event type');
}

/**
 * Single-process Node coordinator. Its append-only, hash-chained journal keeps
 * receipt sequences and pending financial operations durable across restarts.
 * Multi-process/edge-region deployments must replace it with a shared ordered
 * aggregator rather than sharing this file over NFS/SMB.
 */
export class ControlEdgeBillingCoordinator implements EdgeBillingCoordinator {
  readonly #baseUrl: URL;
  readonly #binding: EdgeControlPolicyBinding;
  readonly #leaseToken: string;
  readonly #signer: PayloadSigner;
  readonly #journalFile: string;
  readonly #fetch: typeof fetch;
  readonly #now: () => number;
  readonly #randomHex: () => string;
  readonly #requestTimeoutMs: number;
  readonly #retryIntervalMs: number;
  readonly #reservations = new Map<string, ReservationState>();
  readonly #recoveredReservations = new Set<string>();
  readonly #pendingSettlements = new Map<string, PendingSettlement>();
  readonly #pendingReleases = new Map<string, PendingRelease>();
  readonly #reserving = new Map<string, Promise<EdgeBillingReservation>>();
  #lastJournalHash: string | null = null;
  #journalIndex = 0;
  #lastSequence = 0;
  #journalQueue: Promise<void> = Promise.resolve();
  #settlementQueue: Promise<void> = Promise.resolve();
  #retryTimer?: ReturnType<typeof setInterval>;

  private constructor(options: ControlEdgeBillingCoordinatorOptions) {
    try {
      this.#baseUrl = normalizeEdgeControlBaseUrl(options.controlBaseUrl);
      this.#binding = normalizeEdgeControlBinding(options.binding);
    } catch {
      configurationError('Control URL or deployment binding');
    }
    this.#leaseToken = options.leaseToken.trim();
    if (this.#leaseToken.length < 32 || this.#leaseToken.length > 8_192
      || /\s/u.test(this.#leaseToken)) configurationError('lease token');
    this.#signer = options.signer;
    if (!/^[a-f0-9]{16}$/u.test(this.#signer.keyId)) configurationError('receipt signer key ID');
    this.#journalFile = options.journalFile.trim();
    if (!this.#journalFile) configurationError('billing journal path');
    this.#fetch = options.fetch ?? fetch;
    this.#now = options.now ?? Date.now;
    this.#randomHex = options.randomHex ?? (() => randomBytes(16).toString('hex'));
    this.#requestTimeoutMs = boundedInteger(
      options.requestTimeoutMs, DEFAULT_TIMEOUT_MS, 500, 60_000, 'request timeout',
    );
    this.#retryIntervalMs = boundedInteger(
      options.retryIntervalMs, DEFAULT_RETRY_MS, 1_000, 60 * 60 * 1000, 'retry interval',
    );
  }

  static async create(
    options: ControlEdgeBillingCoordinatorOptions,
  ): Promise<ControlEdgeBillingCoordinator> {
    const coordinator = new ControlEdgeBillingCoordinator(options);
    await coordinator.#loadJournal();
    if (options.bootstrapReceiptKey !== false) await coordinator.#bootstrapReceiptKey();
    await coordinator.flushPending();
    coordinator.#retryTimer = setInterval(() => {
      void coordinator.flushPending();
    }, coordinator.#retryIntervalMs);
    coordinator.#retryTimer.unref?.();
    return coordinator;
  }

  close(): void {
    if (this.#retryTimer) clearInterval(this.#retryTimer);
    this.#retryTimer = undefined;
  }

  async reserve(request: EdgeBillingReservationRequest): Promise<EdgeBillingReservation> {
    assertIdentity(this.#binding, request);
    if (!validUnits(request.reserveUnits)) throw new Error('Edge billing reserve units are invalid');
    const existing = this.#reservations.get(request.requestId);
    if (existing?.status === 'active') return { reservationId: existing.reservationId };
    if (existing) throw new Error('Edge billing request ID was already finalized');
    const active = this.#reserving.get(request.requestId);
    if (active) return active;
    const task = this.#createReservation(request);
    this.#reserving.set(request.requestId, task);
    try {
      return await task;
    } finally {
      this.#reserving.delete(request.requestId);
    }
  }

  async settle(request: EdgeBillingSettlementRequest): Promise<void> {
    assertIdentity(this.#binding, request);
    if (!IDENTIFIER.test(request.routeId) || !validTokenCount(request.usage.inputTokens)
      || !validTokenCount(request.usage.outputTokens) || !validUnits(request.usage.totalTokens)
      || request.usage.inputTokens + request.usage.outputTokens !== request.usage.totalTokens
      || !Number.isSafeInteger(request.occurredAtMs) || request.occurredAtMs < 1) {
      throw new Error('Edge billing settlement evidence is invalid');
    }
    await this.#serializeSettlement(async () => {
      const state = this.#activeReservation(request.requestId, request.reservation);
      if (this.#pendingSettlements.has(request.requestId)) return;
      const issuedAtMs = this.#now();
      const sequence = this.#lastSequence + 1;
      const random = this.#randomHex();
      if (!/^[a-f0-9]{32}$/u.test(random)) configurationError('receipt ID generator');
      const receipt: ExecutionReceiptV2Payload = {
        version: 2,
        receiptId: `exec_${random}`,
        deploymentId: request.deploymentId,
        organizationId: request.organizationId,
        taskId: stableId('edge_', request.requestId),
        moduleId: 'model_gateway',
        units: request.usage.totalTokens,
        model: request.publicModel,
        issuedAtMs,
        expiresAtMs: issuedAtMs + RECEIPT_LIFETIME_MS,
        sequence,
        policyVersion: request.policyVersion,
      };
      const envelope: SignedExecutionReceiptV2 = {
        receipt,
        signingKeyId: this.#signer.keyId,
        signature: await this.#signer.sign(receipt),
      };
      const pending = {
        requestId: request.requestId,
        reservationId: state.reservationId,
        envelope,
      };
      await this.#append({ type: 'settlement_pending', ...pending });
      this.#pendingSettlements.set(request.requestId, pending);
      this.#lastSequence = sequence;
      await this.#flushSettlementsInOrder();
    });
  }

  async release(request: EdgeBillingReleaseRequest): Promise<void> {
    assertIdentity(this.#binding, request);
    if (!Number.isSafeInteger(request.occurredAtMs) || request.occurredAtMs < 1) {
      throw new Error('Edge billing release evidence is invalid');
    }
    const state = this.#activeReservation(request.requestId, request.reservation);
    if (this.#pendingReleases.has(request.requestId)) return;
    const pending = {
      requestId: request.requestId,
      reservationId: state.reservationId,
      idempotencyKey: stableId('edge-release:', request.requestId),
      reason: request.reason,
    };
    await this.#append({ type: 'release_pending', ...pending });
    this.#pendingReleases.set(request.requestId, pending);
    await this.#flushRelease(pending);
  }

  async markUncertain(request: EdgeBillingUncertainRequest): Promise<void> {
    assertIdentity(this.#binding, request);
    if (!IDENTIFIER.test(request.routeId) || !Number.isSafeInteger(request.occurredAtMs)
      || request.occurredAtMs < 1) {
      throw new Error('Edge billing uncertain evidence is invalid');
    }
    const state = this.#activeReservation(request.requestId, request.reservation);
    await this.#append({
      type: 'uncertain',
      requestId: request.requestId,
      routeId: request.routeId,
      reason: request.reason,
      occurredAtMs: request.occurredAtMs,
    });
    this.#recoveredReservations.delete(request.requestId);
    this.#reservations.set(request.requestId, { ...state, status: 'uncertain' });
  }

  async flushPending(): Promise<void> {
    await this.#serializeSettlement(() => this.#flushSettlementsInOrder());
    await Promise.all([...this.#pendingReleases.values()].map((item) => this.#flushRelease(item)));
  }

  operationalStatus(): EdgeBillingOperationalStatus {
    let activeReservations = 0;
    let uncertainReservations = 0;
    for (const reservation of this.#reservations.values()) {
      if (reservation.status === 'active') activeReservations += 1;
      if (reservation.status === 'uncertain') uncertainReservations += 1;
    }
    const pendingSettlements = this.#pendingSettlements.size;
    const pendingReleases = this.#pendingReleases.size;
    const recoveredReservations = this.#recoveredReservations.size;
    const state = pendingSettlements > 0 || pendingReleases > 0
      ? 'unavailable'
      : recoveredReservations > 0 || uncertainReservations > 0
        ? 'degraded'
        : 'ready';
    return {
      state,
      activeReservations,
      recoveredReservations,
      pendingSettlements,
      pendingReleases,
      uncertainReservations,
      journalEntries: this.#journalIndex,
      lastReceiptSequence: this.#lastSequence,
    };
  }

  async #createReservation(
    request: EdgeBillingReservationRequest,
  ): Promise<EdgeBillingReservation> {
    let response: unknown;
    try {
      response = await this.#post('/v1/billing/holds', {
        ...this.#binding,
        module: 'model_gateway',
        units: request.reserveUnits,
        expiresInSeconds: 900,
        idempotencyKey: stableId('edge-hold:', request.requestId),
      });
    } catch (error) {
      if (error instanceof ControlBillingRequestError && error.status === 402) {
        throw new EdgeBillingAdmissionError(402, 'EDGE_CREDIT_REQUIRED', 'insufficient credits');
      }
      throw new EdgeBillingAdmissionError(503, 'EDGE_BILLING_UNAVAILABLE', 'Control unavailable');
    }
    const id = reservationId(response);
    await this.#append({ type: 'reserved', requestId: request.requestId, reservationId: id });
    this.#reservations.set(request.requestId, { reservationId: id, status: 'active' });
    return { reservationId: id };
  }

  #activeReservation(requestId: string, reservation: EdgeBillingReservation): ReservationState {
    const state = this.#reservations.get(requestId);
    if (!state || state.status !== 'active' || state.reservationId !== reservation.reservationId) {
      throw new Error('Edge billing reservation is not active');
    }
    return state;
  }

  async #flushSettlementsInOrder(): Promise<void> {
    const pending = [...this.#pendingSettlements.values()]
      .sort((left, right) => left.envelope.receipt.sequence - right.envelope.receipt.sequence);
    for (const item of pending) {
      try {
        await this.#post(`/v1/billing/holds/${item.reservationId}/execution-receipts`, {
          licenseId: this.#binding.licenseId,
          machineFingerprint: this.#binding.machineFingerprint,
          envelope: item.envelope,
        });
      } catch (error) {
        if (!(error instanceof ControlBillingRequestError)
          || error.status !== 409
          || error.code !== 'CREDIT_HOLD_UNAVAILABLE') return;
        try {
          await this.#post('/v1/billing/execution-receipts', {
            licenseId: this.#binding.licenseId,
            machineFingerprint: this.#binding.machineFingerprint,
            envelope: item.envelope,
          });
        } catch {
          return;
        }
      }
      await this.#append({ type: 'settled', requestId: item.requestId });
      this.#pendingSettlements.delete(item.requestId);
      this.#recoveredReservations.delete(item.requestId);
      const current = this.#reservations.get(item.requestId);
      if (current) this.#reservations.set(item.requestId, { ...current, status: 'settled' });
    }
  }

  async #flushRelease(item: PendingRelease): Promise<void> {
    try {
      await this.#post(`/v1/billing/holds/${item.reservationId}/release`, {
        ...this.#binding,
        idempotencyKey: item.idempotencyKey,
      });
    } catch {
      return;
    }
    await this.#append({ type: 'released', requestId: item.requestId });
    this.#pendingReleases.delete(item.requestId);
    this.#recoveredReservations.delete(item.requestId);
    const current = this.#reservations.get(item.requestId);
    if (current) this.#reservations.set(item.requestId, { ...current, status: 'released' });
  }

  async #bootstrapReceiptKey(): Promise<void> {
    const issuedAtMs = this.#now();
    const claim = {
      version: 1 as const,
      ...this.#binding,
      keyId: this.#signer.keyId,
      publicKeyPem: this.#signer.publicKeyPem,
      issuedAtMs,
      expiresAtMs: issuedAtMs + RECEIPT_KEY_LIFETIME_MS,
      nonce: randomBytes(24).toString('base64url'),
    };
    await this.#post('/v1/billing/execution-receipt-keys/bootstrap', {
      ...claim,
      signature: await this.#signer.sign(claim),
    });
  }

  async #post(path: string, body: unknown): Promise<unknown> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.#requestTimeoutMs);
    let response: Response;
    try {
      response = await this.#fetch(new URL(path, this.#baseUrl), {
        method: 'POST',
        headers: {
          accept: 'application/json',
          authorization: `Bearer ${this.#leaseToken}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify(body),
        redirect: 'error',
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timeout);
    }
    let parsed: unknown = null;
    try {
      parsed = await readEdgeControlResponseJson(response);
    } catch {
      throw new Error('Control billing response is invalid');
    }
    if (!response.ok) {
      throw new ControlBillingRequestError(response.status, responseErrorCode(parsed));
    }
    return parsed;
  }

  async #loadJournal(): Promise<void> {
    await mkdir(dirname(this.#journalFile), { recursive: true });
    let content = '';
    try {
      content = await readFile(this.#journalFile, 'utf8');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
    if (!content) return;
    if (!content.endsWith('\n')) configurationError('billing journal is truncated');
    for (const line of content.split('\n').filter(Boolean)) {
      let raw: unknown;
      try {
        raw = JSON.parse(line) as unknown;
      } catch {
        configurationError('billing journal JSON');
      }
      const body = raw as Record<string, unknown>;
      const payload = journalPayload(body, this.#journalIndex + 1, this.#lastJournalHash);
      if (body.hash !== digest(payload)) {
        configurationError('billing journal hash chain');
      }
      this.#journalIndex = payload.index;
      this.#lastJournalHash = body.hash;
      this.#apply(payload);
    }
  }

  async #append(
    event: JournalEvent<JournalPayload>,
  ): Promise<void> {
    const operation = async () => {
      const payload = {
        version: 1 as const,
        index: this.#journalIndex + 1,
        previousHash: this.#lastJournalHash,
        ...event,
      } as JournalPayload;
      const record: JournalRecord = { ...payload, hash: digest(payload) };
      const file = await open(this.#journalFile, 'a', 0o600);
      try {
        await file.appendFile(`${JSON.stringify(record)}\n`, 'utf8');
        await file.sync();
      } finally {
        await file.close();
      }
      this.#journalIndex = payload.index;
      this.#lastJournalHash = record.hash;
    };
    const result = this.#journalQueue.then(operation, operation);
    this.#journalQueue = result.then(() => undefined, () => undefined);
    return result;
  }

  #apply(event: JournalPayload): void {
    if (event.type === 'reserved') {
      this.#reservations.set(event.requestId, {
        reservationId: event.reservationId,
        status: 'active',
      });
      this.#recoveredReservations.add(event.requestId);
    } else if (event.type === 'settlement_pending') {
      this.#pendingSettlements.set(event.requestId, {
        requestId: event.requestId,
        reservationId: event.reservationId,
        envelope: event.envelope,
      });
      this.#lastSequence = Math.max(this.#lastSequence, event.envelope.receipt.sequence);
    } else if (event.type === 'release_pending') {
      this.#pendingReleases.set(event.requestId, {
        requestId: event.requestId,
        reservationId: event.reservationId,
        idempotencyKey: event.idempotencyKey,
      });
    } else {
      const current = this.#reservations.get(event.requestId);
      if (current) this.#reservations.set(event.requestId, { ...current, status: event.type });
      if (event.type === 'settled') this.#pendingSettlements.delete(event.requestId);
      if (event.type === 'released') this.#pendingReleases.delete(event.requestId);
      this.#recoveredReservations.delete(event.requestId);
    }
  }

  async #serializeSettlement(operation: () => Promise<void>): Promise<void> {
    const result = this.#settlementQueue.then(operation, operation);
    this.#settlementQueue = result.then(() => undefined, () => undefined);
    return result;
  }
}

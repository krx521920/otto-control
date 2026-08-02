import { createHash, randomUUID, timingSafeEqual, verify } from 'node:crypto';

import { AUDIT_GENESIS_HASH } from '../../audit-chain.js';
import type { AuditAnchorPayload } from '../../contracts/audit-anchor.js';
import type {
  AuditWitnessEvidenceEnvelope,
  AuditWitnessEvidencePollResult,
  AuditWitnessEvidenceRecoveryResult,
  AuditWitnessEvidenceRecord,
  AuditWitnessEvidenceStatusSummary,
  AuditWitnessEvidenceView,
  AuditWitnessReceiptRecord,
  AuditWitnessReceiptView,
  AuditWitnessSourceSummary,
} from '../../contracts/audit-witness.js';
import { canonicalJson, ed25519PublicKeyId } from '../../crypto/signed-envelope.js';
import { conflict, invalidRequest, notFound, unauthorized } from '../../errors.js';
import type { ControlStore } from '../../storage/control-store.js';
import type { AuditWitnessSource } from './source-config.js';
import type { AuditWitnessWormObjectStore } from './worm-object-store.js';

const ANCHOR_ID = /^anchor_[a-f0-9]{32}$/u;
const HASH = /^[a-f0-9]{64}$/u;
const KEY_ID = /^[a-f0-9]{16}$/u;
const SIGNATURE = /^ed25519:[A-Za-z0-9_-]{86}$/u;
const MAX_FUTURE_SKEW_MS = 5 * 60_000;
const EVIDENCE_LEASE_MS = 2 * 60_000;
const MAX_EVIDENCE_BATCH_SIZE = 10;
const DAY_MS = 24 * 60 * 60_000;

function objectValue(value: unknown, name: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw invalidRequest(`${name} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exactString(value: unknown, name: string, pattern?: RegExp): string {
  if (typeof value !== 'string' || !value || value.length > 2_048 || (pattern && !pattern.test(value))) {
    throw invalidRequest(`${name} is invalid`);
  }
  return value;
}

function safeInteger(value: unknown, name: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw invalidRequest(`${name} must be a non-negative safe integer`);
  }
  return value;
}

function receiptView(record: AuditWitnessReceiptRecord): AuditWitnessReceiptView {
  return { ...record, receivedAt: record.receivedAt.toISOString() };
}

function evidenceView(record: AuditWitnessEvidenceRecord): AuditWitnessEvidenceView {
  return {
    ...record,
    nextAttemptAt: record.nextAttemptAt.toISOString(),
    leaseUntil: record.leaseUntil?.toISOString() ?? null,
    objectLockRetainUntil: record.objectLockRetainUntil?.toISOString() ?? null,
    storedAt: record.storedAt?.toISOString() ?? null,
    verifiedAt: record.verifiedAt?.toISOString() ?? null,
    createdAt: record.createdAt.toISOString(),
    updatedAt: record.updatedAt.toISOString(),
  };
}

function evidenceEnvelope(record: AuditWitnessReceiptRecord): AuditWitnessEvidenceEnvelope {
  return {
    version: 1,
    receiptId: record.id,
    sourceId: record.sourceId,
    anchorId: record.anchorId,
    fingerprint: record.fingerprint,
    issuer: record.issuer,
    chainSequence: record.chainSequence,
    headHash: record.headHash,
    signingKeyId: record.signingKeyId,
    payload: record.payload,
    receivedAt: record.receivedAt.toISOString(),
  };
}

function evidenceBody(record: AuditWitnessReceiptRecord): Buffer {
  return Buffer.from(canonicalJson(evidenceEnvelope(record)), 'utf8');
}

function safeStorageError(error: unknown): string {
  return (error instanceof Error ? error.message : String(error))
    .replace(/https?:\/\/[^\s/]+[^\s]*/giu, '[OBJECT_STORE]')
    .replace(/(authorization|secret|token|credential|access.?key)\s*[:=]\s*[^\s]+/giu, '$1=[REDACTED]')
    .replace(/[A-Za-z]:\\[^\s]+|\/(?:[^\s/]+\/){2,}[^\s]*/gu, '[LOCAL_PATH]')
    .replace(/\s+/gu, ' ')
    .trim()
    .slice(0, 500) || 'audit WORM evidence storage failed';
}

function retryDelayMs(attempt: number): number {
  return Math.min(6 * 60 * 60_000, 10_000 * (2 ** Math.max(0, attempt - 1)));
}

function stableFingerprint(issuer: string, lastSequence: number, headHash: string): string {
  return createHash('sha256').update(canonicalJson({ issuer, lastSequence, headHash })).digest('hex');
}

function authenticateSource(
  sources: readonly AuditWitnessSource[],
  token: string,
): AuditWitnessSource {
  const candidate = createHash('sha256').update(token, 'utf8').digest();
  let source: AuditWitnessSource | undefined;
  for (const item of sources) {
    if (timingSafeEqual(candidate, item.tokenHash)) source ??= item;
  }
  if (!token || !source) throw unauthorized('Audit witness authentication failed');
  return source;
}

function normalizedPayload(
  raw: unknown,
  source: AuditWitnessSource,
  now: number,
): AuditAnchorPayload {
  const payload = objectValue(raw, 'audit anchor payload');
  if (payload.version !== 1) throw invalidRequest('audit anchor payload version is unsupported');
  const anchorId = exactString(payload.anchorId, 'anchorId', ANCHOR_ID);
  const fingerprint = exactString(payload.fingerprint, 'fingerprint', HASH);
  const evidence = objectValue(payload.evidence, 'evidence');
  const receipt = objectValue(evidence.receipt, 'evidence.receipt');
  if (receipt.version !== 1) throw invalidRequest('audit receipt version is unsupported');
  const issuer = exactString(receipt.issuer, 'receipt.issuer');
  if (issuer !== source.issuer) throw invalidRequest('audit receipt issuer is not trusted for this source');
  const generatedAt = exactString(receipt.generatedAt, 'receipt.generatedAt');
  const generatedAtMs = Date.parse(generatedAt);
  if (!Number.isFinite(generatedAtMs) || new Date(generatedAtMs).toISOString() !== generatedAt
    || generatedAtMs > now + MAX_FUTURE_SKEW_MS) {
    throw invalidRequest('audit receipt generatedAt is invalid');
  }
  if (receipt.valid !== true || receipt.brokenAtSequence !== null) {
    throw invalidRequest('audit witness accepts only valid chain receipts');
  }
  const checkedEvents = safeInteger(receipt.checkedEvents, 'receipt.checkedEvents');
  const lastSequence = safeInteger(receipt.lastSequence, 'receipt.lastSequence');
  const legacyEventCount = safeInteger(receipt.legacyEventCount, 'receipt.legacyEventCount');
  const firstSequence = receipt.firstSequence;
  if ((lastSequence === 0 && (firstSequence !== null || checkedEvents !== 0))
    || (lastSequence > 0 && (firstSequence !== 1 || checkedEvents !== lastSequence))) {
    throw invalidRequest('audit receipt sequence summary is inconsistent');
  }
  const headHash = exactString(receipt.headHash, 'receipt.headHash', HASH);
  if (lastSequence === 0 && headHash !== AUDIT_GENESIS_HASH) {
    throw invalidRequest('empty audit receipt must use the genesis hash');
  }
  const signingKeyId = exactString(evidence.signingKeyId, 'evidence.signingKeyId', KEY_ID);
  const signature = exactString(evidence.signature, 'evidence.signature', SIGNATURE);
  const normalizedReceipt = {
    version: 1 as const,
    issuer,
    generatedAt,
    valid: true,
    checkedEvents,
    firstSequence: firstSequence as 1 | null,
    lastSequence,
    headHash,
    brokenAtSequence: null,
    legacyEventCount,
  };
  const key = source.publicKeys.get(signingKeyId);
  if (!key || !verify(
    null,
    Buffer.from(canonicalJson(normalizedReceipt)),
    key,
    Buffer.from(signature.slice('ed25519:'.length), 'base64url'),
  )) {
    throw invalidRequest('audit receipt signature verification failed');
  }
  const expectedFingerprint = stableFingerprint(issuer, lastSequence, headHash);
  if (fingerprint !== expectedFingerprint) throw invalidRequest('audit anchor fingerprint is invalid');
  return {
    version: 1,
    anchorId,
    fingerprint,
    evidence: { receipt: normalizedReceipt, signingKeyId, signature },
  };
}

function normalizedEvidenceEnvelope(
  raw: unknown,
  source: AuditWitnessSource,
  now: number,
): AuditWitnessEvidenceEnvelope {
  const value = objectValue(raw, 'audit WORM evidence');
  if (value.version !== 1) throw invalidRequest('audit WORM evidence version is unsupported');
  const payload = normalizedPayload(value.payload, source, now);
  const receivedAt = exactString(value.receivedAt, 'receivedAt');
  const receivedAtMs = Date.parse(receivedAt);
  if (!Number.isFinite(receivedAtMs) || new Date(receivedAtMs).toISOString() !== receivedAt
    || receivedAtMs > now + MAX_FUTURE_SKEW_MS) {
    throw invalidRequest('audit WORM evidence receivedAt is invalid');
  }
  const envelope: AuditWitnessEvidenceEnvelope = {
    version: 1,
    receiptId: exactString(value.receiptId, 'receiptId', /^witness_[a-f0-9]{32}$/u),
    sourceId: exactString(value.sourceId, 'sourceId', /^[a-z][a-z0-9_-]{1,63}$/u),
    anchorId: exactString(value.anchorId, 'anchorId', ANCHOR_ID),
    fingerprint: exactString(value.fingerprint, 'fingerprint', HASH),
    issuer: exactString(value.issuer, 'issuer'),
    chainSequence: safeInteger(value.chainSequence, 'chainSequence'),
    headHash: exactString(value.headHash, 'headHash', HASH),
    signingKeyId: exactString(value.signingKeyId, 'signingKeyId', KEY_ID),
    payload,
    receivedAt,
  };
  if (envelope.sourceId !== source.id || envelope.anchorId !== payload.anchorId
    || envelope.fingerprint !== payload.fingerprint
    || envelope.issuer !== payload.evidence.receipt.issuer
    || envelope.chainSequence !== payload.evidence.receipt.lastSequence
    || envelope.headHash !== payload.evidence.receipt.headHash
    || envelope.signingKeyId !== payload.evidence.signingKeyId) {
    throw invalidRequest('audit WORM evidence envelope does not match its signed payload');
  }
  return envelope;
}

export class AuditWitnessService {
  readonly #store: ControlStore;
  readonly #sources: readonly AuditWitnessSource[];
  readonly #now: () => number;
  readonly #wormStore: AuditWitnessWormObjectStore | null;
  readonly #wormRequired: boolean;
  readonly #retentionDays: number;
  readonly #pollIntervalMs: number;
  readonly #maxAttempts: number;
  #timer: ReturnType<typeof setInterval> | null = null;
  #active: Promise<AuditWitnessEvidencePollResult> | null = null;

  constructor(options: {
    store: ControlStore;
    sources?: readonly AuditWitnessSource[];
    now?: () => number;
    wormStore?: AuditWitnessWormObjectStore | null;
    wormRequired?: boolean;
    retentionDays?: number;
    pollIntervalMs?: number;
    maxAttempts?: number;
  }) {
    this.#store = options.store;
    this.#sources = [...(options.sources ?? [])];
    const ids = new Set<string>();
    const issuers = new Set<string>();
    const tokenHashes = new Set<string>();
    for (const source of this.#sources) {
      const tokenHex = source.tokenHash.toString('hex');
      let issuer: URL;
      try {
        issuer = new URL(source.issuer);
      } catch {
        throw new Error('audit witness source issuer must be an absolute HTTPS URL');
      }
      const keysValid = [...source.publicKeys].every(([keyId, key]) => (
        key.asymmetricKeyType === 'ed25519' && keyId === ed25519PublicKeyId(key)
      ));
      if (!/^[a-z][a-z0-9_-]{1,63}$/u.test(source.id) || source.tokenHash.length !== 32
        || issuer.protocol !== 'https:' || issuer.username || issuer.password || issuer.search
        || issuer.hash || source.publicKeys.size < 1 || !keysValid || ids.has(source.id)
        || issuers.has(source.issuer)
        || tokenHashes.has(tokenHex)) {
        throw new Error('audit witness sources must have unique valid identities, tokens, and keys');
      }
      ids.add(source.id);
      issuers.add(source.issuer);
      tokenHashes.add(tokenHex);
    }
    this.#now = options.now ?? Date.now;
    this.#wormStore = options.wormStore ?? null;
    this.#wormRequired = options.wormRequired ?? false;
    this.#retentionDays = options.retentionDays ?? 2_555;
    this.#pollIntervalMs = options.pollIntervalMs ?? 30_000;
    this.#maxAttempts = options.maxAttempts ?? 20;
    if (this.#wormRequired && !this.#wormStore) {
      throw new Error('required audit WORM object storage is not configured');
    }
  }

  get enabled(): boolean {
    return this.#sources.length > 0;
  }

  get wormEnabled(): boolean {
    return this.#wormStore !== null;
  }

  async assertWormReady(): Promise<void> {
    if (this.#wormRequired) await this.#wormStore!.assertReady();
  }

  async ingest(raw: unknown, token: string): Promise<{
    receipt: AuditWitnessReceiptView;
    replayed: boolean;
  }> {
    const source = authenticateSource(this.#sources, token);
    const payload = normalizedPayload(raw, source, this.#now());
    const receivedAt = new Date(this.#now());
    const record: AuditWitnessReceiptRecord = {
      id: `witness_${randomUUID().replaceAll('-', '')}`,
      sourceId: source.id,
      anchorId: payload.anchorId,
      fingerprint: payload.fingerprint,
      issuer: payload.evidence.receipt.issuer,
      chainSequence: payload.evidence.receipt.lastSequence,
      headHash: payload.evidence.receipt.headHash,
      signingKeyId: payload.evidence.signingKeyId,
      payload,
      receivedAt,
    };
    let evidence: AuditWitnessEvidenceRecord | undefined;
    if (this.#wormStore) {
      const body = evidenceBody(record);
      evidence = {
        receiptId: record.id,
        sourceId: record.sourceId,
        chainSequence: record.chainSequence,
        objectKey: this.#wormStore.objectKey(record.sourceId, record.chainSequence),
        contentSha256: createHash('sha256').update(body).digest('hex'),
        sizeBytes: body.byteLength,
        status: 'pending',
        attempts: 0,
        nextAttemptAt: receivedAt,
        leaseUntil: null,
        lastError: null,
        objectVersionId: null,
        serverSideEncryption: null,
        objectLockMode: null,
        objectLockRetainUntil: null,
        storedAt: null,
        verifiedAt: null,
        createdAt: receivedAt,
        updatedAt: receivedAt,
      };
    }
    const result = await this.#store.ingestAuditWitnessReceipt({
      record,
      evidence,
      audit: {
        actorId: `audit-source:${source.id}`,
        action: 'audit.witness.received',
        targetType: 'audit_witness_receipt',
        targetId: record.id,
        detail: {
          sourceId: source.id,
          issuer: source.issuer,
          anchorId: record.anchorId,
          fingerprint: record.fingerprint,
          chainSequence: record.chainSequence,
          signingKeyId: record.signingKeyId,
        },
      },
    });
    return { receipt: receiptView(result.record), replayed: result.replayed };
  }

  start(onError: (error: unknown) => void): void {
    if (!this.#wormStore || this.#timer) return;
    const tick = (): void => {
      void this.pollEvidenceOnce().catch(onError);
    };
    tick();
    this.#timer = setInterval(tick, this.#pollIntervalMs);
    this.#timer.unref();
  }

  async close(): Promise<void> {
    if (this.#timer) clearInterval(this.#timer);
    this.#timer = null;
    await this.#active;
  }

  async pollEvidenceOnce(): Promise<AuditWitnessEvidencePollResult> {
    if (!this.#wormStore) return {
      enabled: false, processed: 0, stored: 0, retrying: 0, failed: 0,
    };
    if (this.#active) return this.#active;
    const active = this.#pollEvidence().finally(() => {
      if (this.#active === active) this.#active = null;
    });
    this.#active = active;
    return active;
  }

  async evidenceStatus(limit = 50): Promise<AuditWitnessEvidenceStatusSummary> {
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
      throw invalidRequest('audit WORM evidence limit must be between 1 and 100');
    }
    const summary = await this.#store.summarizeAuditWitnessEvidence();
    const evidence = await this.#store.listAuditWitnessEvidence({ limit });
    return {
      enabled: this.wormEnabled,
      required: this.#wormRequired,
      healthy: this.wormEnabled ? summary.counts.failed === 0 : !this.#wormRequired,
      ...summary.counts,
      oldestPendingAt: summary.oldestPendingAt?.toISOString() ?? null,
      latestVerifiedAt: summary.latestVerifiedAt?.toISOString() ?? null,
      evidence: evidence.map(evidenceView),
    };
  }

  async retryEvidence(receiptId: string, actorId: string): Promise<AuditWitnessEvidenceView> {
    if (!/^witness_[a-f0-9]{32}$/u.test(receiptId)) {
      throw invalidRequest('audit WORM evidence receipt id is invalid');
    }
    if (!this.#wormStore) throw conflict('audit WORM evidence storage is disabled');
    const retriedAt = new Date(this.#now());
    const record = await this.#store.retryAuditWitnessEvidence({
      receiptId,
      retriedAt,
      audit: {
        actorId,
        action: 'audit.witness.worm_retried',
        targetType: 'audit_witness_evidence',
        targetId: receiptId,
        detail: {},
      },
    });
    if (!record) throw conflict('only failed audit WORM evidence can be retried');
    return evidenceView(record);
  }

  async verifyEvidence(receiptId: string): Promise<{
    verified: true;
    evidence: AuditWitnessEvidenceView;
  }> {
    if (!/^witness_[a-f0-9]{32}$/u.test(receiptId)) {
      throw invalidRequest('audit WORM evidence receipt id is invalid');
    }
    if (!this.#wormStore) throw conflict('audit WORM evidence storage is disabled');
    const record = await this.#store.getAuditWitnessEvidence(receiptId);
    if (!record) throw notFound('audit WORM evidence does not exist');
    const receipt = await this.#store.getAuditWitnessReceipt(receiptId);
    if (!receipt) throw conflict('audit WORM evidence receipt index is missing');
    await this.#verifyStoredObject(record, evidenceBody(receipt));
    return { verified: true, evidence: evidenceView(record) };
  }

  async recoverEvidence(input: {
    continuationToken?: unknown;
    limit?: unknown;
  }, actorId: string): Promise<AuditWitnessEvidenceRecoveryResult> {
    if (!this.#wormStore) throw conflict('audit WORM evidence storage is disabled');
    const continuationToken = input.continuationToken === undefined || input.continuationToken === ''
      ? undefined
      : exactString(input.continuationToken, 'continuationToken');
    const limit = input.limit === undefined ? 100 : Number(input.limit);
    if (!Number.isInteger(limit) || limit < 1 || limit > 1_000) {
      throw invalidRequest('audit WORM recovery limit must be between 1 and 1000');
    }
    const listed = await this.#wormStore.list({ continuationToken, limit });
    const result: AuditWitnessEvidenceRecoveryResult = {
      processed: 0,
      restored: 0,
      replayed: 0,
      continuationToken: listed.continuationToken,
    };
    for (const objectKey of listed.objectKeys) {
      const body = await this.#wormStore.read(objectKey);
      let raw: unknown;
      try {
        raw = JSON.parse(Buffer.from(body).toString('utf8'));
      } catch {
        throw conflict('audit WORM recovery found invalid JSON evidence');
      }
      const sourceId = objectValue(raw, 'audit WORM evidence').sourceId;
      const source = this.#sources.find((item) => item.id === sourceId);
      if (!source) throw conflict('audit WORM recovery found an unconfigured evidence source');
      const envelope = normalizedEvidenceEnvelope(raw, source, this.#now());
      if (!Buffer.from(canonicalJson(envelope), 'utf8').equals(Buffer.from(body))) {
        throw conflict('audit WORM recovery evidence is not canonical JSON');
      }
      if (objectKey !== this.#wormStore.objectKey(envelope.sourceId, envelope.chainSequence)) {
        throw conflict('audit WORM recovery object key does not match its evidence identity');
      }
      const receipt: AuditWitnessReceiptRecord = {
        id: envelope.receiptId,
        sourceId: envelope.sourceId,
        anchorId: envelope.anchorId,
        fingerprint: envelope.fingerprint,
        issuer: envelope.issuer,
        chainSequence: envelope.chainSequence,
        headHash: envelope.headHash,
        signingKeyId: envelope.signingKeyId,
        payload: envelope.payload,
        receivedAt: new Date(envelope.receivedAt),
      };
      const digest = createHash('sha256').update(body).digest('hex');
      const inspected = await this.#wormStore.inspect(objectKey);
      const now = new Date(this.#now());
      const evidence: AuditWitnessEvidenceRecord = {
        receiptId: receipt.id,
        sourceId: receipt.sourceId,
        chainSequence: receipt.chainSequence,
        objectKey,
        contentSha256: digest,
        sizeBytes: body.byteLength,
        status: 'stored',
        attempts: 1,
        nextAttemptAt: now,
        leaseUntil: null,
        lastError: null,
        objectVersionId: inspected.versionId,
        serverSideEncryption: inspected.serverSideEncryption,
        objectLockMode: inspected.objectLockMode,
        objectLockRetainUntil: inspected.objectLockRetainUntil
          ? new Date(inspected.objectLockRetainUntil)
          : null,
        storedAt: now,
        verifiedAt: now,
        createdAt: receipt.receivedAt,
        updatedAt: now,
      };
      await this.#verifyStoredObject(evidence, body, inspected);
      const restored = await this.#store.restoreAuditWitnessEvidence({
        receipt,
        evidence,
        audit: {
          actorId,
          action: 'audit.witness.worm_recovered',
          targetType: 'audit_witness_evidence',
          targetId: receipt.id,
          detail: {
            sourceId: receipt.sourceId,
            chainSequence: receipt.chainSequence,
            contentSha256: digest,
            objectVersionId: inspected.versionId,
          },
        },
      });
      result.processed += 1;
      if (restored.replayed) result.replayed += 1;
      else result.restored += 1;
    }
    return result;
  }

  async list(raw: { sourceId?: unknown; limit?: unknown }): Promise<{
    enabled: boolean;
    sources: AuditWitnessSourceSummary[];
    receipts: AuditWitnessReceiptView[];
  }> {
    const sourceId = raw.sourceId === undefined || raw.sourceId === ''
      ? undefined
      : exactString(raw.sourceId, 'sourceId', /^[a-z][a-z0-9_-]{1,63}$/u);
    if (sourceId && !this.#sources.some((source) => source.id === sourceId)) {
      throw invalidRequest('audit witness sourceId is not configured');
    }
    const limit = raw.limit === undefined || raw.limit === '' ? 50 : Number(raw.limit);
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
      throw invalidRequest('audit witness receipt limit must be between 1 and 100');
    }
    return {
      enabled: this.enabled,
      sources: this.#sources.map((source) => ({
        id: source.id,
        issuer: source.issuer,
        signingKeyIds: [...source.publicKeys.keys()].sort(),
      })),
      receipts: (await this.#store.listAuditWitnessReceipts({ sourceId, limit })).map(receiptView),
    };
  }

  async #pollEvidence(): Promise<AuditWitnessEvidencePollResult> {
    const result: AuditWitnessEvidencePollResult = {
      enabled: true, processed: 0, stored: 0, retrying: 0, failed: 0,
    };
    while (result.processed < MAX_EVIDENCE_BATCH_SIZE) {
      const claimedAt = new Date(this.#now());
      const record = await this.#store.claimAuditWitnessEvidence({
        now: claimedAt,
        leaseUntil: new Date(claimedAt.getTime() + EVIDENCE_LEASE_MS),
      });
      if (!record) break;
      result.processed += 1;
      try {
        const receipt = await this.#store.getAuditWitnessReceipt(record.receiptId);
        if (!receipt) throw new Error('audit WORM evidence receipt index is missing');
        const body = evidenceBody(receipt);
        const digest = createHash('sha256').update(body).digest('hex');
        if (digest !== record.contentSha256 || body.byteLength !== record.sizeBytes) {
          throw new Error('audit WORM evidence differs from its transactional digest');
        }
        const retainUntil = new Date(record.createdAt.getTime() + this.#retentionDays * DAY_MS);
        const stored = await this.#wormStore!.put({
          objectKey: record.objectKey,
          body,
          sha256: record.contentSha256,
          retainUntil,
        });
        await this.#verifyStoredObject(record, body, stored);
        const finishedAt = new Date(this.#now());
        const finished = await this.#store.finishAuditWitnessEvidence({
          receiptId: record.receiptId,
          expectedLeaseUntil: record.leaseUntil!,
          status: 'stored',
          nextAttemptAt: finishedAt,
          lastError: null,
          objectVersionId: stored.versionId,
          serverSideEncryption: stored.serverSideEncryption,
          objectLockMode: stored.objectLockMode,
          objectLockRetainUntil: stored.objectLockRetainUntil
            ? new Date(stored.objectLockRetainUntil)
            : null,
          storedAt: finishedAt,
          verifiedAt: finishedAt,
          updatedAt: finishedAt,
          audit: {
            actorId: 'system:audit-worm-worker',
            action: 'audit.witness.worm_stored',
            targetType: 'audit_witness_evidence',
            targetId: record.receiptId,
            detail: {
              sourceId: record.sourceId,
              chainSequence: record.chainSequence,
              contentSha256: record.contentSha256,
              objectVersionId: stored.versionId,
              objectLockMode: stored.objectLockMode,
              objectLockRetainUntil: stored.objectLockRetainUntil,
            },
          },
        });
        if (!finished) throw new Error('audit WORM evidence lease was lost before completion');
        result.stored += 1;
      } catch (error) {
        const failedAt = new Date(this.#now());
        const terminal = record.attempts >= this.#maxAttempts;
        const finished = await this.#store.finishAuditWitnessEvidence({
          receiptId: record.receiptId,
          expectedLeaseUntil: record.leaseUntil!,
          status: terminal ? 'failed' : 'retrying',
          nextAttemptAt: terminal
            ? failedAt
            : new Date(failedAt.getTime() + retryDelayMs(record.attempts)),
          lastError: safeStorageError(error),
          objectVersionId: null,
          serverSideEncryption: null,
          objectLockMode: null,
          objectLockRetainUntil: null,
          storedAt: null,
          verifiedAt: null,
          updatedAt: failedAt,
          audit: terminal ? {
            actorId: 'system:audit-worm-worker',
            action: 'audit.witness.worm_failed',
            targetType: 'audit_witness_evidence',
            targetId: record.receiptId,
            detail: {
              sourceId: record.sourceId,
              chainSequence: record.chainSequence,
              attempts: record.attempts,
            },
          } : null,
        });
        if (!finished) throw new Error('audit WORM evidence lease was lost before retry scheduling');
        if (terminal) result.failed += 1;
        else result.retrying += 1;
      }
    }
    return result;
  }

  async #verifyStoredObject(
    record: AuditWitnessEvidenceRecord,
    expectedBody: Uint8Array,
    inspectedInput?: Awaited<ReturnType<AuditWitnessWormObjectStore['inspect']>>,
  ): Promise<void> {
    const inspected = inspectedInput ?? await this.#wormStore!.inspect(record.objectKey);
    if (inspected.objectKey !== record.objectKey || inspected.sizeBytes !== record.sizeBytes
      || inspected.checksumSha256 !== record.contentSha256 || !inspected.versionId
      || inspected.serverSideEncryption !== this.#wormStore!.requiredEncryption
      || inspected.objectLockMode !== this.#wormStore!.requiredLockMode) {
      throw new Error('audit WORM object metadata does not satisfy the evidence policy');
    }
    const retainUntil = inspected.objectLockRetainUntil
      ? Date.parse(inspected.objectLockRetainUntil)
      : Number.NaN;
    const expectedRetainUntil = record.createdAt.getTime() + this.#retentionDays * DAY_MS;
    if (!Number.isFinite(retainUntil) || retainUntil < expectedRetainUntil - 1_000) {
      throw new Error('audit WORM object retention is shorter than the configured policy');
    }
    const actualBody = await this.#wormStore!.read(record.objectKey);
    const actualHash = createHash('sha256').update(actualBody).digest('hex');
    const expectedHash = createHash('sha256').update(expectedBody).digest('hex');
    if (actualBody.byteLength !== expectedBody.byteLength || actualHash !== expectedHash
      || actualHash !== record.contentSha256) {
      throw new Error('audit WORM object bytes do not match the accepted receipt');
    }
  }
}

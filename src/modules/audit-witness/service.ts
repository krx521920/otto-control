import { createHash, randomUUID, timingSafeEqual, verify } from 'node:crypto';

import { AUDIT_GENESIS_HASH } from '../../audit-chain.js';
import type { AuditAnchorPayload } from '../../contracts/audit-anchor.js';
import type {
  AuditWitnessReceiptRecord,
  AuditWitnessReceiptView,
  AuditWitnessSourceSummary,
} from '../../contracts/audit-witness.js';
import { canonicalJson, ed25519PublicKeyId } from '../../crypto/signed-envelope.js';
import { invalidRequest, unauthorized } from '../../errors.js';
import type { ControlStore } from '../../storage/control-store.js';
import type { AuditWitnessSource } from './source-config.js';

const ANCHOR_ID = /^anchor_[a-f0-9]{32}$/u;
const HASH = /^[a-f0-9]{64}$/u;
const KEY_ID = /^[a-f0-9]{16}$/u;
const SIGNATURE = /^ed25519:[A-Za-z0-9_-]{86}$/u;
const MAX_FUTURE_SKEW_MS = 5 * 60_000;

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

export class AuditWitnessService {
  readonly #store: ControlStore;
  readonly #sources: readonly AuditWitnessSource[];
  readonly #now: () => number;

  constructor(options: {
    store: ControlStore;
    sources?: readonly AuditWitnessSource[];
    now?: () => number;
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
  }

  get enabled(): boolean {
    return this.#sources.length > 0;
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
    const result = await this.#store.ingestAuditWitnessReceipt({
      record,
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
}

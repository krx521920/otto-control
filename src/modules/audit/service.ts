import { AUDIT_GENESIS_HASH, auditEventHash } from '../../audit-chain.js';
import type {
  AuditEventQuery,
  AuditEventRecord,
  AuditEventView,
  AuditIntegrityReceipt,
  SignedAuditIntegrityReceipt,
} from '../../contracts/audit.js';
import { signPayload, type PayloadSigner } from '../../crypto/signed-envelope.js';
import { invalidRequest } from '../../errors.js';
import type { ControlStore } from '../../storage/control-store.js';

const MAX_PAGE_SIZE = 200;
const MAX_EXPORT_ROWS = 10_000;
const VERIFY_BATCH_SIZE = 1_000;
const SENSITIVE_KEY = /(password|secret|token|credential|signature|ciphertext|private.?key)/iu;

function optionalText(value: unknown, name: string, maximumLength = 160): string | undefined {
  if (value === undefined || value === null || value === '') return undefined;
  if (typeof value !== 'string' || !value.trim() || value.length > maximumLength) {
    throw invalidRequest(`${name} must be a non-empty string up to ${maximumLength} characters`);
  }
  return value.trim();
}

function positiveInteger(value: unknown, name: string, maximum: number): number | undefined {
  if (value === undefined || value === null || value === '') return undefined;
  const normalized = typeof value === 'string' ? value.trim() : value;
  if ((typeof normalized !== 'string' && typeof normalized !== 'number')
    || !/^\d+$/u.test(String(normalized))) {
    throw invalidRequest(`${name} must be a positive integer`);
  }
  const parsed = Number(normalized);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > maximum) {
    throw invalidRequest(`${name} must be between 1 and ${maximum}`);
  }
  return parsed;
}

function optionalDate(value: unknown, name: string): Date | undefined {
  const normalized = optionalText(value, name, 64);
  if (!normalized) return undefined;
  const parsed = new Date(normalized);
  if (!Number.isFinite(parsed.getTime())) throw invalidRequest(`${name} must be an ISO timestamp`);
  return parsed;
}

function eventQuery(raw: Record<string, unknown>, maximum: number): AuditEventQuery {
  const from = optionalDate(raw.from, 'from');
  const to = optionalDate(raw.to, 'to');
  if (from && to && from > to) throw invalidRequest('from must be earlier than or equal to to');
  return {
    actorId: optionalText(raw.actorId, 'actorId'),
    action: optionalText(raw.action, 'action'),
    targetType: optionalText(raw.targetType, 'targetType'),
    targetId: optionalText(raw.targetId, 'targetId'),
    from,
    to,
    beforeId: positiveInteger(raw.beforeId, 'beforeId', Number.MAX_SAFE_INTEGER),
    limit: positiveInteger(raw.limit, 'limit', maximum) ?? Math.min(50, maximum),
  };
}

function sanitize(value: unknown, depth = 0): unknown {
  if (depth > 8) return '[MAX_DEPTH]';
  if (typeof value === 'string') return value.length > 2_000 ? `${value.slice(0, 2_000)}...` : value;
  if (Array.isArray(value)) return value.slice(0, 100).map((item) => sanitize(item, depth + 1));
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>)
      .slice(0, 100)
      .map(([key, item]) => [key, SENSITIVE_KEY.test(key) ? '[REDACTED]' : sanitize(item, depth + 1)]));
  }
  return value;
}

function eventView(event: AuditEventRecord): AuditEventView {
  return {
    ...event,
    detail: sanitize(event.detail) as Record<string, unknown>,
    createdAt: event.createdAt.toISOString(),
  };
}

function csvCell(value: unknown): string {
  const normalized = value === null || value === undefined ? '' : String(value);
  return `"${normalized.replaceAll('"', '""')}"`;
}

export class AuditService {
  readonly #store: ControlStore;
  readonly #signer: PayloadSigner;
  readonly #now: () => number;

  constructor(options: { store: ControlStore; signer: PayloadSigner; now?: () => number }) {
    this.#store = options.store;
    this.#signer = options.signer;
    this.#now = options.now ?? Date.now;
  }

  async events(raw: Record<string, unknown>): Promise<{
    events: AuditEventView[];
    nextBeforeId: number | null;
  }> {
    const query = eventQuery(raw, MAX_PAGE_SIZE);
    const records = await this.#store.listAuditEvents({ ...query, limit: query.limit + 1 });
    const hasMore = records.length > query.limit;
    const page = records.slice(0, query.limit);
    return {
      events: page.map(eventView),
      nextBeforeId: hasMore ? page.at(-1)!.id : null,
    };
  }

  async exportCsv(raw: Record<string, unknown>): Promise<string> {
    const query = eventQuery({ ...raw, limit: MAX_EXPORT_ROWS }, MAX_EXPORT_ROWS);
    const records = await this.#store.listAuditEvents(query);
    const header = [
      'id', 'createdAt', 'actorId', 'action', 'targetType', 'targetId',
      'chainSequence', 'previousHash', 'eventHash', 'detail',
    ];
    const rows = records.map((event) => {
      const view = eventView(event);
      return [
        view.id, view.createdAt, view.actorId, view.action, view.targetType, view.targetId,
        view.chainSequence, view.previousHash, view.eventHash, JSON.stringify(view.detail),
      ];
    });
    return `\uFEFF${[header, ...rows].map((row) => row.map(csvCell).join(',')).join('\r\n')}\r\n`;
  }

  async verify(): Promise<SignedAuditIntegrityReceipt> {
    const state = await this.#store.getAuditChainState();
    let checkedEvents = 0;
    let previousHash = AUDIT_GENESIS_HASH;
    let expectedSequence = 1;
    let brokenAtSequence: number | null = null;

    while (expectedSequence <= state.lastSequence && brokenAtSequence === null) {
      const batch = await this.#store.listChainedAuditEvents({
        afterSequence: expectedSequence - 1,
        throughSequence: state.lastSequence,
        limit: VERIFY_BATCH_SIZE,
      });
      if (batch.length === 0) {
        brokenAtSequence = expectedSequence;
        break;
      }
      for (const event of batch) {
        if (event.chainSequence !== expectedSequence
          || event.previousHash !== previousHash
          || event.eventHash !== auditEventHash({
            sequence: expectedSequence,
            previousHash,
            actorId: event.actorId,
            action: event.action,
            targetType: event.targetType,
            targetId: event.targetId,
            detail: event.detail,
            createdAt: event.createdAt,
          })) {
          brokenAtSequence = expectedSequence;
          break;
        }
        checkedEvents += 1;
        previousHash = event.eventHash;
        expectedSequence += 1;
      }
    }
    if (brokenAtSequence === null
      && (checkedEvents !== state.lastSequence || previousHash !== state.headHash)) {
      brokenAtSequence = Math.max(1, expectedSequence);
    }
    const receipt: AuditIntegrityReceipt = {
      version: 1,
      generatedAt: new Date(this.#now()).toISOString(),
      valid: brokenAtSequence === null,
      checkedEvents,
      firstSequence: state.lastSequence === 0 ? null : 1,
      lastSequence: state.lastSequence,
      headHash: state.headHash,
      brokenAtSequence,
      legacyEventCount: await this.#store.countLegacyAuditEvents(),
    };
    return { receipt, ...await signPayload(this.#signer, receipt) };
  }
}

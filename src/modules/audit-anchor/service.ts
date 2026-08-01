import { createHash, randomUUID } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';

import type {
  AuditAnchorPayload,
  AuditAnchorPollResult,
  AuditAnchorRecord,
  AuditAnchorView,
} from '../../contracts/audit-anchor.js';
import { canonicalJson } from '../../crypto/signed-envelope.js';
import { conflict, invalidRequest, notFound } from '../../errors.js';
import type { ControlStore } from '../../storage/control-store.js';
import type { AuditService } from '../audit/service.js';

const DELIVERY_LEASE_MS = 2 * 60_000;
const MAX_BATCH_SIZE = 10;
const MAX_TOKEN_BYTES = 4 * 1024;

type AnchorFetch = typeof fetch;

export interface AuditAnchorServiceOptions {
  store: ControlStore;
  audit: AuditService;
  url?: string | null;
  tokenFile?: string | null;
  anchorIntervalMs?: number;
  pollIntervalMs?: number;
  timeoutMs?: number;
  maxAttempts?: number;
  now?: () => number;
  fetcher?: AnchorFetch;
}

function parseUrl(value: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error('audit anchor URL must be an absolute HTTPS URL');
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) {
    throw new Error('audit anchor URL must use HTTPS without credentials or fragments');
  }
  return url;
}

function loadToken(path: string): string {
  let metadata: ReturnType<typeof statSync>;
  let token: string;
  try {
    metadata = statSync(path);
    token = readFileSync(path, 'utf8').trim();
  } catch {
    throw new Error('audit anchor token file could not be read');
  }
  if (!metadata.isFile() || metadata.size < 32 || metadata.size > MAX_TOKEN_BYTES
    || Buffer.byteLength(token, 'utf8') < 32 || /\s/u.test(token)) {
    throw new Error('audit anchor token file must contain a 32-4096 byte token without whitespace');
  }
  return token;
}

function safeDeliveryError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return message
    .replace(/https:\/\/[^\s/]+[^\s]*/giu, '[ANCHOR_ENDPOINT]')
    .replace(/(authorization|secret|token|credential)\s*[:=]\s*[^\s]+/giu, '$1=[REDACTED]')
    .replace(/[A-Za-z]:\\[^\s]+|\/(?:[^\s/]+\/){2,}[^\s]*/gu, '[LOCAL_PATH]')
    .replace(/\s+/gu, ' ')
    .trim()
    .slice(0, 500) || 'audit anchor delivery failed';
}

function retryDelayMs(attempt: number): number {
  return Math.min(60 * 60_000, 30_000 * (2 ** Math.max(0, attempt - 1)));
}

function anchorView(record: AuditAnchorRecord): AuditAnchorView {
  return {
    ...record,
    nextAttemptAt: record.nextAttemptAt.toISOString(),
    leaseUntil: record.leaseUntil?.toISOString() ?? null,
    deliveredAt: record.deliveredAt?.toISOString() ?? null,
    createdAt: record.createdAt.toISOString(),
    updatedAt: record.updatedAt.toISOString(),
  };
}

export class AuditAnchorService {
  readonly #store: ControlStore;
  readonly #audit: AuditService;
  readonly #url: URL | null;
  readonly #token: string | null;
  readonly #anchorIntervalMs: number;
  readonly #pollIntervalMs: number;
  readonly #timeoutMs: number;
  readonly #maxAttempts: number;
  readonly #now: () => number;
  readonly #fetcher: AnchorFetch;
  #timer: ReturnType<typeof setInterval> | null = null;
  #active: Promise<AuditAnchorPollResult> | null = null;

  constructor(options: AuditAnchorServiceOptions) {
    if (options.url && !options.tokenFile) {
      throw new Error('audit anchor token file is required with the URL');
    }
    this.#store = options.store;
    this.#audit = options.audit;
    this.#url = options.url ? parseUrl(options.url) : null;
    this.#token = options.url && options.tokenFile ? loadToken(options.tokenFile) : null;
    this.#anchorIntervalMs = options.anchorIntervalMs ?? 15 * 60_000;
    this.#pollIntervalMs = options.pollIntervalMs ?? 60_000;
    this.#timeoutMs = options.timeoutMs ?? 10_000;
    this.#maxAttempts = options.maxAttempts ?? 8;
    this.#now = options.now ?? Date.now;
    this.#fetcher = options.fetcher ?? fetch;
  }

  get enabled(): boolean {
    return this.#url !== null && this.#token !== null;
  }

  start(onError: (error: unknown) => void): void {
    if (!this.enabled || this.#timer) return;
    const tick = (): void => {
      void this.pollOnce().catch(onError);
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

  async list(limit = 50): Promise<{
    enabled: boolean;
    destinationOrigin: string | null;
    anchors: AuditAnchorView[];
  }> {
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
      throw invalidRequest('audit anchor limit must be between 1 and 100');
    }
    return {
      enabled: this.enabled,
      destinationOrigin: this.#url?.origin ?? null,
      anchors: (await this.#store.listAuditAnchors(limit)).map(anchorView),
    };
  }

  async pollOnce(
    actorId = 'system:audit-anchor-worker',
    force = false,
  ): Promise<AuditAnchorPollResult> {
    if (!this.enabled) return this.#emptyResult();
    if (this.#active) return this.#active;
    const active = this.#poll(actorId, force).finally(() => {
      if (this.#active === active) this.#active = null;
    });
    this.#active = active;
    return active;
  }

  async retry(id: string, actorId: string): Promise<AuditAnchorView> {
    if (!/^anchor_[a-f0-9]{32}$/u.test(id)) throw invalidRequest('audit anchor id is invalid');
    const current = await this.#store.getAuditAnchor(id);
    if (!current) throw notFound('audit anchor not found');
    if (current.status !== 'failed') throw conflict('only failed audit anchors can be retried');
    if (!this.enabled) throw conflict('audit anchor destination is disabled');
    const retriedAt = new Date(this.#now());
    const retried = await this.#store.retryAuditAnchor({
      id,
      retriedAt,
      audit: {
        actorId,
        action: 'audit.anchor.retried',
        targetType: 'audit_anchor',
        targetId: id,
        detail: { previousAttempts: current.attempts, fingerprint: current.fingerprint },
      },
    });
    if (!retried) throw conflict('audit anchor changed concurrently; reload and retry');
    return anchorView(retried);
  }

  #emptyResult(): AuditAnchorPollResult {
    return {
      enabled: false,
      destinationOrigin: null,
      enqueued: false,
      chainValid: null,
      processed: 0,
      delivered: 0,
      retrying: 0,
      failed: 0,
    };
  }

  async #poll(actorId: string, force: boolean): Promise<AuditAnchorPollResult> {
    const now = new Date(this.#now());
    const latest = await this.#store.getLatestAuditAnchor();
    const due = force || !latest
      || latest.createdAt.getTime() <= now.getTime() - this.#anchorIntervalMs;
    let enqueued = false;
    let chainValid: boolean | null = null;
    if (due) {
      const evidence = await this.#audit.verify();
      chainValid = evidence.receipt.valid;
      if (chainValid) {
        const fingerprint = createHash('sha256').update(canonicalJson({
          issuer: evidence.receipt.issuer,
          lastSequence: evidence.receipt.lastSequence,
          headHash: evidence.receipt.headHash,
        })).digest('hex');
        const id = `anchor_${randomUUID().replaceAll('-', '')}`;
        const payload: AuditAnchorPayload = { version: 1, anchorId: id, fingerprint, evidence };
        const queued = await this.#store.enqueueAuditAnchor({
          id,
          fingerprint,
          payload,
          createdAt: now,
          audit: {
            actorId,
            action: 'audit.anchor.enqueued',
            targetType: 'audit_anchor',
            targetId: id,
            detail: {
              fingerprint,
              lastSequence: evidence.receipt.lastSequence,
              headHash: evidence.receipt.headHash,
            },
          },
        });
        enqueued = queued.created;
      }
    }

    const result: AuditAnchorPollResult = {
      enabled: true,
      destinationOrigin: this.#url!.origin,
      enqueued,
      chainValid,
      processed: 0,
      delivered: 0,
      retrying: 0,
      failed: 0,
    };
    while (result.processed < MAX_BATCH_SIZE) {
      const claimedAt = new Date(this.#now());
      const anchor = await this.#store.claimAuditAnchor({
        now: claimedAt,
        leaseUntil: new Date(claimedAt.getTime() + DELIVERY_LEASE_MS),
      });
      if (!anchor) break;
      result.processed += 1;
      try {
        const remoteReference = await this.#deliver(anchor);
        const deliveredAt = new Date(this.#now());
        const finished = await this.#store.finishAuditAnchor({
          id: anchor.id,
          expectedLeaseUntil: anchor.leaseUntil!,
          status: 'delivered',
          nextAttemptAt: deliveredAt,
          lastError: null,
          deliveredAt,
          remoteReference,
          updatedAt: deliveredAt,
          audit: {
            actorId: 'system:audit-anchor-worker',
            action: 'audit.anchor.delivered',
            targetType: 'audit_anchor',
            targetId: anchor.id,
            detail: { attempts: anchor.attempts, fingerprint: anchor.fingerprint, remoteReference },
          },
        });
        if (!finished) throw new Error('audit anchor lease was lost before completion');
        result.delivered += 1;
      } catch (error) {
        const failedAt = new Date(this.#now());
        const terminal = anchor.attempts >= this.#maxAttempts;
        const finished = await this.#store.finishAuditAnchor({
          id: anchor.id,
          expectedLeaseUntil: anchor.leaseUntil!,
          status: terminal ? 'failed' : 'retrying',
          nextAttemptAt: terminal
            ? failedAt
            : new Date(failedAt.getTime() + retryDelayMs(anchor.attempts)),
          lastError: safeDeliveryError(error),
          deliveredAt: null,
          remoteReference: null,
          updatedAt: failedAt,
          audit: terminal ? {
            actorId: 'system:audit-anchor-worker',
            action: 'audit.anchor.failed',
            targetType: 'audit_anchor',
            targetId: anchor.id,
            detail: { attempts: anchor.attempts, fingerprint: anchor.fingerprint },
          } : null,
        });
        if (!finished) throw new Error('audit anchor lease was lost before retry scheduling');
        if (terminal) result.failed += 1;
        else result.retrying += 1;
      }
    }
    return result;
  }

  async #deliver(anchor: AuditAnchorRecord): Promise<string | null> {
    const response = await this.#fetcher(this.#url!, {
      method: 'POST',
      redirect: 'manual',
      signal: AbortSignal.timeout(this.#timeoutMs),
      headers: {
        authorization: `Bearer ${this.#token!}`,
        'content-type': 'application/json',
        'user-agent': 'otto-control-audit-anchor/1',
        'x-otto-audit-anchor-id': anchor.id,
        'x-otto-audit-fingerprint': anchor.fingerprint,
      },
      body: JSON.stringify(anchor.payload),
    });
    const remoteReference = response.headers.get('x-otto-audit-anchor-reference')?.trim() || null;
    await response.body?.cancel();
    if (response.status < 200 || response.status >= 300) {
      throw new Error(`audit anchor endpoint returned HTTP ${response.status}`);
    }
    if (remoteReference && (remoteReference.length > 200 || /[\u0000-\u001f\u007f]/u.test(remoteReference))) {
      throw new Error('audit anchor endpoint returned an invalid reference');
    }
    return remoteReference;
  }
}

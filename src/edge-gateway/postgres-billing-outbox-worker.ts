import type {
  EdgeBillingCoordinator,
  EdgeBillingOutboxAction,
  PreparedEdgeBillingDelivery,
} from './billing-coordinator.js';
import type { PostgresEdgeRequestLedger } from './postgres-request-ledger.js';

const SEQUENCE_SCOPE = /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,159}$/u;
const DEFAULT_INTERVAL_MS = 5_000;
const DEFAULT_BATCH_SIZE = 25;
const MAX_BATCH_SIZE = 100;

export interface PostgresEdgeBillingOutboxWorkerOptions {
  ledger: PostgresEdgeRequestLedger;
  coordinator: EdgeBillingCoordinator;
  sequenceScope: string;
  intervalMs?: number;
  batchSize?: number;
  leaseDurationMs?: number;
  onError?: (error: unknown) => void;
}

export interface PostgresEdgeBillingOutboxWorkerSnapshot {
  state: 'ready' | 'degraded' | 'stopped';
  running: boolean;
  delivered: number;
  retried: number;
  lastErrorCode: string | null;
}

function positiveInteger(
  value: number | undefined,
  fallback: number,
  maximum: number,
  name: string,
): number {
  const normalized = value ?? fallback;
  if (!Number.isSafeInteger(normalized) || normalized < 1 || normalized > maximum) {
    throw new TypeError(`${name} is invalid`);
  }
  return normalized;
}

function deliveryErrorCode(error: unknown): string {
  if (error instanceof Error && error.name === 'EdgeRequestLedgerConflictError') {
    return 'EDGE_BILLING_OUTBOX_FENCED';
  }
  return 'EDGE_BILLING_DELIVERY_FAILED';
}

export class PostgresEdgeBillingOutboxWorker {
  readonly #ledger: PostgresEdgeRequestLedger;
  readonly #coordinator: EdgeBillingCoordinator;
  readonly #sequenceScope: string;
  readonly #intervalMs: number;
  readonly #batchSize: number;
  readonly #leaseDurationMs?: number;
  readonly #onError?: (error: unknown) => void;
  #timer: ReturnType<typeof setTimeout> | null = null;
  #running: Promise<number> | null = null;
  #closed = false;
  #delivered = 0;
  #retried = 0;
  #lastErrorCode: string | null = null;

  constructor(options: PostgresEdgeBillingOutboxWorkerOptions) {
    const sequenceScope = options.sequenceScope.trim();
    if (!SEQUENCE_SCOPE.test(sequenceScope)) {
      throw new TypeError('edge billing outbox sequence scope is invalid');
    }
    if (!options.coordinator.prepareSettlementDelivery
      || !options.coordinator.prepareReleaseDelivery
      || !options.coordinator.prepareUncertainDelivery
      || !options.coordinator.deliverPrepared) {
      throw new TypeError('edge billing coordinator does not support the shared outbox');
    }
    this.#ledger = options.ledger;
    this.#coordinator = options.coordinator;
    this.#sequenceScope = sequenceScope;
    this.#intervalMs = positiveInteger(
      options.intervalMs,
      DEFAULT_INTERVAL_MS,
      60 * 60 * 1_000,
      'edge billing outbox interval',
    );
    this.#batchSize = positiveInteger(
      options.batchSize,
      DEFAULT_BATCH_SIZE,
      MAX_BATCH_SIZE,
      'edge billing outbox batch size',
    );
    if (options.leaseDurationMs !== undefined) {
      this.#leaseDurationMs = positiveInteger(
        options.leaseDurationMs,
        options.leaseDurationMs,
        24 * 60 * 60 * 1_000,
        'edge billing outbox lease duration',
      );
    }
    this.#onError = options.onError;
  }

  start(): void {
    if (this.#closed || this.#timer) return;
    this.#schedule(0);
  }

  flush(): Promise<number> {
    if (this.#closed) return Promise.resolve(0);
    if (this.#running) return this.#running;
    this.#running = this.#flushBatch()
      .catch((error) => {
        this.#lastErrorCode = deliveryErrorCode(error);
        this.#onError?.(error);
        return 0;
      })
      .finally(() => {
        this.#running = null;
      });
    return this.#running;
  }

  snapshot(): PostgresEdgeBillingOutboxWorkerSnapshot {
    return {
      state: this.#closed
        ? 'stopped'
        : this.#lastErrorCode
          ? 'degraded'
          : 'ready',
      running: this.#running !== null,
      delivered: this.#delivered,
      retried: this.#retried,
      lastErrorCode: this.#lastErrorCode,
    };
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    if (this.#timer) clearTimeout(this.#timer);
    this.#timer = null;
    await this.#running;
  }

  async #flushBatch(): Promise<number> {
    const claimed = await this.#ledger.claimBillingActions({
      sequenceScope: this.#sequenceScope,
      limit: this.#batchSize,
      ...(this.#leaseDurationMs === undefined
        ? {}
        : { leaseDurationMs: this.#leaseDurationMs }),
      prepare: ({ action, sequence }) => this.#prepare(action, sequence),
    });
    let delivered = 0;
    for (const item of claimed) {
      try {
        await this.#coordinator.deliverPrepared!(
          item.preparedDelivery as PreparedEdgeBillingDelivery,
        );
        await this.#ledger.ackBillingAction({
          requestId: item.requestId,
          claimEpoch: item.claimEpoch,
        });
        this.#delivered += 1;
        delivered += 1;
        this.#lastErrorCode = null;
      } catch (error) {
        const errorCode = deliveryErrorCode(error);
        this.#lastErrorCode = errorCode;
        this.#retried += 1;
        try {
          await this.#ledger.retryBillingAction({
            requestId: item.requestId,
            claimEpoch: item.claimEpoch,
            errorCode,
          });
        } catch (retryError) {
          this.#onError?.(retryError);
        }
        this.#onError?.(error);
      }
    }
    return delivered;
  }

  #prepare(
    action: EdgeBillingOutboxAction,
    sequence: number,
  ): Promise<PreparedEdgeBillingDelivery> | PreparedEdgeBillingDelivery {
    if (action.type === 'settle') {
      return this.#coordinator.prepareSettlementDelivery!(action.request, sequence);
    }
    if (action.type === 'release') {
      return this.#coordinator.prepareReleaseDelivery!(action.request);
    }
    return this.#coordinator.prepareUncertainDelivery!(action.request);
  }

  #schedule(delayMs: number): void {
    this.#timer = setTimeout(() => {
      this.#timer = null;
      void this.flush().finally(() => {
        if (!this.#closed) this.#schedule(this.#intervalMs);
      });
    }, delayMs);
    this.#timer.unref?.();
  }
}

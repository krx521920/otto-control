import type { EdgeGatewayBackgroundContext } from './gateway.js';

export interface EdgeGatewayBackgroundTaskSnapshot {
  state: 'ready' | 'degraded' | 'unavailable';
  activeTasks: number;
  maximumTasks: number;
  peakActiveTasks: number;
  failedTasks: number;
  overflowedTasks: number;
  lastFailureAtMs: number | null;
  lastOverflowAtMs: number | null;
}

export interface EdgeGatewayBackgroundTaskWaiter {
  waitForIdle(timeoutMs: number): Promise<boolean>;
  snapshot(): EdgeGatewayBackgroundTaskSnapshot;
}

const DEFAULT_MAXIMUM_TASKS = 1_024;
const MAXIMUM_TASK_LIMIT = 100_000;

function validTimeout(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0 || value > 300_000) {
    throw new Error('background task drain timeout must be an integer between 0 and 300000');
  }
  return value;
}

/**
 * Tracks response-detached work so a Node process does not report a graceful
 * drain before durable billing and outcome operations have finished.
 */
export class InMemoryEdgeGatewayBackgroundTasks
implements EdgeGatewayBackgroundContext, EdgeGatewayBackgroundTaskWaiter {
  readonly #tasks = new Set<Promise<void>>();
  readonly #idleWaiters = new Set<() => void>();
  readonly #maximumTasks: number;
  #peakActiveTasks = 0;
  #failedTasks = 0;
  #overflowedTasks = 0;
  #lastFailureAtMs: number | null = null;
  #lastOverflowAtMs: number | null = null;

  constructor(maximumTasks = DEFAULT_MAXIMUM_TASKS) {
    if (!Number.isSafeInteger(maximumTasks)
      || maximumTasks < 1
      || maximumTasks > MAXIMUM_TASK_LIMIT) {
      throw new Error(`maximum background tasks must be an integer between 1 and ${MAXIMUM_TASK_LIMIT}`);
    }
    this.#maximumTasks = maximumTasks;
  }

  waitUntil(task: Promise<unknown>): void {
    if (this.#tasks.size >= this.#maximumTasks) {
      this.#overflowedTasks += 1;
      this.#lastOverflowAtMs = Date.now();
      void Promise.resolve(task).catch(() => {
        this.#recordFailure();
      });
      return;
    }
    const tracked = Promise.resolve(task)
      .catch(() => {
        this.#recordFailure();
      })
      .then(() => undefined);
    this.#tasks.add(tracked);
    this.#peakActiveTasks = Math.max(this.#peakActiveTasks, this.#tasks.size);
    void tracked.then(() => {
      this.#tasks.delete(tracked);
      if (this.#tasks.size === 0) {
        for (const resolve of this.#idleWaiters) resolve();
        this.#idleWaiters.clear();
      }
    });
  }

  async waitForIdle(timeoutMs: number): Promise<boolean> {
    validTimeout(timeoutMs);
    if (this.#tasks.size === 0) return true;
    return new Promise<boolean>((resolve) => {
      const finish = (idle: boolean) => {
        clearTimeout(timer);
        this.#idleWaiters.delete(onIdle);
        resolve(idle);
      };
      const onIdle = () => finish(true);
      const timer = setTimeout(() => finish(false), timeoutMs);
      this.#idleWaiters.add(onIdle);
    });
  }

  snapshot(): EdgeGatewayBackgroundTaskSnapshot {
    const activeTasks = this.#tasks.size;
    return {
      state: this.#overflowedTasks > 0 || activeTasks >= this.#maximumTasks
        ? 'unavailable'
        : this.#failedTasks > 0
          ? 'degraded'
          : 'ready',
      activeTasks,
      maximumTasks: this.#maximumTasks,
      peakActiveTasks: this.#peakActiveTasks,
      failedTasks: this.#failedTasks,
      overflowedTasks: this.#overflowedTasks,
      lastFailureAtMs: this.#lastFailureAtMs,
      lastOverflowAtMs: this.#lastOverflowAtMs,
    };
  }

  isAccepting(): boolean {
    return this.snapshot().state !== 'unavailable';
  }

  #recordFailure(): void {
    this.#failedTasks += 1;
    this.#lastFailureAtMs = Date.now();
  }
}

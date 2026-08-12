export type EdgeGatewayLifecycleState = 'accepting' | 'draining' | 'stopped';

export interface EdgeGatewayLifecycleSnapshot {
  state: EdgeGatewayLifecycleState;
  activeRequests: number;
  drainStartedAtMs: number | null;
}

export interface EdgeGatewayLifecycleLease {
  release(): void;
}

export interface EdgeGatewayLifecycle {
  isAccepting(): boolean;
  acquire(): EdgeGatewayLifecycleLease | null;
  beginDrain(): boolean;
  waitForIdle(timeoutMs: number): Promise<boolean>;
  markStopped(): void;
  snapshot(): EdgeGatewayLifecycleSnapshot;
}

function validTime(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${name} must be a non-negative safe integer`);
  }
  return value;
}

function validTimeout(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0 || value > 300_000) {
    throw new Error('lifecycle drain timeout must be an integer between 0 and 300000');
  }
  return value;
}

/**
 * Process-local lifecycle gate used by the supported single-Node deployment.
 * Request leases are owned by the HTTP adapter rather than the model stream so
 * authentication, error responses and downstream writes are all part of the
 * same graceful-drain accounting window.
 */
export class InMemoryEdgeGatewayLifecycle implements EdgeGatewayLifecycle {
  readonly #now: () => number;
  readonly #idleWaiters = new Set<() => void>();
  #state: EdgeGatewayLifecycleState = 'accepting';
  #activeRequests = 0;
  #drainStartedAtMs: number | null = null;

  constructor(options: { now?: () => number } = {}) {
    this.#now = options.now ?? Date.now;
  }

  isAccepting(): boolean {
    return this.#state === 'accepting';
  }

  acquire(): EdgeGatewayLifecycleLease | null {
    if (!this.isAccepting()) return null;
    this.#activeRequests += 1;
    let released = false;
    return {
      release: () => {
        if (released) return;
        released = true;
        this.#activeRequests -= 1;
        if (this.#activeRequests === 0) {
          for (const resolve of this.#idleWaiters) resolve();
          this.#idleWaiters.clear();
        }
      },
    };
  }

  beginDrain(): boolean {
    if (this.#state !== 'accepting') return false;
    this.#drainStartedAtMs = validTime(this.#now(), 'lifecycle drain time');
    this.#state = 'draining';
    return true;
  }

  async waitForIdle(timeoutMs: number): Promise<boolean> {
    validTimeout(timeoutMs);
    if (this.#activeRequests === 0) return true;
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

  markStopped(): void {
    this.#state = 'stopped';
  }

  snapshot(): EdgeGatewayLifecycleSnapshot {
    return {
      state: this.#state,
      activeRequests: this.#activeRequests,
      drainStartedAtMs: this.#drainStartedAtMs,
    };
  }
}

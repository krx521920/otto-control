const ROUTE_ID = /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,159}$/u;

export interface EdgeRouteCircuitSnapshot {
  trackedRoutes: number;
  failingRoutes: number;
  openRoutes: number;
  probeReadyRoutes: number;
  halfOpenRoutes: number;
  failureThreshold: number;
  cooldownMs: number;
}

export interface EdgeRouteAttempt {
  succeeded(): void;
  failed(atMs: number): void;
  cancelled(): void;
}

export interface EdgeRouteCircuitBreaker {
  acquire(routeId: string, now: number): EdgeRouteAttempt | null;
  snapshot(): EdgeRouteCircuitSnapshot;
}

interface RouteFailureState {
  consecutiveFailures: number;
  openUntil: number;
  probeInFlight: boolean;
  updatedAt: number;
}

export interface InMemoryEdgeRouteCircuitBreakerOptions {
  failureThreshold?: number;
  cooldownMs?: number;
  maximumEntries?: number;
  now?: () => number;
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
    throw new Error(`${name} must be an integer between ${minimum} and ${maximum}`);
  }
  return result;
}

/**
 * Process-local route circuit breaker for a single Node gateway. It retains no
 * tenant or content data: only signed-policy route IDs and aggregate failure
 * state. Multi-process gateways need a shared health coordinator if they want
 * one circuit state across every replica.
 */
export class InMemoryEdgeRouteCircuitBreaker implements EdgeRouteCircuitBreaker {
  readonly #failureThreshold: number;
  readonly #cooldownMs: number;
  readonly #maximumEntries: number;
  readonly #now: () => number;
  readonly #states = new Map<string, RouteFailureState>();

  constructor(options: InMemoryEdgeRouteCircuitBreakerOptions = {}) {
    this.#failureThreshold = boundedInteger(
      options.failureThreshold, 5, 1, 1_000, 'circuit breaker failure threshold',
    );
    this.#cooldownMs = boundedInteger(
      options.cooldownMs, 30_000, 1_000, 3_600_000, 'circuit breaker cooldown',
    );
    this.#maximumEntries = boundedInteger(
      options.maximumEntries, 10_000, 1, 1_000_000, 'circuit breaker capacity',
    );
    this.#now = options.now ?? Date.now;
  }

  acquire(routeId: string, now: number): EdgeRouteAttempt | null {
    if (!ROUTE_ID.test(routeId) || !Number.isSafeInteger(now) || now < 0) {
      throw new Error('circuit breaker route attempt is invalid');
    }
    const state = this.#states.get(routeId);
    if (!state) return this.#attempt(routeId, false);
    if (state.probeInFlight || state.openUntil > now) return null;
    if (state.openUntil > 0) {
      state.probeInFlight = true;
      state.updatedAt = now;
      return this.#attempt(routeId, true);
    }
    return this.#attempt(routeId, false);
  }

  snapshot(): EdgeRouteCircuitSnapshot {
    const now = this.#now();
    let failingRoutes = 0;
    let openRoutes = 0;
    let probeReadyRoutes = 0;
    let halfOpenRoutes = 0;
    for (const state of this.#states.values()) {
      if (state.probeInFlight) halfOpenRoutes += 1;
      else if (state.openUntil > now) openRoutes += 1;
      else if (state.openUntil > 0) probeReadyRoutes += 1;
      else failingRoutes += 1;
    }
    return {
      trackedRoutes: this.#states.size,
      failingRoutes,
      openRoutes,
      probeReadyRoutes,
      halfOpenRoutes,
      failureThreshold: this.#failureThreshold,
      cooldownMs: this.#cooldownMs,
    };
  }

  #attempt(routeId: string, probe: boolean): EdgeRouteAttempt {
    let completed = false;
    const complete = (outcome: 'succeeded' | 'failed' | 'cancelled', atMs?: number) => {
      if (completed) return;
      completed = true;
      if (outcome === 'succeeded') {
        this.#states.delete(routeId);
        return;
      }
      if (outcome === 'cancelled') {
        if (probe) {
          const state = this.#states.get(routeId);
          if (state) state.probeInFlight = false;
        }
        return;
      }
      if (!Number.isSafeInteger(atMs) || Number(atMs) < 0) {
        throw new Error('circuit breaker failure time is invalid');
      }
      let state = this.#states.get(routeId);
      if (!state) {
        this.#makeCapacity();
        state = {
          consecutiveFailures: 0,
          openUntil: 0,
          probeInFlight: false,
          updatedAt: Number(atMs),
        };
        this.#states.set(routeId, state);
      } else state.probeInFlight = false;
      state.consecutiveFailures = probe
        ? this.#failureThreshold
        : Math.min(this.#failureThreshold, state.consecutiveFailures + 1);
      state.openUntil = state.consecutiveFailures >= this.#failureThreshold
        ? Math.min(Number.MAX_SAFE_INTEGER, Number(atMs) + this.#cooldownMs)
        : 0;
      state.updatedAt = Number(atMs);
    };
    return {
      succeeded: () => complete('succeeded'),
      failed: (atMs) => complete('failed', atMs),
      cancelled: () => complete('cancelled'),
    };
  }

  #makeCapacity(): void {
    if (this.#states.size < this.#maximumEntries) return;
    let oldestRoute: string | null = null;
    let oldestUpdate = Number.POSITIVE_INFINITY;
    for (const [routeId, state] of this.#states) {
      if (state.updatedAt < oldestUpdate) {
        oldestRoute = routeId;
        oldestUpdate = state.updatedAt;
      }
    }
    this.#states.delete(oldestRoute!);
  }
}

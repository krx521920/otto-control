export interface EdgeRateLimitResult {
  allowed: boolean;
  remaining: number;
  retryAfterSeconds: number;
  banned?: boolean;
}

export interface EdgeRateLimiter {
  consume(input: {
    key: string;
    limit: number;
    windowMs: number;
    now: number;
  }): Promise<EdgeRateLimitResult>;
  healthCheck?(): Promise<void>;
}

export class EdgeRateLimitUnavailableError extends Error {
  constructor() {
    super('edge rate limiter is unavailable');
    this.name = 'EdgeRateLimitUnavailableError';
  }
}

export function validateRateLimitInput(input: {
  key: string;
  limit: number;
  windowMs: number;
  now: number;
}): void {
  if (!input.key || input.key.length > 1_024) {
    throw new Error('rate limit key must contain 1 to 1024 characters');
  }
  if (!Number.isSafeInteger(input.limit) || input.limit < 1 || input.limit > 1_000_000) {
    throw new Error('rate limit must be an integer between 1 and 1000000');
  }
  if (!Number.isSafeInteger(input.windowMs) || input.windowMs < 1_000 || input.windowMs > 86_400_000) {
    throw new Error('rate limit window must be an integer between 1000 and 86400000');
  }
  if (!Number.isSafeInteger(input.now) || input.now < 0) {
    throw new Error('rate limit time must be a non-negative integer');
  }
}

interface FixedWindowEntry {
  count: number;
  resetsAt: number;
}

/**
 * Development and single-isolate limiter. Production multi-POP deployments
 * must inject a platform-native atomic limiter; eventually-consistent edge KV
 * is not sufficient for authoritative quotas.
 */
export class InMemoryEdgeRateLimiter implements EdgeRateLimiter {
  readonly #entries = new Map<string, FixedWindowEntry>();
  readonly #maximumEntries: number;

  constructor(maximumEntries = 10_000) {
    if (!Number.isSafeInteger(maximumEntries) || maximumEntries < 1) {
      throw new Error('maximumEntries must be a positive integer');
    }
    this.#maximumEntries = maximumEntries;
  }

  async consume(input: {
    key: string;
    limit: number;
    windowMs: number;
    now: number;
  }): Promise<EdgeRateLimitResult> {
    validateRateLimitInput(input);
    let entry = this.#entries.get(input.key);
    if (!entry || input.now >= entry.resetsAt) {
      if (this.#entries.size >= this.#maximumEntries) this.#prune(input.now);
      entry = { count: 0, resetsAt: input.now + input.windowMs };
      this.#entries.set(input.key, entry);
    }
    if (entry.count >= input.limit) {
      return {
        allowed: false,
        remaining: 0,
        retryAfterSeconds: Math.max(1, Math.ceil((entry.resetsAt - input.now) / 1_000)),
      };
    }
    entry.count += 1;
    return {
      allowed: true,
      remaining: Math.max(0, input.limit - entry.count),
      retryAfterSeconds: 0,
    };
  }

  #prune(now: number): void {
    for (const [key, entry] of this.#entries) {
      if (now >= entry.resetsAt) this.#entries.delete(key);
    }
    while (this.#entries.size >= this.#maximumEntries) {
      const oldest = this.#entries.keys().next().value as string | undefined;
      if (!oldest) break;
      this.#entries.delete(oldest);
    }
  }
}

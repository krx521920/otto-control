import { createHmac } from 'node:crypto';

import { createClient, type RedisClientOptions } from 'redis';

import {
  EdgeRateLimitUnavailableError,
  type EdgeRateLimiter,
  type EdgeRateLimitResult,
  validateRateLimitInput,
} from './rate-limit.js';

const REDIS_RATE_LIMIT_SCRIPT = `
local ban_ttl = redis.call('PTTL', KEYS[3])
if ban_ttl > 0 then
  return {0, 0, math.ceil(ban_ttl / 1000), 1}
end

local count = redis.call('INCR', KEYS[1])
local counter_ttl
if count == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[2])
  counter_ttl = tonumber(ARGV[2])
else
  counter_ttl = redis.call('PTTL', KEYS[1])
end

if count <= tonumber(ARGV[1]) then
  return {1, tonumber(ARGV[1]) - count, 0, 0}
end

local strikes = redis.call('INCR', KEYS[2])
if strikes == 1 then
  redis.call('PEXPIRE', KEYS[2], ARGV[4])
end
if strikes >= tonumber(ARGV[3]) then
  redis.call('SET', KEYS[3], '1', 'PX', ARGV[5])
  redis.call('DEL', KEYS[1], KEYS[2])
  return {0, 0, math.ceil(tonumber(ARGV[5]) / 1000), 1}
end

if counter_ttl < 1 then counter_ttl = tonumber(ARGV[2]) end
return {0, 0, math.max(1, math.ceil(counter_ttl / 1000)), 0}
`;

export interface RedisEdgeClientLike {
  connect(): Promise<unknown>;
  ping(): Promise<string>;
  eval(
    script: string,
    options: { keys: string[]; arguments: string[] },
  ): Promise<unknown>;
  quit(): Promise<unknown>;
  disconnect(): void;
  on(event: 'error', listener: (error: Error) => void): unknown;
}

export interface RedisEdgeRateLimiterOptions {
  client: Pick<RedisEdgeClientLike, 'eval' | 'ping'>;
  keySecret: Uint8Array;
  keyPrefix?: string;
  banThreshold?: number;
  strikeWindowMs?: number;
  banMs?: number;
}

function boundedInteger(
  value: number | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
  name: string,
): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < minimum || resolved > maximum) {
    throw new Error(`${name} must be an integer between ${minimum} and ${maximum}`);
  }
  return resolved;
}

function keyPrefix(value: string | undefined): string {
  const resolved = value?.trim() || 'otto-edge';
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,63}$/u.test(resolved)) {
    throw new Error('Redis edge rate limit key prefix is invalid');
  }
  return resolved;
}

function result(value: unknown): EdgeRateLimitResult {
  if (!Array.isArray(value) || value.length !== 4) {
    throw new EdgeRateLimitUnavailableError();
  }
  const [allowed, remaining, retryAfterSeconds, banned] = value;
  if (![allowed, remaining, retryAfterSeconds, banned].every(
    (item) => typeof item === 'number' && Number.isSafeInteger(item) && item >= 0,
  ) || (allowed !== 0 && allowed !== 1) || (banned !== 0 && banned !== 1)) {
    throw new EdgeRateLimitUnavailableError();
  }
  if (allowed === 1) {
    if (retryAfterSeconds !== 0 || banned !== 0) throw new EdgeRateLimitUnavailableError();
    return { allowed: true, remaining, retryAfterSeconds: 0 };
  }
  if (remaining !== 0 || retryAfterSeconds < 1) throw new EdgeRateLimitUnavailableError();
  return banned === 1
    ? { allowed: false, remaining: 0, retryAfterSeconds, banned: true }
    : { allowed: false, remaining: 0, retryAfterSeconds };
}

/**
 * Redis-backed atomic limiter for multiple Node gateway replicas. Redis keys
 * contain only an HMAC digest, and the Lua script updates the window, strike
 * counter and temporary ban in one operation (including Redis Cluster slots).
 */
export class RedisEdgeRateLimiter implements EdgeRateLimiter {
  readonly #client: Pick<RedisEdgeClientLike, 'eval' | 'ping'>;
  readonly #keySecret: Buffer;
  readonly #keyPrefix: string;
  readonly #banThreshold: number;
  readonly #strikeWindowMs: number;
  readonly #banMs: number;

  constructor(options: RedisEdgeRateLimiterOptions) {
    if (options.keySecret.byteLength < 32 || options.keySecret.byteLength > 4_096) {
      throw new Error('Redis edge rate limit key secret must contain 32 to 4096 bytes');
    }
    this.#client = options.client;
    this.#keySecret = Buffer.from(options.keySecret);
    this.#keyPrefix = keyPrefix(options.keyPrefix);
    this.#banThreshold = boundedInteger(options.banThreshold, 20, 1, 1_000, 'banThreshold');
    this.#strikeWindowMs = boundedInteger(
      options.strikeWindowMs,
      5 * 60_000,
      60_000,
      24 * 60 * 60_000,
      'strikeWindowMs',
    );
    this.#banMs = boundedInteger(
      options.banMs,
      15 * 60_000,
      60_000,
      7 * 24 * 60 * 60_000,
      'banMs',
    );
  }

  async healthCheck(): Promise<void> {
    try {
      if (await this.#client.ping() !== 'PONG') throw new Error('unexpected Redis PING response');
    } catch {
      throw new EdgeRateLimitUnavailableError();
    }
  }

  async consume(input: {
    key: string;
    limit: number;
    windowMs: number;
    now: number;
  }): Promise<EdgeRateLimitResult> {
    validateRateLimitInput(input);
    const digest = createHmac('sha256', this.#keySecret).update(input.key).digest('hex');
    const slot = `{${digest}}`;
    try {
      return result(await this.#client.eval(REDIS_RATE_LIMIT_SCRIPT, {
        keys: [
          `${this.#keyPrefix}:rl:${slot}:counter`,
          `${this.#keyPrefix}:rl:${slot}:strikes`,
          `${this.#keyPrefix}:rl:${slot}:ban`,
        ],
        arguments: [
          String(input.limit),
          String(input.windowMs),
          String(this.#banThreshold),
          String(this.#strikeWindowMs),
          String(this.#banMs),
        ],
      }));
    } catch (error) {
      if (error instanceof EdgeRateLimitUnavailableError) throw error;
      throw new EdgeRateLimitUnavailableError();
    }
  }
}

export async function createNodeRedisEdgeRateLimiter(input: {
  connectionString: string;
  keySecret: Uint8Array;
  keyPrefix?: string;
  banThreshold?: number;
  strikeWindowMs?: number;
  banMs?: number;
  connectTimeoutMs?: number;
  allowInsecure?: boolean;
  clientFactory?: (options: RedisClientOptions) => RedisEdgeClientLike;
}): Promise<RedisEdgeRateLimiter> {
  let url: URL;
  try {
    url = new URL(input.connectionString);
  } catch {
    throw new Error('OTTO_EDGE_REDIS_URL must be a valid Redis URL');
  }
  if (url.protocol !== 'rediss:' && !(input.allowInsecure && url.protocol === 'redis:')) {
    throw new Error('OTTO_EDGE_REDIS_URL must use rediss unless insecure Redis is explicitly allowed');
  }
  const connectTimeout = boundedInteger(
    input.connectTimeoutMs,
    10_000,
    500,
    120_000,
    'connectTimeoutMs',
  );
  const options: RedisClientOptions = {
    url: input.connectionString,
    disableOfflineQueue: true,
    socket: { connectTimeout },
  };
  const client = input.clientFactory
    ? input.clientFactory(options)
    : (createClient(options) as unknown as RedisEdgeClientLike);
  client.on('error', () => {
    // Operations fail closed. Never log client options because URLs may contain credentials.
  });
  let connected = false;
  try {
    await client.connect();
    connected = true;
    const limiter = new RedisEdgeRateLimiter({
      client,
      keySecret: input.keySecret,
      keyPrefix: input.keyPrefix,
      banThreshold: input.banThreshold,
      strikeWindowMs: input.strikeWindowMs,
      banMs: input.banMs,
    });
    await limiter.healthCheck();
    return limiter;
  } catch (error) {
    try {
      if (connected) await client.quit();
      else client.disconnect();
    } catch {
      // Preserve the connection or readiness failure.
    }
    throw error;
  }
}

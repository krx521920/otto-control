import { createHmac } from 'node:crypto';

import { describe, expect, it, vi } from 'vitest';

import { EdgeRateLimitUnavailableError } from '../src/edge-gateway/rate-limit.js';
import {
  createNodeRedisEdgeRateLimiter,
  RedisEdgeRateLimiter,
  type RedisEdgeClientLike,
} from '../src/edge-gateway/redis-rate-limit.js';

const NOW = Date.parse('2026-08-12T08:00:00.000Z');
const SECRET = Buffer.from('edge-rate-limit-test-secret-with-32-bytes-minimum', 'utf8');

function client(result: unknown = [1, 9, 0, 0]) {
  return {
    eval: vi.fn(async (
      _script: string,
      _options: { keys: string[]; arguments: string[] },
    ): Promise<unknown> => {
      void _script;
      void _options;
      return result;
    }),
    ping: vi.fn(async () => 'PONG'),
  };
}

function input(key = 'dep\0org\0account') {
  return { key, limit: 10, windowMs: 60_000, now: NOW };
}

describe('Redis edge rate limiter', () => {
  it('uses HMAC-only co-slotted keys and atomic script arguments', async () => {
    const redis = client();
    const limiter = new RedisEdgeRateLimiter({
      client: redis,
      keySecret: SECRET,
      keyPrefix: 'tenant-edge',
      banThreshold: 7,
      strikeWindowMs: 120_000,
      banMs: 600_000,
    });

    await expect(limiter.consume(input())).resolves.toEqual({
      allowed: true, remaining: 9, retryAfterSeconds: 0,
    });
    expect(redis.eval).toHaveBeenCalledTimes(1);
    const [, options] = redis.eval.mock.calls[0]!;
    const digest = createHmac('sha256', SECRET).update(input().key).digest('hex');
    expect(options.keys).toEqual([
      `tenant-edge:rl:{${digest}}:counter`,
      `tenant-edge:rl:{${digest}}:strikes`,
      `tenant-edge:rl:{${digest}}:ban`,
    ]);
    expect(options.arguments).toEqual(['10', '60000', '7', '120000', '600000']);
    expect(JSON.stringify(options.keys)).not.toContain('account');
    expect(JSON.stringify(options.keys)).not.toContain('dep');
  });

  it('returns ordinary throttling and a distinct temporary traffic ban', async () => {
    const redis = client([0, 0, 42, 0]);
    const limiter = new RedisEdgeRateLimiter({ client: redis, keySecret: SECRET });
    await expect(limiter.consume(input())).resolves.toEqual({
      allowed: false, remaining: 0, retryAfterSeconds: 42,
    });

    redis.eval.mockResolvedValueOnce([0, 0, 900, 1]);
    await expect(limiter.consume(input())).resolves.toEqual({
      allowed: false, remaining: 0, retryAfterSeconds: 900, banned: true,
    });
  });

  it.each([
    null,
    [],
    [1, 0, 0],
    [2, 0, 0, 0],
    [1, 9, 1, 0],
    [1, 9, 0, 1],
    [0, 1, 1, 0],
    [0, 0, 0, 0],
    ['1', 9, 0, 0],
    [1, -1, 0, 0],
  ])('fails closed for an invalid Redis script result: %j', async (value) => {
    const limiter = new RedisEdgeRateLimiter({ client: client(value), keySecret: SECRET });
    await expect(limiter.consume(input())).rejects.toBeInstanceOf(
      EdgeRateLimitUnavailableError,
    );
  });

  it('fails closed for Redis operation and health failures', async () => {
    const redis = client();
    redis.eval.mockRejectedValueOnce(new Error('credential-bearing Redis failure'));
    const limiter = new RedisEdgeRateLimiter({ client: redis, keySecret: SECRET });
    await expect(limiter.consume(input())).rejects.toEqual(
      new EdgeRateLimitUnavailableError(),
    );
    redis.ping.mockResolvedValueOnce('LOADING');
    await expect(limiter.healthCheck()).rejects.toBeInstanceOf(
      EdgeRateLimitUnavailableError,
    );
    redis.ping.mockRejectedValueOnce(new Error('offline'));
    await expect(limiter.healthCheck()).rejects.toBeInstanceOf(
      EdgeRateLimitUnavailableError,
    );
  });

  it('validates secrets, options, prefixes and consume inputs', async () => {
    const redis = client();
    expect(() => new RedisEdgeRateLimiter({ client: redis, keySecret: Buffer.alloc(31) }))
      .toThrow('32 to 4096');
    expect(() => new RedisEdgeRateLimiter({ client: redis, keySecret: Buffer.alloc(4097) }))
      .toThrow('32 to 4096');
    expect(() => new RedisEdgeRateLimiter({ client: redis, keySecret: SECRET, keyPrefix: '{bad}' }))
      .toThrow('prefix');
    expect(() => new RedisEdgeRateLimiter({ client: redis, keySecret: SECRET, banThreshold: 0 }))
      .toThrow('banThreshold');
    expect(() => new RedisEdgeRateLimiter({ client: redis, keySecret: SECRET, strikeWindowMs: 59_999 }))
      .toThrow('strikeWindowMs');
    expect(() => new RedisEdgeRateLimiter({ client: redis, keySecret: SECRET, banMs: 59_999 }))
      .toThrow('banMs');

    const limiter = new RedisEdgeRateLimiter({ client: redis, keySecret: SECRET });
    await expect(limiter.consume({ ...input(), key: '' })).rejects.toThrow('key');
    await expect(limiter.consume({ ...input(), limit: 0 })).rejects.toThrow('limit');
    await expect(limiter.consume({ ...input(), windowMs: 999 })).rejects.toThrow('window');
    await expect(limiter.consume({ ...input(), now: -1 })).rejects.toThrow('time');
    expect(redis.eval).not.toHaveBeenCalled();
  });
});

describe('Node Redis edge rate limiter composition', () => {
  function redisClient(overrides: Partial<RedisEdgeClientLike> = {}): RedisEdgeClientLike {
    return {
      connect: vi.fn(async () => undefined),
      ping: vi.fn(async () => 'PONG'),
      eval: vi.fn(async () => [1, 0, 0, 0]),
      quit: vi.fn(async () => undefined),
      disconnect: vi.fn(),
      on: vi.fn(),
      ...overrides,
    };
  }

  it('connects and verifies Redis without exposing credentials', async () => {
    const redis = redisClient();
    const factory = vi.fn(() => redis);
    const limiter = await createNodeRedisEdgeRateLimiter({
      connectionString: 'rediss://user:secret@redis.internal:6379/0',
      keySecret: SECRET,
      connectTimeoutMs: 2_500,
      clientFactory: factory,
    });

    expect(factory).toHaveBeenCalledWith(expect.objectContaining({
      url: 'rediss://user:secret@redis.internal:6379/0',
      disableOfflineQueue: true,
      socket: { connectTimeout: 2_500 },
    }));
    expect(redis.on).toHaveBeenCalledWith('error', expect.any(Function));
    expect(redis.connect).toHaveBeenCalledTimes(1);
    expect(redis.ping).toHaveBeenCalledTimes(1);
    await expect(limiter.consume(input())).resolves.toEqual({
      allowed: true, remaining: 0, retryAfterSeconds: 0,
    });
  });

  it('requires TLS unless insecure development Redis is explicitly enabled', async () => {
    await expect(createNodeRedisEdgeRateLimiter({
      connectionString: 'redis://localhost:6379', keySecret: SECRET,
    })).rejects.toThrow('must use rediss');
    await expect(createNodeRedisEdgeRateLimiter({
      connectionString: 'not a url', keySecret: SECRET,
    })).rejects.toThrow('valid Redis URL');
    await expect(createNodeRedisEdgeRateLimiter({
      connectionString: 'redis://localhost:6379',
      keySecret: SECRET,
      allowInsecure: true,
      clientFactory: () => redisClient(),
    })).resolves.toBeInstanceOf(RedisEdgeRateLimiter);
  });

  it('disconnects failed connections and quits connections that fail readiness', async () => {
    const connectFailure = redisClient({
      connect: vi.fn(async () => { throw new Error('connect failed'); }),
    });
    await expect(createNodeRedisEdgeRateLimiter({
      connectionString: 'rediss://redis.internal',
      keySecret: SECRET,
      clientFactory: () => connectFailure,
    })).rejects.toThrow('connect failed');
    expect(connectFailure.disconnect).toHaveBeenCalledTimes(1);
    expect(connectFailure.quit).not.toHaveBeenCalled();

    const pingFailure = redisClient({ ping: vi.fn(async () => 'NOPE') });
    await expect(createNodeRedisEdgeRateLimiter({
      connectionString: 'rediss://redis.internal',
      keySecret: SECRET,
      clientFactory: () => pingFailure,
    })).rejects.toBeInstanceOf(EdgeRateLimitUnavailableError);
    expect(pingFailure.quit).toHaveBeenCalledTimes(1);
    expect(pingFailure.disconnect).not.toHaveBeenCalled();
  });
});

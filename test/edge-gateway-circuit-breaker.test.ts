import { describe, expect, it } from 'vitest';

import { InMemoryEdgeRouteCircuitBreaker } from '../src/edge-gateway/circuit-breaker.js';

describe('Edge Gateway route circuit breaker', () => {
  it('opens at the exact failure threshold and admits one half-open probe', () => {
    let now = 1_000;
    const breaker = new InMemoryEdgeRouteCircuitBreaker({
      failureThreshold: 2,
      cooldownMs: 1_000,
      now: () => now,
    });
    breaker.acquire('route-a', now)!.failed(now);
    expect(breaker.snapshot()).toMatchObject({ failingRoutes: 1, openRoutes: 0 });
    breaker.acquire('route-a', now + 1)!.failed(now + 1);
    expect(breaker.snapshot()).toMatchObject({ failingRoutes: 0, openRoutes: 1 });
    expect(breaker.acquire('route-a', 2_000)).toBeNull();

    now = 2_001;
    const probe = breaker.acquire('route-a', now);
    expect(probe).not.toBeNull();
    expect(breaker.acquire('route-a', now)).toBeNull();
    expect(breaker.snapshot()).toMatchObject({ halfOpenRoutes: 1, openRoutes: 0 });
    probe!.succeeded();
    probe!.failed(now);
    expect(breaker.snapshot()).toMatchObject({
      trackedRoutes: 0,
      failingRoutes: 0,
      openRoutes: 0,
      halfOpenRoutes: 0,
    });
  });

  it('reopens after a failed probe and allows a cancelled probe to be retried', () => {
    let now = 10_000;
    const breaker = new InMemoryEdgeRouteCircuitBreaker({
      failureThreshold: 1,
      cooldownMs: 2_000,
      now: () => now,
    });
    breaker.acquire('route-a', now)!.failed(now);
    now = 12_000;
    const firstProbe = breaker.acquire('route-a', now)!;
    firstProbe.cancelled();
    expect(breaker.snapshot().probeReadyRoutes).toBe(1);
    const retryProbe = breaker.acquire('route-a', now)!;
    retryProbe.failed(now);
    expect(breaker.snapshot().openRoutes).toBe(1);
    expect(breaker.acquire('route-a', now + 1_999)).toBeNull();
    now += 2_000;
    expect(breaker.acquire('route-a', now)).not.toBeNull();
  });

  it('does not let an older normal cancellation release a newer half-open probe', () => {
    const breaker = new InMemoryEdgeRouteCircuitBreaker({
      failureThreshold: 1,
      cooldownMs: 1_000,
    });
    const older = breaker.acquire('route-a', 1)!;
    breaker.acquire('route-a', 1)!.failed(1);
    const probe = breaker.acquire('route-a', 1_001)!;
    older.cancelled();
    expect(breaker.acquire('route-a', 1_001)).toBeNull();
    probe.succeeded();
  });

  it('allows a probe cancellation after its state was capacity-evicted', () => {
    const breaker = new InMemoryEdgeRouteCircuitBreaker({
      failureThreshold: 1,
      cooldownMs: 1_000,
      maximumEntries: 1,
    });
    breaker.acquire('route-a', 1)!.failed(1);
    const probe = breaker.acquire('route-a', 1_001)!;
    breaker.acquire('route-b', 1_002)!.failed(1_002);
    expect(() => probe.cancelled()).not.toThrow();
  });

  it('resets consecutive failures after any successful route response', () => {
    const breaker = new InMemoryEdgeRouteCircuitBreaker({ failureThreshold: 2 });
    breaker.acquire('route-a', 1)!.failed(1);
    breaker.acquire('route-a', 2)!.succeeded();
    expect(breaker.snapshot().trackedRoutes).toBe(0);
    breaker.acquire('route-a', 3)!.failed(3);
    expect(breaker.acquire('route-a', 4)).not.toBeNull();
  });

  it('bounds retained route state by evicting the least recently failed route', () => {
    const breaker = new InMemoryEdgeRouteCircuitBreaker({
      failureThreshold: 1,
      cooldownMs: 10_000,
      maximumEntries: 2,
      now: () => 300,
    });
    breaker.acquire('route-a', 100)!.failed(100);
    breaker.acquire('route-b', 200)!.failed(200);
    breaker.acquire('route-c', 300)!.failed(300);
    expect(breaker.snapshot()).toMatchObject({ trackedRoutes: 2, openRoutes: 2 });
    expect(breaker.acquire('route-a', 300)).not.toBeNull();
    expect(breaker.acquire('route-b', 300)).toBeNull();
    expect(breaker.acquire('route-c', 300)).toBeNull();
  });

  it('evicts the first inserted route when update timestamps are equal', () => {
    const breaker = new InMemoryEdgeRouteCircuitBreaker({
      failureThreshold: 1,
      cooldownMs: 10_000,
      maximumEntries: 2,
    });
    breaker.acquire('route-a', 100)!.failed(100);
    breaker.acquire('route-b', 100)!.failed(100);
    breaker.acquire('route-c', 100)!.failed(100);
    expect(breaker.acquire('route-a', 100)).not.toBeNull();
    expect(breaker.acquire('route-b', 100)).toBeNull();
  });

  it.each([
    [{ failureThreshold: 0 }],
    [{ cooldownMs: 999 }],
    [{ maximumEntries: 0 }],
    [{ failureThreshold: 1_001 }],
    [{ cooldownMs: 3_600_001 }],
  ])('rejects unsafe configuration %#', (options) => {
    expect(() => new InMemoryEdgeRouteCircuitBreaker(options)).toThrow('must be an integer');
  });

  it('accepts every exact configuration maximum', () => {
    expect(() => new InMemoryEdgeRouteCircuitBreaker({
      failureThreshold: 1_000,
      cooldownMs: 3_600_000,
      maximumEntries: 1_000_000,
    })).not.toThrow();
  });

  it('rejects malformed route attempts and failure timestamps', () => {
    const breaker = new InMemoryEdgeRouteCircuitBreaker();
    expect(() => breaker.acquire('', 1)).toThrow('route attempt');
    expect(() => breaker.acquire('route-a', -1)).toThrow('route attempt');
    expect(breaker.acquire('route-a', 0)).not.toBeNull();
    const attempt = breaker.acquire('route-a', 1)!;
    expect(() => attempt.failed(-1)).toThrow('failure time');
    expect(() => breaker.acquire('route-b', 1)!.failed(0)).not.toThrow();
  });

  it('enforces exact route ID syntax and length boundaries', () => {
    const breaker = new InMemoryEdgeRouteCircuitBreaker();
    for (const routeId of ['a', 'a-_.:9', 'x'.repeat(160)]) {
      expect(breaker.acquire(routeId, 1)).not.toBeNull();
    }
    for (const routeId of ['_route', 'route!', `!${'x'.repeat(160)}`, 'x'.repeat(161)]) {
      expect(() => breaker.acquire(routeId, 1)).toThrow('route attempt');
    }
  });
});

import { describe, expect, it, vi } from 'vitest';

import {
  normalizeEdgeBillingReservation,
  normalizeEdgeConcurrencyLease,
  normalizeEdgeRateLimitResult,
  normalizeEdgeRouteAttempt,
} from '../src/edge-gateway/adapter-contracts.js';

describe('edge gateway adapter contracts', () => {
  it('snapshots a concurrency release capability with its receiver', () => {
    const source = {
      released: false,
      release() { this.released = true; },
    };
    const lease = normalizeEdgeConcurrencyLease(source);
    source.release = () => { throw new Error('mutated release'); };

    lease!.release();

    expect(source.released).toBe(true);
  });

  it.each([
    null,
    undefined,
    {},
    Object.assign([], { release: vi.fn() }),
    { release: true },
  ])(
    'rejects a malformed concurrency lease %#',
    (value) => {
      expect(normalizeEdgeConcurrencyLease(value)).toBeNull();
    },
  );

  it('rejects a concurrency lease whose capability getter throws', () => {
    const value = Object.defineProperty({}, 'release', {
      get() { throw new Error('hostile release getter'); },
    });
    expect(normalizeEdgeConcurrencyLease(value)).toBeNull();
  });

  it('snapshots every route completion capability with its receiver', () => {
    const calls: Array<string | number> = [];
    const source = {
      prefix: 'route',
      succeeded() { calls.push(`${this.prefix}:succeeded`); },
      failed(atMs: number) { calls.push(atMs); },
      cancelled() { calls.push(`${this.prefix}:cancelled`); },
    };
    const attempt = normalizeEdgeRouteAttempt(source)!;
    source.succeeded = () => { throw new Error('mutated succeeded'); };
    source.failed = () => { throw new Error('mutated failed'); };
    source.cancelled = () => { throw new Error('mutated cancelled'); };

    attempt.succeeded();
    attempt.failed(123);
    attempt.cancelled();

    expect(calls).toEqual(['route:succeeded', 123, 'route:cancelled']);
  });

  it.each([
    null,
    {},
    Object.assign([], {
      succeeded: vi.fn(),
      failed: vi.fn(),
      cancelled: vi.fn(),
    }),
    { succeeded: vi.fn(), failed: vi.fn() },
    { succeeded: vi.fn(), cancelled: vi.fn() },
    { failed: vi.fn(), cancelled: vi.fn() },
  ])('rejects a malformed route attempt %#', (value) => {
    expect(normalizeEdgeRouteAttempt(value)).toBeNull();
  });

  it('rejects a route attempt whose capability getter throws', () => {
    const value = Object.defineProperty({
      failed: vi.fn(),
      cancelled: vi.fn(),
    }, 'succeeded', {
      get() { throw new Error('hostile succeeded getter'); },
    });
    expect(normalizeEdgeRouteAttempt(value)).toBeNull();
  });

  it('copies a bounded billing reservation without retaining extra data', () => {
    expect(normalizeEdgeBillingReservation({
      reservationId: 'hold_0123456789abcdef0123456789abcdef',
      privateMetadata: 'must not propagate',
    })).toEqual({ reservationId: 'hold_0123456789abcdef0123456789abcdef' });
    expect(normalizeEdgeBillingReservation({ reservationId: 'a' }))
      .toEqual({ reservationId: 'a' });
    const maximum = `h${'x'.repeat(159)}`;
    expect(normalizeEdgeBillingReservation({ reservationId: maximum }))
      .toEqual({ reservationId: maximum });
  });

  it.each([
    null,
    {},
    Object.assign([], { reservationId: 'valid_array_id' }),
    { reservationId: 7 },
    { reservationId: '_invalid' },
    { reservationId: 'invalid!' },
    { reservationId: `h${'x'.repeat(160)}` },
  ])('rejects a malformed billing reservation %#', (value) => {
    expect(normalizeEdgeBillingReservation(value)).toBeNull();
  });

  it('rejects a billing reservation whose identifier getter throws', () => {
    const value = Object.defineProperty({}, 'reservationId', {
      get() { throw new Error('hostile reservation getter'); },
    });
    expect(normalizeEdgeBillingReservation(value)).toBeNull();
  });

  it('copies valid allowed and denied rate-limit results', () => {
    expect(normalizeEdgeRateLimitResult({
      allowed: true,
      remaining: 9,
      retryAfterSeconds: 0,
      privateMetadata: 'must not propagate',
    }, 10)).toEqual({ allowed: true, remaining: 9, retryAfterSeconds: 0 });
    expect(normalizeEdgeRateLimitResult({
      allowed: true,
      remaining: 0,
      retryAfterSeconds: 0,
      banned: false,
    }, 1)).toEqual({ allowed: true, remaining: 0, retryAfterSeconds: 0 });
    expect(normalizeEdgeRateLimitResult({
      allowed: false,
      remaining: 0,
      retryAfterSeconds: 1,
    }, 10)).toEqual({ allowed: false, remaining: 0, retryAfterSeconds: 1 });
    expect(normalizeEdgeRateLimitResult({
      allowed: false,
      remaining: 0,
      retryAfterSeconds: 604_800,
      banned: true,
    }, 10)).toEqual({
      allowed: false,
      remaining: 0,
      retryAfterSeconds: 604_800,
      banned: true,
    });
    expect(normalizeEdgeRateLimitResult({
      allowed: true,
      remaining: 999_999,
      retryAfterSeconds: 0,
    }, 1_000_000)).toEqual({
      allowed: true,
      remaining: 999_999,
      retryAfterSeconds: 0,
    });
  });

  it.each([
    null,
    Object.assign([], { allowed: true, remaining: 0, retryAfterSeconds: 0 }),
    {},
    { allowed: 1, remaining: 0, retryAfterSeconds: 0 },
    { allowed: true, remaining: -1, retryAfterSeconds: 0 },
    { allowed: true, remaining: 1.5, retryAfterSeconds: 0 },
    { allowed: true, remaining: 10, retryAfterSeconds: 0 },
    { allowed: true, remaining: 0, retryAfterSeconds: 1 },
    { allowed: true, remaining: 0, retryAfterSeconds: 0, banned: true },
    { allowed: false, remaining: 1, retryAfterSeconds: 1 },
    { allowed: false, remaining: 0, retryAfterSeconds: 0 },
    { allowed: false, remaining: 0, retryAfterSeconds: 1.5 },
    { allowed: false, remaining: 0, retryAfterSeconds: 604_801 },
    { allowed: false, remaining: 0, retryAfterSeconds: 1, banned: 'true' },
  ])('rejects a malformed rate-limit result %#', (value) => {
    expect(normalizeEdgeRateLimitResult(value, 10)).toBeNull();
  });

  it.each([0, 1.5, 1_000_001])('rejects an invalid rate-limit ceiling %#', (limit) => {
    expect(normalizeEdgeRateLimitResult({
      allowed: false,
      remaining: 0,
      retryAfterSeconds: 1,
    }, limit)).toBeNull();
  });

  it('rejects a rate-limit result whose field getter throws', () => {
    const value = Object.defineProperty({
      remaining: 0,
      retryAfterSeconds: 0,
    }, 'allowed', {
      get() { throw new Error('hostile allowed getter'); },
    });
    expect(normalizeEdgeRateLimitResult(value, 10)).toBeNull();
  });
});

import type { EdgeBillingReservation } from './billing-coordinator.js';
import type { EdgeRouteAttempt } from './circuit-breaker.js';
import type { EdgeConcurrencyLease } from './concurrency-limit.js';
import type { EdgeRateLimitResult } from './rate-limit.js';

function isReservationId(value: string): boolean {
  return /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,159}$/u.test(value);
}

export function normalizeEdgeConcurrencyLease(value: unknown): EdgeConcurrencyLease | null {
  try {
    if (Array.isArray(value)) return null;
    const target = value as Record<string, unknown>;
    const release = target.release;
    if (typeof release !== 'function') return null;
    return { release: () => Reflect.apply(release, target, []) as void };
  } catch {
    return null;
  }
}

export function normalizeEdgeRouteAttempt(value: unknown): EdgeRouteAttempt | null {
  try {
    if (Array.isArray(value)) return null;
    const target = value as Record<string, unknown>;
    const succeeded = target.succeeded;
    const failed = target.failed;
    const cancelled = target.cancelled;
    if (typeof succeeded !== 'function'
      || typeof failed !== 'function'
      || typeof cancelled !== 'function') return null;
    return {
      succeeded: () => Reflect.apply(succeeded, target, []) as void,
      failed: (atMs) => Reflect.apply(failed, target, [atMs]) as void,
      cancelled: () => Reflect.apply(cancelled, target, []) as void,
    };
  } catch {
    return null;
  }
}

export function normalizeEdgeBillingReservation(value: unknown): EdgeBillingReservation | null {
  try {
    if (Array.isArray(value)) return null;
    const target = value as Record<string, unknown>;
    const reservationId = target.reservationId;
    return typeof reservationId === 'string' && isReservationId(reservationId)
      ? { reservationId }
      : null;
  } catch {
    return null;
  }
}

export function normalizeEdgeRateLimitResult(
  value: unknown,
  limit: number,
): EdgeRateLimitResult | null {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1_000_000) return null;
  try {
    if (Array.isArray(value)) return null;
    const target = value as Record<string, unknown>;
    const allowed = target.allowed;
    const remaining = target.remaining;
    const retryAfterSeconds = target.retryAfterSeconds;
    const banned = target.banned;
    if (typeof allowed !== 'boolean'
      || !Number.isSafeInteger(remaining)
      || Number(remaining) < 0
      || !Number.isSafeInteger(retryAfterSeconds)
      || (banned !== undefined && typeof banned !== 'boolean')) return null;
    if (allowed) {
      if (Number(remaining) >= limit || retryAfterSeconds !== 0 || banned === true) return null;
      return { allowed: true, remaining: Number(remaining), retryAfterSeconds: 0 };
    }
    if (remaining !== 0
      || Number(retryAfterSeconds) < 1
      || Number(retryAfterSeconds) > 604_800) return null;
    return banned === true
      ? { allowed: false, remaining: 0, retryAfterSeconds: Number(retryAfterSeconds), banned: true }
      : { allowed: false, remaining: 0, retryAfterSeconds: Number(retryAfterSeconds) };
  } catch {
    return null;
  }
}

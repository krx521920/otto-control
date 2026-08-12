import { describe, expect, it } from 'vitest';

import { InMemoryEdgeConcurrencyLimiter } from '../src/edge-gateway/concurrency-limit.js';

describe('Edge Gateway process-local concurrency limiter', () => {
  it('enforces both global and per-subject limits and releases slots idempotently', () => {
    const limiter = new InMemoryEdgeConcurrencyLimiter(3, 2);
    const first = limiter.acquire('subject-a');
    const second = limiter.acquire('subject-a');
    const third = limiter.acquire('subject-b');
    expect(first).not.toBeNull();
    expect(second).not.toBeNull();
    expect(third).not.toBeNull();
    expect(limiter.acquire('subject-a')).toBeNull();
    expect(limiter.acquire('subject-c')).toBeNull();
    expect(limiter.snapshot()).toEqual({
      activeRequests: 3,
      globalLimit: 3,
      trackedSubjects: 2,
      subjectsAtLimit: 1,
      perSubjectLimit: 2,
    });

    first!.release();
    first!.release();
    const replacement = limiter.acquire('subject-c');
    expect(replacement).not.toBeNull();
    expect(limiter.snapshot()).toMatchObject({
      activeRequests: 3,
      trackedSubjects: 3,
      subjectsAtLimit: 0,
    });

    second!.release();
    third!.release();
    replacement!.release();
    expect(limiter.snapshot()).toMatchObject({
      activeRequests: 0,
      trackedSubjects: 0,
      subjectsAtLimit: 0,
    });
  });

  it('enforces the per-subject boundary before global capacity is exhausted', () => {
    const limiter = new InMemoryEdgeConcurrencyLimiter(4, 2);
    const first = limiter.acquire('subject-a');
    const second = limiter.acquire('subject-a');
    expect(first).not.toBeNull();
    expect(second).not.toBeNull();
    expect(limiter.snapshot().activeRequests).toBe(2);
    expect(limiter.acquire('subject-a')).toBeNull();
    const other = limiter.acquire('subject-b');
    expect(other).not.toBeNull();
    first!.release();
    second!.release();
    other!.release();
  });

  it.each([
    [0, 1],
    [1.5, 1],
    [1_000_001, 1],
    [2, 3],
  ])('rejects unsafe limit configuration %#', (globalLimit, perSubjectLimit) => {
    expect(() => new InMemoryEdgeConcurrencyLimiter(globalLimit, perSubjectLimit)).toThrow();
  });

  it('accepts the exact minimum and maximum limit boundaries', () => {
    expect(() => new InMemoryEdgeConcurrencyLimiter(1, 1)).not.toThrow();
    expect(() => new InMemoryEdgeConcurrencyLimiter(1_000_000, 1_000_000)).not.toThrow();
  });

  it('rejects lower-bound violations even when both limits match', () => {
    expect(() => new InMemoryEdgeConcurrencyLimiter(0, 0)).toThrow('between 1 and 1000000');
    expect(() => new InMemoryEdgeConcurrencyLimiter(-1, -1)).toThrow('between 1 and 1000000');
  });

  it('rejects malformed subject keys without changing counters', () => {
    const limiter = new InMemoryEdgeConcurrencyLimiter(2, 1);
    expect(() => limiter.acquire('')).toThrow('subject key');
    expect(() => limiter.acquire('x'.repeat(1_025))).toThrow('subject key');
    const exactBoundary = limiter.acquire('x'.repeat(1_024));
    expect(exactBoundary).not.toBeNull();
    exactBoundary!.release();
    expect(limiter.snapshot()).toMatchObject({ activeRequests: 0, trackedSubjects: 0 });
  });
});

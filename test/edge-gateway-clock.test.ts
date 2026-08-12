import { describe, expect, it } from 'vitest';

import {
  normalizeEdgeClock,
  readEdgeClockAtOrAfter,
} from '../src/edge-gateway/clock.js';

describe('edge gateway clock', () => {
  it('normalizes non-negative safe integer boundaries', () => {
    expect(normalizeEdgeClock(0)).toBe(0);
    expect(normalizeEdgeClock(Number.MAX_SAFE_INTEGER)).toBe(Number.MAX_SAFE_INTEGER);
  });

  it.each([
    null,
    undefined,
    '1',
    -1,
    0.5,
    Number.NaN,
    Number.POSITIVE_INFINITY,
    Number.MAX_SAFE_INTEGER + 1,
  ])('rejects an invalid clock value %#', (value) => {
    expect(normalizeEdgeClock(value)).toBeNull();
  });

  it('returns a valid clock at or after the request floor', () => {
    expect(readEdgeClockAtOrAfter(() => 101, 100)).toBe(101);
    expect(readEdgeClockAtOrAfter(() => 100, 100)).toBe(100);
  });

  it.each([
    () => null as never,
    () => 99,
    () => -1,
    () => 1.5,
    () => Number.NaN,
    () => { throw new Error('clock backend unavailable'); },
  ])('uses the request floor when the runtime clock is unsafe %#', (now) => {
    expect(readEdgeClockAtOrAfter(now, 100)).toBe(100);
  });

  it.each([-1, 0.5, Number.NaN, Number.MAX_SAFE_INTEGER + 1])(
    'rejects an invalid clock floor %#',
    (floor) => {
      expect(() => readEdgeClockAtOrAfter(() => 100, floor)).toThrow(
        'edge clock floor is invalid',
      );
    },
  );
});

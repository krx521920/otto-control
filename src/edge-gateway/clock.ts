export function normalizeEdgeClock(value: unknown): number | null {
  return Number.isSafeInteger(value) && Number(value) >= 0
    ? Number(value)
    : null;
}

export function readEdgeClockAtOrAfter(now: () => number, floor: number): number {
  const normalizedFloor = normalizeEdgeClock(floor);
  if (normalizedFloor === null) throw new Error('edge clock floor is invalid');
  try {
    const value = normalizeEdgeClock(now());
    return Math.max(normalizedFloor, Number(value));
  } catch {
    return normalizedFloor;
  }
}

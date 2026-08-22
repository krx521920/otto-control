function isEdgeRequestId(value: string): boolean {
  return /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$/u.test(value);
}

export function normalizeEdgeRequestId(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const normalized = value.trim();
  return isEdgeRequestId(normalized) ? normalized : null;
}

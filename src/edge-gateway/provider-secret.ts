const MAXIMUM_PROVIDER_SECRET_LENGTH = 8_192;

function isHttpVisibleAscii(value: string): boolean {
  return /^[\x21-\x7e]+$/u.test(value);
}

/**
 * Provider credentials become HTTP header values. Keep this validation in the
 * portable core so Node and edge runtimes enforce the same byte-safe contract.
 */
export function normalizeEdgeProviderSecret(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const normalized = value.trim();
  if (
    !normalized
    || normalized.length > MAXIMUM_PROVIDER_SECRET_LENGTH
    || !isHttpVisibleAscii(normalized)
  ) {
    return null;
  }
  return normalized;
}

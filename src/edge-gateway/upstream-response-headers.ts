const MAXIMUM_UPSTREAM_REQUEST_ID_LENGTH = 256;

function isVisibleAscii(value: string): boolean {
  return /^[\x21-\x7e]+$/u.test(value);
}

function isSafeContentType(value: string): boolean {
  return value === 'application/json'
    || value === 'application/problem+json'
    || value === 'application/x-ndjson'
    || value === 'text/event-stream';
}

export function normalizeEdgeUpstreamContentType(value: string | null): string {
  if (!value) return 'application/octet-stream';
  const mediaType = value.split(';', 1)[0]!.trim().toLowerCase();
  return isSafeContentType(mediaType)
    ? mediaType
    : 'application/octet-stream';
}

export function normalizeEdgeUpstreamRequestId(value: string | null): string | null {
  const normalized = value?.trim() ?? '';
  if (
    !normalized
    || normalized.length > MAXIMUM_UPSTREAM_REQUEST_ID_LENGTH
    || !isVisibleAscii(normalized)
  ) {
    return null;
  }
  return normalized;
}

const MAXIMUM_ALLOWED_ORIGINS = 256;

export interface EdgeUpstreamOriginPolicy {
  allows(upstreamUrl: string): boolean;
}

function normalizedHttpsOrigin(value: unknown): string {
  if (typeof value !== 'string') {
    throw new Error('edge upstream origin is invalid');
  }
  if (value.length > 2_048) {
    throw new Error('edge upstream origin is invalid');
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error('edge upstream origin is invalid');
  }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password
    || parsed.pathname !== '/' || parsed.search || parsed.hash) {
    throw new Error('edge upstream origin must be an HTTPS origin without credentials or path');
  }
  return parsed.origin;
}

export class StaticEdgeUpstreamOriginPolicy implements EdgeUpstreamOriginPolicy {
  readonly #origins: ReadonlySet<string>;

  constructor(origins: readonly string[]) {
    if (!Array.isArray(origins) || origins.length < 1 || origins.length > MAXIMUM_ALLOWED_ORIGINS) {
      throw new Error('edge upstream origin allowlist must contain 1 to 256 origins');
    }
    const normalized = origins.map(normalizedHttpsOrigin);
    if (new Set(normalized).size !== normalized.length) {
      throw new Error('edge upstream origin allowlist must not contain duplicates');
    }
    this.#origins = new Set(normalized);
  }

  allows(upstreamUrl: string): boolean {
    try {
      return this.#origins.has(new URL(upstreamUrl).origin);
    } catch {
      return false;
    }
  }
}

export function normalizeEdgeUpstreamOriginPolicy(
  value: unknown,
): StaticEdgeUpstreamOriginPolicy {
  if (value === null) {
    throw new Error('edge upstream origin policy must be a JSON object');
  }
  if (typeof value !== 'object') {
    throw new Error('edge upstream origin policy must be a JSON object');
  }
  if (Array.isArray(value)) {
    throw new Error('edge upstream origin policy must be a JSON object');
  }
  const body = value as Record<string, unknown>;
  if (Object.keys(body).some((field) => field !== 'version' && field !== 'allowedOrigins')
    || body.version !== 1 || !Array.isArray(body.allowedOrigins)) {
    throw new Error('edge upstream origin policy fields are invalid');
  }
  return new StaticEdgeUpstreamOriginPolicy(body.allowedOrigins as string[]);
}

import type {
  EdgeModelRouteV1,
  EdgeProviderAuthentication,
} from '../contracts/edge-gateway.js';
import { isSafeEdgeAuthenticationHeaderName } from './protocol.js';

const MAXIMUM_ALLOWED_UPSTREAMS = 256;
const MAXIMUM_AUTHENTICATIONS_PER_UPSTREAM = 16;

export interface EdgeUpstreamOriginPolicy {
  allows(route: EdgeModelRouteV1): boolean;
}

export interface EdgeUpstreamRule {
  origin: string;
  authentications: readonly EdgeProviderAuthentication[];
}

interface NormalizedRule {
  origin: string;
  authenticationKeys: ReadonlySet<string> | null;
}

function objectValue(value: unknown, message: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(message);
  }
  return value as Record<string, unknown>;
}

function hasExactFields(body: Record<string, unknown>, fields: readonly string[]): boolean {
  const actual = Object.keys(body);
  return actual.length === fields.length && actual.every((field) => fields.includes(field));
}

function validSecretBinding(value: string): boolean {
  return /^[A-Z][A-Z0-9_]{2,127}$/u.test(value);
}

function validAuthenticationHeader(value: string): boolean {
  return isSafeEdgeAuthenticationHeaderName(value);
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

function authenticationKey(value: unknown): string {
  const body = objectValue(value, 'edge upstream authentication is invalid');
  const type = body.type;
  const expectedFields = type === 'bearer'
    ? ['type', 'secretBinding']
    : type === 'header' ? ['type', 'headerName', 'secretBinding'] : null;
  if (!expectedFields || !hasExactFields(body, expectedFields)) {
    throw new Error('edge upstream authentication is invalid');
  }
  const secretBinding = typeof body.secretBinding === 'string'
    ? body.secretBinding.trim()
    : '';
  if (!validSecretBinding(secretBinding)) {
    throw new Error('edge upstream secret binding is invalid');
  }
  if (type === 'bearer') return `bearer\0${secretBinding}`;
  const headerName = typeof body.headerName === 'string'
    ? body.headerName.trim().toLowerCase()
    : '';
  if (!validAuthenticationHeader(headerName)) {
    throw new Error('edge upstream authentication header is invalid');
  }
  return `header\0${headerName}\0${secretBinding}`;
}

function normalizeCredentialBoundRule(value: unknown): NormalizedRule {
  const body = objectValue(value, 'edge upstream rule is invalid');
  if (!hasExactFields(body, ['origin', 'authentications'])
    || !Array.isArray(body.authentications)
    || body.authentications.length < 1
    || body.authentications.length > MAXIMUM_AUTHENTICATIONS_PER_UPSTREAM) {
    throw new Error('edge upstream rule is invalid');
  }
  const authenticationKeys = body.authentications.map(authenticationKey);
  if (new Set(authenticationKeys).size !== authenticationKeys.length) {
    throw new Error('edge upstream rule authentication entries must not contain duplicates');
  }
  return {
    origin: normalizedHttpsOrigin(body.origin),
    authenticationKeys: new Set(authenticationKeys),
  };
}

/**
 * String entries preserve the v1 origin-only policy for migration. Object rules
 * bind every approved origin to an explicit set of provider credentials.
 */
export class StaticEdgeUpstreamOriginPolicy implements EdgeUpstreamOriginPolicy {
  readonly #rules: ReadonlyMap<string, NormalizedRule>;

  constructor(entries: readonly (string | EdgeUpstreamRule)[]) {
    if (!Array.isArray(entries) || entries.length < 1
      || entries.length > MAXIMUM_ALLOWED_UPSTREAMS) {
      throw new Error('edge upstream allowlist must contain 1 to 256 entries');
    }
    const normalized = entries.map((entry) => (
      typeof entry === 'string'
        ? { origin: normalizedHttpsOrigin(entry), authenticationKeys: null }
        : normalizeCredentialBoundRule(entry)
    ));
    if (new Set(normalized.map((rule) => rule.origin)).size !== normalized.length) {
      throw new Error('edge upstream allowlist must not contain duplicate origins');
    }
    this.#rules = new Map(normalized.map((rule) => [rule.origin, rule]));
  }

  allows(route: EdgeModelRouteV1): boolean {
    let origin: string;
    try {
      origin = new URL(route.upstreamUrl).origin;
    } catch {
      return false;
    }
    const rule = this.#rules.get(origin);
    if (!rule) return false;
    if (rule.authenticationKeys === null) return true;
    let key: string;
    try {
      key = authenticationKey(route.authentication);
    } catch {
      return false;
    }
    return rule.authenticationKeys.has(key);
  }
}

export function normalizeEdgeUpstreamOriginPolicy(
  value: unknown,
): StaticEdgeUpstreamOriginPolicy {
  const body = objectValue(value, 'edge upstream origin policy must be a JSON object');
  if (body.version === 1 && hasExactFields(body, ['version', 'allowedOrigins'])
    && Array.isArray(body.allowedOrigins)
    && body.allowedOrigins.every((origin) => typeof origin === 'string')) {
    return new StaticEdgeUpstreamOriginPolicy(body.allowedOrigins as string[]);
  }
  if (body.version === 2 && hasExactFields(body, ['version', 'allowedUpstreams'])
    && Array.isArray(body.allowedUpstreams)
    && body.allowedUpstreams.every((upstream) => (
      upstream !== null && typeof upstream === 'object' && !Array.isArray(upstream)
    ))) {
    return new StaticEdgeUpstreamOriginPolicy(body.allowedUpstreams as EdgeUpstreamRule[]);
  }
  throw new Error('edge upstream origin policy fields are invalid');
}

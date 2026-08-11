import type {
  EdgeAccessTokenV1,
  EdgeGatewayEndpoint,
  EdgeGatewayLimitsV1,
  EdgeGatewayPolicyV1,
  EdgeModelRouteV1,
  EdgeProviderAuthentication,
  SignedEdgeAccessTokenV1,
  SignedEdgeGatewayPolicyV1,
} from '../contracts/edge-gateway.js';

const SIGNATURE_PREFIX = 'ed25519:';
const IDENTIFIER_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,159}$/u;
const SECRET_BINDING_PATTERN = /^[A-Z][A-Z0-9_]{2,127}$/u;
const HEADER_NAME_PATTERN = /^[a-zA-Z0-9!#$%&'*+.^_`|~-]{1,80}$/u;
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
const MAX_TOKEN_DURATION_MS = 15 * 60 * 1000;
const MAX_POLICY_DURATION_MS = 24 * 60 * 60 * 1000;
const TOKEN_ENVELOPE_FIELDS = new Set(['token', 'signingKeyId', 'signature']);
const TOKEN_FIELDS = new Set([
  'version', 'tokenId', 'deploymentId', 'organizationId', 'subjectId', 'scope',
  'policyVersion', 'allowedModels', 'issuedAtMs', 'expiresAtMs',
]);
const POLICY_ENVELOPE_FIELDS = new Set(['policy', 'signingKeyId', 'signature']);
const POLICY_FIELDS = new Set([
  'version', 'policyId', 'policyVersion', 'deploymentId', 'organizationId',
  'routes', 'limits', 'issuedAtMs', 'expiresAtMs',
]);
const ROUTE_FIELDS = new Set([
  'id', 'endpoint', 'publicModel', 'upstreamModel', 'upstreamUrl', 'priority',
  'authentication',
]);
const LIMIT_FIELDS = new Set([
  'maxRequestBytes', 'requestsPerMinute', 'upstreamConnectTimeoutMs',
  'upstreamIdleTimeoutMs', 'maxRouteAttempts',
]);
const AUTH_BEARER_FIELDS = new Set(['type', 'secretBinding']);
const AUTH_HEADER_FIELDS = new Set(['type', 'headerName', 'secretBinding']);
const FORBIDDEN_AUTH_HEADERS = new Set([
  'authorization', 'cookie', 'host', 'proxy-authorization', 'set-cookie',
  'transfer-encoding',
]);

export class EdgeGatewayProtocolError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = 'EdgeGatewayProtocolError';
    this.status = status;
    this.code = code;
  }
}

function protocolError(status: number, code: string, message: string): never {
  throw new EdgeGatewayProtocolError(status, code, message);
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([, item]) => item !== undefined)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, item]) => [key, canonicalize(item)]),
    );
  }
  return value;
}

/** Byte-for-byte compatible with src/crypto/signed-envelope.ts. */
export function edgeCanonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function objectValue(value: unknown, name: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    protocolError(400, 'EDGE_INVALID_ENVELOPE', `${name} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exactFields(value: Record<string, unknown>, expected: Set<string>, name: string): void {
  if (Object.keys(value).some((field) => !expected.has(field))) {
    protocolError(400, 'EDGE_INVALID_ENVELOPE', `${name} contains unsupported fields`);
  }
}

function requiredString(
  value: Record<string, unknown>,
  field: string,
  maximum: number,
): string {
  const item = value[field];
  if (typeof item !== 'string' || !item.trim() || item.trim().length > maximum) {
    protocolError(400, 'EDGE_INVALID_ENVELOPE', `${field} is invalid`);
  }
  return item.trim();
}

function identifier(value: Record<string, unknown>, field: string): string {
  const item = requiredString(value, field, 160);
  if (!IDENTIFIER_PATTERN.test(item)) {
    protocolError(400, 'EDGE_INVALID_ENVELOPE', `${field} is invalid`);
  }
  return item;
}

function safeInteger(
  value: Record<string, unknown>,
  field: string,
  minimum: number,
  maximum: number,
): number {
  const item = Number(value[field]);
  if (!Number.isSafeInteger(item) || item < minimum || item > maximum) {
    protocolError(400, 'EDGE_INVALID_ENVELOPE', `${field} is invalid`);
  }
  return item;
}

function signature(value: unknown): string {
  const item = typeof value === 'string' ? value.trim() : '';
  if (!/^ed25519:[a-zA-Z0-9_-]{86}$/u.test(item)) {
    protocolError(400, 'EDGE_INVALID_SIGNATURE', 'signature is malformed');
  }
  return item;
}

function validateWindow(
  issuedAtMs: number,
  expiresAtMs: number,
  now: number,
  maximumDurationMs: number,
  kind: 'access token' | 'gateway policy',
): void {
  if (issuedAtMs > now + MAX_CLOCK_SKEW_MS) {
    protocolError(401, 'EDGE_NOT_YET_VALID', `${kind} is not yet valid`);
  }
  if (expiresAtMs <= issuedAtMs || expiresAtMs - issuedAtMs > maximumDurationMs) {
    protocolError(400, 'EDGE_INVALID_ENVELOPE', `${kind} validity window is invalid`);
  }
  if (now >= expiresAtMs) {
    protocolError(401, 'EDGE_EXPIRED', `${kind} has expired`);
  }
}

function endpoint(value: unknown): EdgeGatewayEndpoint {
  if (value !== 'chat_completions' && value !== 'responses') {
    protocolError(400, 'EDGE_INVALID_ENVELOPE', 'route.endpoint is invalid');
  }
  return value;
}

function authentication(value: unknown): EdgeProviderAuthentication {
  const body = objectValue(value, 'route.authentication');
  const type = requiredString(body, 'type', 16);
  if (type === 'bearer') {
    exactFields(body, AUTH_BEARER_FIELDS, 'route.authentication');
  } else if (type === 'header') {
    exactFields(body, AUTH_HEADER_FIELDS, 'route.authentication');
  } else {
    protocolError(400, 'EDGE_INVALID_ENVELOPE', 'route.authentication.type is invalid');
  }
  const secretBinding = requiredString(body, 'secretBinding', 128);
  if (!SECRET_BINDING_PATTERN.test(secretBinding)) {
    protocolError(400, 'EDGE_INVALID_ENVELOPE', 'route secret binding is invalid');
  }
  if (type === 'bearer') return { type, secretBinding };
  const headerName = requiredString(body, 'headerName', 80);
  if (!HEADER_NAME_PATTERN.test(headerName) || FORBIDDEN_AUTH_HEADERS.has(headerName.toLowerCase())) {
    protocolError(400, 'EDGE_INVALID_ENVELOPE', 'route authentication header is invalid');
  }
  return { type, headerName, secretBinding };
}

function route(value: unknown): EdgeModelRouteV1 {
  const body = objectValue(value, 'gateway route');
  exactFields(body, ROUTE_FIELDS, 'gateway route');
  const upstreamUrl = requiredString(body, 'upstreamUrl', 2_048);
  let parsed: URL;
  try {
    parsed = new URL(upstreamUrl);
  } catch {
    protocolError(400, 'EDGE_INVALID_ENVELOPE', 'route upstreamUrl is invalid');
  }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password
    || parsed.search || parsed.hash) {
    protocolError(
      400,
      'EDGE_INVALID_ENVELOPE',
      'route upstreamUrl must be HTTPS without credentials, query, or fragment',
    );
  }
  return {
    id: identifier(body, 'id'),
    endpoint: endpoint(body.endpoint),
    publicModel: requiredString(body, 'publicModel', 160),
    upstreamModel: requiredString(body, 'upstreamModel', 160),
    upstreamUrl: parsed.toString(),
    priority: safeInteger(body, 'priority', 0, 10_000),
    authentication: authentication(body.authentication),
  };
}

function limits(value: unknown): EdgeGatewayLimitsV1 {
  const body = objectValue(value, 'gateway limits');
  exactFields(body, LIMIT_FIELDS, 'gateway limits');
  return {
    maxRequestBytes: safeInteger(body, 'maxRequestBytes', 1_024, 20 * 1_024 * 1_024),
    requestsPerMinute: safeInteger(body, 'requestsPerMinute', 1, 1_000_000),
    upstreamConnectTimeoutMs: safeInteger(
      body,
      'upstreamConnectTimeoutMs',
      500,
      60_000,
    ),
    upstreamIdleTimeoutMs: safeInteger(
      body,
      'upstreamIdleTimeoutMs',
      1_000,
      300_000,
    ),
    maxRouteAttempts: safeInteger(body, 'maxRouteAttempts', 1, 8),
  };
}

export function normalizeSignedEdgeGatewayPolicy(
  value: unknown,
  now: number,
): SignedEdgeGatewayPolicyV1 {
  const envelope = objectValue(value, 'gateway policy envelope');
  exactFields(envelope, POLICY_ENVELOPE_FIELDS, 'gateway policy envelope');
  const body = objectValue(envelope.policy, 'gateway policy');
  exactFields(body, POLICY_FIELDS, 'gateway policy');
  if (body.version !== 1) {
    protocolError(400, 'EDGE_INVALID_ENVELOPE', 'gateway policy version is invalid');
  }
  if (!Array.isArray(body.routes) || body.routes.length < 1 || body.routes.length > 64) {
    protocolError(400, 'EDGE_INVALID_ENVELOPE', 'gateway policy routes are invalid');
  }
  const routes = body.routes.map(route);
  if (new Set(routes.map((item) => item.id)).size !== routes.length) {
    protocolError(400, 'EDGE_INVALID_ENVELOPE', 'gateway route ids must be unique');
  }
  const issuedAtMs = safeInteger(body, 'issuedAtMs', 1, Number.MAX_SAFE_INTEGER);
  const expiresAtMs = safeInteger(body, 'expiresAtMs', 1, Number.MAX_SAFE_INTEGER);
  validateWindow(issuedAtMs, expiresAtMs, now, MAX_POLICY_DURATION_MS, 'gateway policy');
  return {
    policy: {
      version: 1,
      policyId: identifier(body, 'policyId'),
      policyVersion: identifier(body, 'policyVersion'),
      deploymentId: identifier(body, 'deploymentId'),
      organizationId: identifier(body, 'organizationId'),
      routes,
      limits: limits(body.limits),
      issuedAtMs,
      expiresAtMs,
    },
    signingKeyId: identifier(envelope, 'signingKeyId'),
    signature: signature(envelope.signature),
  };
}

export function normalizeSignedEdgeAccessToken(
  value: unknown,
  now: number,
): SignedEdgeAccessTokenV1 {
  const envelope = objectValue(value, 'edge access token envelope');
  exactFields(envelope, TOKEN_ENVELOPE_FIELDS, 'edge access token envelope');
  const body = objectValue(envelope.token, 'edge access token');
  exactFields(body, TOKEN_FIELDS, 'edge access token');
  if (body.version !== 1 || body.scope !== 'model_gateway') {
    protocolError(401, 'EDGE_UNAUTHORIZED', 'edge access token is invalid');
  }
  if (!Array.isArray(body.allowedModels) || body.allowedModels.length < 1
    || body.allowedModels.length > 64) {
    protocolError(400, 'EDGE_INVALID_ENVELOPE', 'allowedModels is invalid');
  }
  const allowedModels = body.allowedModels.map((item) => {
    if (typeof item !== 'string' || !item.trim() || item.trim().length > 160) {
      protocolError(400, 'EDGE_INVALID_ENVELOPE', 'allowedModels is invalid');
    }
    return item.trim();
  });
  if (new Set(allowedModels).size !== allowedModels.length) {
    protocolError(400, 'EDGE_INVALID_ENVELOPE', 'allowedModels must be unique');
  }
  const issuedAtMs = safeInteger(body, 'issuedAtMs', 1, Number.MAX_SAFE_INTEGER);
  const expiresAtMs = safeInteger(body, 'expiresAtMs', 1, Number.MAX_SAFE_INTEGER);
  validateWindow(issuedAtMs, expiresAtMs, now, MAX_TOKEN_DURATION_MS, 'access token');
  const token: EdgeAccessTokenV1 = {
    version: 1,
    tokenId: identifier(body, 'tokenId'),
    deploymentId: identifier(body, 'deploymentId'),
    organizationId: identifier(body, 'organizationId'),
    subjectId: identifier(body, 'subjectId'),
    scope: 'model_gateway',
    policyVersion: identifier(body, 'policyVersion'),
    allowedModels,
    issuedAtMs,
    expiresAtMs,
  };
  return {
    token,
    signingKeyId: identifier(envelope, 'signingKeyId'),
    signature: signature(envelope.signature),
  };
}

function base64UrlToBytes(value: string): Uint8Array<ArrayBuffer> {
  if (!/^[a-zA-Z0-9_-]+$/u.test(value)) {
    protocolError(401, 'EDGE_UNAUTHORIZED', 'encoded edge access token is malformed');
  }
  const padding = '='.repeat((4 - (value.length % 4)) % 4);
  let binary: string;
  try {
    binary = atob(value.replace(/-/gu, '+').replace(/_/gu, '/') + padding);
  } catch {
    protocolError(401, 'EDGE_UNAUTHORIZED', 'encoded edge access token is malformed');
  }
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function bytesToBase64Url(value: Uint8Array): string {
  let binary = '';
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/gu, '-').replace(/\//gu, '_').replace(/=+$/gu, '');
}

export function encodeEdgeAccessTokenEnvelope(value: SignedEdgeAccessTokenV1): string {
  return bytesToBase64Url(new TextEncoder().encode(JSON.stringify(value)));
}

export function decodeEdgeAccessTokenEnvelope(value: string, now: number): SignedEdgeAccessTokenV1 {
  if (!value || value.length > 16_384) {
    protocolError(401, 'EDGE_UNAUTHORIZED', 'edge access token is missing or too large');
  }
  try {
    const json = new TextDecoder('utf-8', { fatal: true }).decode(base64UrlToBytes(value));
    return normalizeSignedEdgeAccessToken(JSON.parse(json) as unknown, now);
  } catch (error) {
    if (error instanceof EdgeGatewayProtocolError && error.status === 401) throw error;
    protocolError(401, 'EDGE_UNAUTHORIZED', 'encoded edge access token is malformed');
  }
}

function pemBytes(value: string): Uint8Array<ArrayBuffer> {
  const encoded = value
    .trim()
    .replace(/\\n/gu, '\n')
    .replace(/-----BEGIN PUBLIC KEY-----/gu, '')
    .replace(/-----END PUBLIC KEY-----/gu, '')
    .replace(/\s/gu, '');
  return base64UrlToBytes(encoded.replace(/\+/gu, '-').replace(/\//gu, '_').replace(/=+$/gu, ''));
}

export interface EdgeSignatureVerifier {
  verify(payload: unknown, signingKeyId: string, signature: string): Promise<boolean>;
}

export function createEdgeSignatureVerifier(
  publicKeys: Readonly<Record<string, string>>,
  subtle: SubtleCrypto = crypto.subtle,
): EdgeSignatureVerifier {
  const imported = new Map<string, Promise<CryptoKey>>();
  return {
    async verify(payload, signingKeyId, signatureValue) {
      const publicKeyPem = publicKeys[signingKeyId];
      if (!publicKeyPem) return false;
      let key = imported.get(signingKeyId);
      if (!key) {
        key = subtle.importKey(
          'spki',
          pemBytes(publicKeyPem),
          { name: 'Ed25519' },
          false,
          ['verify'],
        );
        imported.set(signingKeyId, key);
      }
      try {
        return await subtle.verify(
          { name: 'Ed25519' },
          await key,
          base64UrlToBytes(signatureValue.slice(SIGNATURE_PREFIX.length)),
          new TextEncoder().encode(edgeCanonicalJson(payload)),
        );
      } catch {
        return false;
      }
    },
  };
}

export async function verifyGatewayPolicy(
  envelope: SignedEdgeGatewayPolicyV1,
  verifier: EdgeSignatureVerifier,
): Promise<EdgeGatewayPolicyV1> {
  if (!await verifier.verify(envelope.policy, envelope.signingKeyId, envelope.signature)) {
    protocolError(503, 'EDGE_POLICY_SIGNATURE_INVALID', 'gateway policy signature is invalid');
  }
  return envelope.policy;
}

export async function verifyEdgeAccessToken(
  envelope: SignedEdgeAccessTokenV1,
  verifier: EdgeSignatureVerifier,
): Promise<EdgeAccessTokenV1> {
  if (!await verifier.verify(envelope.token, envelope.signingKeyId, envelope.signature)) {
    protocolError(401, 'EDGE_UNAUTHORIZED', 'edge access token signature is invalid');
  }
  return envelope.token;
}

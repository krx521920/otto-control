import { randomBytes } from 'node:crypto';

import type { SignedEdgeGatewayPolicyV1 } from '../contracts/edge-gateway.js';
import { signTelemetryRequest } from '../crypto/telemetry-request.js';
import type { EdgeGatewayPolicySource } from './gateway.js';
import {
  edgeCanonicalJson,
  normalizeSignedEdgeGatewayPolicy,
  type EdgeSignatureVerifier,
  verifyGatewayPolicy,
} from './protocol.js';

const IDENTIFIER_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,159}$/u;
const MACHINE_FINGERPRINT_PATTERN = /^[a-f0-9]{64}$/u;
const RESPONSE_FIELDS = new Set(['policy']);
const MAX_RESPONSE_BYTES = 256 * 1024;
const DEFAULT_REFRESH_BEFORE_EXPIRY_MS = 60_000;
const DEFAULT_REQUEST_TIMEOUT_MS = 10_000;

export interface EdgeControlPolicyBinding {
  licenseId: string;
  deploymentId: string;
  organizationId: string;
  machineFingerprint: string;
}

export interface ControlEdgeGatewayPolicySourceOptions {
  controlBaseUrl: string;
  binding: EdgeControlPolicyBinding;
  leaseToken: string;
  verifier: EdgeSignatureVerifier;
  fetch?: typeof fetch;
  now?: () => number;
  nonce?: () => string;
  refreshBeforeExpiryMs?: number;
  requestTimeoutMs?: number;
}

export class EdgeControlPolicySourceError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'EdgeControlPolicySourceError';
    this.code = code;
  }
}

function sourceError(code: string, message: string): never {
  throw new EdgeControlPolicySourceError(code, message);
}

export function normalizeEdgeControlBaseUrl(value: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(value.trim());
  } catch {
    sourceError('EDGE_CONTROL_CONFIGURATION_INVALID', 'Control base URL is invalid');
  }
  if (parsed.protocol !== 'https:' || !parsed.hostname || parsed.username || parsed.password
    || parsed.search || parsed.hash) {
    sourceError(
      'EDGE_CONTROL_CONFIGURATION_INVALID',
      'Control base URL must be HTTPS without credentials, query, or fragment',
    );
  }
  return parsed;
}

function controlEndpoint(value: string): string {
  return new URL(
    '/v1/edge-gateway/policy/resolve', normalizeEdgeControlBaseUrl(value),
  ).toString();
}

export function normalizeEdgeControlBinding(
  value: EdgeControlPolicyBinding,
): EdgeControlPolicyBinding {
  const normalized = {
    licenseId: value.licenseId?.trim(),
    deploymentId: value.deploymentId?.trim(),
    organizationId: value.organizationId?.trim(),
    machineFingerprint: value.machineFingerprint?.trim().toLowerCase(),
  };
  if (!IDENTIFIER_PATTERN.test(normalized.licenseId)
    || !IDENTIFIER_PATTERN.test(normalized.deploymentId)
    || !IDENTIFIER_PATTERN.test(normalized.organizationId)
    || !MACHINE_FINGERPRINT_PATTERN.test(normalized.machineFingerprint)) {
    sourceError('EDGE_CONTROL_CONFIGURATION_INVALID', 'Control policy binding is invalid');
  }
  return normalized;
}

function boundedInteger(
  value: number | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
  name: string,
): number {
  const normalized = value ?? fallback;
  if (!Number.isSafeInteger(normalized) || normalized < minimum || normalized > maximum) {
    sourceError('EDGE_CONTROL_CONFIGURATION_INVALID', `${name} is invalid`);
  }
  return normalized;
}

function responseObject(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    sourceError('EDGE_CONTROL_RESPONSE_INVALID', 'Control response must be an object');
  }
  const result = value as Record<string, unknown>;
  if (Object.keys(result).some((field) => !RESPONSE_FIELDS.has(field))
    || !Object.hasOwn(result, 'policy')) {
    sourceError('EDGE_CONTROL_RESPONSE_INVALID', 'Control response fields are invalid');
  }
  return result;
}

export async function readEdgeControlResponseJson(response: Response): Promise<unknown> {
  const declaredLength = response.headers.get('content-length');
  if (declaredLength !== null) {
    const parsed = Number(declaredLength);
    if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > MAX_RESPONSE_BYTES) {
      sourceError('EDGE_CONTROL_RESPONSE_INVALID', 'Control response size is invalid');
    }
  }
  if (!response.body) {
    sourceError('EDGE_CONTROL_RESPONSE_INVALID', 'Control response body is missing');
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) break;
      length += result.value.byteLength;
      if (length > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        sourceError('EDGE_CONTROL_RESPONSE_INVALID', 'Control response is too large');
      }
      chunks.push(result.value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown;
  } catch {
    sourceError('EDGE_CONTROL_RESPONSE_INVALID', 'Control response must be valid JSON');
  }
}

function samePolicyIdentity(
  left: SignedEdgeGatewayPolicyV1,
  right: SignedEdgeGatewayPolicyV1,
): boolean {
  return edgeCanonicalJson(left) === edgeCanonicalJson(right);
}

/**
 * Pulls short-lived policy envelopes from Control. Only a policy that passes
 * local Ed25519 verification and binding checks can enter the in-memory cache.
 */
export class ControlEdgeGatewayPolicySource implements EdgeGatewayPolicySource {
  readonly #endpoint: string;
  readonly #binding: EdgeControlPolicyBinding;
  readonly #leaseToken: string;
  readonly #verifier: EdgeSignatureVerifier;
  readonly #fetch: typeof fetch;
  readonly #now: () => number;
  readonly #nonce: () => string;
  readonly #refreshBeforeExpiryMs: number;
  readonly #requestTimeoutMs: number;
  #cached?: SignedEdgeGatewayPolicyV1;
  #refreshing?: Promise<SignedEdgeGatewayPolicyV1>;

  constructor(options: ControlEdgeGatewayPolicySourceOptions) {
    this.#endpoint = controlEndpoint(options.controlBaseUrl);
    this.#binding = normalizeEdgeControlBinding(options.binding);
    this.#leaseToken = options.leaseToken.trim();
    if (this.#leaseToken.length < 32 || this.#leaseToken.length > 8_192
      || /\s/u.test(this.#leaseToken)) {
      sourceError('EDGE_CONTROL_CONFIGURATION_INVALID', 'Control lease token is invalid');
    }
    this.#verifier = options.verifier;
    this.#fetch = options.fetch ?? fetch;
    this.#now = options.now ?? Date.now;
    this.#nonce = options.nonce ?? (() => randomBytes(24).toString('base64url'));
    this.#refreshBeforeExpiryMs = boundedInteger(
      options.refreshBeforeExpiryMs,
      DEFAULT_REFRESH_BEFORE_EXPIRY_MS,
      5_000,
      60 * 60 * 1000,
      'Control policy refresh window',
    );
    this.#requestTimeoutMs = boundedInteger(
      options.requestTimeoutMs,
      DEFAULT_REQUEST_TIMEOUT_MS,
      500,
      60_000,
      'Control policy request timeout',
    );
  }

  async load(): Promise<SignedEdgeGatewayPolicyV1> {
    const now = this.#now();
    if (this.#cached && now < this.#cached.policy.expiresAtMs - this.#refreshBeforeExpiryMs) {
      return this.#cached;
    }
    try {
      return await this.#refresh();
    } catch (error) {
      if (this.#cached && this.#now() < this.#cached.policy.expiresAtMs) return this.#cached;
      throw error;
    }
  }

  async #refresh(): Promise<SignedEdgeGatewayPolicyV1> {
    if (this.#refreshing) return this.#refreshing;
    const task = this.#fetchAndVerify();
    this.#refreshing = task;
    try {
      return await task;
    } finally {
      this.#refreshing = undefined;
    }
  }

  async #fetchAndVerify(): Promise<SignedEdgeGatewayPolicyV1> {
    const timestamp = this.#now();
    const nonce = this.#nonce();
    if (!/^[a-zA-Z0-9_-]{16,128}$/u.test(nonce)) {
      sourceError('EDGE_CONTROL_CONFIGURATION_INVALID', 'Control nonce generator returned invalid data');
    }
    const requestBody = this.#binding;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.#requestTimeoutMs);
    let response: Response;
    try {
      response = await this.#fetch(this.#endpoint, {
        method: 'POST',
        headers: {
          accept: 'application/json',
          authorization: `Bearer ${this.#leaseToken}`,
          'content-type': 'application/json',
          'x-otto-nonce': nonce,
          'x-otto-signature': signTelemetryRequest({
            token: this.#leaseToken,
            timestamp,
            nonce,
            body: requestBody,
          }),
          'x-otto-timestamp': String(timestamp),
        },
        body: JSON.stringify(requestBody),
        redirect: 'error',
        signal: controller.signal,
      });
    } catch (error) {
      if (controller.signal.aborted) {
        sourceError('EDGE_CONTROL_TIMEOUT', 'Control policy request timed out');
      }
      throw error;
    } finally {
      clearTimeout(timeout);
    }
    if (!response.ok) {
      try {
        await response.body?.cancel();
      } catch {
        // Best-effort cancellation; response details are deliberately not exposed.
      }
      sourceError('EDGE_CONTROL_UNAVAILABLE', 'Control rejected the policy request');
    }
    const responseBody = responseObject(await readEdgeControlResponseJson(response));
    const envelope = normalizeSignedEdgeGatewayPolicy(responseBody.policy, this.#now());
    await verifyGatewayPolicy(envelope, this.#verifier);
    if (envelope.policy.deploymentId !== this.#binding.deploymentId
      || envelope.policy.organizationId !== this.#binding.organizationId) {
      sourceError('EDGE_CONTROL_BINDING_MISMATCH', 'Control policy binding does not match gateway');
    }
    const cached = this.#cached;
    if (cached && envelope.policy.issuedAtMs < cached.policy.issuedAtMs) {
      sourceError('EDGE_CONTROL_POLICY_ROLLBACK', 'Control policy is older than cached policy');
    }
    if (cached && envelope.policy.issuedAtMs === cached.policy.issuedAtMs
      && !samePolicyIdentity(cached, envelope)) {
      sourceError('EDGE_CONTROL_POLICY_EQUIVOCATION', 'Control returned conflicting policy state');
    }
    this.#cached = envelope;
    return envelope;
  }
}

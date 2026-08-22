import { createHash, createPublicKey, type KeyObject } from 'node:crypto';

import type {
  SignedKeyringEnvelope,
  SignedKeyringPayload,
} from '../crypto/signing-keyring.js';
import {
  createEdgeSignatureVerifier,
  edgeCanonicalJson,
  type EdgeSignatureVerifier,
} from './protocol.js';

const ENVELOPE_FIELDS = new Set(['keyring', 'signingKeyId', 'signature']);
const KEYRING_FIELDS = new Set([
  'version', 'activeKeyId', 'revisionMs', 'generatedAtMs', 'expiresAtMs', 'keys',
]);
const KEY_FIELDS = new Set([
  'keyId', 'algorithm', 'publicKeyPem', 'provider', 'state',
  'activatedAt', 'retiredAt', 'revokedAt',
]);
const KEY_ID_PATTERN = /^[a-f0-9]{16}$/u;
const SIGNATURE_PATTERN = /^ed25519:[a-zA-Z0-9_-]{86}$/u;
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
const MAX_KEYRING_DURATION_MS = 15 * 60 * 1000;
const MAX_RESPONSE_BYTES = 256 * 1024;
const DEFAULT_REFRESH_INTERVAL_MS = 60_000;
const DEFAULT_REFRESH_BEFORE_EXPIRY_MS = 60_000;
const DEFAULT_UNKNOWN_KEY_RETRY_MS = 10_000;
const DEFAULT_FAILURE_RETRY_MS = 5_000;
const DEFAULT_REQUEST_TIMEOUT_MS = 10_000;

type KeyringKey = SignedKeyringPayload['keys'][number];

const KEY_STATE_TRANSITIONS: Readonly<Record<KeyringKey['state'], ReadonlySet<KeyringKey['state']>>> = {
  standby: new Set(['standby', 'active', 'revoked']),
  active: new Set(['active', 'retired', 'revoked']),
  retired: new Set(['retired', 'revoked']),
  revoked: new Set(['revoked']),
};

export interface ControlEdgeKeyringVerifierOptions {
  controlBaseUrl: string;
  bootstrapPublicKeys: Readonly<Record<string, string>>;
  fetch?: typeof fetch;
  now?: () => number;
  refreshIntervalMs?: number;
  refreshBeforeExpiryMs?: number;
  unknownKeyRetryMs?: number;
  failureRetryMs?: number;
  requestTimeoutMs?: number;
}

export class EdgeControlKeyringError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'EdgeControlKeyringError';
    this.code = code;
  }
}

function keyringError(code: string, message: string): never {
  throw new EdgeControlKeyringError(code, message);
}

function exactObject(
  value: unknown,
  fields: ReadonlySet<string>,
  name: string,
): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    keyringError('EDGE_KEYRING_INVALID', `${name} must be an object`);
  }
  const body = value as Record<string, unknown>;
  if (Object.keys(body).length !== fields.size
    || Object.keys(body).some((field) => !fields.has(field))) {
    keyringError('EDGE_KEYRING_INVALID', `${name} fields are invalid`);
  }
  return body;
}

function integer(
  body: Record<string, unknown>,
  field: string,
  minimum = 1,
): number {
  const value = body[field];
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum) {
    keyringError('EDGE_KEYRING_INVALID', `${field} is invalid`);
  }
  return value;
}

function boundedOption(
  value: number | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
  name: string,
): number {
  const normalized = value ?? fallback;
  if (!Number.isSafeInteger(normalized) || normalized < minimum || normalized > maximum) {
    keyringError('EDGE_KEYRING_CONFIGURATION_INVALID', `${name} is invalid`);
  }
  return normalized;
}

function endpoint(value: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value.trim());
  } catch {
    keyringError('EDGE_KEYRING_CONFIGURATION_INVALID', 'Control base URL is invalid');
  }
  if (parsed.protocol !== 'https:' || !parsed.hostname || parsed.username || parsed.password
    || parsed.search || parsed.hash) {
    keyringError(
      'EDGE_KEYRING_CONFIGURATION_INVALID',
      'Control base URL must be HTTPS without credentials, query, or fragment',
    );
  }
  return new URL('/v1/signing-keyring', parsed).toString();
}

function publicKey(value: unknown, expectedKeyId: string): string {
  if (typeof value !== 'string' || value.length > 8_192) {
    keyringError('EDGE_KEYRING_INVALID', 'keyring public key is invalid');
  }
  let parsed: KeyObject;
  try {
    parsed = createPublicKey(value);
  } catch {
    keyringError('EDGE_KEYRING_INVALID', 'keyring public key is invalid');
  }
  if (parsed.asymmetricKeyType !== 'ed25519') {
    keyringError('EDGE_KEYRING_INVALID', 'keyring public key must be Ed25519');
  }
  const keyId = createHash('sha256')
    .update(parsed.export({ format: 'der', type: 'spki' }))
    .digest('hex')
    .slice(0, 16);
  if (keyId !== expectedKeyId) {
    keyringError('EDGE_KEYRING_INVALID', 'keyring key id does not match public key');
  }
  return value;
}

function timestamp(value: unknown, field: string): string | null {
  if (value === null) return null;
  if (typeof value !== 'string') {
    keyringError('EDGE_KEYRING_INVALID', `${field} is invalid`);
  }
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value) {
    keyringError('EDGE_KEYRING_INVALID', `${field} is invalid`);
  }
  return value;
}

function normalizeKey(value: unknown): KeyringKey {
  const body = exactObject(value, KEY_FIELDS, 'keyring key');
  const keyId = typeof body.keyId === 'string' ? body.keyId : '';
  if (!KEY_ID_PATTERN.test(keyId) || body.algorithm !== 'ed25519') {
    keyringError('EDGE_KEYRING_INVALID', 'keyring key identity is invalid');
  }
  if (body.provider !== 'local' && body.provider !== 'kms' && body.provider !== 'hsm') {
    keyringError('EDGE_KEYRING_INVALID', 'keyring key provider is invalid');
  }
  if (body.state !== 'standby' && body.state !== 'active'
    && body.state !== 'retired' && body.state !== 'revoked') {
    keyringError('EDGE_KEYRING_INVALID', 'keyring key state is invalid');
  }
  const activatedAt = timestamp(body.activatedAt, 'activatedAt');
  const retiredAt = timestamp(body.retiredAt, 'retiredAt');
  const revokedAt = timestamp(body.revokedAt, 'revokedAt');
  const lifecycleValid = body.state === 'revoked'
    ? revokedAt !== null && retiredAt !== null
    : body.state === 'retired'
      ? revokedAt === null && retiredAt !== null
      : revokedAt === null && retiredAt === null;
  if (!lifecycleValid) {
    keyringError('EDGE_KEYRING_INVALID', 'keyring key lifecycle is invalid');
  }
  return {
    keyId,
    algorithm: 'ed25519',
    publicKeyPem: publicKey(body.publicKeyPem, keyId),
    provider: body.provider,
    state: body.state,
    activatedAt,
    retiredAt,
    revokedAt,
  };
}

function normalizeEnvelope(value: unknown, now: number): SignedKeyringEnvelope {
  const envelope = exactObject(value, ENVELOPE_FIELDS, 'keyring envelope');
  const body = exactObject(envelope.keyring, KEYRING_FIELDS, 'keyring');
  if (body.version !== 1 || !Array.isArray(body.keys)
    || body.keys.length < 1 || body.keys.length > 64) {
    keyringError('EDGE_KEYRING_INVALID', 'keyring version or keys are invalid');
  }
  const activeKeyId = typeof body.activeKeyId === 'string' ? body.activeKeyId : '';
  const signingKeyId = typeof envelope.signingKeyId === 'string' ? envelope.signingKeyId : '';
  const signature = typeof envelope.signature === 'string' ? envelope.signature : '';
  if (!KEY_ID_PATTERN.test(activeKeyId) || signingKeyId !== activeKeyId
    || !SIGNATURE_PATTERN.test(signature)) {
    keyringError('EDGE_KEYRING_INVALID', 'keyring signature identity is invalid');
  }
  const revisionMs = integer(body, 'revisionMs');
  const generatedAtMs = integer(body, 'generatedAtMs');
  const expiresAtMs = integer(body, 'expiresAtMs');
  if (generatedAtMs > now + MAX_CLOCK_SKEW_MS || expiresAtMs <= generatedAtMs
    || expiresAtMs - generatedAtMs > MAX_KEYRING_DURATION_MS || now >= expiresAtMs
    || revisionMs > generatedAtMs + MAX_CLOCK_SKEW_MS) {
    keyringError('EDGE_KEYRING_INVALID', 'keyring validity window is invalid');
  }
  const keys = body.keys.map(normalizeKey);
  if (new Set(keys.map((key) => key.keyId)).size !== keys.length
    || keys.filter((key) => key.state === 'active').length !== 1
    || keys.find((key) => key.state === 'active')?.keyId !== activeKeyId) {
    keyringError('EDGE_KEYRING_INVALID', 'keyring active key set is invalid');
  }
  for (const key of keys) {
    const activatedAtMs = key.activatedAt === null ? null : Date.parse(key.activatedAt);
    const retiredAtMs = key.retiredAt === null ? null : Date.parse(key.retiredAt);
    const revokedAtMs = key.revokedAt === null ? null : Date.parse(key.revokedAt);
    if ((activatedAtMs !== null && activatedAtMs > generatedAtMs)
      || (retiredAtMs !== null && (retiredAtMs > generatedAtMs
        || (activatedAtMs !== null && retiredAtMs < activatedAtMs)))
      || (revokedAtMs !== null && (revokedAtMs > generatedAtMs
        || (retiredAtMs !== null && revokedAtMs < retiredAtMs)))) {
      keyringError('EDGE_KEYRING_INVALID', 'keyring key lifecycle chronology is invalid');
    }
  }
  return {
    keyring: {
      version: 1,
      activeKeyId,
      revisionMs,
      generatedAtMs,
      expiresAtMs,
      keys,
    },
    signingKeyId,
    signature,
  };
}

function stableState(value: SignedKeyringPayload): string {
  return edgeCanonicalJson({
    version: value.version,
    activeKeyId: value.activeKeyId,
    revisionMs: value.revisionMs,
    keys: [...value.keys].sort((left, right) => left.keyId.localeCompare(right.keyId)),
  });
}

async function responseJson(response: Response): Promise<unknown> {
  const lengthHeader = response.headers.get('content-length');
  if (lengthHeader !== null) {
    const length = Number(lengthHeader);
    if (!Number.isSafeInteger(length) || length < 0 || length > MAX_RESPONSE_BYTES) {
      keyringError('EDGE_KEYRING_INVALID', 'keyring response size is invalid');
    }
  }
  if (!response.body) keyringError('EDGE_KEYRING_INVALID', 'keyring response body is missing');
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
        keyringError('EDGE_KEYRING_INVALID', 'keyring response is too large');
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
    keyringError('EDGE_KEYRING_INVALID', 'keyring response must be valid JSON');
  }
}

/** Maintains an in-memory, signed, revocation-aware Control trust set. */
export class ControlEdgeKeyringVerifier implements EdgeSignatureVerifier {
  readonly #endpoint: string;
  readonly #fetch: typeof fetch;
  readonly #now: () => number;
  readonly #refreshIntervalMs: number;
  readonly #refreshBeforeExpiryMs: number;
  readonly #unknownKeyRetryMs: number;
  readonly #failureRetryMs: number;
  readonly #requestTimeoutMs: number;
  readonly #keys = new Map<string, string>();
  readonly #states = new Map<string, KeyringKey['state']>();
  #verifier: EdgeSignatureVerifier;
  #envelope?: SignedKeyringEnvelope;
  #lastRefreshAttemptAtMs?: number;
  #lastRefreshAttemptFailed = false;
  #refreshing?: Promise<void>;

  constructor(options: ControlEdgeKeyringVerifierOptions) {
    this.#endpoint = endpoint(options.controlBaseUrl);
    const entries = Object.entries(options.bootstrapPublicKeys);
    if (entries.length < 1 || entries.length > 64) {
      keyringError('EDGE_KEYRING_CONFIGURATION_INVALID', 'bootstrap public keys are invalid');
    }
    for (const [keyId, pem] of entries) {
      if (!KEY_ID_PATTERN.test(keyId)) {
        keyringError('EDGE_KEYRING_CONFIGURATION_INVALID', 'bootstrap key id is invalid');
      }
      this.#keys.set(keyId, publicKey(pem, keyId));
    }
    this.#verifier = createEdgeSignatureVerifier(Object.fromEntries(this.#keys));
    this.#fetch = options.fetch ?? fetch;
    this.#now = options.now ?? Date.now;
    this.#refreshIntervalMs = boundedOption(
      options.refreshIntervalMs,
      DEFAULT_REFRESH_INTERVAL_MS,
      5_000,
      10 * 60 * 1000,
      'keyring refresh interval',
    );
    this.#refreshBeforeExpiryMs = boundedOption(
      options.refreshBeforeExpiryMs,
      DEFAULT_REFRESH_BEFORE_EXPIRY_MS,
      5_000,
      10 * 60 * 1000,
      'keyring refresh window',
    );
    this.#unknownKeyRetryMs = boundedOption(
      options.unknownKeyRetryMs,
      DEFAULT_UNKNOWN_KEY_RETRY_MS,
      1_000,
      60_000,
      'unknown key retry interval',
    );
    this.#failureRetryMs = boundedOption(
      options.failureRetryMs,
      DEFAULT_FAILURE_RETRY_MS,
      1_000,
      60_000,
      'failed refresh retry interval',
    );
    this.#requestTimeoutMs = boundedOption(
      options.requestTimeoutMs,
      DEFAULT_REQUEST_TIMEOUT_MS,
      500,
      60_000,
      'keyring request timeout',
    );
  }

  async verify(payload: unknown, signingKeyId: string, signature: string): Promise<boolean> {
    await this.#ensureFresh(false);
    const now = this.#now();
    if (!this.#keys.has(signingKeyId)
      && (this.#lastRefreshAttemptAtMs === undefined
        || now - this.#lastRefreshAttemptAtMs >= this.#unknownKeyRetryMs)) {
      await this.#ensureFresh(true);
    }
    const state = this.#states.get(signingKeyId);
    if (!this.#keys.has(signingKeyId) || state === undefined
      || state === 'standby' || state === 'retired' || state === 'revoked') {
      return false;
    }
    return this.#verifier.verify(payload, signingKeyId, signature);
  }

  async refresh(): Promise<void> {
    await this.#ensureFresh(true);
  }

  async #ensureFresh(force: boolean): Promise<void> {
    const now = this.#now();
    const envelope = this.#envelope;
    const refreshAt = envelope
      ? Math.min(
          envelope.keyring.generatedAtMs + this.#refreshIntervalMs,
          envelope.keyring.expiresAtMs - this.#refreshBeforeExpiryMs,
        )
      : 0;
    if (!force && envelope && now < refreshAt) return;
    if (!force && envelope && this.#lastRefreshAttemptFailed
      && this.#lastRefreshAttemptAtMs !== undefined
      && now - this.#lastRefreshAttemptAtMs < this.#failureRetryMs) return;
    try {
      await this.#refresh();
    } catch (error) {
      if (this.#envelope && this.#now() < this.#envelope.keyring.expiresAtMs) return;
      throw error;
    }
  }

  async #refresh(): Promise<void> {
    if (this.#refreshing) return this.#refreshing;
    const task = this.#fetchAndApply();
    this.#refreshing = task;
    try {
      await task;
    } finally {
      this.#refreshing = undefined;
    }
  }

  async #fetchAndApply(): Promise<void> {
    this.#lastRefreshAttemptAtMs = this.#now();
    this.#lastRefreshAttemptFailed = true;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.#requestTimeoutMs);
    let response: Response;
    try {
      response = await this.#fetch(this.#endpoint, {
        method: 'GET',
        headers: { accept: 'application/json', 'cache-control': 'no-cache' },
        redirect: 'error',
        signal: controller.signal,
      });
    } catch (error) {
      if (controller.signal.aborted) {
        keyringError('EDGE_KEYRING_TIMEOUT', 'Control keyring request timed out');
      }
      throw error;
    } finally {
      clearTimeout(timeout);
    }
    if (!response.ok) {
      try {
        await response.body?.cancel();
      } catch {
        // Response cancellation is best-effort.
      }
      keyringError('EDGE_KEYRING_UNAVAILABLE', 'Control rejected the keyring request');
    }
    const envelope = normalizeEnvelope(await responseJson(response), this.#now());
    const signingState = this.#states.get(envelope.signingKeyId);
    if ((this.#envelope !== undefined && signingState !== 'active' && signingState !== 'standby')
      || !this.#keys.has(envelope.signingKeyId)
      || !await this.#verifier.verify(
        envelope.keyring,
        envelope.signingKeyId,
        envelope.signature,
      )) {
      keyringError('EDGE_KEYRING_SIGNATURE_INVALID', 'Control keyring signature is invalid');
    }
    const current = this.#envelope;
    if (current && envelope.keyring.revisionMs < current.keyring.revisionMs) {
      keyringError('EDGE_KEYRING_ROLLBACK', 'Control keyring revision moved backwards');
    }
    if (current && envelope.keyring.revisionMs === current.keyring.revisionMs
      && stableState(envelope.keyring) !== stableState(current.keyring)) {
      keyringError('EDGE_KEYRING_EQUIVOCATION', 'Control keyring revision is conflicting');
    }
    const nextKeys = new Map(envelope.keyring.keys.map((key) => [key.keyId, key]));
    const currentKeys = new Map(current?.keyring.keys.map((key) => [key.keyId, key]) ?? []);
    for (const [keyId, pem] of this.#keys) {
      const next = nextKeys.get(keyId);
      if (!next || next.publicKeyPem !== pem) {
        keyringError('EDGE_KEYRING_CONTINUITY_BROKEN', 'Control keyring removed or changed a trusted key');
      }
      const previous = currentKeys.get(keyId);
      if (previous && !KEY_STATE_TRANSITIONS[previous.state].has(next.state)) {
        keyringError('EDGE_KEYRING_CONTINUITY_BROKEN', 'Control keyring moved a key lifecycle backwards');
      }
      if (previous?.state === 'standby' && next.state === 'active'
        && next.activatedAt === null) {
        keyringError('EDGE_KEYRING_CONTINUITY_BROKEN', 'Control keyring activated a key without an activation time');
      }
      if (previous?.activatedAt !== null && previous?.activatedAt !== undefined
        && next.activatedAt !== previous.activatedAt) {
        keyringError('EDGE_KEYRING_CONTINUITY_BROKEN', 'Control keyring changed a key activation time');
      }
      if (previous?.retiredAt !== null && previous?.retiredAt !== undefined
        && next.retiredAt !== previous.retiredAt) {
        keyringError('EDGE_KEYRING_CONTINUITY_BROKEN', 'Control keyring changed a key retirement time');
      }
      if (previous?.revokedAt !== null && previous?.revokedAt !== undefined
        && next.revokedAt !== previous.revokedAt) {
        keyringError('EDGE_KEYRING_CONTINUITY_BROKEN', 'Control keyring changed a key revocation time');
      }
    }
    this.#keys.clear();
    this.#states.clear();
    for (const key of envelope.keyring.keys) {
      this.#keys.set(key.keyId, key.publicKeyPem);
      this.#states.set(key.keyId, key.state);
    }
    const usable = Object.fromEntries(
      [...this.#keys].filter(([keyId]) => {
        const state = this.#states.get(keyId);
        return state === 'active' || state === 'standby';
      }),
    );
    this.#verifier = createEdgeSignatureVerifier(usable);
    this.#envelope = envelope;
    this.#lastRefreshAttemptFailed = false;
  }
}

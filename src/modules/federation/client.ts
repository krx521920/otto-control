import { randomBytes, randomUUID } from 'node:crypto';

import type {
  FederationEnvelope,
  FederationMessageType,
  FederationRoutingMetadata,
  FederationSignedRequest,
  SignedFederationEnvelope,
} from '../../contracts/federation.js';
import { signPayload, type PayloadSigner } from '../../crypto/signed-envelope.js';
import { verifyFederationSignature } from './crypto.js';

export const OTTO_FEDERATION_CAPABILITIES = [
  'federation.v1',
  'chat.e2ee',
  'a2a.e2ee',
] as const;

export interface FederationClientOptions {
  baseUrl: string;
  deploymentId: string;
  signer: PayloadSigner;
  fetch?: typeof fetch;
  timeoutMs?: number;
  maximumResponseBytes?: number;
  now?: () => number;
  allowInsecureLoopback?: boolean;
}

export interface ClaimedFederationEnvelope {
  signed: SignedFederationEnvelope;
  claimToken: string;
}

function federationBaseUrl(value: string, allowInsecureLoopback: boolean): string {
  const url = new URL(value);
  const loopback = url.hostname === '127.0.0.1' || url.hostname === 'localhost' || url.hostname === '::1';
  if (url.protocol !== 'https:' && !(allowInsecureLoopback && loopback && url.protocol === 'http:')) {
    throw new Error('federation base URL must use HTTPS');
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error('federation base URL cannot contain credentials, query, or fragment');
  }
  if (url.pathname !== '/') throw new Error('federation base URL must be an origin without a path');
  return url.toString().replace(/\/$/u, '');
}

function identifier(value: string, name: string): string {
  const normalized = value.trim();
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{2,127}$/u.test(normalized)) {
    throw new Error(`${name} is invalid`);
  }
  return normalized;
}

function nonce(): string {
  return `nonce_${randomBytes(24).toString('base64url')}`;
}

export class FederationClient {
  readonly #baseUrl: string;
  readonly #deploymentId: string;
  readonly #signer: PayloadSigner;
  readonly #fetch: typeof fetch;
  readonly #timeoutMs: number;
  readonly #maximumResponseBytes: number;
  readonly #now: () => number;

  constructor(options: FederationClientOptions) {
    this.#baseUrl = federationBaseUrl(options.baseUrl, options.allowInsecureLoopback ?? false);
    this.#deploymentId = identifier(options.deploymentId, 'deploymentId');
    this.#signer = options.signer;
    this.#fetch = options.fetch ?? fetch;
    this.#timeoutMs = options.timeoutMs ?? 10_000;
    if (this.#timeoutMs < 500 || this.#timeoutMs > 30_000) {
      throw new Error('federation timeout must be between 500 and 30000 milliseconds');
    }
    this.#maximumResponseBytes = options.maximumResponseBytes ?? 16 * 1024 * 1024;
    if (this.#maximumResponseBytes < 64 * 1024 || this.#maximumResponseBytes > 128 * 1024 * 1024) {
      throw new Error('federation response limit must be between 64 KiB and 128 MiB');
    }
    this.#now = options.now ?? Date.now;
  }

  get capabilities(): readonly string[] {
    return OTTO_FEDERATION_CAPABILITIES;
  }

  async sendCiphertext(input: {
    recipientDeploymentId: string;
    type: FederationMessageType;
    ciphertext: string;
    routing: FederationRoutingMetadata;
    messageId?: string;
    expiresInMs?: number;
  }): Promise<{ accepted: boolean; duplicate: boolean; messageId: string; status: string }> {
    return this.sendSignedEnvelope(await this.createSignedEnvelope(input));
  }

  async createSignedEnvelope(input: {
    recipientDeploymentId: string;
    type: FederationMessageType;
    ciphertext: string;
    routing: FederationRoutingMetadata;
    messageId?: string;
    expiresInMs?: number;
  }): Promise<SignedFederationEnvelope> {
    const now = this.#now();
    const expiresInMs = input.expiresInMs ?? 24 * 60 * 60_000;
    if (expiresInMs < 60_000 || expiresInMs > 7 * 24 * 60 * 60_000) {
      throw new Error('federation message lifetime must be between 1 minute and 7 days');
    }
    const envelope: FederationEnvelope = {
      version: 1,
      messageId: input.messageId ?? `fmsg_${randomUUID().replaceAll('-', '')}`,
      type: input.type,
      senderDeploymentId: this.#deploymentId,
      recipientDeploymentId: identifier(input.recipientDeploymentId, 'recipientDeploymentId'),
      issuedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + expiresInMs).toISOString(),
      nonce: nonce(),
      contentType: 'application/otto-e2ee+json',
      ciphertext: input.ciphertext,
      routing: input.routing,
    };
    return { envelope, ...await signPayload(this.#signer, envelope) };
  }

  async sendSignedEnvelope(
    signed: SignedFederationEnvelope,
  ): Promise<{ accepted: boolean; duplicate: boolean; messageId: string; status: string }> {
    if (signed.envelope.senderDeploymentId !== this.#deploymentId) {
      throw new Error('cannot send an envelope signed for another deployment');
    }
    return this.#request('/v1/federation/envelopes', signed);
  }

  async claim(limit = 20): Promise<ClaimedFederationEnvelope[]> {
    const response = await this.#request<{ messages: Array<{
      envelope: FederationEnvelope;
      signingKeyId: string;
      signature: string;
      claimToken: string;
    }> }>('/v1/federation/inbox/claim', await this.#signedRequest({ limit }));
    const output: ClaimedFederationEnvelope[] = [];
    for (const item of response.messages) {
      if (item.envelope.recipientDeploymentId !== this.#deploymentId) {
        throw new Error('federation inbox returned an envelope for a different deployment');
      }
      const key = await this.#request<{
        deploymentId: string;
        keyId: string;
        publicKeyPem: string;
        notBefore: string;
        expiresAt: string | null;
      }>(
        `/v1/federation/directory/${encodeURIComponent(item.envelope.senderDeploymentId)}`
          + `/keys/${encodeURIComponent(item.signingKeyId)}`,
        undefined,
        'GET',
      );
      if (key.deploymentId !== item.envelope.senderDeploymentId || key.keyId !== item.signingKeyId) {
        throw new Error('federation directory returned a mismatched signing key');
      }
      const issuedAt = Date.parse(item.envelope.issuedAt);
      const notBefore = Date.parse(key.notBefore);
      const expiresAt = key.expiresAt === null ? null : Date.parse(key.expiresAt);
      if (
        !Number.isFinite(issuedAt) || !Number.isFinite(notBefore)
        || (expiresAt !== null && !Number.isFinite(expiresAt))
        || issuedAt < notBefore || (expiresAt !== null && issuedAt >= expiresAt)
      ) {
        throw new Error('federation envelope was signed outside the key validity window');
      }
      verifyFederationSignature({
        payload: item.envelope,
        signature: item.signature,
        publicKeyPem: key.publicKeyPem,
      });
      output.push({
        signed: {
          envelope: item.envelope,
          signingKeyId: item.signingKeyId,
          signature: item.signature,
        },
        claimToken: item.claimToken,
      });
    }
    return output;
  }

  async acknowledge(messageId: string, claimToken: string): Promise<void> {
    await this.#request('/v1/federation/inbox/ack', await this.#signedRequest({
      messageId: identifier(messageId, 'messageId'),
      claimToken,
    }));
  }

  async createA2aGrant(input: {
    requesterDeploymentId: string;
    ownerPrincipalId: string;
    requesterPrincipalId: string;
    scopes: string[];
    expiresInMs?: number;
    grantId?: string;
  }): Promise<{ id: string; expiresAt: string; maxUses: number; usedCount: number }> {
    const expiresInMs = input.expiresInMs ?? 10 * 60_000;
    if (expiresInMs < 60_000 || expiresInMs > 24 * 60 * 60_000) {
      throw new Error('A2A grant lifetime must be between 1 minute and 24 hours');
    }
    return this.#request('/v1/federation/a2a/grants', await this.#signedRequest({
      grantId: input.grantId,
      requesterDeploymentId: input.requesterDeploymentId,
      ownerPrincipalId: input.ownerPrincipalId,
      requesterPrincipalId: input.requesterPrincipalId,
      scopes: input.scopes,
      maxUses: 1,
      grantExpiresAt: new Date(this.#now() + expiresInMs).toISOString(),
    }));
  }

  async #signedRequest(body: Record<string, unknown>): Promise<FederationSignedRequest<Record<string, unknown>>> {
    const now = this.#now();
    const request = {
      version: 1 as const,
      deploymentId: this.#deploymentId,
      issuedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 60_000).toISOString(),
      nonce: nonce(),
      ...body,
    };
    return { request, ...await signPayload(this.#signer, request) };
  }

  async #request<T>(
    path: string,
    body?: unknown,
    method = 'POST',
  ): Promise<T> {
    const response = await this.#fetch(`${this.#baseUrl}${path}`, {
      method,
      redirect: 'error',
      headers: body === undefined ? undefined : { 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(this.#timeoutMs),
    });
    const contentType = response.headers.get('content-type') || '';
    if (!contentType.toLowerCase().startsWith('application/json')) {
      throw new Error(`federation gateway returned unexpected content type (${response.status})`);
    }
    const text = await this.#boundedResponseText(response, this.#maximumResponseBytes);
    let payload: unknown;
    try {
      payload = JSON.parse(text);
    } catch {
      throw new Error(`federation gateway returned invalid JSON (${response.status})`);
    }
    if (!response.ok) {
      const message = payload && typeof payload === 'object'
        && 'error' in payload && payload.error && typeof payload.error === 'object'
        && 'message' in payload.error && typeof payload.error.message === 'string'
        ? payload.error.message
        : `federation request failed (${response.status})`;
      throw new Error(message);
    }
    return payload as T;
  }

  async #boundedResponseText(response: Response, maximumBytes: number): Promise<string> {
    const declaredLength = Number(response.headers.get('content-length'));
    if (Number.isFinite(declaredLength) && declaredLength > maximumBytes) {
      await response.body?.cancel();
      throw new Error('federation gateway response is too large');
    }
    if (!response.body) return '';
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maximumBytes) {
        await reader.cancel();
        throw new Error('federation gateway response is too large');
      }
      chunks.push(value);
    }
    return Buffer.concat(chunks).toString('utf8');
  }
}

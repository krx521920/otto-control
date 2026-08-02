import { randomUUID } from 'node:crypto';

import {
  FEDERATION_MESSAGE_TYPES,
  FEDERATION_PROTOCOL_VERSION,
  type FederationA2aGrantRecord,
  type FederationDeploymentRecord,
  type FederationEnvelope,
  type FederationSignedRequest,
  type SignedFederationEnvelope,
} from '../../contracts/federation.js';
import { conflict, forbidden, invalidRequest, notFound, unauthorized } from '../../errors.js';
import { ciphertextSha256, normalizeFederationPublicKey, verifyFederationSignature } from './crypto.js';
import type { FederationStore } from './store.js';

const ID_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._:-]{2,127}$/u;
const NONCE_PATTERN = /^[A-Za-z0-9_-]{16,128}$/u;
const SCOPE_PATTERN = /^[a-z][a-z0-9._:-]{1,63}$/u;
const CAPABILITY_PATTERN = /^[a-z][a-z0-9._:-]{1,63}$/u;
const MAX_ROUTING_VALUE = 256;
const ENVELOPE_KEYS = new Set([
  'version',
  'messageId',
  'type',
  'senderDeploymentId',
  'recipientDeploymentId',
  'issuedAt',
  'expiresAt',
  'nonce',
  'contentType',
  'ciphertext',
  'routing',
]);

function requiredText(value: unknown, name: string, maximum = 256): string {
  if (typeof value !== 'string' || !value.trim() || value.trim().length > maximum) {
    throw invalidRequest(`${name} must be a non-empty string up to ${maximum} characters`);
  }
  return value.trim();
}

function identifier(value: unknown, name: string): string {
  const normalized = requiredText(value, name, 128);
  if (!ID_PATTERN.test(normalized)) throw invalidRequest(`${name} is invalid`);
  return normalized;
}

function stringList(value: unknown, name: string, pattern: RegExp, maximum = 32): string[] {
  if (!Array.isArray(value) || value.length > maximum) {
    throw invalidRequest(`${name} must be an array with at most ${maximum} entries`);
  }
  const normalized = [...new Set(value.map((item) => requiredText(item, name, 64)))];
  if (normalized.some((item) => !pattern.test(item))) throw invalidRequest(`${name} contains an invalid value`);
  return normalized.sort();
}

function timestamp(value: unknown, name: string): Date {
  const parsed = new Date(requiredText(value, name, 64));
  if (!Number.isFinite(parsed.getTime())) throw invalidRequest(`${name} must be an ISO timestamp`);
  return parsed;
}

function signedTimestamp(value: unknown, name: string): Date {
  const text = requiredText(value, name, 64);
  const parsed = new Date(text);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== text) {
    throw invalidRequest(`${name} must use canonical UTC ISO format`);
  }
  return parsed;
}

function httpsOrigin(value: unknown): string {
  let url: URL;
  try {
    url = new URL(requiredText(value, 'origin', 512));
  } catch {
    throw invalidRequest('origin must be an absolute HTTPS URL');
  }
  if (
    url.protocol !== 'https:' || url.username || url.password || url.search || url.hash
    || url.pathname !== '/'
  ) {
    throw invalidRequest('origin must be an HTTPS origin without credentials, path, query, or fragment');
  }
  return url.origin;
}

function boundedInteger(value: unknown, name: string, minimum: number, maximum: number): number {
  if (!Number.isInteger(value) || Number(value) < minimum || Number(value) > maximum) {
    throw invalidRequest(`${name} must be an integer between ${minimum} and ${maximum}`);
  }
  return Number(value);
}

function deploymentView(deployment: FederationDeploymentRecord): Record<string, unknown> {
  return {
    ...deployment,
    createdAt: deployment.createdAt.toISOString(),
    updatedAt: deployment.updatedAt.toISOString(),
  };
}

function grantView(grant: FederationA2aGrantRecord): Record<string, unknown> {
  return {
    ...grant,
    expiresAt: grant.expiresAt.toISOString(),
    revokedAt: grant.revokedAt?.toISOString() ?? null,
    createdAt: grant.createdAt.toISOString(),
  };
}

export interface FederationServiceOptions {
  store: FederationStore;
  maximumClockSkewMs?: number;
  maximumEnvelopeTtlMs?: number;
  maximumRequestTtlMs?: number;
  maximumCiphertextBytes?: number;
  maximumClaimBytes?: number;
  claimTtlMs?: number;
  deliveredRetentionMs?: number;
  now?: () => number;
}

export class FederationService {
  readonly #store: FederationStore;
  readonly #maximumClockSkewMs: number;
  readonly #maximumEnvelopeTtlMs: number;
  readonly #maximumRequestTtlMs: number;
  readonly #maximumCiphertextBytes: number;
  readonly #maximumClaimBytes: number;
  readonly #claimTtlMs: number;
  readonly #deliveredRetentionMs: number;
  readonly #now: () => number;

  constructor(options: FederationServiceOptions) {
    this.#store = options.store;
    this.#maximumClockSkewMs = options.maximumClockSkewMs ?? 5 * 60_000;
    this.#maximumEnvelopeTtlMs = options.maximumEnvelopeTtlMs ?? 7 * 24 * 60 * 60_000;
    this.#maximumRequestTtlMs = options.maximumRequestTtlMs ?? 5 * 60_000;
    this.#maximumCiphertextBytes = options.maximumCiphertextBytes ?? 1024 * 1024;
    this.#maximumClaimBytes = options.maximumClaimBytes
      ?? Math.max(this.#maximumCiphertextBytes, 4 * 1024 * 1024);
    this.#claimTtlMs = options.claimTtlMs ?? 60_000;
    this.#deliveredRetentionMs = options.deliveredRetentionMs ?? 7 * 24 * 60 * 60_000;
    this.#now = options.now ?? Date.now;
  }

  async close(): Promise<void> {
    await this.#store.close();
  }

  async ready(): Promise<boolean> {
    return this.#store.ready();
  }

  async registerDeployment(raw: Record<string, unknown>): Promise<Record<string, unknown>> {
    const now = new Date(this.#now());
    const deployment = await this.#store.registerDeployment({
      id: identifier(raw.id, 'id'),
      displayName: requiredText(raw.displayName, 'displayName', 160),
      origin: httpsOrigin(raw.origin),
      capabilities: stringList(raw.capabilities ?? [], 'capabilities', CAPABILITY_PATTERN),
      maxPendingMessages: raw.maxPendingMessages === undefined
        ? 10_000
        : boundedInteger(raw.maxPendingMessages, 'maxPendingMessages', 100, 1_000_000),
      now,
    });
    await this.#store.appendAuditEvent({
      actorDeploymentId: 'control-admin',
      action: 'federation.deployment.register',
      targetType: 'deployment',
      targetId: deployment.id,
      details: { origin: deployment.origin, capabilities: deployment.capabilities },
      occurredAt: now,
    });
    return deploymentView(deployment);
  }

  async setDeploymentStatus(deploymentId: string, rawStatus: unknown): Promise<Record<string, unknown>> {
    const status = requiredText(rawStatus, 'status', 16);
    if (status !== 'active' && status !== 'blocked' && status !== 'disabled') {
      throw invalidRequest('status must be active, blocked, or disabled');
    }
    const now = new Date(this.#now());
    const deployment = await this.#store.setDeploymentStatus(
      identifier(deploymentId, 'deploymentId'),
      status,
      now,
    );
    if (!deployment) throw notFound('federation deployment not found');
    await this.#store.appendAuditEvent({
      actorDeploymentId: 'control-admin',
      action: 'federation.deployment.status',
      targetType: 'deployment',
      targetId: deployment.id,
      details: { status },
      occurredAt: now,
    });
    return deploymentView(deployment);
  }

  async listDeployments(rawLimit: unknown): Promise<Record<string, unknown>> {
    const limit = rawLimit === undefined ? 100 : boundedInteger(Number(rawLimit), 'limit', 1, 500);
    return { deployments: (await this.#store.listDeployments(limit)).map(deploymentView) };
  }

  async directoryEntry(deploymentId: string): Promise<Record<string, unknown>> {
    const deployment = await this.#store.getDeployment(identifier(deploymentId, 'deploymentId'));
    if (!deployment || deployment.status !== 'active') throw notFound('active federation deployment not found');
    return deploymentView(deployment);
  }

  async directoryKey(deploymentId: string, keyId: string): Promise<Record<string, unknown>> {
    const id = identifier(deploymentId, 'deploymentId');
    await this.#activeDeployment(id);
    const key = await this.#store.getVerificationKey(
      id,
      requiredText(keyId, 'keyId', 64),
    );
    if (!key) throw notFound('federation verification key not found');
    return {
      deploymentId: key.deploymentId,
      keyId: key.keyId,
      publicKeyPem: key.publicKeyPem,
      notBefore: key.notBefore.toISOString(),
      expiresAt: key.expiresAt?.toISOString() ?? null,
    };
  }

  async registerKey(deploymentId: string, raw: Record<string, unknown>): Promise<Record<string, unknown>> {
    const id = identifier(deploymentId, 'deploymentId');
    if (!await this.#store.getDeployment(id)) throw notFound('federation deployment not found');
    const normalized = normalizeFederationPublicKey(raw.publicKeyPem);
    if (raw.keyId !== undefined && requiredText(raw.keyId, 'keyId', 64) !== normalized.keyId) {
      throw invalidRequest('keyId does not match the Ed25519 public key');
    }
    const now = new Date(this.#now());
    const notBefore = raw.notBefore === undefined ? now : timestamp(raw.notBefore, 'notBefore');
    const expiresAt = raw.expiresAt === undefined || raw.expiresAt === null
      ? null
      : timestamp(raw.expiresAt, 'expiresAt');
    if (expiresAt && expiresAt <= notBefore) throw invalidRequest('expiresAt must be after notBefore');
    const key = await this.#store.registerKey({
      deploymentId: id,
      keyId: normalized.keyId,
      publicKeyPem: normalized.publicKeyPem,
      notBefore,
      expiresAt,
      now,
    });
    await this.#store.appendAuditEvent({
      actorDeploymentId: 'control-admin',
      action: 'federation.key.register',
      targetType: 'federation_key',
      targetId: `${id}:${key.keyId}`,
      details: { notBefore: notBefore.toISOString(), expiresAt: expiresAt?.toISOString() ?? null },
      occurredAt: now,
    });
    return {
      ...key,
      publicKeyPem: key.publicKeyPem,
      notBefore: key.notBefore.toISOString(),
      expiresAt: key.expiresAt?.toISOString() ?? null,
      revokedAt: key.revokedAt?.toISOString() ?? null,
      createdAt: key.createdAt.toISOString(),
    };
  }

  async revokeKey(deploymentId: string, keyId: string): Promise<{ revoked: true }> {
    const now = new Date(this.#now());
    const id = identifier(deploymentId, 'deploymentId');
    const normalizedKeyId = requiredText(keyId, 'keyId', 64);
    if (!await this.#store.revokeKey(id, normalizedKeyId, now)) throw notFound('active federation key not found');
    await this.#store.appendAuditEvent({
      actorDeploymentId: 'control-admin',
      action: 'federation.key.revoke',
      targetType: 'federation_key',
      targetId: `${id}:${normalizedKeyId}`,
      details: {},
      occurredAt: now,
    });
    return { revoked: true };
  }

  async setBlock(blockerDeploymentId: string, raw: Record<string, unknown>): Promise<{ blocked: true }> {
    const blocker = identifier(blockerDeploymentId, 'blockerDeploymentId');
    const blocked = identifier(raw.blockedDeploymentId, 'blockedDeploymentId');
    if (blocker === blocked) throw invalidRequest('a deployment cannot block itself');
    if (!await this.#store.getDeployment(blocker) || !await this.#store.getDeployment(blocked)) {
      throw notFound('federation deployment not found');
    }
    const now = new Date(this.#now());
    await this.#store.setBlock({
      blockerDeploymentId: blocker,
      blockedDeploymentId: blocked,
      reason: requiredText(raw.reason, 'reason', 500),
      createdAt: now,
    });
    await this.#store.appendAuditEvent({
      actorDeploymentId: 'control-admin',
      action: 'federation.block.create',
      targetType: 'deployment_pair',
      targetId: `${blocker}:${blocked}`,
      details: {},
      occurredAt: now,
    });
    return { blocked: true };
  }

  async removeBlock(blockerDeploymentId: string, blockedDeploymentId: string): Promise<{ blocked: false }> {
    const blocker = identifier(blockerDeploymentId, 'blockerDeploymentId');
    const blocked = identifier(blockedDeploymentId, 'blockedDeploymentId');
    if (!await this.#store.removeBlock(blocker, blocked)) throw notFound('federation block not found');
    await this.#store.appendAuditEvent({
      actorDeploymentId: 'control-admin',
      action: 'federation.block.remove',
      targetType: 'deployment_pair',
      targetId: `${blocker}:${blocked}`,
      details: {},
      occurredAt: new Date(this.#now()),
    });
    return { blocked: false };
  }

  async createA2aGrant(rawSigned: FederationSignedRequest<Record<string, unknown>>): Promise<Record<string, unknown>> {
    const request = await this.#verifySignedRequest(rawSigned);
    const ownerDeploymentId = request.deploymentId;
    const requesterDeploymentId = identifier(request.requesterDeploymentId, 'requesterDeploymentId');
    if (ownerDeploymentId === requesterDeploymentId) {
      throw invalidRequest('A2A federation grants are only for cross-deployment requests');
    }
    const ownerDeployment = await this.#activeDeployment(ownerDeploymentId);
    const requesterDeployment = await this.#activeDeployment(requesterDeploymentId);
    if (
      !ownerDeployment.capabilities.includes('federation.v1')
      || !ownerDeployment.capabilities.includes('a2a.e2ee')
      || !requesterDeployment.capabilities.includes('federation.v1')
      || !requesterDeployment.capabilities.includes('a2a.e2ee')
    ) {
      throw forbidden('both deployments must advertise federation.v1 and a2a.e2ee');
    }
    if (await this.#store.isBlocked(ownerDeploymentId, requesterDeploymentId)) {
      throw forbidden('federation route is blocked');
    }
    const expiresAt = timestamp(request.grantExpiresAt, 'grantExpiresAt');
    const now = new Date(this.#now());
    if (expiresAt <= now || expiresAt.getTime() - now.getTime() > 24 * 60 * 60_000) {
      throw invalidRequest('A2A grant must expire within the next 24 hours');
    }
    const scopes = stringList(request.scopes, 'scopes', SCOPE_PATTERN, 16);
    if (scopes.length === 0) throw invalidRequest('A2A grant requires at least one scope');
    const grant = await this.#store.createGrant({
      id: request.grantId === undefined
        ? `fgrant_${randomUUID().replaceAll('-', '')}`
        : identifier(request.grantId, 'grantId'),
      ownerDeploymentId,
      requesterDeploymentId,
      ownerPrincipalId: identifier(request.ownerPrincipalId, 'ownerPrincipalId'),
      requesterPrincipalId: identifier(request.requesterPrincipalId, 'requesterPrincipalId'),
      scopes,
      maxUses: request.maxUses === undefined ? 1 : boundedInteger(request.maxUses, 'maxUses', 1, 10),
      expiresAt,
      now,
    });
    await this.#store.appendAuditEvent({
      actorDeploymentId: ownerDeploymentId,
      action: 'federation.a2a_grant.create',
      targetType: 'a2a_grant',
      targetId: grant.id,
      details: {
        requesterDeploymentId,
        scopes: grant.scopes,
        expiresAt: grant.expiresAt.toISOString(),
        maxUses: grant.maxUses,
      },
      occurredAt: now,
    });
    return grantView(grant);
  }

  async revokeA2aGrant(rawSigned: FederationSignedRequest<Record<string, unknown>>): Promise<{ revoked: true }> {
    const request = await this.#verifySignedRequest(rawSigned);
    const grantId = identifier(request.grantId, 'grantId');
    if (!await this.#store.revokeGrant(request.deploymentId, grantId, new Date(this.#now()))) {
      throw notFound('active A2A grant not found');
    }
    return { revoked: true };
  }

  async enqueue(raw: SignedFederationEnvelope): Promise<Record<string, unknown>> {
    const signed = await this.#validateEnvelope(raw);
    const now = new Date(this.#now());
    const result = await this.#store.enqueueMessage({
      signed,
      ciphertextSha256: ciphertextSha256(signed.envelope.ciphertext),
      sizeBytes: Buffer.byteLength(signed.envelope.ciphertext, 'utf8'),
      now,
    });
    if (!result.duplicate) {
      await this.#store.appendAuditEvent({
        actorDeploymentId: signed.envelope.senderDeploymentId,
        action: 'federation.message.enqueue',
        targetType: 'federation_message',
        targetId: signed.envelope.messageId,
        details: {
          recipientDeploymentId: signed.envelope.recipientDeploymentId,
          type: signed.envelope.type,
          sizeBytes: result.message.sizeBytes,
          ciphertextSha256: result.message.ciphertextSha256,
        },
        occurredAt: now,
      });
    }
    return {
      accepted: true,
      duplicate: result.duplicate,
      messageId: result.message.messageId,
      status: result.message.status,
      expiresAt: result.message.expiresAt,
    };
  }

  async claim(rawSigned: FederationSignedRequest<Record<string, unknown>>): Promise<Record<string, unknown>> {
    const request = await this.#verifySignedRequest(rawSigned);
    const limit = request.limit === undefined ? 20 : boundedInteger(request.limit, 'limit', 1, 100);
    const claimed = await this.#store.claimMessages({
      recipientDeploymentId: request.deploymentId,
      limit,
      maximumBytes: this.#maximumClaimBytes,
      claimTtlMs: this.#claimTtlMs,
      now: new Date(this.#now()),
    });
    return {
      messages: claimed.map(({ message, claimToken }) => ({
        envelope: {
          version: message.version,
          messageId: message.messageId,
          type: message.type,
          senderDeploymentId: message.senderDeploymentId,
          recipientDeploymentId: message.recipientDeploymentId,
          issuedAt: message.issuedAt,
          expiresAt: message.expiresAt,
          nonce: message.nonce,
          contentType: message.contentType,
          ciphertext: message.ciphertext,
          routing: message.routing,
        },
        signingKeyId: message.signingKeyId,
        signature: message.signature,
        claimToken,
      })),
    };
  }

  async acknowledge(rawSigned: FederationSignedRequest<Record<string, unknown>>): Promise<{ delivered: true }> {
    const request = await this.#verifySignedRequest(rawSigned);
    const messageId = identifier(request.messageId, 'messageId');
    const claimToken = requiredText(request.claimToken, 'claimToken', 256);
    if (!await this.#store.acknowledgeMessage({
      recipientDeploymentId: request.deploymentId,
      messageId,
      claimToken,
      now: new Date(this.#now()),
    })) {
      throw conflict('message claim is missing, expired, or already acknowledged');
    }
    return { delivered: true };
  }

  async status(includeQueue = false): Promise<Record<string, unknown>> {
    const status: Record<string, unknown> = {
      protocolVersion: FEDERATION_PROTOCOL_VERSION,
      privacy: {
        payloadStorage: 'ciphertext-only',
        gatewayCanDecrypt: false,
        visibleMetadata: ['deployment ids', 'message type', 'timestamps', 'size', 'delivery status'],
      },
    };
    if (includeQueue) status.queue = await this.#store.queueStats();
    return status;
  }

  async expire(): Promise<number> {
    const now = new Date(this.#now());
    const result = await this.#store.expireMessages(
      now,
      new Date(now.getTime() - this.#deliveredRetentionMs),
    );
    return result.expired + result.purged;
  }

  async #verifySignedRequest(
    signed: FederationSignedRequest<Record<string, unknown>>,
  ): Promise<FederationSignedRequest<Record<string, unknown>>['request']> {
    if (!signed || typeof signed !== 'object' || !signed.request || typeof signed.request !== 'object') {
      throw invalidRequest('signed federation request is required');
    }
    const request = signed.request;
    if (request.version !== FEDERATION_PROTOCOL_VERSION) throw invalidRequest('unsupported federation version');
    const deploymentId = identifier(request.deploymentId, 'deploymentId');
    const deployment = await this.#activeDeployment(deploymentId);
    const { expiresAt } = this.#validateTimeWindow(request.issuedAt, request.expiresAt, this.#maximumRequestTtlMs);
    const nonce = requiredText(request.nonce, 'nonce', 128);
    if (!NONCE_PATTERN.test(nonce)) throw invalidRequest('nonce is invalid');
    const key = await this.#store.getActiveKey(
      deployment.id,
      requiredText(signed.signingKeyId, 'signingKeyId', 64),
      new Date(this.#now()),
    );
    if (!key) throw unauthorized('active federation signing key not found');
    verifyFederationSignature({ payload: request, signature: signed.signature, publicKeyPem: key.publicKeyPem });
    if (!await this.#store.consumeNonce(deployment.id, nonce, expiresAt, new Date(this.#now()))) {
      throw conflict('federation request nonce has already been used');
    }
    return request;
  }

  async #validateEnvelope(raw: SignedFederationEnvelope): Promise<SignedFederationEnvelope> {
    if (!raw || typeof raw !== 'object' || !raw.envelope || typeof raw.envelope !== 'object') {
      throw invalidRequest('signed federation envelope is required');
    }
    if (Object.keys(raw.envelope).some((key) => !ENVELOPE_KEYS.has(key))) {
      throw invalidRequest('federation envelope contains unsupported fields');
    }
    const envelope = raw.envelope as FederationEnvelope;
    if (envelope.version !== FEDERATION_PROTOCOL_VERSION) throw invalidRequest('unsupported federation version');
    if (!FEDERATION_MESSAGE_TYPES.includes(envelope.type)) throw invalidRequest('federation message type is invalid');
    envelope.messageId = identifier(envelope.messageId, 'messageId');
    envelope.senderDeploymentId = identifier(envelope.senderDeploymentId, 'senderDeploymentId');
    envelope.recipientDeploymentId = identifier(envelope.recipientDeploymentId, 'recipientDeploymentId');
    if (envelope.senderDeploymentId === envelope.recipientDeploymentId) {
      throw invalidRequest('federation messages must cross deployment boundaries');
    }
    const senderDeployment = await this.#activeDeployment(envelope.senderDeploymentId);
    const recipientDeployment = await this.#activeDeployment(envelope.recipientDeploymentId);
    const capability = envelope.type.startsWith('a2a.') ? 'a2a.e2ee' : 'chat.e2ee';
    if (
      !senderDeployment.capabilities.includes('federation.v1')
      || !recipientDeployment.capabilities.includes('federation.v1')
      || !senderDeployment.capabilities.includes(capability)
      || !recipientDeployment.capabilities.includes(capability)
    ) {
      throw forbidden(`both deployments must advertise federation.v1 and ${capability}`);
    }
    if (await this.#store.isBlocked(envelope.senderDeploymentId, envelope.recipientDeploymentId)) {
      throw forbidden('federation route is blocked');
    }
    this.#validateTimeWindow(
      envelope.issuedAt,
      envelope.expiresAt,
      this.#maximumEnvelopeTtlMs,
      false,
    );
    envelope.nonce = requiredText(envelope.nonce, 'nonce', 128);
    if (!NONCE_PATTERN.test(envelope.nonce)) throw invalidRequest('nonce is invalid');
    if (envelope.contentType !== 'application/otto-e2ee+json') {
      throw invalidRequest('federation payload must use application/otto-e2ee+json');
    }
    envelope.ciphertext = requiredText(envelope.ciphertext, 'ciphertext', this.#maximumCiphertextBytes);
    const sizeBytes = Buffer.byteLength(envelope.ciphertext, 'utf8');
    if (sizeBytes > this.#maximumCiphertextBytes) throw invalidRequest('federation ciphertext is too large');
    if (!/^[A-Za-z0-9_-]+$/u.test(envelope.ciphertext)) {
      throw invalidRequest('federation ciphertext must use unpadded base64url encoding');
    }
    if (!envelope.routing || typeof envelope.routing !== 'object') throw invalidRequest('routing metadata is required');
    envelope.routing = {
      conversationId: identifier(envelope.routing.conversationId, 'conversationId'),
      senderPrincipalId: identifier(envelope.routing.senderPrincipalId, 'senderPrincipalId'),
      recipientPrincipalId: identifier(envelope.routing.recipientPrincipalId, 'recipientPrincipalId'),
      ...(envelope.routing.inReplyTo === undefined ? {} : {
        inReplyTo: identifier(envelope.routing.inReplyTo, 'inReplyTo'),
      }),
      ...(envelope.routing.a2aGrantId === undefined ? {} : {
        a2aGrantId: identifier(envelope.routing.a2aGrantId, 'a2aGrantId'),
      }),
      ...(envelope.routing.a2aScope === undefined ? {} : {
        a2aScope: requiredText(envelope.routing.a2aScope, 'a2aScope', MAX_ROUTING_VALUE),
      }),
    };
    if (envelope.type === 'a2a.request' && (!envelope.routing.a2aGrantId || !envelope.routing.a2aScope)) {
      throw forbidden('A2A request requires a scoped one-time grant');
    }
    if (envelope.type === 'a2a.response' && !envelope.routing.inReplyTo) {
      throw invalidRequest('A2A response must reference its request');
    }
    if (envelope.type === 'chat.receipt' && !envelope.routing.inReplyTo) {
      throw invalidRequest('chat receipt must reference its message');
    }
    const key = await this.#store.getActiveKey(
      envelope.senderDeploymentId,
      requiredText(raw.signingKeyId, 'signingKeyId', 64),
      new Date(this.#now()),
    );
    if (!key) throw unauthorized('active federation signing key not found');
    verifyFederationSignature({ payload: envelope, signature: raw.signature, publicKeyPem: key.publicKeyPem });
    return raw;
  }

  async #activeDeployment(deploymentId: string): Promise<FederationDeploymentRecord> {
    const deployment = await this.#store.getDeployment(deploymentId);
    if (!deployment || deployment.status !== 'active') throw forbidden('federation deployment is not active');
    return deployment;
  }

  #validateTimeWindow(
    rawIssuedAt: unknown,
    rawExpiresAt: unknown,
    maximumTtlMs: number,
    requireFreshIssue = true,
  ): {
    issuedAt: Date;
    expiresAt: Date;
  } {
    const issuedAt = signedTimestamp(rawIssuedAt, 'issuedAt');
    const expiresAt = signedTimestamp(rawExpiresAt, 'expiresAt');
    const now = this.#now();
    if (issuedAt.getTime() > now + this.#maximumClockSkewMs) {
      throw unauthorized('federation timestamp is in the future');
    }
    if (requireFreshIssue && issuedAt.getTime() < now - this.#maximumClockSkewMs) {
      throw unauthorized('federation timestamp is outside the accepted clock window');
    }
    if (expiresAt.getTime() <= now) throw unauthorized('federation request has expired');
    if (expiresAt.getTime() - issuedAt.getTime() > maximumTtlMs) {
      throw invalidRequest('federation expiry exceeds the allowed TTL');
    }
    return { issuedAt, expiresAt };
  }
}

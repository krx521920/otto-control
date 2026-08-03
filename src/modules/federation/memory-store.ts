import { randomBytes } from 'node:crypto';

import type {
  FederationA2aGrantRecord,
  FederationAuditEventInput,
  FederationBlockRecord,
  FederationClaimedMessage,
  FederationDeploymentKeyRecord,
  FederationDeploymentRecord,
  FederationDeploymentUsage,
  FederationQueueStats,
  FederationStoredMessage,
} from '../../contracts/federation.js';
import { capacityExceeded, conflict, forbidden } from '../../errors.js';
import { claimTokenHash } from './crypto.js';
import {
  messageFromEnvelope,
  type CreateFederationGrantInput,
  type EnqueueFederationMessageInput,
  type EnqueueFederationMessageResult,
  type FederationStore,
  type RegisterFederationDeploymentInput,
  type RegisterFederationKeyInput,
} from './store.js';

interface MemoryMessage extends FederationStoredMessage {
  claimTokenHash: string | null;
}

export class MemoryFederationStore implements FederationStore {
  readonly deployments = new Map<string, FederationDeploymentRecord>();
  readonly keys = new Map<string, FederationDeploymentKeyRecord>();
  readonly nonces = new Map<string, Date>();
  readonly blocks = new Map<string, FederationBlockRecord>();
  readonly grants = new Map<string, FederationA2aGrantRecord>();
  readonly messages = new Map<string, MemoryMessage>();
  readonly rateWindows = new Map<string, number>();
  readonly auditEvents: FederationAuditEventInput[] = [];

  async close(): Promise<void> {
    return Promise.resolve();
  }

  async ready(): Promise<boolean> {
    return true;
  }

  async registerDeployment(input: RegisterFederationDeploymentInput): Promise<FederationDeploymentRecord> {
    const previous = this.deployments.get(input.id);
    const record: FederationDeploymentRecord = {
      id: input.id,
      displayName: input.displayName,
      origin: input.origin,
      status: previous?.status ?? 'active',
      capabilities: [...input.capabilities],
      maxPendingMessages: input.maxPendingMessages,
      maxPendingBytes: input.maxPendingBytes,
      maxRequestsPerMinute: input.maxRequestsPerMinute,
      createdAt: previous?.createdAt ?? input.now,
      updatedAt: input.now,
    };
    this.deployments.set(record.id, record);
    return structuredClone(record);
  }

  async setDeploymentStatus(
    deploymentId: string,
    status: FederationDeploymentRecord['status'],
    now: Date,
  ): Promise<FederationDeploymentRecord | null> {
    const record = this.deployments.get(deploymentId);
    if (!record) return null;
    record.status = status;
    record.updatedAt = now;
    if (status !== 'active') {
      for (const message of this.messages.values()) {
        if (
          (message.status === 'pending' || message.status === 'claimed')
          && (message.senderDeploymentId === deploymentId || message.recipientDeploymentId === deploymentId)
        ) {
          message.status = 'expired';
          message.claimedUntil = null;
          message.claimTokenHash = null;
        }
      }
    }
    return structuredClone(record);
  }

  async getDeployment(deploymentId: string): Promise<FederationDeploymentRecord | null> {
    const record = this.deployments.get(deploymentId);
    return record ? structuredClone(record) : null;
  }

  async listDeployments(limit: number): Promise<FederationDeploymentRecord[]> {
    return [...this.deployments.values()]
      .sort((left, right) => right.updatedAt.getTime() - left.updatedAt.getTime() || left.id.localeCompare(right.id))
      .slice(0, limit)
      .map((record) => structuredClone(record));
  }

  async registerKey(input: RegisterFederationKeyInput): Promise<FederationDeploymentKeyRecord> {
    const existing = this.keys.get(`${input.deploymentId}:${input.keyId}`);
    if (existing?.status === 'revoked') throw conflict('a revoked federation key id cannot be reused');
    const record: FederationDeploymentKeyRecord = {
      deploymentId: input.deploymentId,
      keyId: input.keyId,
      publicKeyPem: input.publicKeyPem,
      status: 'active',
      notBefore: input.notBefore,
      expiresAt: input.expiresAt,
      revokedAt: null,
      createdAt: input.now,
    };
    this.keys.set(`${record.deploymentId}:${record.keyId}`, record);
    return structuredClone(record);
  }

  async revokeKey(deploymentId: string, keyId: string, now: Date): Promise<boolean> {
    const record = this.keys.get(`${deploymentId}:${keyId}`);
    if (!record || record.status !== 'active') return false;
    record.status = 'revoked';
    record.revokedAt = now;
    for (const message of this.messages.values()) {
      if (
        message.senderDeploymentId === deploymentId
        && message.signingKeyId === keyId
        && (message.status === 'pending' || message.status === 'claimed')
      ) {
        message.status = 'expired';
        message.claimedUntil = null;
        message.claimTokenHash = null;
      }
    }
    return true;
  }

  async getActiveKey(
    deploymentId: string,
    keyId: string,
    now: Date,
  ): Promise<FederationDeploymentKeyRecord | null> {
    const record = this.keys.get(`${deploymentId}:${keyId}`);
    if (
      !record || record.status !== 'active' || record.notBefore > now
      || (record.expiresAt && record.expiresAt <= now)
    ) return null;
    return structuredClone(record);
  }

  async getVerificationKey(
    deploymentId: string,
    keyId: string,
  ): Promise<FederationDeploymentKeyRecord | null> {
    const record = this.keys.get(`${deploymentId}:${keyId}`);
    return record?.status === 'active' ? structuredClone(record) : null;
  }

  async consumeNonce(deploymentId: string, nonce: string, expiresAt: Date, now: Date): Promise<boolean> {
    for (const [key, expiry] of this.nonces) if (expiry <= now) this.nonces.delete(key);
    const key = `${deploymentId}:${nonce}`;
    if (this.nonces.has(key)) return false;
    this.nonces.set(key, expiresAt);
    return true;
  }

  async isBlocked(senderDeploymentId: string, recipientDeploymentId: string): Promise<boolean> {
    return this.blocks.has(`${senderDeploymentId}:${recipientDeploymentId}`)
      || this.blocks.has(`${recipientDeploymentId}:${senderDeploymentId}`);
  }

  async setBlock(input: FederationBlockRecord): Promise<void> {
    this.blocks.set(`${input.blockerDeploymentId}:${input.blockedDeploymentId}`, structuredClone(input));
    for (const message of this.messages.values()) {
      if (
        (message.status === 'pending' || message.status === 'claimed')
        && ((message.senderDeploymentId === input.blockerDeploymentId
          && message.recipientDeploymentId === input.blockedDeploymentId)
          || (message.senderDeploymentId === input.blockedDeploymentId
            && message.recipientDeploymentId === input.blockerDeploymentId))
      ) {
        message.status = 'expired';
        message.claimedUntil = null;
        message.claimTokenHash = null;
      }
    }
  }

  async removeBlock(blockerDeploymentId: string, blockedDeploymentId: string): Promise<boolean> {
    return this.blocks.delete(`${blockerDeploymentId}:${blockedDeploymentId}`);
  }

  async consumeRateLimit(deploymentId: string, now: Date): Promise<boolean> {
    const deployment = this.deployments.get(deploymentId);
    if (!deployment) return false;
    const windowStartedAt = Math.floor(now.getTime() / 60_000) * 60_000;
    for (const key of this.rateWindows.keys()) {
      const timestamp = Number(key.slice(key.lastIndexOf(':') + 1));
      if (timestamp < windowStartedAt - 60_000) this.rateWindows.delete(key);
    }
    const key = `${deploymentId}:${windowStartedAt}`;
    const count = this.rateWindows.get(key) ?? 0;
    if (count >= deployment.maxRequestsPerMinute) return false;
    this.rateWindows.set(key, count + 1);
    return true;
  }

  async createGrant(input: CreateFederationGrantInput): Promise<FederationA2aGrantRecord> {
    if (this.grants.has(input.id)) throw conflict('A2A grant already exists');
    const record: FederationA2aGrantRecord = {
      id: input.id,
      ownerDeploymentId: input.ownerDeploymentId,
      requesterDeploymentId: input.requesterDeploymentId,
      ownerPrincipalId: input.ownerPrincipalId,
      requesterPrincipalId: input.requesterPrincipalId,
      scopes: [...input.scopes],
      maxUses: input.maxUses,
      usedCount: 0,
      expiresAt: input.expiresAt,
      revokedAt: null,
      createdAt: input.now,
    };
    this.grants.set(record.id, record);
    return structuredClone(record);
  }

  async revokeGrant(ownerDeploymentId: string, grantId: string, now: Date): Promise<boolean> {
    const record = this.grants.get(grantId);
    if (!record || record.ownerDeploymentId !== ownerDeploymentId || record.revokedAt) return false;
    record.revokedAt = now;
    return true;
  }

  async enqueueMessage(input: EnqueueFederationMessageInput): Promise<EnqueueFederationMessageResult> {
    const envelope = input.signed.envelope;
    const existing = this.messages.get(envelope.messageId);
    if (existing) {
      if (
        existing.senderDeploymentId !== envelope.senderDeploymentId
        || existing.ciphertextSha256 !== input.ciphertextSha256
      ) throw conflict('messageId already belongs to a different federation envelope');
      return { message: structuredClone(existing), duplicate: true };
    }
    const recipient = this.deployments.get(envelope.recipientDeploymentId);
    const pendingMessages = [...this.messages.values()].filter((message) =>
      message.recipientDeploymentId === envelope.recipientDeploymentId
      && (message.status === 'pending' || message.status === 'claimed'));
    const pendingBytes = pendingMessages.reduce((total, message) => total + message.sizeBytes, 0);
    if (
      !recipient
      || pendingMessages.length >= recipient.maxPendingMessages
      || pendingBytes + input.sizeBytes > recipient.maxPendingBytes
    ) throw capacityExceeded('recipient federation inbox capacity is exhausted');

    let a2aGrant: FederationA2aGrantRecord | null = null;
    if (envelope.type === 'a2a.request') {
      const grant = this.grants.get(envelope.routing.a2aGrantId!);
      if (
        !grant || grant.ownerDeploymentId !== envelope.recipientDeploymentId
        || grant.requesterDeploymentId !== envelope.senderDeploymentId
        || grant.ownerPrincipalId !== envelope.routing.recipientPrincipalId
        || grant.requesterPrincipalId !== envelope.routing.senderPrincipalId
        || !grant.scopes.includes(envelope.routing.a2aScope!)
        || grant.revokedAt || grant.expiresAt <= input.now || grant.usedCount >= grant.maxUses
      ) throw forbidden('A2A grant is invalid, expired, revoked, or already consumed');
      a2aGrant = grant;
    }

    if (envelope.type === 'a2a.response') {
      const request = this.messages.get(envelope.routing.inReplyTo!);
      if (
        !request || request.type !== 'a2a.request'
        || request.senderDeploymentId !== envelope.recipientDeploymentId
        || request.recipientDeploymentId !== envelope.senderDeploymentId
        || request.routing.senderPrincipalId !== envelope.routing.recipientPrincipalId
        || request.routing.recipientPrincipalId !== envelope.routing.senderPrincipalId
      ) throw forbidden('A2A response does not match an authorized request');
    }

    if (envelope.type === 'chat.receipt') {
      const parent = this.messages.get(envelope.routing.inReplyTo!);
      if (
        !parent || parent.type !== 'chat.message'
        || parent.senderDeploymentId !== envelope.recipientDeploymentId
        || parent.recipientDeploymentId !== envelope.senderDeploymentId
        || parent.routing.senderPrincipalId !== envelope.routing.recipientPrincipalId
        || parent.routing.recipientPrincipalId !== envelope.routing.senderPrincipalId
      ) throw forbidden('chat receipt does not match a delivered message route');
    }

    for (const [key, expiry] of this.nonces) if (expiry <= input.now) this.nonces.delete(key);
    const nonceKey = `${envelope.senderDeploymentId}:${envelope.nonce}`;
    if (this.nonces.has(nonceKey)) throw conflict('federation envelope nonce has already been used');

    const message: MemoryMessage = {
      ...messageFromEnvelope({
        envelope,
        signingKeyId: input.signed.signingKeyId,
        signature: input.signed.signature,
        ciphertextSha256: input.ciphertextSha256,
        sizeBytes: input.sizeBytes,
        now: input.now,
      }),
      claimTokenHash: null,
    };
    this.nonces.set(nonceKey, new Date(envelope.expiresAt));
    if (a2aGrant) a2aGrant.usedCount += 1;
    this.messages.set(message.messageId, message);
    return { message: structuredClone(message), duplicate: false };
  }

  async claimMessages(input: {
    recipientDeploymentId: string;
    limit: number;
    maximumBytes: number;
    claimTtlMs: number;
    now: Date;
  }): Promise<FederationClaimedMessage[]> {
    const candidates = [...this.messages.values()]
      .filter((message) => message.recipientDeploymentId === input.recipientDeploymentId
        && new Date(message.expiresAt) > input.now
        && (message.status === 'pending'
          || (message.status === 'claimed' && message.claimedUntil! <= input.now)))
      .sort((left, right) => left.createdAt.getTime() - right.createdAt.getTime()
        || left.messageId.localeCompare(right.messageId))
      .slice(0, input.limit);
    const output: FederationClaimedMessage[] = [];
    let claimedBytes = 0;
    for (const message of candidates) {
      if (output.length > 0 && claimedBytes + message.sizeBytes > input.maximumBytes) break;
      const claimToken = randomBytes(32).toString('base64url');
      message.status = 'claimed';
      message.attempts += 1;
      message.claimedUntil = new Date(input.now.getTime() + input.claimTtlMs);
      message.claimTokenHash = claimTokenHash(claimToken);
      output.push({ message: structuredClone(message), claimToken });
      claimedBytes += message.sizeBytes;
    }
    return output;
  }

  async acknowledgeMessage(input: {
    recipientDeploymentId: string;
    messageId: string;
    claimToken: string;
    now: Date;
  }): Promise<boolean> {
    const message = this.messages.get(input.messageId);
    if (
      !message || message.recipientDeploymentId !== input.recipientDeploymentId
      || message.status !== 'claimed' || !message.claimedUntil || message.claimedUntil <= input.now
      || message.claimTokenHash !== claimTokenHash(input.claimToken)
    ) return false;
    message.status = 'delivered';
    message.claimedUntil = null;
    message.claimTokenHash = null;
    message.deliveredAt = input.now;
    return true;
  }

  async getMessage(messageId: string): Promise<FederationStoredMessage | null> {
    const message = this.messages.get(messageId);
    return message ? structuredClone(message) : null;
  }

  async appendAuditEvent(input: FederationAuditEventInput): Promise<void> {
    this.auditEvents.push(structuredClone(input));
  }

  async listAuditEvents(limit: number): Promise<FederationAuditEventInput[]> {
    return this.auditEvents.slice(-limit).reverse().map((event) => structuredClone(event));
  }

  async queueStats(): Promise<FederationQueueStats> {
    const output: FederationQueueStats = { pending: 0, claimed: 0, delivered: 0, expired: 0 };
    for (const message of this.messages.values()) output[message.status] += 1;
    return output;
  }

  async queueBytes(): Promise<FederationQueueStats> {
    const output: FederationQueueStats = { pending: 0, claimed: 0, delivered: 0, expired: 0 };
    for (const message of this.messages.values()) output[message.status] += message.sizeBytes;
    return output;
  }

  async deploymentUsage(deploymentId: string): Promise<FederationDeploymentUsage> {
    const output: FederationDeploymentUsage = {
      pendingMessages: 0,
      claimedMessages: 0,
      pendingBytes: 0,
      claimedBytes: 0,
    };
    for (const message of this.messages.values()) {
      if (message.recipientDeploymentId !== deploymentId) continue;
      if (message.status === 'pending') {
        output.pendingMessages += 1;
        output.pendingBytes += message.sizeBytes;
      } else if (message.status === 'claimed') {
        output.claimedMessages += 1;
        output.claimedBytes += message.sizeBytes;
      }
    }
    return output;
  }

  async expireMessages(now: Date, deliveredBefore: Date): Promise<{ expired: number; purged: number }> {
    let expired = 0;
    let purged = 0;
    for (const message of this.messages.values()) {
      if ((message.status === 'pending' || message.status === 'claimed') && new Date(message.expiresAt) <= now) {
        message.status = 'expired';
        message.claimedUntil = null;
        message.claimTokenHash = null;
        expired += 1;
      }
    }
    for (const [id, message] of this.messages) {
      if (
        (message.status === 'delivered' && message.deliveredAt && message.deliveredAt <= deliveredBefore)
        || (message.status === 'expired' && new Date(message.expiresAt) <= deliveredBefore)
      ) {
        this.messages.delete(id);
        purged += 1;
      }
    }
    for (const [key, expiry] of this.nonces) if (expiry <= now) this.nonces.delete(key);
    const currentWindow = Math.floor(now.getTime() / 60_000) * 60_000;
    for (const key of this.rateWindows.keys()) {
      const timestamp = Number(key.slice(key.lastIndexOf(':') + 1));
      if (timestamp < currentWindow - 60_000) this.rateWindows.delete(key);
    }
    return { expired, purged };
  }
}

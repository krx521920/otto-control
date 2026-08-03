export const FEDERATION_PROTOCOL_VERSION = 1 as const;

export const FEDERATION_MESSAGE_TYPES = [
  'chat.message',
  'chat.receipt',
  'a2a.request',
  'a2a.response',
] as const;

export type FederationMessageType = (typeof FEDERATION_MESSAGE_TYPES)[number];
export type FederationDeploymentStatus = 'active' | 'blocked' | 'disabled';
export type FederationKeyStatus = 'active' | 'revoked';
export type FederationMessageStatus = 'pending' | 'claimed' | 'delivered' | 'expired';

export interface FederationDeploymentRecord {
  id: string;
  displayName: string;
  origin: string;
  status: FederationDeploymentStatus;
  capabilities: string[];
  maxPendingMessages: number;
  maxPendingBytes: number;
  maxRequestsPerMinute: number;
  createdAt: Date;
  updatedAt: Date;
}

export interface FederationDeploymentKeyRecord {
  deploymentId: string;
  keyId: string;
  publicKeyPem: string;
  status: FederationKeyStatus;
  notBefore: Date;
  expiresAt: Date | null;
  revokedAt: Date | null;
  createdAt: Date;
}

export interface FederationRoutingMetadata {
  conversationId: string;
  senderPrincipalId: string;
  recipientPrincipalId: string;
  inReplyTo?: string;
  a2aGrantId?: string;
  a2aScope?: string;
}

export interface FederationEnvelope {
  version: typeof FEDERATION_PROTOCOL_VERSION;
  messageId: string;
  type: FederationMessageType;
  senderDeploymentId: string;
  recipientDeploymentId: string;
  issuedAt: string;
  expiresAt: string;
  nonce: string;
  contentType: 'application/otto-e2ee+json';
  ciphertext: string;
  routing: FederationRoutingMetadata;
}

export interface SignedFederationEnvelope {
  envelope: FederationEnvelope;
  signingKeyId: string;
  signature: string;
}

export interface FederationSignedRequest<T> {
  request: T & {
    version: typeof FEDERATION_PROTOCOL_VERSION;
    deploymentId: string;
    issuedAt: string;
    expiresAt: string;
    nonce: string;
  };
  signingKeyId: string;
  signature: string;
}

export interface FederationStoredMessage extends FederationEnvelope {
  signingKeyId: string;
  signature: string;
  ciphertextSha256: string;
  sizeBytes: number;
  status: FederationMessageStatus;
  attempts: number;
  claimedUntil: Date | null;
  deliveredAt: Date | null;
  createdAt: Date;
}

export interface FederationClaimedMessage {
  message: FederationStoredMessage;
  claimToken: string;
}

export interface FederationA2aGrantRecord {
  id: string;
  ownerDeploymentId: string;
  requesterDeploymentId: string;
  ownerPrincipalId: string;
  requesterPrincipalId: string;
  scopes: string[];
  maxUses: number;
  usedCount: number;
  expiresAt: Date;
  revokedAt: Date | null;
  createdAt: Date;
}

export interface FederationBlockRecord {
  blockerDeploymentId: string;
  blockedDeploymentId: string;
  reason: string;
  createdAt: Date;
}

export interface FederationAuditEventInput {
  actorDeploymentId: string;
  action: string;
  targetType: string;
  targetId: string;
  details: Record<string, unknown>;
  occurredAt: Date;
}

export interface FederationQueueStats {
  pending: number;
  claimed: number;
  delivered: number;
  expired: number;
}

export interface FederationDeploymentUsage {
  pendingMessages: number;
  claimedMessages: number;
  pendingBytes: number;
  claimedBytes: number;
}

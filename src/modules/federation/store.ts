import type {
  FederationA2aGrantRecord,
  FederationAuditEventInput,
  FederationBlockRecord,
  FederationClaimedMessage,
  FederationDeploymentKeyRecord,
  FederationDeploymentRecord,
  FederationDeploymentUsage,
  FederationEnvelope,
  FederationQueueStats,
  FederationStoredMessage,
  SignedFederationEnvelope,
} from '../../contracts/federation.js';

export interface RegisterFederationDeploymentInput {
  id: string;
  displayName: string;
  origin: string;
  capabilities: string[];
  maxPendingMessages: number;
  maxPendingBytes: number;
  maxRequestsPerMinute: number;
  now: Date;
}

export interface RegisterFederationKeyInput {
  deploymentId: string;
  keyId: string;
  publicKeyPem: string;
  notBefore: Date;
  expiresAt: Date | null;
  now: Date;
}

export interface CreateFederationGrantInput {
  id: string;
  ownerDeploymentId: string;
  requesterDeploymentId: string;
  ownerPrincipalId: string;
  requesterPrincipalId: string;
  scopes: string[];
  maxUses: number;
  expiresAt: Date;
  now: Date;
}

export interface EnqueueFederationMessageInput {
  signed: SignedFederationEnvelope;
  ciphertextSha256: string;
  sizeBytes: number;
  now: Date;
}

export interface EnqueueFederationMessageResult {
  message: FederationStoredMessage;
  duplicate: boolean;
}

export interface FederationStore {
  close(): Promise<void>;
  ready(): Promise<boolean>;
  registerDeployment(input: RegisterFederationDeploymentInput): Promise<FederationDeploymentRecord>;
  setDeploymentStatus(
    deploymentId: string,
    status: FederationDeploymentRecord['status'],
    now: Date,
  ): Promise<FederationDeploymentRecord | null>;
  getDeployment(deploymentId: string): Promise<FederationDeploymentRecord | null>;
  listDeployments(limit: number): Promise<FederationDeploymentRecord[]>;
  registerKey(input: RegisterFederationKeyInput): Promise<FederationDeploymentKeyRecord>;
  revokeKey(deploymentId: string, keyId: string, now: Date): Promise<boolean>;
  getActiveKey(
    deploymentId: string,
    keyId: string,
    now: Date,
  ): Promise<FederationDeploymentKeyRecord | null>;
  getVerificationKey(
    deploymentId: string,
    keyId: string,
  ): Promise<FederationDeploymentKeyRecord | null>;
  consumeNonce(deploymentId: string, nonce: string, expiresAt: Date, now: Date): Promise<boolean>;
  isBlocked(senderDeploymentId: string, recipientDeploymentId: string): Promise<boolean>;
  setBlock(input: FederationBlockRecord): Promise<void>;
  removeBlock(blockerDeploymentId: string, blockedDeploymentId: string): Promise<boolean>;
  consumeRateLimit(deploymentId: string, now: Date): Promise<boolean>;
  createGrant(input: CreateFederationGrantInput): Promise<FederationA2aGrantRecord>;
  revokeGrant(ownerDeploymentId: string, grantId: string, now: Date): Promise<boolean>;
  enqueueMessage(input: EnqueueFederationMessageInput): Promise<EnqueueFederationMessageResult>;
  claimMessages(input: {
    recipientDeploymentId: string;
    limit: number;
    maximumBytes: number;
    claimTtlMs: number;
    now: Date;
  }): Promise<FederationClaimedMessage[]>;
  acknowledgeMessage(input: {
    recipientDeploymentId: string;
    messageId: string;
    claimToken: string;
    now: Date;
  }): Promise<boolean>;
  getMessage(messageId: string): Promise<FederationStoredMessage | null>;
  appendAuditEvent(input: FederationAuditEventInput): Promise<void>;
  listAuditEvents(limit: number): Promise<FederationAuditEventInput[]>;
  queueStats(): Promise<FederationQueueStats>;
  queueBytes(): Promise<FederationQueueStats>;
  deploymentUsage(deploymentId: string): Promise<FederationDeploymentUsage>;
  expireMessages(now: Date, deliveredBefore: Date): Promise<{ expired: number; purged: number }>;
}

export function messageFromEnvelope(input: {
  envelope: FederationEnvelope;
  signingKeyId: string;
  signature: string;
  ciphertextSha256: string;
  sizeBytes: number;
  now: Date;
}): FederationStoredMessage {
  return {
    ...input.envelope,
    signingKeyId: input.signingKeyId,
    signature: input.signature,
    ciphertextSha256: input.ciphertextSha256,
    sizeBytes: input.sizeBytes,
    status: 'pending',
    attempts: 0,
    claimedUntil: null,
    deliveredAt: null,
    createdAt: input.now,
  };
}

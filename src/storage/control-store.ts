import type { OttoLicenseCapability } from '../contracts/license.js';
import type {
  AdminAccountRecord,
  AdminApprovalRecord,
  AdminPrincipal,
  AdminRoleRecord,
  AdminSessionRecord,
} from '../contracts/admin-identity.js';
import type {
  DeploymentTelemetrySummary,
  OttoTelemetryEvent,
  OttoTelemetryReceipt,
} from '../contracts/telemetry.js';
import type { UpdateChannel, UpdateReleaseState } from '../contracts/update-policy.js';

export type RecordStatus = 'active' | 'suspended';

export type SigningKeyState = 'standby' | 'active' | 'retired' | 'revoked';
export type SigningKeyProvider = 'local' | 'kms' | 'hsm';

export interface SigningKeyRecord {
  keyId: string;
  algorithm: 'ed25519';
  publicKeyPem: string;
  provider: SigningKeyProvider;
  state: SigningKeyState;
  createdAt: Date;
  activatedAt: Date | null;
  retiredAt: Date | null;
  revokedAt: Date | null;
  revocationReason: string | null;
  updatedAt: Date;
}

export interface SigningKeyTransition {
  key: SigningKeyRecord;
  activeKey: SigningKeyRecord | null;
  previousActiveKey: SigningKeyRecord | null;
}

export interface CustomerRecord {
  id: string;
  name: string;
  status: RecordStatus;
  createdAt: Date;
  updatedAt: Date;
}

export interface DeploymentRecord {
  id: string;
  customerId: string;
  customerName: string;
  organizationId: string;
  machineFingerprint: string;
  name: string;
  status: RecordStatus;
  createdAt: Date;
  updatedAt: Date;
}

export interface LicenseRecord {
  id: string;
  deploymentId: string;
  customerName: string;
  organizationId: string;
  machineFingerprint: string;
  plan: string;
  issuedAtMs: number;
  expiresAtMs: number;
  seatLimit: number;
  modules: OttoLicenseCapability[];
  offline: boolean;
  telemetryAllowed: boolean;
  leaseEndpoint: string | null;
  tokenVersion: number;
  signature: string;
  signingKeyId: string;
  revokedAtMs: number | null;
  createdAt: Date;
  updatedAt: Date;
}

export type CreateLicenseRecordInput = Omit<LicenseRecord, 'createdAt' | 'updatedAt'>;

export interface AuditEventInput {
  actorId: string;
  action: string;
  targetType: string;
  targetId: string;
  detail: Record<string, unknown>;
}

export interface UpdateDistributionRecord {
  id: string;
  name: string;
  status: RecordStatus;
  createdAt: Date;
  updatedAt: Date;
}

export interface UpdateReleaseRecord {
  id: string;
  distributionId: string;
  version: string;
  sourceCommit: string;
  channel: UpdateChannel;
  rolloutPercent: number;
  state: UpdateReleaseState;
  notes: string;
  fullManifestUrl: string | null;
  fullManifestSha256: string | null;
  incrementalManifestUrl: string | null;
  incrementalManifestSha256: string | null;
  previousReleaseId: string | null;
  publishedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export type CreateUpdateReleaseRecordInput = Omit<
  UpdateReleaseRecord,
  'state' | 'previousReleaseId' | 'publishedAt' | 'createdAt' | 'updatedAt'
>;

export interface UpdateReleaseTransition {
  release: UpdateReleaseRecord;
  fallback: UpdateReleaseRecord | null;
}

export interface DeploymentUpdateAssignmentRecord {
  deploymentId: string;
  distributionId: string;
  updatedAt: Date;
}

export interface ControlStore {
  ping(): Promise<void>;
  close(): Promise<void>;
  createCustomer(input: { id: string; name: string }): Promise<CustomerRecord>;
  createDeployment(input: {
    id: string;
    customerId: string;
    organizationId: string;
    machineFingerprint: string;
    name: string;
  }): Promise<DeploymentRecord>;
  getDeployment(id: string): Promise<DeploymentRecord | null>;
  createLicense(input: CreateLicenseRecordInput): Promise<LicenseRecord>;
  getLicense(id: string): Promise<LicenseRecord | null>;
  revokeLicense(id: string, revokedAtMs: number): Promise<LicenseRecord | null>;
  registerSigningKey(input: {
    keyId: string;
    publicKeyPem: string;
    provider: SigningKeyProvider;
  }): Promise<SigningKeyRecord>;
  getSigningKey(keyId: string): Promise<SigningKeyRecord | null>;
  listSigningKeys(): Promise<SigningKeyRecord[]>;
  activateSigningKey(keyId: string, changedAt: Date): Promise<SigningKeyTransition | null>;
  retireSigningKey(keyId: string, changedAt: Date): Promise<SigningKeyTransition | null>;
  revokeSigningKey(input: {
    keyId: string;
    replacementKeyId: string | null;
    reason: string;
    changedAt: Date;
  }): Promise<SigningKeyTransition | null>;
  countAdminAccounts(): Promise<number>;
  createAdminAccount(input: {
    id: string;
    username: string;
    displayName: string;
    passwordHash: string;
    mfaSecretCiphertext: string;
    enrollmentTokenHash: string;
    enrollmentExpiresAt: Date;
    roleIds: string[];
  }): Promise<AdminAccountRecord>;
  getAdminAccountById(id: string): Promise<AdminAccountRecord | null>;
  getAdminAccountByUsername(username: string): Promise<AdminAccountRecord | null>;
  listAdminAccounts(): Promise<Array<AdminAccountRecord & { roles: string[] }>>;
  listAdminRoles(): Promise<AdminRoleRecord[]>;
  replaceAdminAccountRoles(accountId: string, roleIds: string[]): Promise<string[] | null>;
  setAdminAccountStatus(
    accountId: string,
    status: AdminAccountRecord['status'],
    changedAt: Date,
  ): Promise<AdminAccountRecord | null>;
  confirmAdminEnrollment(input: {
    accountId: string;
    enrollmentTokenHash: string;
    recoveryCodeHashes: string[];
    confirmedAt: Date;
  }): Promise<AdminAccountRecord | null>;
  recordAdminLoginFailure(input: {
    accountId: string;
    failedLoginCount: number;
    lockedUntil: Date | null;
    changedAt: Date;
  }): Promise<void>;
  clearAdminLoginFailures(accountId: string, changedAt: Date): Promise<void>;
  consumeAdminRecoveryCode(accountId: string, codeHash: string, usedAt: Date): Promise<boolean>;
  createAdminSession(input: {
    id: string;
    accountId: string;
    tokenHash: string;
    expiresAt: Date;
    mfaVerifiedAt: Date;
    createdAt: Date;
  }): Promise<AdminSessionRecord>;
  getAdminPrincipalBySessionTokenHash(input: {
    tokenHash: string;
    now: Date;
    idleCutoff: Date;
  }): Promise<AdminPrincipal | null>;
  touchAdminSession(sessionId: string, seenAt: Date): Promise<void>;
  revokeAdminSession(sessionId: string, revokedAt: Date): Promise<void>;
  revokeAdminAccountSessions(accountId: string, revokedAt: Date): Promise<void>;
  createAdminApproval(input: {
    id: string;
    requesterAccountId: string;
    operation: string;
    targetType: string;
    targetId: string;
    requestHash: string;
    requiredApprovals: number;
    expiresAt: Date;
    createdAt: Date;
  }): Promise<AdminApprovalRecord>;
  getAdminApproval(id: string): Promise<AdminApprovalRecord | null>;
  listAdminApprovals(limit: number): Promise<AdminApprovalRecord[]>;
  decideAdminApproval(input: {
    approvalId: string;
    accountId: string;
    decision: 'approve' | 'reject';
    reason: string | null;
    decidedAt: Date;
  }): Promise<AdminApprovalRecord | null>;
  consumeAdminApproval(input: {
    approvalId: string;
    requesterAccountId: string;
    operation: string;
    targetType: string;
    targetId: string;
    requestHash: string;
    executedAt: Date;
  }): Promise<AdminApprovalRecord | null>;
  consumeLeaseNonce(input: {
    deploymentId: string;
    nonce: string;
    expiresAtMs: number;
  }): Promise<boolean>;
  ingestTelemetryBatch(input: {
    deploymentId: string;
    licenseId: string;
    nonce: string;
    nonceExpiresAtMs: number;
    retentionBeforeMs: number;
    receivedAtMs: number;
    events: OttoTelemetryEvent[];
  }): Promise<OttoTelemetryReceipt | null>;
  getDeploymentTelemetrySummary(input: {
    deploymentId: string;
    sinceMs: number;
  }): Promise<DeploymentTelemetrySummary>;
  createUpdateDistribution(input: { id: string; name: string }): Promise<UpdateDistributionRecord>;
  getUpdateDistribution(id: string): Promise<UpdateDistributionRecord | null>;
  assignDeploymentUpdateDistribution(input: {
    deploymentId: string;
    distributionId: string;
    updatedAt: Date;
  }): Promise<DeploymentUpdateAssignmentRecord>;
  hasDeploymentUpdateAssignment(
    deploymentId: string,
    distributionId: string,
  ): Promise<boolean>;
  createUpdateRelease(input: CreateUpdateReleaseRecordInput): Promise<UpdateReleaseRecord>;
  getUpdateRelease(id: string): Promise<UpdateReleaseRecord | null>;
  listUpdateReleases(distributionId: string): Promise<UpdateReleaseRecord[]>;
  activateUpdateRelease(id: string, publishedAt: Date): Promise<UpdateReleaseTransition | null>;
  pauseUpdateRelease(id: string, updatedAt: Date): Promise<UpdateReleaseRecord | null>;
  rollbackUpdateRelease(id: string, updatedAt: Date): Promise<UpdateReleaseTransition | null>;
  getActiveUpdateReleases(distributionId: string): Promise<UpdateReleaseRecord[]>;
  consumeUpdatePolicyNonce(input: {
    deploymentId: string;
    nonce: string;
    expiresAtMs: number;
  }): Promise<boolean>;
  appendAuditEvent(input: AuditEventInput): Promise<void>;
}

import type {
  OttoLicenseCapability,
  OttoSeatEnforcement,
  OttoSeatStatus,
} from '../contracts/license.js';
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
import type {
  ReleaseArtifactKind,
  ReleaseArtifactPlatform,
  ReleaseArtifactState,
} from '../contracts/release-artifact.js';
import type { SignedArtifactCodeSigningEvidence } from '../contracts/artifact-storage.js';
import type {
  BillingRateRecord,
  CreditAccountRecord,
  CreditHoldMutationResult,
  CreditHoldRecord,
  CreditMutationResult,
  CreditStatement,
  CreditTransactionRecord,
  ExecutionReceiptKeyRecord,
  ExecutionReceiptHoldMutationResult,
  ExecutionReceiptMutationResult,
  ExecutionReceiptRecord,
  EdgeBillingAggregationEventRecord,
  EdgeBillingAggregationStatus,
  EdgeBillingNodeRecord,
  SignedExecutionReceiptV2,
  OttoBillingModule,
} from '../contracts/billing.js';
import type {
  AlertDeliveryPayload,
  AlertDeliveryRecord,
  AlertDeliveryStatus,
  AlertSeverity,
} from '../contracts/alert-delivery.js';
import type {
  AuditChainState,
  AuditEventQuery,
  AuditEventRecord,
} from '../contracts/audit.js';
import type {
  AuditAnchorPayload,
  AuditAnchorRecord,
  AuditAnchorStatus,
} from '../contracts/audit-anchor.js';
import type {
  AuditWitnessEvidenceRecord,
  AuditWitnessEvidenceStatus,
  AuditWitnessReceiptRecord,
} from '../contracts/audit-witness.js';
import type {
  EdgeGatewayLimitsV1,
  EdgeModelRouteV1,
} from '../contracts/edge-gateway.js';

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

export type DeploymentEnrollmentStatus = 'pending' | 'claiming' | 'activated' | 'revoked';

export interface DeploymentEnrollmentRecord {
  id: string;
  tokenHash: string;
  requestHash: string | null;
  customerId: string;
  organizationId: string;
  deploymentName: string;
  plan: string;
  licenseExpiresAtMs: number;
  seatLimit: number;
  modules: OttoLicenseCapability[];
  telemetryAllowed: boolean;
  federationGatewayUrl: string | null;
  modelGatewayUrl: string | null;
  telemetryEndpoint: string | null;
  updateDistributionId: string | null;
  status: DeploymentEnrollmentStatus;
  deploymentId: string | null;
  machineFingerprint: string | null;
  licenseId: string;
  claimLeaseId: string | null;
  claimLeaseExpiresAt: Date | null;
  replayExpiresAt: Date | null;
  appVersion: string | null;
  buildCommit: string | null;
  publicOrigin: string | null;
  deploymentKind: string | null;
  expiresAt: Date;
  claimedAt: Date | null;
  activatedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface DeploymentEnrollmentReservation {
  state: 'reserved' | 'in_progress' | 'activated';
  enrollment: DeploymentEnrollmentRecord;
}
export interface EdgeGatewayPolicyRecord {
  deploymentId: string;
  organizationId: string;
  policyVersion: string;
  routes: EdgeModelRouteV1[];
  limits: EdgeGatewayLimitsV1;
  status: RecordStatus;
  updatedBy: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface LicenseRecord {
  id: string;
  revision: number;
  deploymentId: string;
  customerName: string;
  organizationId: string;
  machineFingerprint: string;
  plan: string;
  issuedAtMs: number;
  expiresAtMs: number;
  seatLimit: number;
  gracePeriodMs: number;
  seatEnforcement: OttoSeatEnforcement;
  billingEnforcement?: 'disabled' | 'enforce';
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

export interface CommercialInventoryCounts {
  customers: { total: number; active: number; suspended: number };
  deployments: { total: number; active: number; suspended: number };
  licenses: {
    total: number;
    active: number;
    expiringSoon: number;
    grace: number;
    expired: number;
    revoked: number;
  };
}

export interface CommercialInventorySnapshot {
  generatedAt: Date;
  counts: CommercialInventoryCounts;
  recentCustomers: CustomerRecord[];
  recentDeployments: DeploymentRecord[];
  recentLicenses: LicenseRecord[];
}

export type CreateLicenseRecordInput = Omit<LicenseRecord, 'createdAt' | 'updatedAt'>;

export type LicenseLifecycleChangeType =
  | 'renewed'
  | 'expanded'
  | 'downgraded'
  | 'terms_changed'
  | 'machine_transferred'
  | 'deployment_rebound';

export interface UpdateLicenseRecordInput extends CreateLicenseRecordInput {
  expectedRevision: number;
  actorId: string;
  changeType: LicenseLifecycleChangeType;
  changeDetail: Record<string, unknown>;
  deploymentMachineFingerprint?: {
    deploymentId: string;
    expectedFingerprint: string;
    newFingerprint: string;
  };
  resetSeatUsage?: boolean;
}

export interface LicenseLifecycleEventRecord {
  id: number;
  licenseId: string;
  revision: number;
  changeType: LicenseLifecycleChangeType;
  actorId: string;
  detail: Record<string, unknown>;
  createdAt: Date;
}

export interface LicenseSeatUsageRecord {
  licenseId: string;
  deploymentId: string;
  activeSeats: number;
  seatLimit: number;
  status: OttoSeatStatus;
  overageStartedAtMs: number | null;
  graceExpiresAtMs: number | null;
  lastReportedAtMs: number;
}

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

export interface ReleaseArtifactRecord {
  id: string;
  releaseId: string;
  distributionId: string;
  releaseVersion: string;
  sourceCommit: string;
  kind: ReleaseArtifactKind;
  platform: ReleaseArtifactPlatform;
  url: string;
  sha256: string;
  sizeBytes: number;
  signingKeyId: string;
  signature: string;
  state: ReleaseArtifactState;
  revokedAt: Date | null;
  revokedBy: string | null;
  revocationReason: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export type CreateReleaseArtifactRecordInput = Omit<
  ReleaseArtifactRecord,
  'state' | 'revokedAt' | 'revokedBy' | 'revocationReason' | 'updatedAt'
>;

export interface ReleaseArtifactRevocationResult {
  artifact: ReleaseArtifactRecord;
  releasePaused: boolean;
}

export interface ReleaseArtifactEvidenceRecord {
  artifactId: string;
  objectKey: string;
  objectVersionId: string | null;
  verifiedAt: Date;
  serverSideEncryption: string | null;
  objectLockMode: string | null;
  objectLockRetainUntil: Date | null;
  codeSigning: SignedArtifactCodeSigningEvidence | null;
  createdAt: Date;
}

export interface CreateManagedReleaseArtifactInput {
  artifact: CreateReleaseArtifactRecordInput;
  evidence: Omit<ReleaseArtifactEvidenceRecord, 'artifactId' | 'createdAt'>;
}

export interface ManagedReleaseArtifactRecord {
  artifact: ReleaseArtifactRecord;
  evidence: ReleaseArtifactEvidenceRecord;
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
  getCustomer(id: string): Promise<CustomerRecord | null>;
  getCommercialInventory(input: {
    nowMs: number;
    expiringWithinMs: number;
    recentLimit: number;
  }): Promise<CommercialInventorySnapshot>;
  createDeployment(input: {
    id: string;
    customerId: string;
    organizationId: string;
    machineFingerprint: string;
    name: string;
  }): Promise<DeploymentRecord>;
  getDeployment(id: string): Promise<DeploymentRecord | null>;
  createDeploymentEnrollment(input: {
    id: string;
    tokenHash: string;
    customerId: string;
    organizationId: string;
    deploymentName: string;
    plan: string;
    licenseExpiresAtMs: number;
    seatLimit: number;
    modules: OttoLicenseCapability[];
    telemetryAllowed: boolean;
    federationGatewayUrl: string | null;
    modelGatewayUrl: string | null;
    telemetryEndpoint: string | null;
    updateDistributionId: string | null;
    licenseId: string;
    expiresAt: Date;
  }): Promise<DeploymentEnrollmentRecord>;
  reserveDeploymentEnrollmentClaim(input: {
    tokenHash: string;
    requestHash: string;
    deploymentId: string;
    machineFingerprint: string;
    claimLeaseId: string;
    claimLeaseExpiresAt: Date;
    appVersion: string;
    buildCommit: string;
    publicOrigin: string | null;
    deploymentKind: string;
    now: Date;
  }): Promise<DeploymentEnrollmentReservation | null>;
  completeDeploymentEnrollmentClaim(input: {
    enrollmentId: string;
    claimLeaseId: string;
    activatedAt: Date;
    replayExpiresAt: Date;
  }): Promise<DeploymentEnrollmentRecord | null>;
  upsertEdgeGatewayPolicy(input: {
    deploymentId: string;
    organizationId: string;
    policyVersion: string;
    routes: EdgeModelRouteV1[];
    limits: EdgeGatewayLimitsV1;
    status: RecordStatus;
    updatedBy: string;
    changedAt: Date;
  }): Promise<EdgeGatewayPolicyRecord>;
  getEdgeGatewayPolicy(deploymentId: string): Promise<EdgeGatewayPolicyRecord | null>;
  consumeEdgeGatewayNonce(input: {
    deploymentId: string;
    nonce: string;
    nowMs: number;
    expiresAtMs: number;
  }): Promise<boolean>;
  createLicense(input: CreateLicenseRecordInput): Promise<LicenseRecord>;
  getLicense(id: string): Promise<LicenseRecord | null>;
  revokeLicense(id: string, revokedAtMs: number): Promise<LicenseRecord | null>;
  updateLicense(input: UpdateLicenseRecordInput): Promise<LicenseRecord | null>;
  listLicenseLifecycleEvents(licenseId: string, limit: number): Promise<LicenseLifecycleEventRecord[]>;
  getLicenseSeatUsage(licenseId: string): Promise<LicenseSeatUsageRecord | null>;
  recordLicenseSeatUsage(input: {
    licenseId: string;
    deploymentId: string;
    activeSeats: number;
    seatLimit: number;
    gracePeriodMs: number;
    enforcement: OttoSeatEnforcement;
    reportedAtMs: number;
  }): Promise<LicenseSeatUsageRecord>;
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
    request: Record<string, unknown>;
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
    nowMs: number;
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
  createReleaseArtifact(input: CreateReleaseArtifactRecordInput): Promise<ReleaseArtifactRecord>;
  createManagedReleaseArtifact(
    input: CreateManagedReleaseArtifactInput,
  ): Promise<ManagedReleaseArtifactRecord>;
  getReleaseArtifact(id: string): Promise<ReleaseArtifactRecord | null>;
  getReleaseArtifactEvidence(id: string): Promise<ReleaseArtifactEvidenceRecord | null>;
  listReleaseArtifacts(releaseId: string): Promise<ReleaseArtifactRecord[]>;
  revokeReleaseArtifact(input: {
    id: string;
    actorId: string;
    reason: string;
    revokedAt: Date;
  }): Promise<ReleaseArtifactRevocationResult | null>;
  consumeUpdatePolicyNonce(input: {
    deploymentId: string;
    nonce: string;
    expiresAtMs: number;
  }): Promise<boolean>;
  getCreditAccount(
    customerId: string,
    organizationId: string,
  ): Promise<CreditAccountRecord | null>;
  setBillingRate(input: {
    customerId: string;
    module: OttoBillingModule;
    unitSize: number;
    creditsPerUnit: number;
    actorId: string;
    changedAt: Date;
  }): Promise<BillingRateRecord>;
  getBillingRate(customerId: string, module: OttoBillingModule): Promise<BillingRateRecord | null>;
  listBillingRates(customerId: string): Promise<BillingRateRecord[]>;
  topUpCredits(input: {
    transactionId: string;
    customerId: string;
    organizationId: string;
    amount: number;
    idempotencyKey: string;
    referenceId: string;
    description: string;
    metadata: Record<string, unknown>;
    occurredAt: Date;
  }): Promise<CreditMutationResult>;
  createCreditHold(input: {
    holdId: string;
    transactionId: string;
    customerId: string;
    organizationId: string;
    deploymentId: string;
    module: OttoBillingModule;
    amount: number;
    idempotencyKey: string;
    expiresAt: Date;
    occurredAt: Date;
  }): Promise<CreditHoldMutationResult>;
  getCreditHold(id: string): Promise<CreditHoldRecord | null>;
  listExpiredCreditHolds(input: {
    customerId: string;
    expiredBefore: Date;
    limit: number;
  }): Promise<CreditHoldRecord[]>;
  captureCreditHold(input: {
    transactionId: string;
    holdId: string;
    customerId: string;
    amount: number;
    idempotencyKey: string;
    referenceId: string;
    description: string;
    occurredAt: Date;
  }): Promise<CreditHoldMutationResult | null>;
  releaseCreditHold(input: {
    transactionId: string;
    holdId: string;
    customerId: string;
    idempotencyKey: string;
    reason: 'released' | 'expired';
    description: string;
    occurredAt: Date;
  }): Promise<CreditHoldMutationResult | null>;
  consumeCredits(input: {
    transactionId: string;
    customerId: string;
    organizationId: string;
    deploymentId: string;
    module: OttoBillingModule;
    amount: number;
    idempotencyKey: string;
    referenceId: string;
    description: string;
    metadata: Record<string, unknown>;
    occurredAt: Date;
  }): Promise<CreditMutationResult>;
  registerExecutionReceiptKey(input: {
    deploymentId: string;
    keyId: string;
    publicKeyPem: string;
    notBefore: Date;
    expiresAt: Date | null;
    createdAt: Date;
  }): Promise<ExecutionReceiptKeyRecord>;
  bootstrapExecutionReceiptKey(input: {
    deploymentId: string;
    keyId: string;
    publicKeyPem: string;
    notBefore: Date;
    expiresAt: Date;
    createdAt: Date;
  }): Promise<{ key: ExecutionReceiptKeyRecord; replayed: boolean }>;
  revokeExecutionReceiptKey(input: {
    deploymentId: string;
    keyId: string;
    revokedAt: Date;
  }): Promise<ExecutionReceiptKeyRecord | null>;
  getExecutionReceiptKey(
    deploymentId: string,
    keyId: string,
  ): Promise<ExecutionReceiptKeyRecord | null>;
  listExecutionReceiptKeys(deploymentId: string): Promise<ExecutionReceiptKeyRecord[]>;
  ingestExecutionReceipt(input: {
    transactionId: string;
    customerId: string;
    amount: number;
    envelope: SignedExecutionReceiptV2;
    metadata: Record<string, unknown>;
    receivedAt: Date;
    edgeNodeId?: string;
  }): Promise<ExecutionReceiptMutationResult>;
  settleCreditHoldWithExecutionReceipt(input: {
    transactionId: string;
    holdId: string;
    customerId: string;
    amount: number;
    envelope: SignedExecutionReceiptV2;
    metadata: Record<string, unknown>;
    receivedAt: Date;
    edgeNodeId?: string;
  }): Promise<ExecutionReceiptHoldMutationResult | null>;
  getExecutionReceipt(receiptId: string): Promise<ExecutionReceiptRecord | null>;
  listExecutionReceipts(input: {
    customerId: string;
    from: Date;
    to: Date;
    organizationId?: string;
    deploymentId?: string;
    module?: OttoBillingModule;
    limit: number;
  }): Promise<ExecutionReceiptRecord[]>;
  registerEdgeBillingNode(input: {
    nodeId: string;
    deploymentId: string;
    organizationId: string;
    signingKeyId: string;
    createdAt: Date;
  }): Promise<EdgeBillingNodeRecord>;
  revokeEdgeBillingNode(input: {
    nodeId: string;
    deploymentId: string;
    revokedAt: Date;
  }): Promise<EdgeBillingNodeRecord | null>;
  getEdgeBillingNode(nodeId: string): Promise<EdgeBillingNodeRecord | null>;
  listEdgeBillingNodes(deploymentId: string): Promise<EdgeBillingNodeRecord[]>;
  enqueueEdgeBillingEvent(input: {
    eventId: string;
    nodeId: string;
    nodeSequence: number;
    customerId: string;
    deploymentId: string;
    organizationId: string;
    holdId: string | null;
    envelope: SignedExecutionReceiptV2;
    payloadSha256: string;
    receivedAt: Date;
  }): Promise<{ event: EdgeBillingAggregationEventRecord; replayed: boolean }>;
  listReadyEdgeBillingEvents(input: {
    now: Date;
    limit: number;
    nodeId?: string;
  }): Promise<EdgeBillingAggregationEventRecord[]>;
  markEdgeBillingEventReconciled(input: {
    eventId: string;
    reconciledAt: Date;
  }): Promise<EdgeBillingAggregationEventRecord | null>;
  markEdgeBillingEventFailed(input: {
    eventId: string;
    errorCode: string;
    nextAttemptAt: Date;
    deadLetter: boolean;
    updatedAt: Date;
  }): Promise<EdgeBillingAggregationEventRecord | null>;
  retryEdgeBillingDeadLetters(input: { now: Date; limit: number }): Promise<number>;
  getEdgeBillingAggregationStatus(deploymentId?: string): Promise<EdgeBillingAggregationStatus>;
  refundCredits(input: {
    transactionId: string;
    customerId: string;
    relatedTransactionId: string;
    amount: number;
    idempotencyKey: string;
    referenceId: string;
    description: string;
    metadata: Record<string, unknown>;
    occurredAt: Date;
  }): Promise<CreditMutationResult | null>;
  listCreditTransactions(input: {
    customerId: string;
    from: Date;
    to: Date;
    organizationId?: string;
    module?: OttoBillingModule;
    limit: number;
  }): Promise<CreditTransactionRecord[]>;
  getCreditStatement(input: {
    customerId: string;
    from: Date;
    to: Date;
  }): Promise<CreditStatement | null>;
  enqueueAlertDelivery(input: {
    id: string;
    channelId: string;
    source: AlertDeliveryRecord['source'];
    eventType: AlertDeliveryRecord['eventType'];
    fingerprint: string;
    severity: AlertSeverity;
    payload: AlertDeliveryPayload;
    createdAt: Date;
    audit: AuditEventInput;
  }): Promise<{ record: AlertDeliveryRecord; created: boolean }>;
  claimAlertDelivery(input: {
    now: Date;
    leaseUntil: Date;
    channelIds: string[];
  }): Promise<AlertDeliveryRecord | null>;
  finishAlertDelivery(input: {
    id: string;
    expectedLeaseUntil: Date;
    status: Extract<AlertDeliveryStatus, 'delivered' | 'retrying' | 'failed'>;
    nextAttemptAt: Date;
    lastError: string | null;
    deliveredAt: Date | null;
    updatedAt: Date;
    audit: AuditEventInput | null;
  }): Promise<AlertDeliveryRecord | null>;
  getAlertDelivery(id: string): Promise<AlertDeliveryRecord | null>;
  retryAlertDelivery(input: {
    id: string;
    retriedAt: Date;
    audit: AuditEventInput;
  }): Promise<AlertDeliveryRecord | null>;
  listAlertDeliveries(limit: number): Promise<AlertDeliveryRecord[]>;
  pruneAlertDeliveries(before: Date): Promise<number>;
  listAuditEvents(input: AuditEventQuery): Promise<AuditEventRecord[]>;
  listChainedAuditEvents(input: {
    afterSequence: number;
    throughSequence: number;
    limit: number;
  }): Promise<AuditEventRecord[]>;
  getAuditChainState(): Promise<AuditChainState>;
  countLegacyAuditEvents(): Promise<number>;
  enqueueAuditAnchor(input: {
    id: string;
    fingerprint: string;
    payload: AuditAnchorPayload;
    createdAt: Date;
    audit: AuditEventInput;
  }): Promise<{ record: AuditAnchorRecord; created: boolean }>;
  claimAuditAnchor(input: { now: Date; leaseUntil: Date }): Promise<AuditAnchorRecord | null>;
  finishAuditAnchor(input: {
    id: string;
    expectedLeaseUntil: Date;
    status: Extract<AuditAnchorStatus, 'delivered' | 'retrying' | 'failed'>;
    nextAttemptAt: Date;
    lastError: string | null;
    deliveredAt: Date | null;
    remoteReference: string | null;
    updatedAt: Date;
    audit: AuditEventInput | null;
  }): Promise<AuditAnchorRecord | null>;
  getAuditAnchor(id: string): Promise<AuditAnchorRecord | null>;
  getLatestAuditAnchor(): Promise<AuditAnchorRecord | null>;
  retryAuditAnchor(input: {
    id: string;
    retriedAt: Date;
    audit: AuditEventInput;
  }): Promise<AuditAnchorRecord | null>;
  listAuditAnchors(limit: number): Promise<AuditAnchorRecord[]>;
  ingestAuditWitnessReceipt(input: {
    record: AuditWitnessReceiptRecord;
    evidence?: AuditWitnessEvidenceRecord;
    audit: AuditEventInput;
  }): Promise<{ record: AuditWitnessReceiptRecord; replayed: boolean }>;
  listAuditWitnessReceipts(input: {
    sourceId?: string;
    limit: number;
  }): Promise<AuditWitnessReceiptRecord[]>;
  getAuditWitnessReceipt(id: string): Promise<AuditWitnessReceiptRecord | null>;
  claimAuditWitnessEvidence(input: {
    now: Date;
    leaseUntil: Date;
  }): Promise<AuditWitnessEvidenceRecord | null>;
  finishAuditWitnessEvidence(input: {
    receiptId: string;
    expectedLeaseUntil: Date;
    status: Extract<AuditWitnessEvidenceStatus, 'stored' | 'retrying' | 'failed'>;
    nextAttemptAt: Date;
    lastError: string | null;
    objectVersionId: string | null;
    serverSideEncryption: string | null;
    objectLockMode: string | null;
    objectLockRetainUntil: Date | null;
    storedAt: Date | null;
    verifiedAt: Date | null;
    updatedAt: Date;
    audit: AuditEventInput | null;
  }): Promise<AuditWitnessEvidenceRecord | null>;
  retryAuditWitnessEvidence(input: {
    receiptId: string;
    retriedAt: Date;
    audit: AuditEventInput;
  }): Promise<AuditWitnessEvidenceRecord | null>;
  listAuditWitnessEvidence(input: {
    status?: AuditWitnessEvidenceStatus;
    limit: number;
  }): Promise<AuditWitnessEvidenceRecord[]>;
  getAuditWitnessEvidence(receiptId: string): Promise<AuditWitnessEvidenceRecord | null>;
  restoreAuditWitnessEvidence(input: {
    receipt: AuditWitnessReceiptRecord;
    evidence: AuditWitnessEvidenceRecord;
    audit: AuditEventInput;
  }): Promise<{ record: AuditWitnessEvidenceRecord; replayed: boolean }>;
  summarizeAuditWitnessEvidence(): Promise<{
    counts: Record<AuditWitnessEvidenceStatus, number>;
    oldestPendingAt: Date | null;
    latestVerifiedAt: Date | null;
  }>;
  appendAuditEvent(input: AuditEventInput): Promise<void>;
}

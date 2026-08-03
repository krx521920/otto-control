import type {
  AuditEventInput,
  CommercialInventorySnapshot,
  ControlStore,
  CreateManagedReleaseArtifactInput,
  CreateLicenseRecordInput,
  CreateReleaseArtifactRecordInput,
  CreateUpdateReleaseRecordInput,
  CustomerRecord,
  DeploymentUpdateAssignmentRecord,
  DeploymentRecord,
  LicenseLifecycleEventRecord,
  LicenseRecord,
  LicenseSeatUsageRecord,
  ManagedReleaseArtifactRecord,
  ReleaseArtifactRecord,
  ReleaseArtifactEvidenceRecord,
  ReleaseArtifactRevocationResult,
  SigningKeyProvider,
  SigningKeyRecord,
  SigningKeyTransition,
  UpdateDistributionRecord,
  UpdateLicenseRecordInput,
  UpdateReleaseRecord,
  UpdateReleaseTransition,
} from '../../src/storage/control-store.js';
import type { OttoSeatEnforcement, OttoSeatStatus } from '../../src/contracts/license.js';
import type {
  DeploymentTelemetrySummary,
  OttoTelemetryEvent,
  OttoTelemetryReceipt,
} from '../../src/contracts/telemetry.js';
import type {
  AdminAccountRecord,
  AdminApprovalRecord,
  AdminPermission,
  AdminPrincipal,
  AdminRoleRecord,
  AdminSessionRecord,
} from '../../src/contracts/admin-identity.js';
import type {
  BillingRateRecord,
  CreditAccountRecord,
  CreditHoldMutationResult,
  CreditHoldRecord,
  CreditMutationResult,
  CreditStatement,
  CreditTransactionRecord,
  ExecutionReceiptKeyRecord,
  ExecutionReceiptMutationResult,
  ExecutionReceiptRecord,
  OttoBillingModule,
  SignedExecutionReceiptV2,
} from '../../src/contracts/billing.js';
import type {
  AlertDeliveryPayload,
  AlertDeliveryRecord,
  AlertDeliveryStatus,
  AlertSeverity,
} from '../../src/contracts/alert-delivery.js';
import type {
  AuditChainState,
  AuditEventQuery,
  AuditEventRecord,
} from '../../src/contracts/audit.js';
import type {
  AuditAnchorPayload,
  AuditAnchorRecord,
  AuditAnchorStatus,
} from '../../src/contracts/audit-anchor.js';
import type {
  AuditWitnessEvidenceRecord,
  AuditWitnessEvidenceStatus,
  AuditWitnessReceiptRecord,
} from '../../src/contracts/audit-witness.js';
import { AUDIT_GENESIS_HASH, auditEventHash } from '../../src/audit-chain.js';
import { conflict } from '../../src/errors.js';

const role = (
  id: string,
  name: string,
  permissions: AdminPermission[],
): AdminRoleRecord => ({ id, name, permissions, system: true });

const ALL_PERMISSIONS: AdminPermission[] = [
  'commercial.read', 'customer.create', 'deployment.create', 'license.issue', 'license.read',
  'license.export',
  'license.revoke', 'license.manage', 'license.transfer', 'license.usage.read',
  'signing_key.read', 'signing_key.manage', 'telemetry.read',
  'backup.read',
  'alert.read', 'alert.manage',
  'update_distribution.manage', 'update_release.create', 'update_release.read',
  'update_release.publish', 'identity.read', 'identity.manage', 'approval.request',
  'approval.read', 'approval.decide',
  'billing.read', 'billing.topup', 'billing.manage', 'billing.refund',
  'audit.read', 'audit.export', 'audit.verify', 'audit.anchor.manage',
  'customer_delivery.read',
];

interface StoredTelemetryEvent extends OttoTelemetryEvent {
  deploymentId: string;
  licenseId: string;
  receivedAtMs: number;
}

export class MemoryControlStore implements ControlStore {
  readonly customers = new Map<string, CustomerRecord>();
  readonly deployments = new Map<string, DeploymentRecord>();
  readonly licenses = new Map<string, LicenseRecord>();
  readonly licenseLifecycleEvents: LicenseLifecycleEventRecord[] = [];
  readonly licenseSeatUsage = new Map<string, LicenseSeatUsageRecord>();
  readonly signingKeys = new Map<string, SigningKeyRecord>();
  readonly nonces = new Map<string, number>();
  readonly audits: AuditEventInput[] = [];
  readonly auditRecords: AuditEventRecord[] = [];
  readonly telemetryEvents = new Map<string, StoredTelemetryEvent>();
  readonly telemetryNonces = new Set<string>();
  readonly updateDistributions = new Map<string, UpdateDistributionRecord>();
  readonly updateReleases = new Map<string, UpdateReleaseRecord>();
  readonly releaseArtifacts = new Map<string, ReleaseArtifactRecord>();
  readonly releaseArtifactEvidence = new Map<string, ReleaseArtifactEvidenceRecord>();
  readonly updateAssignments = new Map<string, DeploymentUpdateAssignmentRecord>();
  readonly updatePolicyNonces = new Set<string>();
  readonly adminAccounts = new Map<string, AdminAccountRecord>();
  readonly adminAccountRoles = new Map<string, string[]>();
  readonly adminEnrollments = new Map<string, { tokenHash: string; expiresAt: Date }>();
  readonly adminRecoveryCodes = new Map<string, Set<string>>();
  readonly adminSessions = new Map<string, AdminSessionRecord>();
  readonly adminApprovals = new Map<string, AdminApprovalRecord>();
  readonly adminApprovalDecisions = new Map<string, Map<string, 'approve' | 'reject'>>();
  readonly creditAccounts = new Map<string, CreditAccountRecord>();
  readonly billingRates = new Map<string, BillingRateRecord>();
  readonly creditHolds = new Map<string, CreditHoldRecord>();
  readonly creditTransactions = new Map<string, CreditTransactionRecord>();
  readonly executionReceiptKeys = new Map<string, ExecutionReceiptKeyRecord>();
  readonly executionReceipts = new Map<string, ExecutionReceiptRecord>();
  readonly executionReceiptSequences = new Map<string, number>();
  readonly alertDeliveries = new Map<string, AlertDeliveryRecord>();
  readonly auditAnchors = new Map<string, AuditAnchorRecord>();
  readonly auditWitnessReceipts: AuditWitnessReceiptRecord[] = [];
  readonly auditWitnessEvidence = new Map<string, AuditWitnessEvidenceRecord>();
  #auditHeadHash = AUDIT_GENESIS_HASH;
  readonly adminRoles = new Map<string, AdminRoleRecord>([
    ['super_admin', role('super_admin', 'Super administrator', ALL_PERMISSIONS)],
    ['security_admin', role('security_admin', 'Security administrator', [
      'signing_key.read', 'signing_key.manage', 'identity.read', 'identity.manage',
      'approval.request', 'approval.read', 'approval.decide', 'backup.read',
      'alert.read', 'alert.manage',
      'audit.read', 'audit.export', 'audit.verify', 'audit.anchor.manage',
    ])],
    ['license_admin', role('license_admin', 'License administrator', [
      'commercial.read', 'customer.create', 'deployment.create', 'license.issue', 'license.read',
      'license.export',
      'license.revoke', 'license.manage', 'license.transfer', 'license.usage.read',
      'telemetry.read', 'approval.request', 'approval.read',
      'billing.read', 'billing.topup', 'billing.manage', 'billing.refund',
    ])],
    ['release_admin', role('release_admin', 'Release administrator', [
      'update_distribution.manage', 'update_release.create', 'update_release.read',
      'update_release.publish', 'approval.request', 'approval.read',
    ])],
    ['auditor', role('auditor', 'Auditor', [
      'commercial.read', 'license.read', 'license.usage.read', 'signing_key.read', 'telemetry.read',
      'update_release.read',
      'identity.read', 'approval.read', 'backup.read',
      'alert.read',
      'billing.read',
      'audit.read', 'audit.export', 'audit.verify',
    ])],
  ]);

  async ping(): Promise<void> {}
  async close(): Promise<void> {}

  async createCustomer(input: { id: string; name: string }): Promise<CustomerRecord> {
    if (this.customers.has(input.id)) throw new Error('customer already exists');
    const now = new Date();
    const customer: CustomerRecord = {
      ...input,
      status: 'active',
      createdAt: now,
      updatedAt: now,
    };
    this.customers.set(customer.id, customer);
    return customer;
  }

  async getCommercialInventory(input: {
    nowMs: number;
    expiringWithinMs: number;
    recentLimit: number;
  }): Promise<CommercialInventorySnapshot> {
    const customers = [...this.customers.values()];
    const deployments = [...this.deployments.values()];
    const licenses = [...this.licenses.values()];
    const recent = <T extends { id: string; updatedAt: Date }>(records: T[]): T[] => records
      .sort((left, right) => (
        right.updatedAt.getTime() - left.updatedAt.getTime()
        || right.id.localeCompare(left.id)
      ))
      .slice(0, input.recentLimit);
    return {
      generatedAt: new Date(input.nowMs),
      counts: {
        customers: {
          total: customers.length,
          active: customers.filter((record) => record.status === 'active').length,
          suspended: customers.filter((record) => record.status === 'suspended').length,
        },
        deployments: {
          total: deployments.length,
          active: deployments.filter((record) => record.status === 'active').length,
          suspended: deployments.filter((record) => record.status === 'suspended').length,
        },
        licenses: {
          total: licenses.length,
          active: licenses.filter((record) => (
            record.revokedAtMs === null && record.expiresAtMs > input.nowMs
          )).length,
          expiringSoon: licenses.filter((record) => (
            record.revokedAtMs === null
            && record.expiresAtMs > input.nowMs
            && record.expiresAtMs <= input.nowMs + input.expiringWithinMs
          )).length,
          grace: licenses.filter((record) => (
            record.revokedAtMs === null
            && record.expiresAtMs <= input.nowMs
            && record.expiresAtMs + record.gracePeriodMs > input.nowMs
          )).length,
          expired: licenses.filter((record) => (
            record.revokedAtMs === null
            && record.expiresAtMs + record.gracePeriodMs <= input.nowMs
          )).length,
          revoked: licenses.filter((record) => record.revokedAtMs !== null).length,
        },
      },
      recentCustomers: recent(customers),
      recentDeployments: recent(deployments),
      recentLicenses: recent(licenses),
    };
  }

  async createDeployment(input: {
    id: string;
    customerId: string;
    organizationId: string;
    machineFingerprint: string;
    name: string;
  }): Promise<DeploymentRecord> {
    const customer = this.customers.get(input.customerId);
    if (!customer) throw new Error('customer does not exist');
    const now = new Date();
    const deployment: DeploymentRecord = {
      ...input,
      customerName: customer.name,
      status: 'active',
      createdAt: now,
      updatedAt: now,
    };
    this.deployments.set(deployment.id, deployment);
    return deployment;
  }

  async getDeployment(id: string): Promise<DeploymentRecord | null> {
    return this.deployments.get(id) ?? null;
  }

  async createLicense(input: CreateLicenseRecordInput): Promise<LicenseRecord> {
    const now = new Date();
    const license = { ...input, createdAt: now, updatedAt: now };
    this.licenses.set(license.id, license);
    return license;
  }

  async getLicense(id: string): Promise<LicenseRecord | null> {
    return this.licenses.get(id) ?? null;
  }

  async revokeLicense(id: string, revokedAtMs: number): Promise<LicenseRecord | null> {
    const existing = this.licenses.get(id);
    if (!existing) return null;
    const updated = {
      ...existing,
      revokedAtMs: existing.revokedAtMs ?? revokedAtMs,
      updatedAt: new Date(revokedAtMs),
    };
    this.licenses.set(id, updated);
    return updated;
  }

  async updateLicense(input: UpdateLicenseRecordInput): Promise<LicenseRecord | null> {
    const existing = this.licenses.get(input.id);
    if (!existing || existing.revision !== input.expectedRevision) return null;
    if (input.deploymentMachineFingerprint) {
      const binding = input.deploymentMachineFingerprint;
      const deployment = this.deployments.get(binding.deploymentId);
      if (!deployment || deployment.machineFingerprint !== binding.expectedFingerprint) return null;
      this.deployments.set(binding.deploymentId, {
        ...deployment,
        machineFingerprint: binding.newFingerprint,
        updatedAt: new Date(),
      });
    }
    const updated: LicenseRecord = {
      ...input,
      createdAt: existing.createdAt,
      updatedAt: new Date(),
    };
    this.licenses.set(input.id, updated);
    if (input.resetSeatUsage) this.licenseSeatUsage.delete(input.id);
    this.licenseLifecycleEvents.push({
      id: this.licenseLifecycleEvents.length + 1,
      licenseId: input.id,
      revision: input.revision,
      changeType: input.changeType,
      actorId: input.actorId,
      detail: input.changeDetail,
      createdAt: updated.updatedAt,
    });
    return updated;
  }

  async listLicenseLifecycleEvents(
    licenseId: string,
    limit: number,
  ): Promise<LicenseLifecycleEventRecord[]> {
    return this.licenseLifecycleEvents
      .filter((event) => event.licenseId === licenseId)
      .sort((left, right) => right.revision - left.revision)
      .slice(0, limit);
  }

  async getLicenseSeatUsage(licenseId: string): Promise<LicenseSeatUsageRecord | null> {
    return this.licenseSeatUsage.get(licenseId) ?? null;
  }

  async recordLicenseSeatUsage(input: {
    licenseId: string;
    deploymentId: string;
    activeSeats: number;
    seatLimit: number;
    gracePeriodMs: number;
    enforcement: OttoSeatEnforcement;
    reportedAtMs: number;
  }): Promise<LicenseSeatUsageRecord> {
    const previous = this.licenseSeatUsage.get(input.licenseId);
    const overLimit = input.activeSeats > input.seatLimit;
    const overageStartedAtMs = overLimit && input.enforcement === 'enforce'
      ? previous?.overageStartedAtMs ?? input.reportedAtMs
      : null;
    const graceExpiresAtMs = overageStartedAtMs === null
      ? null
      : overageStartedAtMs + input.gracePeriodMs;
    const status: OttoSeatStatus = !overLimit
      ? 'within_limit'
      : input.enforcement === 'monitor'
        ? 'over_limit_monitor'
        : input.reportedAtMs >= graceExpiresAtMs!
          ? 'blocked'
          : 'overage_grace';
    const record: LicenseSeatUsageRecord = {
      licenseId: input.licenseId,
      deploymentId: input.deploymentId,
      activeSeats: input.activeSeats,
      seatLimit: input.seatLimit,
      status,
      overageStartedAtMs,
      graceExpiresAtMs,
      lastReportedAtMs: input.reportedAtMs,
    };
    this.licenseSeatUsage.set(input.licenseId, record);
    return record;
  }

  async registerSigningKey(input: {
    keyId: string;
    publicKeyPem: string;
    provider: SigningKeyProvider;
  }): Promise<SigningKeyRecord> {
    const existing = this.signingKeys.get(input.keyId);
    if (existing) {
      if (existing.publicKeyPem !== input.publicKeyPem || existing.provider !== input.provider) {
        throw new Error('signing key id is already bound to another provider or public key');
      }
      return existing;
    }
    const now = new Date();
    const key: SigningKeyRecord = {
      ...input,
      algorithm: 'ed25519',
      state: 'standby',
      createdAt: now,
      activatedAt: null,
      retiredAt: null,
      revokedAt: null,
      revocationReason: null,
      updatedAt: now,
    };
    this.signingKeys.set(key.keyId, key);
    return key;
  }

  async getSigningKey(keyId: string): Promise<SigningKeyRecord | null> {
    return this.signingKeys.get(keyId) ?? null;
  }

  async listSigningKeys(): Promise<SigningKeyRecord[]> {
    return [...this.signingKeys.values()];
  }

  async activateSigningKey(
    keyId: string,
    changedAt: Date,
  ): Promise<SigningKeyTransition | null> {
    const target = this.signingKeys.get(keyId);
    if (!target) return null;
    if (target.state === 'revoked') throw new Error('revoked signing key cannot be activated');
    const previous = [...this.signingKeys.values()].find((key) => key.state === 'active');
    if (previous && previous.keyId !== keyId) {
      this.signingKeys.set(previous.keyId, {
        ...previous,
        state: 'retired',
        retiredAt: changedAt,
        updatedAt: changedAt,
      });
    }
    const active: SigningKeyRecord = {
      ...target,
      state: 'active',
      activatedAt: target.activatedAt ?? changedAt,
      retiredAt: null,
      updatedAt: changedAt,
    };
    this.signingKeys.set(keyId, active);
    return { key: active, activeKey: active, previousActiveKey: previous ?? null };
  }

  async retireSigningKey(
    keyId: string,
    changedAt: Date,
  ): Promise<SigningKeyTransition | null> {
    const target = this.signingKeys.get(keyId);
    if (!target) return null;
    if (target.state === 'active') throw new Error('activate a replacement before retiring the active key');
    if (target.state === 'revoked') throw new Error('revoked signing key cannot be retired');
    const retired: SigningKeyRecord = {
      ...target,
      state: 'retired',
      retiredAt: target.retiredAt ?? changedAt,
      updatedAt: changedAt,
    };
    this.signingKeys.set(keyId, retired);
    return {
      key: retired,
      activeKey: [...this.signingKeys.values()].find((key) => key.state === 'active') ?? null,
      previousActiveKey: null,
    };
  }

  async revokeSigningKey(input: {
    keyId: string;
    replacementKeyId: string | null;
    reason: string;
    changedAt: Date;
  }): Promise<SigningKeyTransition | null> {
    const target = this.signingKeys.get(input.keyId);
    if (!target) return null;
    if (target.state === 'revoked') {
      return {
        key: target,
        activeKey: [...this.signingKeys.values()].find((key) => key.state === 'active') ?? null,
        previousActiveKey: null,
      };
    }
    let activeKey = [...this.signingKeys.values()].find((key) => key.state === 'active') ?? null;
    if (target.state === 'active') {
      if (!input.replacementKeyId || input.replacementKeyId === input.keyId) {
        throw new Error('revoking the active key requires a different replacement key');
      }
      const replacement = this.signingKeys.get(input.replacementKeyId);
      if (!replacement || replacement.state === 'revoked') {
        throw new Error('replacement signing key does not exist');
      }
      activeKey = {
        ...replacement,
        state: 'active',
        activatedAt: replacement.activatedAt ?? input.changedAt,
        retiredAt: null,
        updatedAt: input.changedAt,
      };
      this.signingKeys.set(activeKey.keyId, activeKey);
    }
    const revoked: SigningKeyRecord = {
      ...target,
      state: 'revoked',
      revokedAt: input.changedAt,
      retiredAt: target.retiredAt ?? input.changedAt,
      revocationReason: input.reason,
      updatedAt: input.changedAt,
    };
    this.signingKeys.set(input.keyId, revoked);
    return {
      key: revoked,
      activeKey: activeKey?.keyId === revoked.keyId ? null : activeKey,
      previousActiveKey: target.state === 'active' ? target : null,
    };
  }

  async countAdminAccounts(): Promise<number> {
    return this.adminAccounts.size;
  }

  async createAdminAccount(input: {
    id: string;
    username: string;
    displayName: string;
    passwordHash: string;
    mfaSecretCiphertext: string;
    enrollmentTokenHash: string;
    enrollmentExpiresAt: Date;
    roleIds: string[];
  }): Promise<AdminAccountRecord> {
    if ([...this.adminAccounts.values()].some((account) => account.username === input.username)) {
      throw new Error('admin account already exists');
    }
    if (input.roleIds.some((roleId) => !this.adminRoles.has(roleId))) {
      throw new Error('admin role does not exist');
    }
    const now = new Date();
    const account: AdminAccountRecord = {
      id: input.id,
      username: input.username,
      displayName: input.displayName,
      passwordHash: input.passwordHash,
      mfaSecretCiphertext: input.mfaSecretCiphertext,
      status: 'pending',
      failedLoginCount: 0,
      lockedUntil: null,
      mfaConfirmedAt: null,
      createdAt: now,
      updatedAt: now,
    };
    this.adminAccounts.set(account.id, account);
    this.adminAccountRoles.set(account.id, [...new Set(input.roleIds)]);
    this.adminEnrollments.set(account.id, {
      tokenHash: input.enrollmentTokenHash,
      expiresAt: input.enrollmentExpiresAt,
    });
    return account;
  }

  async getAdminAccountById(id: string): Promise<AdminAccountRecord | null> {
    return this.adminAccounts.get(id) ?? null;
  }

  async getAdminAccountByUsername(username: string): Promise<AdminAccountRecord | null> {
    return [...this.adminAccounts.values()].find((account) => account.username === username) ?? null;
  }

  async listAdminAccounts(): Promise<Array<AdminAccountRecord & { roles: string[] }>> {
    return [...this.adminAccounts.values()].map((account) => ({
      ...account,
      roles: [...(this.adminAccountRoles.get(account.id) ?? [])],
    }));
  }

  async listAdminRoles(): Promise<AdminRoleRecord[]> {
    return [...this.adminRoles.values()].map((entry) => ({
      ...entry,
      permissions: [...entry.permissions],
    }));
  }

  async replaceAdminAccountRoles(accountId: string, roleIds: string[]): Promise<string[] | null> {
    if (!this.adminAccounts.has(accountId)) return null;
    if (roleIds.some((roleId) => !this.adminRoles.has(roleId))) {
      throw new Error('admin role does not exist');
    }
    const roles = [...new Set(roleIds)];
    this.adminAccountRoles.set(accountId, roles);
    return roles;
  }

  async setAdminAccountStatus(
    accountId: string,
    status: AdminAccountRecord['status'],
    changedAt: Date,
  ): Promise<AdminAccountRecord | null> {
    const account = this.adminAccounts.get(accountId);
    if (!account) return null;
    const updated = { ...account, status, updatedAt: changedAt };
    this.adminAccounts.set(accountId, updated);
    return updated;
  }

  async confirmAdminEnrollment(input: {
    accountId: string;
    enrollmentTokenHash: string;
    recoveryCodeHashes: string[];
    confirmedAt: Date;
  }): Promise<AdminAccountRecord | null> {
    const account = this.adminAccounts.get(input.accountId);
    const enrollment = this.adminEnrollments.get(input.accountId);
    if (!account || !enrollment || enrollment.tokenHash !== input.enrollmentTokenHash) return null;
    if (enrollment.expiresAt.getTime() <= input.confirmedAt.getTime()) return null;
    const updated: AdminAccountRecord = {
      ...account,
      status: 'active',
      mfaConfirmedAt: input.confirmedAt,
      updatedAt: input.confirmedAt,
    };
    this.adminAccounts.set(account.id, updated);
    this.adminEnrollments.delete(account.id);
    this.adminRecoveryCodes.set(account.id, new Set(input.recoveryCodeHashes));
    return updated;
  }

  async recordAdminLoginFailure(input: {
    accountId: string;
    failedLoginCount: number;
    lockedUntil: Date | null;
    changedAt: Date;
  }): Promise<void> {
    const account = this.adminAccounts.get(input.accountId);
    if (!account) return;
    this.adminAccounts.set(account.id, {
      ...account,
      failedLoginCount: input.failedLoginCount,
      lockedUntil: input.lockedUntil,
      updatedAt: input.changedAt,
    });
  }

  async clearAdminLoginFailures(accountId: string, changedAt: Date): Promise<void> {
    const account = this.adminAccounts.get(accountId);
    if (!account) return;
    this.adminAccounts.set(account.id, {
      ...account,
      failedLoginCount: 0,
      lockedUntil: null,
      updatedAt: changedAt,
    });
  }

  async consumeAdminRecoveryCode(
    accountId: string,
    codeHash: string,
    usedAt: Date,
  ): Promise<boolean> {
    void usedAt;
    const codes = this.adminRecoveryCodes.get(accountId);
    if (!codes?.delete(codeHash)) return false;
    return true;
  }

  async createAdminSession(input: {
    id: string;
    accountId: string;
    tokenHash: string;
    expiresAt: Date;
    mfaVerifiedAt: Date;
    createdAt: Date;
  }): Promise<AdminSessionRecord> {
    const account = this.adminAccounts.get(input.accountId);
    if (!account) throw new Error('admin account does not exist');
    const session: AdminSessionRecord = {
      ...input,
      username: account.username,
      displayName: account.displayName,
      lastSeenAt: input.createdAt,
      revokedAt: null,
    };
    this.adminSessions.set(session.id, session);
    return session;
  }

  async getAdminPrincipalBySessionTokenHash(input: {
    tokenHash: string;
    now: Date;
    idleCutoff: Date;
  }): Promise<AdminPrincipal | null> {
    const session = [...this.adminSessions.values()].find((entry) => entry.tokenHash === input.tokenHash);
    if (!session || session.revokedAt || session.expiresAt <= input.now || session.lastSeenAt < input.idleCutoff) {
      return null;
    }
    const account = this.adminAccounts.get(session.accountId);
    if (!account || account.status !== 'active') return null;
    const roles = this.adminAccountRoles.get(account.id) ?? [];
    const permissions = [...new Set(roles.flatMap((roleId) => (
      this.adminRoles.get(roleId)?.permissions ?? []
    )))];
    return {
      accountId: account.id,
      sessionId: session.id,
      username: account.username,
      displayName: account.displayName,
      roles: [...roles],
      permissions,
      mfaVerifiedAt: session.mfaVerifiedAt,
    };
  }

  async touchAdminSession(sessionId: string, seenAt: Date): Promise<void> {
    const session = this.adminSessions.get(sessionId);
    if (session) this.adminSessions.set(sessionId, { ...session, lastSeenAt: seenAt });
  }

  async revokeAdminSession(sessionId: string, revokedAt: Date): Promise<void> {
    const session = this.adminSessions.get(sessionId);
    if (session) this.adminSessions.set(sessionId, { ...session, revokedAt });
  }

  async revokeAdminAccountSessions(accountId: string, revokedAt: Date): Promise<void> {
    for (const [id, session] of this.adminSessions) {
      if (session.accountId === accountId && !session.revokedAt) {
        this.adminSessions.set(id, { ...session, revokedAt });
      }
    }
  }

  async createAdminApproval(input: {
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
  }): Promise<AdminApprovalRecord> {
    const approval: AdminApprovalRecord = {
      ...input,
      status: 'pending',
      approvalCount: 0,
      executedAt: null,
      updatedAt: input.createdAt,
    };
    this.adminApprovals.set(approval.id, approval);
    return approval;
  }

  async getAdminApproval(id: string): Promise<AdminApprovalRecord | null> {
    return this.adminApprovals.get(id) ?? null;
  }

  async listAdminApprovals(limit: number): Promise<AdminApprovalRecord[]> {
    return [...this.adminApprovals.values()]
      .sort((left, right) => right.createdAt.getTime() - left.createdAt.getTime())
      .slice(0, limit);
  }

  async decideAdminApproval(input: {
    approvalId: string;
    accountId: string;
    decision: 'approve' | 'reject';
    reason: string | null;
    decidedAt: Date;
  }): Promise<AdminApprovalRecord | null> {
    const approval = this.adminApprovals.get(input.approvalId);
    if (!approval) return null;
    if (approval.requesterAccountId === input.accountId) throw new Error('self approval is not allowed');
    if (approval.status !== 'pending' || approval.expiresAt <= input.decidedAt) return approval;
    const decisions = this.adminApprovalDecisions.get(approval.id) ?? new Map();
    if (decisions.has(input.accountId)) throw new Error('approval decision already exists');
    decisions.set(input.accountId, input.decision);
    this.adminApprovalDecisions.set(approval.id, decisions);
    const approvalCount = [...decisions.values()].filter((decision) => decision === 'approve').length;
    const status = input.decision === 'reject'
      ? 'rejected' as const
      : approvalCount >= approval.requiredApprovals ? 'approved' as const : 'pending' as const;
    const updated = { ...approval, status, approvalCount, updatedAt: input.decidedAt };
    this.adminApprovals.set(approval.id, updated);
    return updated;
  }

  async consumeAdminApproval(input: {
    approvalId: string;
    requesterAccountId: string;
    operation: string;
    targetType: string;
    targetId: string;
    requestHash: string;
    executedAt: Date;
  }): Promise<AdminApprovalRecord | null> {
    const approval = this.adminApprovals.get(input.approvalId);
    if (!approval || approval.status !== 'approved' || approval.expiresAt <= input.executedAt) return null;
    if (
      approval.requesterAccountId !== input.requesterAccountId
      || approval.operation !== input.operation
      || approval.targetType !== input.targetType
      || approval.targetId !== input.targetId
      || approval.requestHash !== input.requestHash
    ) return null;
    const updated: AdminApprovalRecord = {
      ...approval,
      status: 'executed',
      executedAt: input.executedAt,
      updatedAt: input.executedAt,
    };
    this.adminApprovals.set(approval.id, updated);
    return updated;
  }

  async consumeLeaseNonce(input: {
    deploymentId: string;
    nonce: string;
    nowMs: number;
    expiresAtMs: number;
  }): Promise<boolean> {
    for (const [nonce, expiresAtMs] of this.nonces) {
      if (expiresAtMs < input.nowMs) this.nonces.delete(nonce);
    }
    const key = `${input.deploymentId}\0${input.nonce}`;
    if (this.nonces.has(key)) return false;
    this.nonces.set(key, input.expiresAtMs);
    return true;
  }

  async ingestTelemetryBatch(input: {
    deploymentId: string;
    licenseId: string;
    nonce: string;
    nonceExpiresAtMs: number;
    retentionBeforeMs: number;
    receivedAtMs: number;
    events: OttoTelemetryEvent[];
  }): Promise<OttoTelemetryReceipt | null> {
    const nonceKey = `${input.deploymentId}\0${input.nonce}`;
    if (this.telemetryNonces.has(nonceKey)) return null;
    this.telemetryNonces.add(nonceKey);
    for (const [key, event] of this.telemetryEvents) {
      if (event.receivedAtMs < input.retentionBeforeMs) this.telemetryEvents.delete(key);
    }
    let accepted = 0;
    let duplicates = 0;
    for (const event of input.events) {
      const key = `${input.deploymentId}\0${event.id}`;
      if (this.telemetryEvents.has(key)) {
        duplicates += 1;
      } else {
        accepted += 1;
        this.telemetryEvents.set(key, {
          ...event,
          deploymentId: input.deploymentId,
          licenseId: input.licenseId,
          receivedAtMs: input.receivedAtMs,
        });
      }
    }
    return { accepted, duplicates };
  }

  async getDeploymentTelemetrySummary(input: {
    deploymentId: string;
    sinceMs: number;
  }): Promise<DeploymentTelemetrySummary> {
    const allEvents = [...this.telemetryEvents.values()]
      .filter((event) => event.deploymentId === input.deploymentId);
    const events = allEvents.filter((event) => event.receivedAtMs >= input.sinceMs);
    const eventCounts: Record<string, number> = {};
    for (const event of events) {
      eventCounts[event.eventType] = (eventCounts[event.eventType] ?? 0) + 1;
    }
    const latestRuntimeHealth = allEvents
      .filter((event) => event.eventType === 'runtime_health')
      .sort((left, right) => right.createdAtMs - left.createdAtMs)[0];
    const lastSeen = allEvents
      .map((event) => event.receivedAtMs)
      .sort((left, right) => right - left)[0];
    return {
      deploymentId: input.deploymentId,
      evidenceTrust: 'customer_server_reported',
      since: new Date(input.sinceMs).toISOString(),
      totalEvents: events.length,
      lastSeenAt: lastSeen === undefined ? null : new Date(lastSeen).toISOString(),
      eventCounts,
      latestRuntimeHealth: latestRuntimeHealth
        ? {
            createdAt: new Date(latestRuntimeHealth.createdAtMs).toISOString(),
            receivedAt: new Date(latestRuntimeHealth.receivedAtMs).toISOString(),
            payload: latestRuntimeHealth.payload,
          }
        : null,
    };
  }

  async createUpdateDistribution(input: {
    id: string;
    name: string;
  }): Promise<UpdateDistributionRecord> {
    if (this.updateDistributions.has(input.id)) throw new Error('distribution already exists');
    const now = new Date();
    const distribution: UpdateDistributionRecord = {
      ...input,
      status: 'active',
      createdAt: now,
      updatedAt: now,
    };
    this.updateDistributions.set(distribution.id, distribution);
    return distribution;
  }

  async getUpdateDistribution(id: string): Promise<UpdateDistributionRecord | null> {
    return this.updateDistributions.get(id) ?? null;
  }

  async assignDeploymentUpdateDistribution(input: {
    deploymentId: string;
    distributionId: string;
    updatedAt: Date;
  }): Promise<DeploymentUpdateAssignmentRecord> {
    if (!this.deployments.has(input.deploymentId)) throw new Error('deployment does not exist');
    if (!this.updateDistributions.has(input.distributionId)) {
      throw new Error('distribution does not exist');
    }
    const assignment = { ...input };
    this.updateAssignments.set(`${input.deploymentId}\0${input.distributionId}`, assignment);
    return assignment;
  }

  async hasDeploymentUpdateAssignment(
    deploymentId: string,
    distributionId: string,
  ): Promise<boolean> {
    return this.updateAssignments.has(`${deploymentId}\0${distributionId}`);
  }

  async createUpdateRelease(input: CreateUpdateReleaseRecordInput): Promise<UpdateReleaseRecord> {
    if (!this.updateDistributions.has(input.distributionId)) {
      throw new Error('distribution does not exist');
    }
    if (this.updateReleases.has(input.id)) throw new Error('release already exists');
    const duplicate = [...this.updateReleases.values()].some((release) => (
      release.distributionId === input.distributionId
      && release.version === input.version
      && release.channel === input.channel
    ));
    if (duplicate) throw new Error('release already exists');
    const now = new Date();
    const release: UpdateReleaseRecord = {
      ...input,
      state: 'draft',
      previousReleaseId: null,
      publishedAt: null,
      createdAt: now,
      updatedAt: now,
    };
    this.updateReleases.set(release.id, release);
    return release;
  }

  async getUpdateRelease(id: string): Promise<UpdateReleaseRecord | null> {
    return this.updateReleases.get(id) ?? null;
  }

  async listUpdateReleases(distributionId: string): Promise<UpdateReleaseRecord[]> {
    return [...this.updateReleases.values()]
      .filter((release) => release.distributionId === distributionId)
      .sort((left, right) => right.createdAt.getTime() - left.createdAt.getTime());
  }

  async activateUpdateRelease(
    id: string,
    publishedAt: Date,
  ): Promise<UpdateReleaseTransition | null> {
    const candidate = this.updateReleases.get(id);
    if (!candidate) return null;
    if (candidate.state === 'active') throw new Error('release is already active');
    if (candidate.state === 'rolled_back') throw new Error('release cannot be reactivated');
    const previous = [...this.updateReleases.values()].find((release) => (
      release.id !== id
      && release.distributionId === candidate.distributionId
      && release.channel === candidate.channel
      && release.state === 'active'
    ));
    if (previous) {
      this.updateReleases.set(previous.id, {
        ...previous,
        state: 'paused',
        updatedAt: publishedAt,
      });
    }
    const release: UpdateReleaseRecord = {
      ...candidate,
      state: 'active',
      previousReleaseId: previous?.id ?? null,
      publishedAt: candidate.publishedAt ?? publishedAt,
      updatedAt: publishedAt,
    };
    this.updateReleases.set(id, release);
    return { release, fallback: previous ?? null };
  }

  async pauseUpdateRelease(id: string, updatedAt: Date): Promise<UpdateReleaseRecord | null> {
    const existing = this.updateReleases.get(id);
    if (!existing) return null;
    if (existing.state !== 'active') return null;
    const release: UpdateReleaseRecord = { ...existing, state: 'paused', updatedAt };
    this.updateReleases.set(id, release);
    return release;
  }

  async rollbackUpdateRelease(
    id: string,
    updatedAt: Date,
  ): Promise<UpdateReleaseTransition | null> {
    const existing = this.updateReleases.get(id);
    if (!existing) return null;
    if (existing.state !== 'active' && existing.state !== 'paused') {
      throw new Error('release cannot be rolled back');
    }
    const release: UpdateReleaseRecord = { ...existing, state: 'rolled_back', updatedAt };
    this.updateReleases.set(id, release);
    const previous = existing.previousReleaseId
      ? this.updateReleases.get(existing.previousReleaseId)
      : undefined;
    const fallback = previous
      ? { ...previous, state: 'active' as const, updatedAt }
      : null;
    if (fallback) this.updateReleases.set(fallback.id, fallback);
    return { release, fallback };
  }

  async getActiveUpdateReleases(distributionId: string): Promise<UpdateReleaseRecord[]> {
    const priority = { required: 0, stable: 1, canary: 2 } as const;
    return [...this.updateReleases.values()]
      .filter((release) => release.distributionId === distributionId && release.state === 'active')
      .sort((left, right) => priority[left.channel] - priority[right.channel]);
  }

  async createReleaseArtifact(
    input: CreateReleaseArtifactRecordInput,
  ): Promise<ReleaseArtifactRecord> {
    if (!this.updateReleases.has(input.releaseId)) throw conflict('release does not exist');
    if (this.releaseArtifacts.has(input.id)) throw conflict('release artifact already exists');
    const duplicate = [...this.releaseArtifacts.values()].some((artifact) => (
      artifact.releaseId === input.releaseId
      && artifact.kind === input.kind
      && artifact.platform === input.platform
    ));
    if (duplicate) throw conflict('release artifact already exists for this kind and platform');
    const artifact: ReleaseArtifactRecord = {
      ...input,
      state: 'active',
      revokedAt: null,
      revokedBy: null,
      revocationReason: null,
      updatedAt: input.createdAt,
    };
    this.releaseArtifacts.set(artifact.id, artifact);
    return artifact;
  }

  async getReleaseArtifact(id: string): Promise<ReleaseArtifactRecord | null> {
    return this.releaseArtifacts.get(id) ?? null;
  }

  async createManagedReleaseArtifact(
    input: CreateManagedReleaseArtifactInput,
  ): Promise<ManagedReleaseArtifactRecord> {
    if ([...this.releaseArtifactEvidence.values()].some(
      (evidence) => evidence.objectKey === input.evidence.objectKey,
    )) {
      throw conflict('managed release object already exists');
    }
    const artifact = await this.createReleaseArtifact(input.artifact);
    const evidence: ReleaseArtifactEvidenceRecord = {
      artifactId: artifact.id,
      ...input.evidence,
      createdAt: artifact.createdAt,
    };
    this.releaseArtifactEvidence.set(artifact.id, evidence);
    return { artifact, evidence };
  }

  async getReleaseArtifactEvidence(id: string): Promise<ReleaseArtifactEvidenceRecord | null> {
    return this.releaseArtifactEvidence.get(id) ?? null;
  }

  async listReleaseArtifacts(releaseId: string): Promise<ReleaseArtifactRecord[]> {
    return [...this.releaseArtifacts.values()]
      .filter((artifact) => artifact.releaseId === releaseId)
      .sort((left, right) => left.createdAt.getTime() - right.createdAt.getTime());
  }

  async revokeReleaseArtifact(input: {
    id: string;
    actorId: string;
    reason: string;
    revokedAt: Date;
  }): Promise<ReleaseArtifactRevocationResult | null> {
    const existing = this.releaseArtifacts.get(input.id);
    if (!existing || existing.state !== 'active') return null;
    const artifact: ReleaseArtifactRecord = {
      ...existing,
      state: 'revoked',
      revokedAt: input.revokedAt,
      revokedBy: input.actorId,
      revocationReason: input.reason,
      updatedAt: input.revokedAt,
    };
    this.releaseArtifacts.set(input.id, artifact);
    const release = this.updateReleases.get(artifact.releaseId);
    const releasePaused = release?.state === 'active';
    if (releasePaused) {
      this.updateReleases.set(release.id, {
        ...release,
        state: 'paused',
        updatedAt: input.revokedAt,
      });
    }
    return { artifact, releasePaused };
  }

  async consumeUpdatePolicyNonce(input: {
    deploymentId: string;
    nonce: string;
    expiresAtMs: number;
  }): Promise<boolean> {
    const key = `${input.deploymentId}\0${input.nonce}`;
    if (this.updatePolicyNonces.has(key)) return false;
    this.updatePolicyNonces.add(key);
    return true;
  }

  #creditAccount(customerId: string, create = false): CreditAccountRecord | null {
    const existing = this.creditAccounts.get(customerId);
    if (existing) return existing;
    if (!create) return null;
    if (!this.customers.has(customerId)) throw conflict('customer does not exist');
    const now = new Date();
    const account: CreditAccountRecord = {
      customerId,
      availableBalance: 0,
      frozenBalance: 0,
      totalToppedUp: 0,
      totalConsumed: 0,
      totalRefunded: 0,
      version: 1,
      createdAt: now,
      updatedAt: now,
    };
    this.creditAccounts.set(customerId, account);
    return account;
  }

  #transactionByKey(customerId: string, key: string): CreditTransactionRecord | null {
    return [...this.creditTransactions.values()].find((transaction) => (
      transaction.customerId === customerId && transaction.idempotencyKey === key
    )) ?? null;
  }

  #updateCreditAccount(
    current: CreditAccountRecord,
    values: Partial<CreditAccountRecord>,
    changedAt: Date,
  ): CreditAccountRecord {
    const account = {
      ...current,
      ...values,
      version: current.version + 1,
      updatedAt: changedAt,
    };
    this.creditAccounts.set(current.customerId, account);
    return account;
  }

  async getCreditAccount(customerId: string): Promise<CreditAccountRecord | null> {
    return this.#creditAccount(customerId);
  }

  async setBillingRate(input: {
    customerId: string;
    module: OttoBillingModule;
    unitSize: number;
    creditsPerUnit: number;
    actorId: string;
    changedAt: Date;
  }): Promise<BillingRateRecord> {
    if (!this.customers.has(input.customerId)) throw conflict('customer does not exist');
    const key = `${input.customerId}\0${input.module}`;
    const existing = this.billingRates.get(key);
    const rate: BillingRateRecord = {
      customerId: input.customerId,
      module: input.module,
      unitSize: input.unitSize,
      creditsPerUnit: input.creditsPerUnit,
      updatedBy: input.actorId,
      createdAt: existing?.createdAt ?? input.changedAt,
      updatedAt: input.changedAt,
    };
    this.billingRates.set(key, rate);
    return rate;
  }

  async getBillingRate(
    customerId: string,
    module: OttoBillingModule,
  ): Promise<BillingRateRecord | null> {
    return this.billingRates.get(`${customerId}\0${module}`) ?? null;
  }

  async listBillingRates(customerId: string): Promise<BillingRateRecord[]> {
    return [...this.billingRates.values()]
      .filter((rate) => rate.customerId === customerId)
      .sort((left, right) => left.module.localeCompare(right.module));
  }

  async topUpCredits(input: {
    transactionId: string;
    customerId: string;
    amount: number;
    idempotencyKey: string;
    referenceId: string;
    description: string;
    metadata: Record<string, unknown>;
    occurredAt: Date;
  }): Promise<CreditMutationResult> {
    const current = this.#creditAccount(input.customerId, true)!;
    const replay = this.#transactionByKey(input.customerId, input.idempotencyKey);
    if (replay) {
      if (
        replay.type !== 'topup' || replay.availableDelta !== input.amount ||
        replay.referenceId !== input.referenceId
      ) throw conflict('idempotency key was already used for a different operation');
      return { account: current, transaction: replay, replayed: true };
    }
    const account = this.#updateCreditAccount(current, {
      availableBalance: current.availableBalance + input.amount,
      totalToppedUp: current.totalToppedUp + input.amount,
    }, input.occurredAt);
    const transaction: CreditTransactionRecord = {
      id: input.transactionId,
      customerId: input.customerId,
      organizationId: null,
      deploymentId: null,
      module: null,
      type: 'topup',
      availableDelta: input.amount,
      frozenDelta: 0,
      billedAmount: 0,
      availableAfter: account.availableBalance,
      frozenAfter: account.frozenBalance,
      idempotencyKey: input.idempotencyKey,
      referenceId: input.referenceId,
      relatedTransactionId: null,
      description: input.description,
      metadata: input.metadata,
      occurredAt: input.occurredAt,
      createdAt: input.occurredAt,
    };
    this.creditTransactions.set(transaction.id, transaction);
    return { account, transaction, replayed: false };
  }

  async createCreditHold(input: {
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
  }): Promise<CreditHoldMutationResult> {
    const current = this.#creditAccount(input.customerId, true)!;
    const replay = [...this.creditHolds.values()].find((hold) => (
      hold.customerId === input.customerId && hold.idempotencyKey === input.idempotencyKey
    ));
    if (replay) {
      if (
        replay.organizationId !== input.organizationId || replay.deploymentId !== input.deploymentId ||
        replay.module !== input.module || replay.amount !== input.amount
      ) throw conflict('idempotency key was already used for a different hold');
      return {
        account: current,
        hold: replay,
        transaction: this.#transactionByKey(input.customerId, input.idempotencyKey)!,
        replayed: true,
      };
    }
    if (current.availableBalance < input.amount) throw conflict('insufficient available credits');
    const account = this.#updateCreditAccount(current, {
      availableBalance: current.availableBalance - input.amount,
      frozenBalance: current.frozenBalance + input.amount,
    }, input.occurredAt);
    const hold: CreditHoldRecord = {
      id: input.holdId,
      customerId: input.customerId,
      organizationId: input.organizationId,
      deploymentId: input.deploymentId,
      module: input.module,
      amount: input.amount,
      status: 'active',
      idempotencyKey: input.idempotencyKey,
      expiresAt: input.expiresAt,
      createdAt: input.occurredAt,
      updatedAt: input.occurredAt,
    };
    this.creditHolds.set(hold.id, hold);
    const transaction: CreditTransactionRecord = {
      id: input.transactionId,
      customerId: input.customerId,
      organizationId: input.organizationId,
      deploymentId: input.deploymentId,
      module: input.module,
      type: 'freeze',
      availableDelta: -input.amount,
      frozenDelta: input.amount,
      billedAmount: 0,
      availableAfter: account.availableBalance,
      frozenAfter: account.frozenBalance,
      idempotencyKey: input.idempotencyKey,
      referenceId: input.holdId,
      relatedTransactionId: null,
      description: 'Credit hold created',
      metadata: {},
      occurredAt: input.occurredAt,
      createdAt: input.occurredAt,
    };
    this.creditTransactions.set(transaction.id, transaction);
    return { account, hold, transaction, replayed: false };
  }

  async getCreditHold(id: string): Promise<CreditHoldRecord | null> {
    return this.creditHolds.get(id) ?? null;
  }

  async listExpiredCreditHolds(input: {
    customerId: string;
    expiredBefore: Date;
    limit: number;
  }): Promise<CreditHoldRecord[]> {
    return [...this.creditHolds.values()]
      .filter((hold) => (
        hold.customerId === input.customerId && hold.status === 'active'
        && hold.expiresAt <= input.expiredBefore
      ))
      .sort((left, right) => left.expiresAt.getTime() - right.expiresAt.getTime())
      .slice(0, input.limit);
  }

  async captureCreditHold(input: {
    transactionId: string;
    holdId: string;
    customerId: string;
    amount: number;
    idempotencyKey: string;
    referenceId: string;
    description: string;
    occurredAt: Date;
  }): Promise<CreditHoldMutationResult | null> {
    const current = this.#creditAccount(input.customerId);
    if (!current) return null;
    const replay = this.#transactionByKey(input.customerId, input.idempotencyKey);
    if (replay) {
      if (
        replay.type !== 'capture' || replay.referenceId !== input.referenceId ||
        replay.metadata.holdId !== input.holdId || replay.billedAmount !== input.amount
      ) throw conflict('idempotency key was already used for a different operation');
      return { account: current, hold: this.creditHolds.get(input.holdId)!, transaction: replay, replayed: true };
    }
    const hold = this.creditHolds.get(input.holdId);
    if (!hold || hold.customerId !== input.customerId) return null;
    if (hold.status !== 'active') throw conflict('credit hold is no longer active');
    if (hold.expiresAt.getTime() <= input.occurredAt.getTime()) throw conflict('credit hold has expired');
    const availableDelta = hold.amount - input.amount;
    if (current.availableBalance + availableDelta < 0) {
      throw conflict('insufficient available credits for capture');
    }
    const account = this.#updateCreditAccount(current, {
      availableBalance: current.availableBalance + availableDelta,
      frozenBalance: current.frozenBalance - hold.amount,
      totalConsumed: current.totalConsumed + input.amount,
    }, input.occurredAt);
    const updatedHold = { ...hold, status: 'captured' as const, updatedAt: input.occurredAt };
    this.creditHolds.set(hold.id, updatedHold);
    const transaction: CreditTransactionRecord = {
      id: input.transactionId,
      customerId: input.customerId,
      organizationId: hold.organizationId,
      deploymentId: hold.deploymentId,
      module: hold.module,
      type: 'capture',
      availableDelta,
      frozenDelta: -hold.amount,
      billedAmount: input.amount,
      availableAfter: account.availableBalance,
      frozenAfter: account.frozenBalance,
      idempotencyKey: input.idempotencyKey,
      referenceId: input.referenceId,
      relatedTransactionId: null,
      description: input.description,
      metadata: { holdId: input.holdId },
      occurredAt: input.occurredAt,
      createdAt: input.occurredAt,
    };
    this.creditTransactions.set(transaction.id, transaction);
    return { account, hold: updatedHold, transaction, replayed: false };
  }

  async releaseCreditHold(input: {
    transactionId: string;
    holdId: string;
    customerId: string;
    idempotencyKey: string;
    reason: 'released' | 'expired';
    description: string;
    occurredAt: Date;
  }): Promise<CreditHoldMutationResult | null> {
    const current = this.#creditAccount(input.customerId);
    if (!current) return null;
    const replay = this.#transactionByKey(input.customerId, input.idempotencyKey);
    if (replay) {
      if (replay.type !== 'release' || replay.referenceId !== input.holdId) {
        throw conflict('idempotency key was already used for a different operation');
      }
      return { account: current, hold: this.creditHolds.get(input.holdId)!, transaction: replay, replayed: true };
    }
    const hold = this.creditHolds.get(input.holdId);
    if (!hold || hold.customerId !== input.customerId) return null;
    if (hold.status !== 'active') throw conflict('credit hold is no longer active');
    const account = this.#updateCreditAccount(current, {
      availableBalance: current.availableBalance + hold.amount,
      frozenBalance: current.frozenBalance - hold.amount,
    }, input.occurredAt);
    const updatedHold = { ...hold, status: input.reason, updatedAt: input.occurredAt };
    this.creditHolds.set(hold.id, updatedHold);
    const transaction: CreditTransactionRecord = {
      id: input.transactionId,
      customerId: input.customerId,
      organizationId: hold.organizationId,
      deploymentId: hold.deploymentId,
      module: hold.module,
      type: 'release',
      availableDelta: hold.amount,
      frozenDelta: -hold.amount,
      billedAmount: 0,
      availableAfter: account.availableBalance,
      frozenAfter: account.frozenBalance,
      idempotencyKey: input.idempotencyKey,
      referenceId: input.holdId,
      relatedTransactionId: null,
      description: input.description,
      metadata: { reason: input.reason },
      occurredAt: input.occurredAt,
      createdAt: input.occurredAt,
    };
    this.creditTransactions.set(transaction.id, transaction);
    return { account, hold: updatedHold, transaction, replayed: false };
  }

  async consumeCredits(input: {
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
  }): Promise<CreditMutationResult> {
    const current = this.#creditAccount(input.customerId, true)!;
    const replay = this.#transactionByKey(input.customerId, input.idempotencyKey);
    if (replay) {
      if (
        replay.type !== 'consume' || replay.billedAmount !== input.amount ||
        replay.organizationId !== input.organizationId || replay.deploymentId !== input.deploymentId ||
        replay.module !== input.module || replay.referenceId !== input.referenceId
      ) throw conflict('idempotency key was already used for a different operation');
      return { account: current, transaction: replay, replayed: true };
    }
    if (current.availableBalance < input.amount) throw conflict('insufficient available credits');
    const account = this.#updateCreditAccount(current, {
      availableBalance: current.availableBalance - input.amount,
      totalConsumed: current.totalConsumed + input.amount,
    }, input.occurredAt);
    const transaction: CreditTransactionRecord = {
      id: input.transactionId,
      customerId: input.customerId,
      organizationId: input.organizationId,
      deploymentId: input.deploymentId,
      module: input.module,
      type: 'consume',
      availableDelta: -input.amount,
      frozenDelta: 0,
      billedAmount: input.amount,
      availableAfter: account.availableBalance,
      frozenAfter: account.frozenBalance,
      idempotencyKey: input.idempotencyKey,
      referenceId: input.referenceId,
      relatedTransactionId: null,
      description: input.description,
      metadata: input.metadata,
      occurredAt: input.occurredAt,
      createdAt: input.occurredAt,
    };
    this.creditTransactions.set(transaction.id, transaction);
    return { account, transaction, replayed: false };
  }

  async registerExecutionReceiptKey(input: {
    deploymentId: string;
    keyId: string;
    publicKeyPem: string;
    notBefore: Date;
    expiresAt: Date | null;
    createdAt: Date;
  }): Promise<ExecutionReceiptKeyRecord> {
    if (!this.deployments.has(input.deploymentId)) throw conflict('deployment does not exist');
    const mapKey = `${input.deploymentId}\0${input.keyId}`;
    const existing = this.executionReceiptKeys.get(mapKey);
    if (existing) {
      if (existing.publicKeyPem !== input.publicKeyPem
        || existing.notBefore.getTime() !== input.notBefore.getTime()
        || existing.expiresAt?.getTime() !== input.expiresAt?.getTime()) {
        throw conflict('execution receipt key id is already bound to different key material');
      }
      if (existing.status !== 'active') {
        throw conflict('revoked execution receipt key cannot be reused');
      }
      return existing;
    }
    const record: ExecutionReceiptKeyRecord = {
      ...input,
      status: 'active',
      revokedAt: null,
    };
    this.executionReceiptKeys.set(mapKey, record);
    return record;
  }

  async bootstrapExecutionReceiptKey(input: {
    deploymentId: string;
    keyId: string;
    publicKeyPem: string;
    notBefore: Date;
    expiresAt: Date;
    createdAt: Date;
  }): Promise<{ key: ExecutionReceiptKeyRecord; replayed: boolean }> {
    if (!this.deployments.has(input.deploymentId)) throw conflict('deployment does not exist');
    const deploymentKeys = [...this.executionReceiptKeys.values()]
      .filter((key) => key.deploymentId === input.deploymentId);
    const sameKey = deploymentKeys.find((key) => key.keyId === input.keyId);
    if (sameKey) {
      if (sameKey.status !== 'active' || sameKey.publicKeyPem !== input.publicKeyPem) {
        throw conflict('execution receipt key is not active');
      }
      return { key: sameKey, replayed: true };
    }
    if (deploymentKeys.length > 0) {
      throw conflict('execution receipt key rotation requires administrator approval');
    }
    const key: ExecutionReceiptKeyRecord = {
      ...input,
      status: 'active',
      revokedAt: null,
    };
    this.executionReceiptKeys.set(`${input.deploymentId}\0${input.keyId}`, key);
    return { key, replayed: false };
  }

  async revokeExecutionReceiptKey(input: {
    deploymentId: string;
    keyId: string;
    revokedAt: Date;
  }): Promise<ExecutionReceiptKeyRecord | null> {
    const mapKey = `${input.deploymentId}\0${input.keyId}`;
    const existing = this.executionReceiptKeys.get(mapKey);
    if (!existing) return null;
    if (existing.status === 'revoked') return existing;
    const record: ExecutionReceiptKeyRecord = {
      ...existing,
      status: 'revoked',
      revokedAt: input.revokedAt,
    };
    this.executionReceiptKeys.set(mapKey, record);
    return record;
  }

  async getExecutionReceiptKey(
    deploymentId: string,
    keyId: string,
  ): Promise<ExecutionReceiptKeyRecord | null> {
    return this.executionReceiptKeys.get(`${deploymentId}\0${keyId}`) ?? null;
  }

  async listExecutionReceiptKeys(deploymentId: string): Promise<ExecutionReceiptKeyRecord[]> {
    return [...this.executionReceiptKeys.values()]
      .filter((record) => record.deploymentId === deploymentId)
      .sort((left, right) => right.createdAt.getTime() - left.createdAt.getTime());
  }

  async ingestExecutionReceipt(input: {
    transactionId: string;
    customerId: string;
    amount: number;
    envelope: SignedExecutionReceiptV2;
    metadata: Record<string, unknown>;
    receivedAt: Date;
  }): Promise<ExecutionReceiptMutationResult> {
    const evidence = input.envelope.receipt;
    const current = this.#creditAccount(input.customerId, true)!;
    const replay = this.executionReceipts.get(evidence.receiptId);
    if (replay) {
      const replayEvidence = {
        receipt: {
          version: replay.version,
          receiptId: replay.receiptId,
          deploymentId: replay.deploymentId,
          organizationId: replay.organizationId,
          taskId: replay.taskId,
          moduleId: replay.moduleId,
          units: replay.units,
          model: replay.model,
          issuedAtMs: replay.issuedAtMs,
          expiresAtMs: replay.expiresAtMs,
          sequence: replay.sequence,
          policyVersion: replay.policyVersion,
        },
        signingKeyId: replay.signingKeyId,
        signature: replay.signature,
      };
      if (replay.customerId !== input.customerId
        || JSON.stringify(replayEvidence) !== JSON.stringify(input.envelope)) {
        throw conflict('execution receipt id was already used for different evidence');
      }
      const transaction = this.creditTransactions.get(replay.transactionId);
      if (!transaction) throw new Error('execution receipt transaction is missing');
      return { account: current, transaction, receipt: replay, replayed: true };
    }
    const key = await this.getExecutionReceiptKey(evidence.deploymentId, input.envelope.signingKeyId);
    if (!key || key.status !== 'active') throw conflict('execution receipt signing key is inactive');
    const expectedSequence = (this.executionReceiptSequences.get(evidence.deploymentId) ?? 0) + 1;
    if (evidence.sequence !== expectedSequence) {
      throw conflict(`execution receipt sequence must be ${expectedSequence}`);
    }
    if ([...this.executionReceipts.values()].some((record) => (
      record.deploymentId === evidence.deploymentId && record.taskId === evidence.taskId
    ))) throw conflict('task already has a billed execution receipt');
    if (current.availableBalance < input.amount) throw conflict('insufficient available credits');

    const account = this.#updateCreditAccount(current, {
      availableBalance: current.availableBalance - input.amount,
      totalConsumed: current.totalConsumed + input.amount,
    }, input.receivedAt);
    const transaction: CreditTransactionRecord = {
      id: input.transactionId,
      customerId: input.customerId,
      organizationId: evidence.organizationId,
      deploymentId: evidence.deploymentId,
      module: evidence.moduleId,
      type: 'consume',
      availableDelta: -input.amount,
      frozenDelta: 0,
      billedAmount: input.amount,
      availableAfter: account.availableBalance,
      frozenAfter: account.frozenBalance,
      idempotencyKey: `receipt:${evidence.receiptId}`,
      referenceId: evidence.taskId,
      relatedTransactionId: null,
      description: 'Verified signed execution receipt',
      metadata: input.metadata,
      occurredAt: new Date(evidence.issuedAtMs),
      createdAt: input.receivedAt,
    };
    const receipt: ExecutionReceiptRecord = {
      ...evidence,
      customerId: input.customerId,
      signingKeyId: input.envelope.signingKeyId,
      signature: input.envelope.signature,
      transactionId: input.transactionId,
      verificationStatus: 'verified',
      receivedAt: input.receivedAt,
    };
    this.creditTransactions.set(transaction.id, transaction);
    this.executionReceipts.set(receipt.receiptId, receipt);
    this.executionReceiptSequences.set(receipt.deploymentId, receipt.sequence);
    return { account, transaction, receipt, replayed: false };
  }

  async getExecutionReceipt(receiptId: string): Promise<ExecutionReceiptRecord | null> {
    return this.executionReceipts.get(receiptId) ?? null;
  }

  async listExecutionReceipts(input: {
    customerId: string;
    from: Date;
    to: Date;
    organizationId?: string;
    deploymentId?: string;
    module?: OttoBillingModule;
    limit: number;
  }): Promise<ExecutionReceiptRecord[]> {
    return [...this.executionReceipts.values()]
      .filter((receipt) => (
        receipt.customerId === input.customerId
        && receipt.receivedAt >= input.from
        && receipt.receivedAt < input.to
        && (!input.organizationId || receipt.organizationId === input.organizationId)
        && (!input.deploymentId || receipt.deploymentId === input.deploymentId)
        && (!input.module || receipt.moduleId === input.module)
      ))
      .sort((left, right) => right.receivedAt.getTime() - left.receivedAt.getTime())
      .slice(0, input.limit);
  }

  async refundCredits(input: {
    transactionId: string;
    customerId: string;
    relatedTransactionId: string;
    amount: number;
    idempotencyKey: string;
    referenceId: string;
    description: string;
    metadata: Record<string, unknown>;
    occurredAt: Date;
  }): Promise<CreditMutationResult | null> {
    const current = this.#creditAccount(input.customerId);
    if (!current) return null;
    const replay = this.#transactionByKey(input.customerId, input.idempotencyKey);
    if (replay) {
      if (
        replay.type !== 'refund' || replay.billedAmount !== input.amount ||
        replay.relatedTransactionId !== input.relatedTransactionId ||
        replay.referenceId !== input.referenceId
      ) throw conflict('idempotency key was already used for a different operation');
      return { account: current, transaction: replay, replayed: true };
    }
    const original = this.creditTransactions.get(input.relatedTransactionId);
    if (!original || original.customerId !== input.customerId || !['consume', 'capture'].includes(original.type)) {
      return null;
    }
    const refunded = [...this.creditTransactions.values()]
      .filter((transaction) => transaction.type === 'refund' && transaction.relatedTransactionId === original.id)
      .reduce((sum, transaction) => sum + transaction.billedAmount, 0);
    if (refunded + input.amount > original.billedAmount) {
      throw conflict('refund exceeds the remaining refundable amount');
    }
    const account = this.#updateCreditAccount(current, {
      availableBalance: current.availableBalance + input.amount,
      totalRefunded: current.totalRefunded + input.amount,
    }, input.occurredAt);
    const transaction: CreditTransactionRecord = {
      id: input.transactionId,
      customerId: input.customerId,
      organizationId: original.organizationId,
      deploymentId: original.deploymentId,
      module: original.module,
      type: 'refund',
      availableDelta: input.amount,
      frozenDelta: 0,
      billedAmount: input.amount,
      availableAfter: account.availableBalance,
      frozenAfter: account.frozenBalance,
      idempotencyKey: input.idempotencyKey,
      referenceId: input.referenceId,
      relatedTransactionId: original.id,
      description: input.description,
      metadata: {
        ...input.metadata,
        executionReceiptId: original.metadata.executionReceiptId,
        receiptVerificationStatus: original.metadata.receiptVerificationStatus,
      },
      occurredAt: input.occurredAt,
      createdAt: input.occurredAt,
    };
    this.creditTransactions.set(transaction.id, transaction);
    return { account, transaction, replayed: false };
  }

  async listCreditTransactions(input: {
    customerId: string;
    from: Date;
    to: Date;
    organizationId?: string;
    module?: OttoBillingModule;
    limit: number;
  }): Promise<CreditTransactionRecord[]> {
    return [...this.creditTransactions.values()]
      .filter((transaction) => (
        transaction.customerId === input.customerId
        && transaction.occurredAt >= input.from
        && transaction.occurredAt < input.to
        && (!input.organizationId || transaction.organizationId === input.organizationId)
        && (!input.module || transaction.module === input.module)
      ))
      .sort((left, right) => right.occurredAt.getTime() - left.occurredAt.getTime())
      .slice(0, input.limit);
  }

  async getCreditStatement(input: {
    customerId: string;
    from: Date;
    to: Date;
  }): Promise<CreditStatement | null> {
    if (!this.#creditAccount(input.customerId)) return null;
    const transactions = [...this.creditTransactions.values()]
      .filter((transaction) => transaction.customerId === input.customerId);
    const openingBalance = transactions
      .filter((transaction) => transaction.occurredAt < input.from)
      .reduce((sum, transaction) => sum + transaction.availableDelta + transaction.frozenDelta, 0);
    const period = transactions.filter((transaction) => (
      transaction.occurredAt >= input.from && transaction.occurredAt < input.to
    ));
    const lineMap = new Map<string, CreditStatement['lines'][number]>();
    for (const transaction of period) {
      if (!transaction.organizationId || !transaction.module) continue;
      if (!['consume', 'capture', 'refund'].includes(transaction.type)) continue;
      const key = `${transaction.organizationId}\0${transaction.module}`;
      const line = lineMap.get(key) ?? {
        organizationId: transaction.organizationId,
        module: transaction.module,
        consumedCredits: 0,
        refundedCredits: 0,
        netCredits: 0,
        transactionCount: 0,
      };
      if (transaction.type === 'refund') line.refundedCredits += transaction.billedAmount;
      else line.consumedCredits += transaction.billedAmount;
      line.netCredits = line.consumedCredits - line.refundedCredits;
      line.transactionCount += 1;
      lineMap.set(key, line);
    }
    const periodDelta = period.reduce(
      (sum, transaction) => sum + transaction.availableDelta + transaction.frozenDelta,
      0,
    );
    return {
      customerId: input.customerId,
      from: input.from,
      to: input.to,
      openingBalance,
      closingBalance: openingBalance + periodDelta,
      totalToppedUp: period.filter((item) => item.type === 'topup')
        .reduce((sum, item) => sum + item.availableDelta, 0),
      totalConsumed: period.filter((item) => ['consume', 'capture'].includes(item.type))
        .reduce((sum, item) => sum + item.billedAmount, 0),
      totalRefunded: period.filter((item) => item.type === 'refund')
        .reduce((sum, item) => sum + item.billedAmount, 0),
      lines: [...lineMap.values()].sort((left, right) => (
        left.organizationId.localeCompare(right.organizationId) || left.module.localeCompare(right.module)
      )),
    };
  }

  async enqueueAlertDelivery(input: {
    id: string;
    channelId: string;
    source: AlertDeliveryRecord['source'];
    eventType: AlertDeliveryRecord['eventType'];
    fingerprint: string;
    severity: AlertSeverity;
    payload: AlertDeliveryPayload;
    createdAt: Date;
    audit: AuditEventInput;
  }): Promise<{ record: AlertDeliveryRecord; created: boolean }> {
    const existing = [...this.alertDeliveries.values()]
      .find((delivery) => delivery.fingerprint === input.fingerprint
        && delivery.channelId === input.channelId);
    if (existing) return { record: existing, created: false };
    const { audit, ...deliveryInput } = input;
    const record: AlertDeliveryRecord = {
      ...deliveryInput,
      status: 'pending',
      attempts: 0,
      nextAttemptAt: input.createdAt,
      leaseUntil: null,
      lastError: null,
      deliveredAt: null,
      updatedAt: input.createdAt,
    };
    this.alertDeliveries.set(record.id, record);
    this.#recordAudit(audit);
    return { record, created: true };
  }

  async claimAlertDelivery(input: {
    now: Date;
    leaseUntil: Date;
    channelIds: string[];
  }): Promise<AlertDeliveryRecord | null> {
    const record = [...this.alertDeliveries.values()]
      .filter((delivery) => (
        input.channelIds.includes(delivery.channelId)
        && ((['pending', 'retrying'].includes(delivery.status)
          && delivery.nextAttemptAt <= input.now)
        || (delivery.status === 'delivering'
          && delivery.leaseUntil !== null && delivery.leaseUntil <= input.now))
      ))
      .sort((left, right) => (
        left.nextAttemptAt.getTime() - right.nextAttemptAt.getTime()
        || left.createdAt.getTime() - right.createdAt.getTime()
        || left.id.localeCompare(right.id)
      ))[0];
    if (!record) return null;
    const claimed: AlertDeliveryRecord = {
      ...record,
      status: 'delivering',
      attempts: record.attempts + 1,
      leaseUntil: input.leaseUntil,
      updatedAt: input.now,
    };
    this.alertDeliveries.set(claimed.id, claimed);
    return claimed;
  }

  async finishAlertDelivery(input: {
    id: string;
    expectedLeaseUntil: Date;
    status: Extract<AlertDeliveryStatus, 'delivered' | 'retrying' | 'failed'>;
    nextAttemptAt: Date;
    lastError: string | null;
    deliveredAt: Date | null;
    updatedAt: Date;
    audit: AuditEventInput | null;
  }): Promise<AlertDeliveryRecord | null> {
    const record = this.alertDeliveries.get(input.id);
    if (!record || record.status !== 'delivering'
      || record.leaseUntil?.getTime() !== input.expectedLeaseUntil.getTime()) return null;
    const { audit, expectedLeaseUntil: _expectedLeaseUntil, ...deliveryInput } = input;
    void _expectedLeaseUntil;
    const finished: AlertDeliveryRecord = {
      ...record,
      ...deliveryInput,
      leaseUntil: null,
    };
    this.alertDeliveries.set(finished.id, finished);
    if (audit) this.#recordAudit(audit);
    return finished;
  }

  async listAlertDeliveries(limit: number): Promise<AlertDeliveryRecord[]> {
    return [...this.alertDeliveries.values()]
      .sort((left, right) => (
        right.createdAt.getTime() - left.createdAt.getTime()
        || right.id.localeCompare(left.id)
      ))
      .slice(0, limit);
  }

  async getAlertDelivery(id: string): Promise<AlertDeliveryRecord | null> {
    return this.alertDeliveries.get(id) ?? null;
  }

  async retryAlertDelivery(input: {
    id: string;
    retriedAt: Date;
    audit: AuditEventInput;
  }): Promise<AlertDeliveryRecord | null> {
    const record = this.alertDeliveries.get(input.id);
    if (!record || record.status !== 'failed') return null;
    const retried: AlertDeliveryRecord = {
      ...record,
      status: 'pending',
      attempts: 0,
      nextAttemptAt: input.retriedAt,
      leaseUntil: null,
      lastError: null,
      deliveredAt: null,
      updatedAt: input.retriedAt,
    };
    this.alertDeliveries.set(retried.id, retried);
    this.#recordAudit(input.audit);
    return retried;
  }

  async pruneAlertDeliveries(before: Date): Promise<number> {
    let deleted = 0;
    for (const [id, delivery] of this.alertDeliveries) {
      if (['delivered', 'failed'].includes(delivery.status) && delivery.updatedAt < before) {
        this.alertDeliveries.delete(id);
        deleted += 1;
      }
    }
    return deleted;
  }

  async listAuditEvents(input: AuditEventQuery): Promise<AuditEventRecord[]> {
    return this.auditRecords
      .filter((event) => (
        (input.actorId === undefined || event.actorId === input.actorId)
        && (input.action === undefined || event.action === input.action)
        && (input.targetType === undefined || event.targetType === input.targetType)
        && (input.targetId === undefined || event.targetId === input.targetId)
        && (input.from === undefined || event.createdAt >= input.from)
        && (input.to === undefined || event.createdAt <= input.to)
        && (input.beforeId === undefined || event.id < input.beforeId)
      ))
      .sort((left, right) => right.id - left.id)
      .slice(0, input.limit);
  }

  async listChainedAuditEvents(input: {
    afterSequence: number;
    throughSequence: number;
    limit: number;
  }): Promise<AuditEventRecord[]> {
    return this.auditRecords
      .filter((event) => (event.chainSequence ?? 0) > input.afterSequence
        && (event.chainSequence ?? 0) <= input.throughSequence)
      .sort((left, right) => (left.chainSequence ?? 0) - (right.chainSequence ?? 0))
      .slice(0, input.limit);
  }

  async getAuditChainState(): Promise<AuditChainState> {
    return {
      lastSequence: this.auditRecords.length,
      headHash: this.#auditHeadHash,
      updatedAt: this.auditRecords.at(-1)?.createdAt ?? new Date(0),
    };
  }

  async countLegacyAuditEvents(): Promise<number> {
    return 0;
  }

  async enqueueAuditAnchor(input: {
    id: string;
    fingerprint: string;
    payload: AuditAnchorPayload;
    createdAt: Date;
    audit: AuditEventInput;
  }): Promise<{ record: AuditAnchorRecord; created: boolean }> {
    const existing = [...this.auditAnchors.values()]
      .find((anchor) => anchor.fingerprint === input.fingerprint);
    if (existing) return { record: existing, created: false };
    const record: AuditAnchorRecord = {
      id: input.id,
      fingerprint: input.fingerprint,
      payload: input.payload,
      status: 'pending',
      attempts: 0,
      nextAttemptAt: input.createdAt,
      leaseUntil: null,
      lastError: null,
      deliveredAt: null,
      remoteReference: null,
      createdAt: input.createdAt,
      updatedAt: input.createdAt,
    };
    this.auditAnchors.set(record.id, record);
    this.#recordAudit(input.audit);
    return { record, created: true };
  }

  async claimAuditAnchor(input: {
    now: Date;
    leaseUntil: Date;
  }): Promise<AuditAnchorRecord | null> {
    const record = [...this.auditAnchors.values()]
      .filter((anchor) => (
        (['pending', 'retrying'].includes(anchor.status) && anchor.nextAttemptAt <= input.now)
        || (anchor.status === 'delivering'
          && anchor.leaseUntil !== null && anchor.leaseUntil <= input.now)
      ))
      .sort((left, right) => (
        left.nextAttemptAt.getTime() - right.nextAttemptAt.getTime()
        || left.createdAt.getTime() - right.createdAt.getTime()
        || left.id.localeCompare(right.id)
      ))[0];
    if (!record) return null;
    const claimed: AuditAnchorRecord = {
      ...record,
      status: 'delivering',
      attempts: record.attempts + 1,
      leaseUntil: input.leaseUntil,
      updatedAt: input.now,
    };
    this.auditAnchors.set(claimed.id, claimed);
    return claimed;
  }

  async finishAuditAnchor(input: {
    id: string;
    expectedLeaseUntil: Date;
    status: Extract<AuditAnchorStatus, 'delivered' | 'retrying' | 'failed'>;
    nextAttemptAt: Date;
    lastError: string | null;
    deliveredAt: Date | null;
    remoteReference: string | null;
    updatedAt: Date;
    audit: AuditEventInput | null;
  }): Promise<AuditAnchorRecord | null> {
    const record = this.auditAnchors.get(input.id);
    if (!record || record.status !== 'delivering'
      || record.leaseUntil?.getTime() !== input.expectedLeaseUntil.getTime()) return null;
    const { audit, expectedLeaseUntil: _expectedLeaseUntil, ...anchorInput } = input;
    void _expectedLeaseUntil;
    const finished: AuditAnchorRecord = { ...record, ...anchorInput, leaseUntil: null };
    this.auditAnchors.set(finished.id, finished);
    if (audit) this.#recordAudit(audit);
    return finished;
  }

  async getAuditAnchor(id: string): Promise<AuditAnchorRecord | null> {
    return this.auditAnchors.get(id) ?? null;
  }

  async getLatestAuditAnchor(): Promise<AuditAnchorRecord | null> {
    return [...this.auditAnchors.values()].sort((left, right) => (
      right.createdAt.getTime() - left.createdAt.getTime()
      || right.id.localeCompare(left.id)
    ))[0] ?? null;
  }

  async retryAuditAnchor(input: {
    id: string;
    retriedAt: Date;
    audit: AuditEventInput;
  }): Promise<AuditAnchorRecord | null> {
    const record = this.auditAnchors.get(input.id);
    if (!record || record.status !== 'failed') return null;
    const retried: AuditAnchorRecord = {
      ...record,
      status: 'pending',
      attempts: 0,
      nextAttemptAt: input.retriedAt,
      leaseUntil: null,
      lastError: null,
      deliveredAt: null,
      remoteReference: null,
      updatedAt: input.retriedAt,
    };
    this.auditAnchors.set(retried.id, retried);
    this.#recordAudit(input.audit);
    return retried;
  }

  async listAuditAnchors(limit: number): Promise<AuditAnchorRecord[]> {
    return [...this.auditAnchors.values()]
      .sort((left, right) => (
        right.createdAt.getTime() - left.createdAt.getTime()
        || right.id.localeCompare(left.id)
      ))
      .slice(0, limit);
  }

  async ingestAuditWitnessReceipt(input: {
    record: AuditWitnessReceiptRecord;
    evidence?: AuditWitnessEvidenceRecord;
    audit: AuditEventInput;
  }): Promise<{ record: AuditWitnessReceiptRecord; replayed: boolean }> {
    const replay = this.auditWitnessReceipts.find((receipt) => (
      receipt.sourceId === input.record.sourceId
      && receipt.fingerprint === input.record.fingerprint
    ));
    if (replay) return { record: replay, replayed: true };
    if (this.auditWitnessReceipts.some((receipt) => (
      receipt.sourceId === input.record.sourceId && receipt.anchorId === input.record.anchorId
    ))) throw conflict('audit witness anchor id was reused');
    const latest = this.auditWitnessReceipts
      .filter((receipt) => receipt.sourceId === input.record.sourceId)
      .sort((left, right) => right.chainSequence - left.chainSequence)[0];
    if (latest && input.record.chainSequence < latest.chainSequence) {
      throw conflict('audit witness rejected a chain sequence rollback');
    }
    if (latest && input.record.chainSequence === latest.chainSequence
      && input.record.headHash !== latest.headHash) {
      throw conflict('audit witness detected conflicting heads at the same sequence');
    }
    this.auditWitnessReceipts.push(input.record);
    if (input.evidence) this.auditWitnessEvidence.set(input.evidence.receiptId, input.evidence);
    this.#recordAudit(input.audit);
    return { record: input.record, replayed: false };
  }

  async listAuditWitnessReceipts(input: {
    sourceId?: string;
    limit: number;
  }): Promise<AuditWitnessReceiptRecord[]> {
    return this.auditWitnessReceipts
      .filter((receipt) => !input.sourceId || receipt.sourceId === input.sourceId)
      .sort((left, right) => (
        right.receivedAt.getTime() - left.receivedAt.getTime()
        || right.id.localeCompare(left.id)
      ))
      .slice(0, input.limit);
  }

  async getAuditWitnessReceipt(id: string): Promise<AuditWitnessReceiptRecord | null> {
    return this.auditWitnessReceipts.find((record) => record.id === id) ?? null;
  }

  async claimAuditWitnessEvidence(input: {
    now: Date;
    leaseUntil: Date;
  }): Promise<AuditWitnessEvidenceRecord | null> {
    const record = [...this.auditWitnessEvidence.values()]
      .filter((item) => (
        ((item.status === 'pending' || item.status === 'retrying')
          && item.nextAttemptAt.getTime() <= input.now.getTime())
        || (item.status === 'storing'
          && (item.leaseUntil?.getTime() ?? Number.POSITIVE_INFINITY) <= input.now.getTime())
      ))
      .sort((left, right) => left.nextAttemptAt.getTime() - right.nextAttemptAt.getTime())[0];
    if (!record) return null;
    const claimed: AuditWitnessEvidenceRecord = {
      ...record,
      status: 'storing',
      attempts: record.attempts + 1,
      leaseUntil: input.leaseUntil,
      lastError: null,
      updatedAt: input.now,
    };
    this.auditWitnessEvidence.set(claimed.receiptId, claimed);
    return claimed;
  }

  async finishAuditWitnessEvidence(input: {
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
  }): Promise<AuditWitnessEvidenceRecord | null> {
    const current = this.auditWitnessEvidence.get(input.receiptId);
    if (!current || current.status !== 'storing'
      || current.leaseUntil?.getTime() !== input.expectedLeaseUntil.getTime()) return null;
    const finished: AuditWitnessEvidenceRecord = {
      ...current,
      status: input.status,
      nextAttemptAt: input.nextAttemptAt,
      leaseUntil: null,
      lastError: input.lastError,
      objectVersionId: input.objectVersionId,
      serverSideEncryption: input.serverSideEncryption,
      objectLockMode: input.objectLockMode,
      objectLockRetainUntil: input.objectLockRetainUntil,
      storedAt: input.storedAt,
      verifiedAt: input.verifiedAt,
      updatedAt: input.updatedAt,
    };
    this.auditWitnessEvidence.set(finished.receiptId, finished);
    if (input.audit) this.#recordAudit(input.audit);
    return finished;
  }

  async retryAuditWitnessEvidence(input: {
    receiptId: string;
    retriedAt: Date;
    audit: AuditEventInput;
  }): Promise<AuditWitnessEvidenceRecord | null> {
    const current = this.auditWitnessEvidence.get(input.receiptId);
    if (!current || current.status !== 'failed') return null;
    const retried: AuditWitnessEvidenceRecord = {
      ...current,
      status: 'pending',
      attempts: 0,
      nextAttemptAt: input.retriedAt,
      leaseUntil: null,
      lastError: null,
      updatedAt: input.retriedAt,
    };
    this.auditWitnessEvidence.set(retried.receiptId, retried);
    this.#recordAudit(input.audit);
    return retried;
  }

  async listAuditWitnessEvidence(input: {
    status?: AuditWitnessEvidenceStatus;
    limit: number;
  }): Promise<AuditWitnessEvidenceRecord[]> {
    return [...this.auditWitnessEvidence.values()]
      .filter((record) => !input.status || record.status === input.status)
      .sort((left, right) => (
        right.updatedAt.getTime() - left.updatedAt.getTime()
        || right.receiptId.localeCompare(left.receiptId)
      ))
      .slice(0, input.limit);
  }

  async getAuditWitnessEvidence(receiptId: string): Promise<AuditWitnessEvidenceRecord | null> {
    return this.auditWitnessEvidence.get(receiptId) ?? null;
  }

  async restoreAuditWitnessEvidence(input: {
    receipt: AuditWitnessReceiptRecord;
    evidence: AuditWitnessEvidenceRecord;
    audit: AuditEventInput;
  }): Promise<{ record: AuditWitnessEvidenceRecord; replayed: boolean }> {
    const existing = [...this.auditWitnessEvidence.values()].find((record) => (
      record.sourceId === input.evidence.sourceId
      && record.chainSequence === input.evidence.chainSequence
    ));
    if (existing) {
      const receipt = this.auditWitnessReceipts.find((item) => item.id === existing.receiptId)!;
      if (receipt.fingerprint !== input.receipt.fingerprint
        || existing.contentSha256 !== input.evidence.contentSha256
        || existing.objectKey !== input.evidence.objectKey) {
        throw conflict('audit WORM recovery detected conflicting evidence at the same sequence');
      }
      return { record: existing, replayed: true };
    }
    const byId = this.auditWitnessReceipts.find((record) => record.id === input.receipt.id);
    if (byId && (byId.sourceId !== input.receipt.sourceId
      || byId.fingerprint !== input.receipt.fingerprint)) {
      throw conflict('audit WORM recovery receipt id conflicts with PostgreSQL');
    }
    if (!byId) this.auditWitnessReceipts.push(input.receipt);
    this.auditWitnessEvidence.set(input.evidence.receiptId, input.evidence);
    this.#recordAudit(input.audit);
    return { record: input.evidence, replayed: false };
  }

  async summarizeAuditWitnessEvidence(): Promise<{
    counts: Record<AuditWitnessEvidenceStatus, number>;
    oldestPendingAt: Date | null;
    latestVerifiedAt: Date | null;
  }> {
    const values = [...this.auditWitnessEvidence.values()];
    const dates = values
      .filter((record) => record.status === 'pending' || record.status === 'storing'
        || record.status === 'retrying')
      .map((record) => record.createdAt.getTime());
    const verified = values
      .flatMap((record) => record.verifiedAt ? [record.verifiedAt.getTime()] : []);
    return {
      counts: {
        pending: values.filter((record) => record.status === 'pending').length,
        storing: values.filter((record) => record.status === 'storing').length,
        retrying: values.filter((record) => record.status === 'retrying').length,
        stored: values.filter((record) => record.status === 'stored').length,
        failed: values.filter((record) => record.status === 'failed').length,
      },
      oldestPendingAt: dates.length ? new Date(Math.min(...dates)) : null,
      latestVerifiedAt: verified.length ? new Date(Math.max(...verified)) : null,
    };
  }

  async appendAuditEvent(input: AuditEventInput): Promise<void> {
    this.#recordAudit(input);
  }

  #recordAudit(input: AuditEventInput): void {
    const sequence = this.auditRecords.length + 1;
    const createdAt = new Date();
    const previousHash = this.#auditHeadHash;
    const eventHash = auditEventHash({
      sequence,
      previousHash,
      actorId: input.actorId,
      action: input.action,
      targetType: input.targetType,
      targetId: input.targetId,
      detail: input.detail,
      createdAt,
    });
    this.audits.push(input);
    this.auditRecords.push({
      id: sequence,
      actorId: input.actorId,
      action: input.action,
      targetType: input.targetType,
      targetId: input.targetId,
      detail: input.detail,
      chainSequence: sequence,
      previousHash,
      eventHash,
      createdAt,
    });
    this.#auditHeadHash = eventHash;
  }
}

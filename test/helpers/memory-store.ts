import type {
  AuditEventInput,
  ControlStore,
  CreateLicenseRecordInput,
  CreateUpdateReleaseRecordInput,
  CustomerRecord,
  DeploymentUpdateAssignmentRecord,
  DeploymentRecord,
  LicenseLifecycleEventRecord,
  LicenseRecord,
  LicenseSeatUsageRecord,
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

const role = (
  id: string,
  name: string,
  permissions: AdminPermission[],
): AdminRoleRecord => ({ id, name, permissions, system: true });

const ALL_PERMISSIONS: AdminPermission[] = [
  'customer.create', 'deployment.create', 'license.issue', 'license.read',
  'license.revoke', 'license.manage', 'license.transfer', 'license.usage.read',
  'signing_key.read', 'signing_key.manage', 'telemetry.read',
  'update_distribution.manage', 'update_release.create', 'update_release.read',
  'update_release.publish', 'identity.read', 'identity.manage', 'approval.request',
  'approval.read', 'approval.decide',
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
  readonly nonces = new Set<string>();
  readonly audits: AuditEventInput[] = [];
  readonly telemetryEvents = new Map<string, StoredTelemetryEvent>();
  readonly telemetryNonces = new Set<string>();
  readonly updateDistributions = new Map<string, UpdateDistributionRecord>();
  readonly updateReleases = new Map<string, UpdateReleaseRecord>();
  readonly updateAssignments = new Map<string, DeploymentUpdateAssignmentRecord>();
  readonly updatePolicyNonces = new Set<string>();
  readonly adminAccounts = new Map<string, AdminAccountRecord>();
  readonly adminAccountRoles = new Map<string, string[]>();
  readonly adminEnrollments = new Map<string, { tokenHash: string; expiresAt: Date }>();
  readonly adminRecoveryCodes = new Map<string, Set<string>>();
  readonly adminSessions = new Map<string, AdminSessionRecord>();
  readonly adminApprovals = new Map<string, AdminApprovalRecord>();
  readonly adminApprovalDecisions = new Map<string, Map<string, 'approve' | 'reject'>>();
  readonly adminRoles = new Map<string, AdminRoleRecord>([
    ['super_admin', role('super_admin', 'Super administrator', ALL_PERMISSIONS)],
    ['security_admin', role('security_admin', 'Security administrator', [
      'signing_key.read', 'signing_key.manage', 'identity.read', 'identity.manage',
      'approval.request', 'approval.read', 'approval.decide',
    ])],
    ['license_admin', role('license_admin', 'License administrator', [
      'customer.create', 'deployment.create', 'license.issue', 'license.read',
      'license.revoke', 'license.manage', 'license.transfer', 'license.usage.read',
      'telemetry.read', 'approval.request', 'approval.read',
    ])],
    ['release_admin', role('release_admin', 'Release administrator', [
      'update_distribution.manage', 'update_release.create', 'update_release.read',
      'update_release.publish', 'approval.request', 'approval.read',
    ])],
    ['auditor', role('auditor', 'Auditor', [
      'license.read', 'license.usage.read', 'signing_key.read', 'telemetry.read', 'update_release.read',
      'identity.read', 'approval.read',
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
    expiresAtMs: number;
  }): Promise<boolean> {
    const key = `${input.deploymentId}\0${input.nonce}`;
    if (this.nonces.has(key)) return false;
    this.nonces.add(key);
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

  async appendAuditEvent(input: AuditEventInput): Promise<void> {
    this.audits.push(input);
  }
}

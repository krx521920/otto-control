import { createHash, randomUUID } from 'node:crypto';

import type {
  AdminAccountRecord,
  AdminAccountView,
  AdminApprovalRecord,
  AdminPermission,
  AdminPrincipal,
  AdminRoleRecord,
} from '../../contracts/admin-identity.js';
import { ADMIN_APPROVAL_OPERATIONS } from '../../contracts/admin-identity.js';
import { canonicalJson } from '../../crypto/signed-envelope.js';
import {
  approvalRequired,
  conflict,
  forbidden,
  invalidRequest,
  notFound,
  unauthorized,
} from '../../errors.js';
import type { ControlStore } from '../../storage/control-store.js';
import {
  createRecoveryCodes,
  decryptMfaSecret,
  encryptMfaSecret,
  generateMfaSecret,
  hashAdminPassword,
  hashOpaqueToken,
  hashRecoveryCode,
  randomOpaqueToken,
  verifyAdminPassword,
  verifyTotpCode,
} from './crypto.js';

const USERNAME_PATTERN = /^[a-z0-9][a-z0-9._-]{2,63}$/u;
const ROLE_PATTERN = /^[a-z][a-z0-9_]{2,63}$/u;
const MAX_FAILED_LOGINS = 5;
const LOGIN_LOCK_MS = 15 * 60 * 1000;
const MAX_APPROVAL_REQUEST_BYTES = 16 * 1024;

function id(prefix: string): string {
  return `${prefix}_${randomUUID().replace(/-/gu, '')}`;
}

function normalizedUsername(value: string): string {
  const username = value.trim().toLowerCase();
  if (!USERNAME_PATTERN.test(username)) {
    throw invalidRequest('username must be 3-64 lowercase letters, digits, dots, underscores or hyphens');
  }
  return username;
}

function requiredText(value: string, name: string, maxLength: number): string {
  const result = value.trim();
  if (!result) throw invalidRequest(`${name} is required`);
  if (result.length > maxLength) throw invalidRequest(`${name} is too long`);
  return result;
}

const APPROVAL_REQUEST_FIELDS: Readonly<Record<string, readonly string[]>> = {
  'license.revoke': [],
  'license.transfer_machine': ['machineFingerprint'],
  'license.rebind_deployment': ['deploymentId'],
  'signing_key.activate': [],
  'signing_key.retire': [],
  'signing_key.revoke': ['replacementKeyId', 'reason'],
  'update_release.activate': [],
  'update_release.rollback': [],
  'release_artifact.revoke': ['reason'],
  'billing.rate.set': ['module', 'unitSize', 'creditsPerUnit'],
  'billing.topup': [
    'organizationId', 'amount', 'idempotencyKey', 'referenceId', 'description',
  ],
  'billing.refund': ['amount', 'idempotencyKey', 'transactionId', 'referenceId', 'description'],
  'billing.execution_receipt_key.register': [
    'publicKeyPem', 'keyId', 'notBefore', 'expiresAt',
  ],
  'billing.execution_receipt_key.revoke': [],
  'customer_erasure.execute': [],
  'legal_hold.create': ['customerId', 'scope', 'reason', 'expiresAt'],
  'legal_hold.release': ['reason'],
  'forensic_export.create': ['customerId', 'reason'],
};

function approvalRequestSnapshot(operation: string, value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw invalidRequest('approval request must be an object');
  }
  const source = value as Record<string, unknown>;
  const snapshot = Object.fromEntries(
    APPROVAL_REQUEST_FIELDS[operation]!.filter((key) => source[key] !== undefined)
      .map((key) => [key, source[key]]),
  );
  const serialized = canonicalJson(snapshot);
  if (Buffer.byteLength(serialized, 'utf8') > MAX_APPROVAL_REQUEST_BYTES) {
    throw invalidRequest('approval request exceeds 16 KiB');
  }
  return JSON.parse(serialized) as Record<string, unknown>;
}

function validatePassword(password: string): void {
  if (password.length < 12 || password.length > 128) {
    throw invalidRequest('password must contain between 12 and 128 characters');
  }
  if (!/[a-z]/u.test(password) || !/[A-Z]/u.test(password) || !/\d/u.test(password)) {
    throw invalidRequest('password must contain uppercase, lowercase and numeric characters');
  }
}

function accountView(account: AdminAccountRecord & { roles?: string[] }): AdminAccountView {
  return {
    id: account.id,
    username: account.username,
    displayName: account.displayName,
    status: account.status,
    roles: [...(account.roles ?? [])],
    mfaEnabled: account.mfaConfirmedAt !== null,
    createdAt: account.createdAt.toISOString(),
    updatedAt: account.updatedAt.toISOString(),
  };
}

export interface AdminIdentityServiceOptions {
  store: ControlStore;
  controlSecret: string;
  now?: () => number;
  sessionDurationMs?: number;
  sessionIdleMs?: number;
  enrollmentDurationMs?: number;
  approvalDurationMs?: number;
}

export interface AdminEnrollmentResult {
  account: AdminAccountView;
  enrollmentToken: string;
  mfaSecret: string;
  otpauthUri: string;
}

export interface AdminSessionResult {
  token: string;
  expiresAt: string;
  principal: AdminPrincipal;
}

export class AdminIdentityService {
  readonly #store: ControlStore;
  readonly #controlSecret: string;
  readonly #now: () => number;
  readonly #sessionDurationMs: number;
  readonly #sessionIdleMs: number;
  readonly #enrollmentDurationMs: number;
  readonly #approvalDurationMs: number;
  readonly #dummyPasswordHash: Promise<string>;

  constructor(options: AdminIdentityServiceOptions) {
    this.#store = options.store;
    this.#controlSecret = options.controlSecret;
    this.#now = options.now ?? Date.now;
    this.#sessionDurationMs = options.sessionDurationMs ?? 8 * 60 * 60 * 1000;
    this.#sessionIdleMs = options.sessionIdleMs ?? 30 * 60 * 1000;
    this.#enrollmentDurationMs = options.enrollmentDurationMs ?? 15 * 60 * 1000;
    this.#approvalDurationMs = options.approvalDurationMs ?? 30 * 60 * 1000;
    this.#dummyPasswordHash = hashAdminPassword(randomOpaqueToken());
  }

  async hasAccounts(): Promise<boolean> {
    return (await this.#store.countAdminAccounts()) > 0;
  }

  async bootstrap(input: {
    username: string;
    displayName: string;
    password: string;
  }): Promise<AdminEnrollmentResult> {
    if (await this.hasAccounts()) throw conflict('administrator bootstrap is already complete');
    return this.#createAccount('bootstrap', { ...input, roleIds: ['super_admin'] });
  }

  async createAccount(
    actor: AdminPrincipal,
    input: { username: string; displayName: string; password: string; roleIds: string[] },
  ): Promise<AdminEnrollmentResult> {
    this.requirePermission(actor, 'identity.manage');
    return this.#createAccount(actor.accountId, input);
  }

  async #createAccount(
    actorId: string,
    input: { username: string; displayName: string; password: string; roleIds: string[] },
  ): Promise<AdminEnrollmentResult> {
    const username = normalizedUsername(input.username);
    const displayName = requiredText(input.displayName, 'displayName', 100);
    validatePassword(input.password);
    const roleIds = [...new Set(input.roleIds.map((roleId) => roleId.trim()))];
    if (!roleIds.length || roleIds.some((roleId) => !ROLE_PATTERN.test(roleId))) {
      throw invalidRequest('at least one valid role is required');
    }
    const availableRoles = new Set((await this.#store.listAdminRoles()).map((role) => role.id));
    if (roleIds.some((roleId) => !availableRoles.has(roleId))) throw invalidRequest('admin role does not exist');
    const mfaSecret = generateMfaSecret();
    const enrollmentToken = randomOpaqueToken();
    const now = new Date(this.#now());
    const account = await this.#store.createAdminAccount({
      id: id('adm'),
      username,
      displayName,
      passwordHash: await hashAdminPassword(input.password),
      mfaSecretCiphertext: encryptMfaSecret(mfaSecret, this.#controlSecret),
      enrollmentTokenHash: hashOpaqueToken(enrollmentToken),
      enrollmentExpiresAt: new Date(now.getTime() + this.#enrollmentDurationMs),
      roleIds,
    });
    await this.#audit(actorId, 'admin.account.create', 'admin_account', account.id, {
      username,
      roleIds,
    });
    return {
      account: accountView({ ...account, roles: roleIds }),
      enrollmentToken,
      mfaSecret,
      otpauthUri: `otpauth://totp/Otto%20Control:${encodeURIComponent(username)}?secret=${mfaSecret}&issuer=Otto%20Control&algorithm=SHA1&digits=6&period=30`,
    };
  }

  async confirmEnrollment(input: {
    accountId: string;
    enrollmentToken: string;
    totpCode: string;
  }): Promise<AdminSessionResult & { recoveryCodes: string[] }> {
    const account = await this.#store.getAdminAccountById(input.accountId);
    if (!account || account.status !== 'pending') throw unauthorized('Enrollment is invalid or expired');
    const secret = decryptMfaSecret(account.mfaSecretCiphertext, this.#controlSecret);
    const nowMs = this.#now();
    if (!verifyTotpCode(secret, input.totpCode.trim(), nowMs)) {
      throw unauthorized('Enrollment is invalid or expired');
    }
    const recoveryCodes = createRecoveryCodes();
    const confirmed = await this.#store.confirmAdminEnrollment({
      accountId: account.id,
      enrollmentTokenHash: hashOpaqueToken(input.enrollmentToken),
      recoveryCodeHashes: recoveryCodes.map((code) => hashRecoveryCode(code, this.#controlSecret)),
      confirmedAt: new Date(nowMs),
    });
    if (!confirmed) throw unauthorized('Enrollment is invalid or expired');
    const session = await this.#issueSession(confirmed, nowMs);
    await this.#audit(account.id, 'admin.enrollment.confirm', 'admin_account', account.id, {});
    return { ...session, recoveryCodes };
  }

  async login(input: {
    username: string;
    password: string;
    totpCode?: string;
    recoveryCode?: string;
  }): Promise<AdminSessionResult> {
    const nowMs = this.#now();
    const account = await this.#store.getAdminAccountByUsername(input.username.trim().toLowerCase());
    const passwordValid = await verifyAdminPassword(
      input.password,
      account?.passwordHash ?? await this.#dummyPasswordHash,
    );
    if (account?.lockedUntil && account.lockedUntil.getTime() > nowMs) {
      throw unauthorized('Administrator account is temporarily locked');
    }
    if (!account || account.status !== 'active' || !account.mfaConfirmedAt || !passwordValid) {
      if (account) await this.#recordLoginFailure(account, nowMs);
      throw unauthorized('Invalid administrator credentials');
    }
    let mfaValid = false;
    if (input.totpCode) {
      const secret = decryptMfaSecret(account.mfaSecretCiphertext, this.#controlSecret);
      mfaValid = verifyTotpCode(secret, input.totpCode.trim(), nowMs);
    } else if (input.recoveryCode) {
      mfaValid = await this.#store.consumeAdminRecoveryCode(
        account.id,
        hashRecoveryCode(input.recoveryCode, this.#controlSecret),
        new Date(nowMs),
      );
    }
    if (!mfaValid) {
      await this.#recordLoginFailure(account, nowMs);
      throw unauthorized('Invalid administrator credentials');
    }
    await this.#store.clearAdminLoginFailures(account.id, new Date(nowMs));
    const result = await this.#issueSession(account, nowMs);
    await this.#audit(account.id, 'admin.login.success', 'admin_session', result.principal.sessionId, {});
    return result;
  }

  async #recordLoginFailure(account: AdminAccountRecord, nowMs: number): Promise<void> {
    const failedLoginCount = account.failedLoginCount + 1;
    await this.#store.recordAdminLoginFailure({
      accountId: account.id,
      failedLoginCount: failedLoginCount >= MAX_FAILED_LOGINS ? 0 : failedLoginCount,
      lockedUntil: failedLoginCount >= MAX_FAILED_LOGINS
        ? new Date(nowMs + LOGIN_LOCK_MS)
        : null,
      changedAt: new Date(nowMs),
    });
    await this.#audit(account.id, 'admin.login.failure', 'admin_account', account.id, {});
  }

  async #issueSession(account: AdminAccountRecord, nowMs: number): Promise<AdminSessionResult> {
    const token = randomOpaqueToken();
    const expiresAt = new Date(nowMs + this.#sessionDurationMs);
    const session = await this.#store.createAdminSession({
      id: id('ads'),
      accountId: account.id,
      tokenHash: hashOpaqueToken(token),
      expiresAt,
      mfaVerifiedAt: new Date(nowMs),
      createdAt: new Date(nowMs),
    });
    const principal = await this.#store.getAdminPrincipalBySessionTokenHash({
      tokenHash: hashOpaqueToken(token),
      now: new Date(nowMs),
      idleCutoff: new Date(nowMs - this.#sessionIdleMs),
    });
    if (!principal) throw new Error(`new administrator session ${session.id} could not be resolved`);
    return { token, expiresAt: expiresAt.toISOString(), principal };
  }

  async authenticate(token: string): Promise<AdminPrincipal> {
    if (!token) throw unauthorized();
    const nowMs = this.#now();
    const principal = await this.#store.getAdminPrincipalBySessionTokenHash({
      tokenHash: hashOpaqueToken(token),
      now: new Date(nowMs),
      idleCutoff: new Date(nowMs - this.#sessionIdleMs),
    });
    if (!principal) throw unauthorized('Administrator session is invalid or expired');
    await this.#store.touchAdminSession(principal.sessionId, new Date(nowMs));
    return principal;
  }

  async logout(principal: AdminPrincipal): Promise<void> {
    const now = new Date(this.#now());
    await this.#store.revokeAdminSession(principal.sessionId, now);
    await this.#audit(principal.accountId, 'admin.logout', 'admin_session', principal.sessionId, {});
  }

  requirePermission(principal: AdminPrincipal, permission: AdminPermission): void {
    if (!principal.permissions.includes(permission)) throw forbidden(`Missing permission: ${permission}`);
  }

  async listAccounts(principal: AdminPrincipal): Promise<AdminAccountView[]> {
    this.requirePermission(principal, 'identity.read');
    return (await this.#store.listAdminAccounts()).map(accountView);
  }

  async listRoles(principal: AdminPrincipal): Promise<AdminRoleRecord[]> {
    this.requirePermission(principal, 'identity.read');
    return this.#store.listAdminRoles();
  }

  async replaceRoles(
    principal: AdminPrincipal,
    accountId: string,
    roleIds: string[],
  ): Promise<string[]> {
    this.requirePermission(principal, 'identity.manage');
    const roles = [...new Set(roleIds.map((roleId) => roleId.trim()))];
    if (!roles.length) throw invalidRequest('at least one role is required');
    const account = await this.#store.getAdminAccountById(accountId);
    if (!account) throw notFound('administrator account not found');
    await this.#protectLastSuperAdmin(accountId, roles, account.status);
    const updated = await this.#store.replaceAdminAccountRoles(accountId, roles);
    if (!updated) throw notFound('administrator account not found');
    await this.#store.revokeAdminAccountSessions(accountId, new Date(this.#now()));
    await this.#audit(principal.accountId, 'admin.roles.replace', 'admin_account', accountId, { roleIds: updated });
    return updated;
  }

  async setAccountStatus(
    principal: AdminPrincipal,
    accountId: string,
    status: AdminAccountRecord['status'],
  ): Promise<AdminAccountView> {
    this.requirePermission(principal, 'identity.manage');
    if (status === 'pending') throw invalidRequest('an administrator cannot be returned to pending status');
    if (principal.accountId === accountId && status === 'disabled') {
      throw conflict('an administrator cannot disable their own account');
    }
    const account = await this.#store.getAdminAccountById(accountId);
    if (!account) throw notFound('administrator account not found');
    const existing = (await this.#store.listAdminAccounts()).find((entry) => entry.id === accountId)!;
    await this.#protectLastSuperAdmin(accountId, existing.roles, status);
    const now = new Date(this.#now());
    const updated = await this.#store.setAdminAccountStatus(accountId, status, now);
    if (!updated) throw notFound('administrator account not found');
    if (status === 'disabled') await this.#store.revokeAdminAccountSessions(accountId, now);
    await this.#audit(principal.accountId, 'admin.status.change', 'admin_account', accountId, { status });
    return accountView({ ...updated, roles: existing.roles });
  }

  async #protectLastSuperAdmin(
    accountId: string,
    proposedRoles: string[],
    proposedStatus: AdminAccountRecord['status'],
  ): Promise<void> {
    const accounts = await this.#store.listAdminAccounts();
    const activeSuperAdmins = accounts.filter((account) => (
      account.status === 'active' && account.roles.includes('super_admin')
    ));
    const targetIsLast = activeSuperAdmins.length === 1 && activeSuperAdmins[0]!.id === accountId;
    if (targetIsLast && (proposedStatus !== 'active' || !proposedRoles.includes('super_admin'))) {
      throw conflict('the last active super administrator must be preserved');
    }
  }

  approvalHash(input: {
    operation: string;
    targetType: string;
    targetId: string;
    request: unknown;
  }): string {
    return createHash('sha256').update(canonicalJson(input)).digest('hex');
  }

  async requestApproval(
    principal: AdminPrincipal,
    input: { operation: string; targetType: string; targetId: string; request: unknown },
  ): Promise<AdminApprovalRecord> {
    this.requirePermission(principal, 'approval.request');
    const operation = requiredText(input.operation, 'operation', 128);
    const targetType = requiredText(input.targetType, 'targetType', 80);
    const targetId = requiredText(input.targetId, 'targetId', 160);
    if (!(ADMIN_APPROVAL_OPERATIONS as readonly string[]).includes(operation)) {
      throw invalidRequest('operation is not eligible for approval');
    }
    const request = approvalRequestSnapshot(operation, input.request);
    const now = new Date(this.#now());
    const requestHash = this.approvalHash({ operation, targetType, targetId, request });
    const duplicate = (await this.#store.listAdminApprovals(500)).find((approval) => (
      approval.requesterAccountId === principal.accountId &&
      approval.operation === operation &&
      approval.targetType === targetType &&
      approval.targetId === targetId &&
      approval.requestHash === requestHash &&
      ['pending', 'approved'].includes(approval.status) &&
      approval.expiresAt > now
    ));
    if (duplicate) throw conflict(`matching approval is already ${duplicate.status}`);
    const approval = await this.#store.createAdminApproval({
      id: id('apr'),
      requesterAccountId: principal.accountId,
      operation,
      targetType,
      targetId,
      requestHash,
      request,
      requiredApprovals: 1,
      expiresAt: new Date(now.getTime() + this.#approvalDurationMs),
      createdAt: now,
    });
    await this.#audit(principal.accountId, 'admin.approval.request', 'admin_approval', approval.id, {
      operation,
      targetType,
      targetId,
    });
    return approval;
  }

  async listApprovals(principal: AdminPrincipal, limit = 100): Promise<AdminApprovalRecord[]> {
    this.requirePermission(principal, 'approval.read');
    const normalizedLimit = Number.isFinite(limit) ? Math.trunc(limit) : 100;
    return this.#store.listAdminApprovals(Math.max(1, Math.min(500, normalizedLimit)));
  }

  async decideApproval(
    principal: AdminPrincipal,
    approvalId: string,
    decision: 'approve' | 'reject',
    reason: string | null,
  ): Promise<AdminApprovalRecord> {
    this.requirePermission(principal, 'approval.decide');
    const approval = await this.#store.decideAdminApproval({
      approvalId,
      accountId: principal.accountId,
      decision,
      reason: reason?.trim().slice(0, 500) || null,
      decidedAt: new Date(this.#now()),
    });
    if (!approval) throw notFound('approval request not found');
    await this.#audit(principal.accountId, `admin.approval.${decision}`, 'admin_approval', approval.id, {
      status: approval.status,
    });
    return approval;
  }

  async consumeApproval(
    principal: AdminPrincipal,
    approvalId: string,
    input: { operation: string; targetType: string; targetId: string; request: unknown },
  ): Promise<void> {
    const consumed = await this.#store.consumeAdminApproval({
      approvalId,
      requesterAccountId: principal.accountId,
      operation: input.operation,
      targetType: input.targetType,
      targetId: input.targetId,
      requestHash: this.approvalHash(input),
      executedAt: new Date(this.#now()),
    });
    if (!consumed) {
      throw approvalRequired('A valid approval from another administrator is required');
    }
    await this.#audit(principal.accountId, 'admin.approval.consume', 'admin_approval', approvalId, {
      operation: input.operation,
      targetType: input.targetType,
      targetId: input.targetId,
    });
  }

  async #audit(
    actorId: string,
    action: string,
    targetType: string,
    targetId: string,
    detail: Record<string, unknown>,
  ): Promise<void> {
    await this.#store.appendAuditEvent({ actorId, action, targetType, targetId, detail });
  }
}

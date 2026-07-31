export const ADMIN_PERMISSIONS = [
  'customer.create',
  'deployment.create',
  'license.issue',
  'license.read',
  'license.revoke',
  'license.manage',
  'license.transfer',
  'license.usage.read',
  'signing_key.read',
  'signing_key.manage',
  'telemetry.read',
  'update_distribution.manage',
  'update_release.create',
  'update_release.read',
  'update_release.publish',
  'identity.read',
  'identity.manage',
  'approval.request',
  'approval.read',
  'approval.decide',
  'billing.read',
  'billing.topup',
  'billing.manage',
  'billing.refund',
] as const;

export type AdminPermission = (typeof ADMIN_PERMISSIONS)[number];
export type AdminAccountStatus = 'pending' | 'active' | 'disabled';
export type AdminApprovalStatus = 'pending' | 'approved' | 'rejected' | 'executed' | 'expired';

export interface AdminAccountRecord {
  id: string;
  username: string;
  displayName: string;
  passwordHash: string;
  mfaSecretCiphertext: string;
  status: AdminAccountStatus;
  failedLoginCount: number;
  lockedUntil: Date | null;
  mfaConfirmedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface AdminAccountView {
  id: string;
  username: string;
  displayName: string;
  status: AdminAccountStatus;
  roles: string[];
  mfaEnabled: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface AdminRoleRecord {
  id: string;
  name: string;
  permissions: AdminPermission[];
  system: boolean;
}

export interface AdminSessionRecord {
  id: string;
  accountId: string;
  username: string;
  displayName: string;
  tokenHash: string;
  expiresAt: Date;
  lastSeenAt: Date;
  mfaVerifiedAt: Date;
  revokedAt: Date | null;
  createdAt: Date;
}

export interface AdminPrincipal {
  accountId: string;
  sessionId: string;
  username: string;
  displayName: string;
  roles: string[];
  permissions: AdminPermission[];
  mfaVerifiedAt: Date;
}

export interface AdminApprovalRecord {
  id: string;
  requesterAccountId: string;
  operation: string;
  targetType: string;
  targetId: string;
  requestHash: string;
  status: AdminApprovalStatus;
  requiredApprovals: number;
  approvalCount: number;
  expiresAt: Date;
  executedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

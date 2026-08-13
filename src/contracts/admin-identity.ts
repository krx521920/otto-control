export const ADMIN_PERMISSIONS = [
  'commercial.read',
  'customer.create',
  'deployment.create',
  'license.issue',
  'license.read',
  'license.export',
  'license.revoke',
  'license.manage',
  'license.transfer',
  'license.usage.read',
  'signing_key.read',
  'signing_key.manage',
  'telemetry.read',
  'backup.read',
  'alert.read',
  'alert.manage',
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
  'edge_gateway.read',
  'edge_gateway.manage',
  'audit.read',
  'audit.export',
  'audit.verify',
  'audit.anchor.manage',
  'data_governance.read',
  'data_governance.manage',
  'data_export.create',
  'customer_erasure.manage',
  'legal_hold.manage',
  'forensic_export.create',
  'customer_delivery.read',
] as const;

export type AdminPermission = (typeof ADMIN_PERMISSIONS)[number];
export type AdminAccountStatus = 'pending' | 'active' | 'disabled';
export type AdminApprovalStatus = 'pending' | 'approved' | 'rejected' | 'executed' | 'expired';
export const ADMIN_APPROVAL_OPERATIONS = [
  'license.revoke',
  'license.transfer_machine',
  'license.rebind_deployment',
  'signing_key.activate',
  'signing_key.retire',
  'signing_key.revoke',
  'update_release.activate',
  'update_release.rollback',
  'release_artifact.revoke',
  'billing.rate.set',
  'billing.topup',
  'billing.refund',
  'billing.execution_receipt_key.register',
  'billing.execution_receipt_key.revoke',
  'billing.edge_node.register',
  'billing.edge_node.revoke',
  'customer_erasure.execute',
  'legal_hold.create',
  'legal_hold.release',
  'forensic_export.create',
] as const;
export type AdminApprovalOperation = (typeof ADMIN_APPROVAL_OPERATIONS)[number];

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
  request: Record<string, unknown>;
  status: AdminApprovalStatus;
  requiredApprovals: number;
  approvalCount: number;
  expiresAt: Date;
  executedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

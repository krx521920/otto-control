export type DataGovernanceRequestType =
  | 'customer_export'
  | 'customer_erasure'
  | 'forensic_export';

export type DataGovernanceRequestStatus =
  | 'pending'
  | 'completed'
  | 'blocked'
  | 'failed';

export type DataDisposition = 'deleted' | 'anonymized' | 'retained' | 'restricted';

export interface DataGovernanceConfig {
  dataRegion: string;
  allowedRegions: string[];
  crossBorderEnabled: boolean;
  crossBorderAssessmentId: string | null;
  policyVersion: string;
  policyEffectiveAt: string;
  controllerName: string;
  privacyContact: string;
  customerErasureGraceDays: number;
  privacyRequestSlaDays: number;
  billingRetentionDays: number;
  auditRetentionDays: number;
  exportRecordRetentionDays: number;
  retentionPollIntervalMs: number;
}

export interface DataGovernanceStateRecord {
  dataRegion: string;
  allowedRegions: string[];
  crossBorderEnabled: boolean;
  crossBorderAssessmentId: string | null;
  policyVersion: string;
  policySha256: string;
  policyEffectiveAt: Date;
  controllerName: string;
  privacyContact: string;
  initializedAt: Date;
  updatedAt: Date;
}

export interface DataGovernanceRequestRecord {
  id: string;
  customerId: string;
  type: DataGovernanceRequestType;
  status: DataGovernanceRequestStatus;
  reason: string;
  requestedBy: string;
  earliestExecutionAt: Date | null;
  dueAt: Date;
  manifestSha256: string | null;
  result: Record<string, unknown> | null;
  completedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface LegalHoldRecord {
  id: string;
  customerId: string;
  scope: string[];
  reason: string;
  createdBy: string;
  expiresAt: Date | null;
  releasedAt: Date | null;
  releasedBy: string | null;
  releaseReason: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface PrivacyAcceptanceRecord {
  id: string;
  customerId: string;
  policyVersion: string;
  policySha256: string;
  acceptedBy: string;
  acceptedAt: Date;
}

export interface CustomerDataExportSnapshot {
  customer: {
    id: string;
    name: string;
    status: string;
    dataRegion: string;
    erasedAt: string | null;
    createdAt: string;
    updatedAt: string;
  };
  deployments: Array<{
    id: string;
    organizationId: string;
    machineFingerprint: string;
    name: string;
    status: string;
    createdAt: string;
    updatedAt: string;
  }>;
  licenses: Array<{
    id: string;
    deploymentId: string;
    plan: string;
    issuedAtMs: number;
    expiresAtMs: number;
    seatLimit: number;
    modules: string[];
    offline: boolean;
    telemetryAllowed: boolean;
    seatEnforcement?: string;
    billingEnforcement?: string;
    revokedAtMs: number | null;
    createdAt: string;
    updatedAt: string;
  }>;
  billing: {
    account: Record<string, unknown> | null;
    accounts: Array<Record<string, unknown>>;
    rates: Array<Record<string, unknown>>;
    transactions: Array<Record<string, unknown>>;
  };
  telemetry: {
    totalEvents: number;
    byType: Record<string, number>;
    firstReceivedAt: string | null;
    lastReceivedAt: string | null;
  };
  privacyAcceptances: PrivacyAcceptanceRecord[];
}

export interface CustomerErasureResult {
  requestId: string;
  customerId: string;
  completedAt: string;
  dispositions: Array<{
    dataClass: string;
    disposition: DataDisposition;
    records: number;
    reason: string;
    retainUntil: string | null;
  }>;
}

export interface RetentionRunResult {
  telemetryEventsDeleted: number;
  expiredNoncesDeleted: number;
  expiredExportPayloadsRestricted: number;
  deploymentEnrollmentsSanitized: number;
}

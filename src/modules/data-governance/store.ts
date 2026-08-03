import type {
  CustomerDataExportSnapshot,
  CustomerErasureResult,
  DataGovernanceRequestRecord,
  DataGovernanceRequestType,
  DataGovernanceStateRecord,
  LegalHoldRecord,
  PrivacyAcceptanceRecord,
  RetentionRunResult,
} from '../../contracts/data-governance.js';

export interface DataGovernanceStore {
  initializeDataGovernanceState(
    input: Omit<DataGovernanceStateRecord, 'initializedAt' | 'updatedAt'>,
  ): Promise<DataGovernanceStateRecord>;
  getDataGovernanceState(): Promise<DataGovernanceStateRecord | null>;
  createDataGovernanceRequest(input: {
    id: string;
    customerId: string;
    type: DataGovernanceRequestType;
    reason: string;
    requestedBy: string;
    earliestExecutionAt: Date | null;
    dueAt: Date;
    createdAt: Date;
  }): Promise<DataGovernanceRequestRecord>;
  getDataGovernanceRequest(id: string): Promise<DataGovernanceRequestRecord | null>;
  completeDataGovernanceRequest(input: {
    id: string;
    status: 'completed' | 'blocked' | 'failed';
    manifestSha256: string | null;
    result: Record<string, unknown>;
    completedAt: Date;
  }): Promise<DataGovernanceRequestRecord | null>;
  exportCustomerGovernanceData(customerId: string): Promise<CustomerDataExportSnapshot | null>;
  createLegalHold(input: {
    id: string;
    customerId: string;
    scope: string[];
    reason: string;
    createdBy: string;
    expiresAt: Date | null;
    createdAt: Date;
  }): Promise<LegalHoldRecord>;
  getLegalHold(id: string): Promise<LegalHoldRecord | null>;
  listActiveLegalHolds(customerId: string, at: Date): Promise<LegalHoldRecord[]>;
  releaseLegalHold(input: {
    id: string;
    releasedBy: string;
    releaseReason: string;
    releasedAt: Date;
  }): Promise<LegalHoldRecord | null>;
  recordPrivacyAcceptance(input: PrivacyAcceptanceRecord): Promise<PrivacyAcceptanceRecord>;
  executeCustomerErasure(input: {
    requestId: string;
    pseudonymSeed: string;
    billingRetainUntil: Date;
    auditRetainUntil: Date;
    completedAt: Date;
  }): Promise<CustomerErasureResult | null>;
  runDataRetention(input: {
    telemetryBefore: Date;
    exportPayloadBefore: Date;
    now: Date;
  }): Promise<RetentionRunResult>;
}

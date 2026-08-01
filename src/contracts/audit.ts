export interface AuditEventRecord {
  id: number;
  actorId: string;
  action: string;
  targetType: string;
  targetId: string;
  detail: Record<string, unknown>;
  chainSequence: number | null;
  previousHash: string | null;
  eventHash: string | null;
  createdAt: Date;
}

export interface AuditEventView extends Omit<AuditEventRecord, 'createdAt'> {
  createdAt: string;
}

export interface AuditEventQuery {
  actorId?: string;
  action?: string;
  targetType?: string;
  targetId?: string;
  from?: Date;
  to?: Date;
  beforeId?: number;
  limit: number;
}

export interface AuditChainState {
  lastSequence: number;
  headHash: string;
  updatedAt: Date;
}

export interface AuditIntegrityReceipt {
  version: 1;
  issuer: string;
  generatedAt: string;
  valid: boolean;
  checkedEvents: number;
  firstSequence: number | null;
  lastSequence: number;
  headHash: string;
  brokenAtSequence: number | null;
  legacyEventCount: number;
}

export interface SignedAuditIntegrityReceipt {
  receipt: AuditIntegrityReceipt;
  signingKeyId: string;
  signature: string;
}

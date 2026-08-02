import type { AuditAnchorPayload } from './audit-anchor.js';

export interface AuditWitnessReceiptRecord {
  id: string;
  sourceId: string;
  anchorId: string;
  fingerprint: string;
  issuer: string;
  chainSequence: number;
  headHash: string;
  signingKeyId: string;
  payload: AuditAnchorPayload;
  receivedAt: Date;
}

export interface AuditWitnessReceiptView extends Omit<AuditWitnessReceiptRecord, 'receivedAt'> {
  receivedAt: string;
}

export interface AuditWitnessSourceSummary {
  id: string;
  issuer: string;
  signingKeyIds: string[];
}

export type AuditWitnessEvidenceStatus =
  | 'pending'
  | 'storing'
  | 'retrying'
  | 'stored'
  | 'failed';

export interface AuditWitnessEvidenceEnvelope {
  version: 1;
  receiptId: string;
  sourceId: string;
  anchorId: string;
  fingerprint: string;
  issuer: string;
  chainSequence: number;
  headHash: string;
  signingKeyId: string;
  payload: AuditAnchorPayload;
  receivedAt: string;
}

export interface AuditWitnessEvidenceRecord {
  receiptId: string;
  sourceId: string;
  chainSequence: number;
  objectKey: string;
  contentSha256: string;
  sizeBytes: number;
  status: AuditWitnessEvidenceStatus;
  attempts: number;
  nextAttemptAt: Date;
  leaseUntil: Date | null;
  lastError: string | null;
  objectVersionId: string | null;
  serverSideEncryption: string | null;
  objectLockMode: string | null;
  objectLockRetainUntil: Date | null;
  storedAt: Date | null;
  verifiedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface AuditWitnessEvidenceView extends Omit<
  AuditWitnessEvidenceRecord,
  | 'nextAttemptAt'
  | 'leaseUntil'
  | 'objectLockRetainUntil'
  | 'storedAt'
  | 'verifiedAt'
  | 'createdAt'
  | 'updatedAt'
> {
  nextAttemptAt: string;
  leaseUntil: string | null;
  objectLockRetainUntil: string | null;
  storedAt: string | null;
  verifiedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface AuditWitnessEvidencePollResult {
  enabled: boolean;
  processed: number;
  stored: number;
  retrying: number;
  failed: number;
}

export interface AuditWitnessEvidenceStatusSummary {
  enabled: boolean;
  required: boolean;
  healthy: boolean;
  pending: number;
  retrying: number;
  storing: number;
  stored: number;
  failed: number;
  oldestPendingAt: string | null;
  latestVerifiedAt: string | null;
  evidence: AuditWitnessEvidenceView[];
}

export interface AuditWitnessEvidenceRecoveryResult {
  processed: number;
  restored: number;
  replayed: number;
  continuationToken: string | null;
}

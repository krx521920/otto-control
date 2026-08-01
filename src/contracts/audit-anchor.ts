import type { SignedAuditIntegrityReceipt } from './audit.js';

export type AuditAnchorStatus =
  | 'pending'
  | 'delivering'
  | 'retrying'
  | 'delivered'
  | 'failed';

export interface AuditAnchorPayload {
  version: 1;
  anchorId: string;
  fingerprint: string;
  evidence: SignedAuditIntegrityReceipt;
}

export interface AuditAnchorRecord {
  id: string;
  fingerprint: string;
  payload: AuditAnchorPayload;
  status: AuditAnchorStatus;
  attempts: number;
  nextAttemptAt: Date;
  leaseUntil: Date | null;
  lastError: string | null;
  deliveredAt: Date | null;
  remoteReference: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface AuditAnchorView extends Omit<
  AuditAnchorRecord,
  'nextAttemptAt' | 'leaseUntil' | 'deliveredAt' | 'createdAt' | 'updatedAt'
> {
  nextAttemptAt: string;
  leaseUntil: string | null;
  deliveredAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface AuditAnchorPollResult {
  enabled: boolean;
  destinationOrigin: string | null;
  enqueued: boolean;
  chainValid: boolean | null;
  processed: number;
  delivered: number;
  retrying: number;
  failed: number;
}

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

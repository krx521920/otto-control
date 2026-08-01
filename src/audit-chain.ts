import { createHash } from 'node:crypto';

import { canonicalJson } from './crypto/signed-envelope.js';

export const AUDIT_GENESIS_HASH = '0'.repeat(64);

export interface AuditHashInput {
  sequence: number;
  previousHash: string;
  actorId: string;
  action: string;
  targetType: string;
  targetId: string;
  detail: Record<string, unknown>;
  createdAt: Date;
}

export function auditEventHash(input: AuditHashInput): string {
  return createHash('sha256').update(canonicalJson({
    version: 1,
    sequence: input.sequence,
    previousHash: input.previousHash,
    actorId: input.actorId,
    action: input.action,
    targetType: input.targetType,
    targetId: input.targetId,
    detail: input.detail,
    createdAt: input.createdAt.toISOString(),
  })).digest('hex');
}

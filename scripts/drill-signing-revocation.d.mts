import type { SigningAuditEvidence } from './signing-audit-evidence.mjs';

export interface SigningRevocationDrillInput {
  controlUrl: URL;
  requesterToken: string;
  approverToken: string;
  auditorToken?: string;
  keyId: string;
  replacementKeyId: string;
  reason: string;
}

export interface SigningRevocationDrillReport {
  version: 1;
  drill: 'signing_key_emergency_revocation';
  startedAt: string;
  completedAt: string;
  result: 'passed';
  revokedKeyId: string;
  activeKeyId: string;
  approvalId: string;
  reason: string;
  publicKeyringVerified: true;
  auditEvidence: SigningAuditEvidence | null;
}

export function runSigningRevocationDrill(
  input: SigningRevocationDrillInput,
): Promise<SigningRevocationDrillReport>;

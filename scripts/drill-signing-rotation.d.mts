import type { SigningAuditEvidence } from './signing-audit-evidence.mjs';

export interface SigningRotationDrillInput {
  controlUrl: URL;
  requesterToken: string;
  approverToken: string;
  auditorToken?: string;
  targetKeyId: string;
  legacyLicenseId?: string | null;
}

export interface SigningRotationDrillReport {
  version: 1;
  drill: 'signing_key_rotation';
  startedAt: string;
  completedAt: string;
  result: 'passed';
  previousKeyId: string;
  activeKeyId: string;
  targetProvider: string;
  targetBackend: string | null;
  targetLocation: string | null;
  approvalId: string;
  legacyLicenseVerification: {
    licenseId: string;
    signingKeyId: string;
    keyState: 'retired';
    verifiedBeforeRotation: true;
    verifiedAfterRotation: true;
  } | null;
  auditEvidence: SigningAuditEvidence | null;
}

export function runSigningRotationDrill(
  input: SigningRotationDrillInput,
): Promise<SigningRotationDrillReport>;

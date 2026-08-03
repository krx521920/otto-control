export interface SigningRevocationDrillInput {
  controlUrl: URL;
  requesterToken: string;
  approverToken: string;
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
}

export function runSigningRevocationDrill(
  input: SigningRevocationDrillInput,
): Promise<SigningRevocationDrillReport>;

export interface SigningRotationDrillInput {
  controlUrl: URL;
  requesterToken: string;
  approverToken: string;
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
}

export function runSigningRotationDrill(
  input: SigningRotationDrillInput,
): Promise<SigningRotationDrillReport>;

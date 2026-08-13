export interface AliyunEsaReleaseArtifact {
  raw: string;
  value?: unknown;
}

export interface AliyunEsaReleasePreflightInput {
  worker: AliyunEsaReleaseArtifact;
  policy: Required<AliyunEsaReleaseArtifact>;
  keyring: Required<AliyunEsaReleaseArtifact>;
  secrets: Required<AliyunEsaReleaseArtifact>;
  canary: Required<AliyunEsaReleaseArtifact>;
  evidence: Required<AliyunEsaReleaseArtifact>;
}

export interface AliyunEsaReleasePreflightResult {
  evidenceId: string;
  workerSha256: string;
  policySha256: string;
  keyringSha256: string;
  secretBindingsSha256: string;
  canaryReportSha256: string;
}

export function validateAliyunEsaRelease(
  input: AliyunEsaReleasePreflightInput,
): AliyunEsaReleasePreflightResult;

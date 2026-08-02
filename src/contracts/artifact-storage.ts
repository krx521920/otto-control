import type {
  ReleaseArtifactKind,
  ReleaseArtifactPlatform,
} from './release-artifact.js';

export type ArtifactCodeSigningSystem =
  | 'authenticode'
  | 'apple_developer_id'
  | 'sigstore'
  | 'linux_package';

export interface ArtifactUploadTicketPayload {
  version: 1;
  id: string;
  artifactId: string;
  releaseId: string;
  distributionId: string;
  releaseVersion: string;
  sourceCommit: string;
  kind: ReleaseArtifactKind;
  platform: ReleaseArtifactPlatform;
  objectKey: string;
  sha256: string;
  sizeBytes: number;
  contentType: string;
  createdBy: string;
  issuedAtMs: number;
  expiresAtMs: number;
}

export interface SignedArtifactUploadTicket {
  ticket: ArtifactUploadTicketPayload;
  signingKeyId: string;
  signature: string;
}

export interface ArtifactCodeSigningEvidencePayload {
  version: 1;
  releaseId: string;
  releaseVersion: string;
  sourceCommit: string;
  kind: ReleaseArtifactKind;
  platform: ReleaseArtifactPlatform;
  sha256: string;
  sizeBytes: number;
  system: ArtifactCodeSigningSystem;
  status: 'valid';
  signerIdentity: string;
  certificateSha256: string;
  timestamped: boolean;
  notarized: boolean;
  verifier: string;
  evidenceSha256: string;
  verifiedAtMs: number;
}

export interface SignedArtifactCodeSigningEvidence {
  evidence: ArtifactCodeSigningEvidencePayload;
  attestationKeyId: string;
  signature: string;
}

export interface ArtifactStorageEvidence {
  artifactId: string;
  objectKey: string;
  objectVersionId: string | null;
  verifiedAt: string;
  serverSideEncryption: string | null;
  objectLockMode: string | null;
  objectLockRetainUntil: string | null;
  codeSigning: SignedArtifactCodeSigningEvidence | null;
}

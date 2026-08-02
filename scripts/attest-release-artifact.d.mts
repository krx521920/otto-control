import type {
  ArtifactCodeSigningEvidencePayload,
  SignedArtifactCodeSigningEvidence,
} from '../src/contracts/artifact-storage.js';
import type {
  ReleaseArtifactKind,
  ReleaseArtifactPlatform,
} from '../src/contracts/release-artifact.js';

export function canonicalJson(value: unknown): string;

export function createAttestation(input: {
  file: string;
  releaseId: string;
  releaseVersion: string;
  sourceCommit: string;
  kind: ReleaseArtifactKind;
  platform: ReleaseArtifactPlatform;
  attestationKeyId: string;
  attestationPrivateKeyFile: string;
  linuxSignature?: string;
  linuxPublicKey?: string;
}): SignedArtifactCodeSigningEvidence & {
  evidence: ArtifactCodeSigningEvidencePayload;
};

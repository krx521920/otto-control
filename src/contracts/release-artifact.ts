import type { ArtifactStorageEvidence } from './artifact-storage.js';

export const RELEASE_ARTIFACT_KINDS = [
  'windows_installer',
  'macos_dmg',
  'linux_archive',
  'enterprise_server',
  'update_manifest',
  'incremental_manifest',
  'skills_component',
  'renderer_patch',
  'server_runtime',
] as const;

export type ReleaseArtifactKind = (typeof RELEASE_ARTIFACT_KINDS)[number];

export const RELEASE_ARTIFACT_PLATFORMS = [
  'windows-x64',
  'windows-arm64',
  'macos-x64',
  'macos-arm64',
  'macos-universal',
  'linux-x64',
  'linux-arm64',
  'any',
] as const;

export type ReleaseArtifactPlatform = (typeof RELEASE_ARTIFACT_PLATFORMS)[number];
export type ReleaseArtifactState = 'active' | 'revoked';

export interface ReleaseArtifactPayload {
  version: 1;
  id: string;
  releaseId: string;
  distributionId: string;
  releaseVersion: string;
  sourceCommit: string;
  kind: ReleaseArtifactKind;
  platform: ReleaseArtifactPlatform;
  url: string;
  sha256: string;
  sizeBytes: number;
  createdAtMs: number;
}

export interface SignedReleaseArtifactEnvelope {
  artifact: ReleaseArtifactPayload;
  signingKeyId: string;
  signature: string;
}

export interface ReleaseArtifactView extends SignedReleaseArtifactEnvelope {
  state: ReleaseArtifactState;
  revokedAt: string | null;
  revokedBy: string | null;
  revocationReason: string | null;
  storage?: ArtifactStorageEvidence | null;
}

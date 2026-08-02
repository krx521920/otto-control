import type { ReleaseArtifactKind, ReleaseArtifactPlatform } from '../../contracts/release-artifact.js';

export interface ArtifactObjectIdentity {
  releaseId: string;
  version: string;
  kind: ReleaseArtifactKind;
  platform: ReleaseArtifactPlatform;
  sha256: string;
}

export interface ArtifactUploadTarget {
  method: 'PUT';
  url: string;
  headers: Record<string, string>;
  expiresAt: string;
}

export interface StoredArtifactObject {
  objectKey: string;
  sizeBytes: number;
  checksumSha256: string;
  versionId: string | null;
  serverSideEncryption: string | null;
  objectLockMode: string | null;
  objectLockRetainUntil: string | null;
}

export interface ArtifactObjectStore {
  readonly managed: true;
  objectKey(identity: ArtifactObjectIdentity): string;
  createUpload(input: {
    objectKey: string;
    sha256: string;
    sizeBytes: number;
    contentType: string;
    expiresAt: Date;
  }): Promise<ArtifactUploadTarget>;
  inspect(objectKey: string): Promise<StoredArtifactObject>;
  createDownloadUrl(objectKey: string, expiresAt: Date): Promise<string>;
}


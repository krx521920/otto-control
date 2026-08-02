export interface AuditWitnessWormObject {
  objectKey: string;
  sizeBytes: number;
  checksumSha256: string;
  versionId: string | null;
  serverSideEncryption: string | null;
  objectLockMode: string | null;
  objectLockRetainUntil: string | null;
}

export interface AuditWitnessWormObjectStore {
  readonly prefix: string;
  readonly requiredLockMode: 'COMPLIANCE' | 'GOVERNANCE';
  readonly requiredEncryption: 'AES256' | 'aws:kms';
  assertReady(): Promise<void>;
  objectKey(sourceId: string, chainSequence: number): string;
  put(input: {
    objectKey: string;
    body: Uint8Array;
    sha256: string;
    retainUntil: Date;
  }): Promise<AuditWitnessWormObject>;
  inspect(objectKey: string): Promise<AuditWitnessWormObject>;
  read(objectKey: string): Promise<Uint8Array>;
  list(input: {
    continuationToken?: string;
    limit: number;
  }): Promise<{ objectKeys: string[]; continuationToken: string | null }>;
}

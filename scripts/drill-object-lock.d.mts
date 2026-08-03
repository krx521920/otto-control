import type { S3Client } from '@aws-sdk/client-s3';

export interface ObjectLockDrillInput {
  bucket: string;
  key: string;
  versionId: string;
  expectedSha256: string;
  minimumRetentionDays: number;
  now: () => number;
}

export interface ObjectLockDrillReport {
  version: 1;
  drill: 's3_object_lock_compliance';
  startedAt: string;
  completedAt: string;
  result: 'passed';
  bucket: string;
  key: string;
  versionId: string;
  sha256: string;
  objectLockMode: 'COMPLIANCE';
  retainUntil: string;
  serverSideEncryption: 'aws:kms';
  kmsKeyId: string;
  deleteCapablePrincipalAttested: true;
  deletionDenied: true;
  objectIntactAfterDeletionAttempt: true;
}

export function runObjectLockDrill(
  input: ObjectLockDrillInput,
  client: S3Client,
): Promise<ObjectLockDrillReport>;

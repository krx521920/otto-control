import { createHash } from 'node:crypto';

import {
  GetObjectCommand,
  GetObjectLockConfigurationCommand,
  GetBucketVersioningCommand,
  HeadObjectCommand,
  PutObjectCommand,
  type S3Client,
} from '@aws-sdk/client-s3';
import { describe, expect, it, vi } from 'vitest';

import { S3AuditWitnessWormObjectStore } from '../src/modules/audit-witness/s3-worm-object-store.js';
import type { AuditWitnessWormStorageConfig } from '../src/modules/audit-witness/worm-storage-config.js';

const config: AuditWitnessWormStorageConfig = {
  endpoint: 'https://audit-storage.example.test',
  bucket: 'otto-audit-evidence',
  region: 'cn-north-1',
  prefix: 'witness/primary',
  forcePathStyle: true,
  accessKeyId: 'audit-access',
  secretAccessKey: 'audit-secret',
  sessionToken: null,
  serverSideEncryption: 'AES256',
  kmsKeyId: null,
  objectLockMode: 'COMPLIANCE',
  retentionDays: 365,
  pollIntervalMs: 30_000,
  maxAttempts: 20,
};

describe('S3 audit witness WORM object store', () => {
  it('fails closed unless bucket versioning and Object Lock are both enabled', async () => {
    const send = vi.fn(async (command: unknown) => {
      if (command instanceof GetBucketVersioningCommand) return { Status: 'Enabled' };
      if (command instanceof GetObjectLockConfigurationCommand) {
        return { ObjectLockConfiguration: { ObjectLockEnabled: 'Enabled' } };
      }
      throw new Error('unexpected command');
    });
    const store = new S3AuditWitnessWormObjectStore(config, {
      client: { send } as unknown as S3Client,
    });
    await expect(store.assertReady()).resolves.toBeUndefined();
    expect(send).toHaveBeenCalledTimes(2);
  });

  it('uses a fork-resistant key and immutable conditional upload controls', async () => {
    const body = Buffer.from('{"version":1}', 'utf8');
    const sha256 = createHash('sha256').update(body).digest('hex');
    const retainUntil = new Date('2027-08-02T00:00:00.000Z');
    const send = vi.fn(async (command: unknown) => {
      if (command instanceof PutObjectCommand) return {};
      if (command instanceof HeadObjectCommand) return {
        ContentLength: body.byteLength,
        ChecksumSHA256: Buffer.from(sha256, 'hex').toString('base64'),
        VersionId: 'version-1',
        ServerSideEncryption: 'AES256',
        ObjectLockMode: 'COMPLIANCE',
        ObjectLockRetainUntilDate: retainUntil,
      };
      throw new Error('unexpected command');
    });
    const store = new S3AuditWitnessWormObjectStore(config, {
      client: { send } as unknown as S3Client,
    });
    const key = store.objectKey('primary-control', 42);
    await expect(store.put({ objectKey: key, body, sha256, retainUntil })).resolves.toMatchObject({
      objectKey: key,
      versionId: 'version-1',
      objectLockMode: 'COMPLIANCE',
    });
    expect(key).toBe('witness/primary/primary-control/00000000000000000042.json');
    const put = send.mock.calls.map((call) => call[0]).find((command) => (
      command instanceof PutObjectCommand
    )) as PutObjectCommand;
    expect(put.input).toMatchObject({
      Bucket: 'otto-audit-evidence',
      Key: key,
      IfNoneMatch: '*',
      ChecksumSHA256: Buffer.from(sha256, 'hex').toString('base64'),
      ServerSideEncryption: 'AES256',
      ObjectLockMode: 'COMPLIANCE',
      ObjectLockRetainUntilDate: retainUntil,
    });
  });

  it('reads real bytes instead of trusting object metadata alone', async () => {
    const body = Buffer.from('immutable evidence', 'utf8');
    const send = vi.fn(async (command: unknown) => {
      expect(command).toBeInstanceOf(GetObjectCommand);
      return { Body: { transformToByteArray: async () => body } };
    });
    const store = new S3AuditWitnessWormObjectStore(config, {
      client: { send } as unknown as S3Client,
    });
    await expect(store.read('witness/primary/object.json')).resolves.toEqual(body);
  });
});

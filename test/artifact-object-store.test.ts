import { HeadObjectCommand, type S3Client } from '@aws-sdk/client-s3';
import type { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { describe, expect, it, vi } from 'vitest';

import { S3ArtifactObjectStore } from '../src/modules/release-artifacts/s3-object-store.js';
import type { ArtifactStorageConfig } from '../src/modules/release-artifacts/storage-config.js';

const config: ArtifactStorageConfig = {
  endpoint: 'https://s3.example.test',
  bucket: 'otto-releases',
  region: 'cn-north-1',
  prefix: 'release/primary',
  forcePathStyle: true,
  accessKeyId: 'access-key',
  secretAccessKey: 'secret-key',
  sessionToken: null,
  serverSideEncryption: 'AES256',
  kmsKeyId: null,
  objectLockRequired: true,
  retentionDays: 365,
  uploadTtlSeconds: 900,
  downloadTtlSeconds: 300,
  cdnBaseUrl: null,
};

describe('S3 artifact object store', () => {
  it('binds checksum, size, encryption and object lock into the presigned upload', async () => {
    const send = vi.fn();
    let signedCommand: unknown;
    const presign = vi.fn(async (...args: unknown[]) => {
      signedCommand = args[1];
      return 'https://s3.example.test/signed-put';
    }) as unknown as typeof getSignedUrl;
    const store = new S3ArtifactObjectStore(config, {
      client: { send } as unknown as S3Client,
      presign,
    });
    const sha256 = 'a'.repeat(64);
    const objectKey = store.objectKey({
      releaseId: 'rel_1234567890abcdef',
      version: '2.1.0',
      kind: 'windows_installer',
      platform: 'windows-x64',
      sha256,
    });
    const upload = await store.createUpload({
      objectKey,
      sha256,
      sizeBytes: 1234,
      contentType: 'application/vnd.microsoft.portable-executable',
      expiresAt: new Date(Date.now() + 60_000),
    });

    expect(objectKey).toBe(`release/primary/rel_1234567890abcdef/2.1.0/windows-x64/windows_installer-${sha256}`);
    expect(upload).toMatchObject({
      method: 'PUT',
      url: 'https://s3.example.test/signed-put',
      headers: {
        'content-length': '1234',
        'x-amz-checksum-sha256': Buffer.from(sha256, 'hex').toString('base64'),
        'x-amz-server-side-encryption': 'AES256',
        'x-amz-object-lock-mode': 'COMPLIANCE',
      },
    });
    const command = signedCommand as { input: Record<string, unknown> };
    expect(command.input).toMatchObject({
      Bucket: 'otto-releases',
      Key: objectKey,
      ContentLength: 1234,
      ChecksumSHA256: Buffer.from(sha256, 'hex').toString('base64'),
      ServerSideEncryption: 'AES256',
      ObjectLockMode: 'COMPLIANCE',
    });
  });

  it('reads checksum and immutable storage evidence before registration', async () => {
    const sha256 = 'b'.repeat(64);
    const send = vi.fn(async (command: unknown) => {
      expect(command).toBeInstanceOf(HeadObjectCommand);
      return {
        ContentLength: 99,
        ChecksumSHA256: Buffer.from(sha256, 'hex').toString('base64'),
        VersionId: 'version-1',
        ServerSideEncryption: 'AES256',
        ObjectLockMode: 'COMPLIANCE',
        ObjectLockRetainUntilDate: new Date('2027-08-02T00:00:00.000Z'),
      };
    });
    const store = new S3ArtifactObjectStore(config, {
      client: { send } as unknown as S3Client,
      presign: vi.fn(async () => 'https://s3.example.test/download'),
    });
    await expect(store.inspect('release/object')).resolves.toEqual({
      objectKey: 'release/object',
      sizeBytes: 99,
      checksumSha256: sha256,
      versionId: 'version-1',
      serverSideEncryption: 'AES256',
      objectLockMode: 'COMPLIANCE',
      objectLockRetainUntil: '2027-08-02T00:00:00.000Z',
    });
  });
});

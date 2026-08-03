import { createHash } from 'node:crypto';

import {
  DeleteObjectCommand,
  GetBucketVersioningCommand,
  GetObjectCommand,
  GetObjectLockConfigurationCommand,
  HeadObjectCommand,
  type S3Client,
} from '@aws-sdk/client-s3';
import { describe, expect, it, vi } from 'vitest';

import { runObjectLockDrill } from '../scripts/drill-object-lock.mjs';

const body = Buffer.from('{"audit":"immutable"}', 'utf8');
const sha256 = createHash('sha256').update(body).digest('hex');
const retainUntil = new Date('2033-08-03T00:00:00.000Z');

function fixtureClient(deleteSucceeds = false): S3Client {
  let headCalls = 0;
  const send = vi.fn(async (command: unknown) => {
    if (command instanceof GetBucketVersioningCommand) return { Status: 'Enabled' };
    if (command instanceof GetObjectLockConfigurationCommand) {
      return { ObjectLockConfiguration: { ObjectLockEnabled: 'Enabled' } };
    }
    if (command instanceof HeadObjectCommand) {
      headCalls += 1;
      return {
        VersionId: 'version-42',
        ContentLength: body.byteLength,
        ChecksumSHA256: Buffer.from(sha256, 'hex').toString('base64'),
        ServerSideEncryption: 'aws:kms',
        SSEKMSKeyId: 'arn:aws:kms:cn-north-1:123456789012:key/evidence',
        ObjectLockMode: 'COMPLIANCE',
        ObjectLockRetainUntilDate: retainUntil,
      };
    }
    if (command instanceof GetObjectCommand) {
      return { Body: { transformToByteArray: async () => body } };
    }
    if (command instanceof DeleteObjectCommand) {
      if (deleteSucceeds) return {};
      throw Object.assign(new Error('Access Denied'), {
        name: 'AccessDenied',
        $metadata: { httpStatusCode: 403 },
      });
    }
    throw new Error('unexpected command');
  });
  const client = { send } as unknown as S3Client;
  Object.defineProperty(client, 'headCalls', { get: () => headCalls });
  return client;
}

describe('Object Lock production drill', () => {
  it('proves deletion is denied and the exact encrypted version remains intact', async () => {
    const client = fixtureClient();
    await expect(runObjectLockDrill({
      bucket: 'otto-audit-evidence',
      key: 'witness/primary/42.json',
      versionId: 'version-42',
      expectedSha256: sha256,
      minimumRetentionDays: 30,
      now: () => Date.parse('2026-08-03T00:00:00.000Z'),
    }, client)).resolves.toMatchObject({
      result: 'passed',
      objectLockMode: 'COMPLIANCE',
      serverSideEncryption: 'aws:kms',
      deletionDenied: true,
      objectIntactAfterDeletionAttempt: true,
    });
  });

  it('fails the drill if a locked version can be deleted', async () => {
    await expect(runObjectLockDrill({
      bucket: 'otto-audit-evidence',
      key: 'witness/primary/42.json',
      versionId: 'version-42',
      expectedSha256: sha256,
      minimumRetentionDays: 30,
      now: () => Date.parse('2026-08-03T00:00:00.000Z'),
    }, fixtureClient(true))).rejects.toThrow('deletion unexpectedly succeeded');
  });
});

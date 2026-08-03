import { createHash } from 'node:crypto';

import {
  DeleteObjectCommand,
  GetBucketVersioningCommand,
  GetBucketPolicyCommand,
  GetObjectCommand,
  GetObjectLockConfigurationCommand,
  GetObjectRetentionCommand,
  HeadObjectCommand,
  PutObjectRetentionCommand,
  type S3Client,
} from '@aws-sdk/client-s3';
import { describe, expect, it, vi } from 'vitest';

import { awsPrincipalMatches, runObjectLockDrill } from '../scripts/drill-object-lock.mjs';

const body = Buffer.from('{"audit":"immutable"}', 'utf8');
const sha256 = createHash('sha256').update(body).digest('hex');
const retainUntil = new Date('2033-08-03T00:00:00.000Z');
const drillPrincipal = 'arn:aws:iam::123456789012:role/otto-object-lock-drill';

function fixtureClient(
  deleteSucceeds = false,
  retentionReductionSucceeds = false,
  policyAllowsDestruction = true,
): S3Client {
  let headCalls = 0;
  const send = vi.fn(async (command: unknown) => {
    if (command instanceof GetBucketVersioningCommand) return { Status: 'Enabled' };
    if (command instanceof GetObjectLockConfigurationCommand) {
      return { ObjectLockConfiguration: { ObjectLockEnabled: 'Enabled' } };
    }
    if (command instanceof GetBucketPolicyCommand) {
      return { Policy: JSON.stringify({ Statement: [{
        Effect: 'Allow',
        Principal: { AWS: drillPrincipal },
        Action: policyAllowsDestruction
          ? ['s3:DeleteObjectVersion', 's3:PutObjectRetention']
          : ['s3:GetObjectVersion'],
        Resource: 'arn:aws:s3:::otto-audit-evidence/*',
      }] }) };
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
    if (command instanceof GetObjectRetentionCommand) {
      return { Retention: { Mode: 'COMPLIANCE', RetainUntilDate: retainUntil } };
    }
    if (command instanceof PutObjectRetentionCommand) {
      if (retentionReductionSucceeds) return {};
      throw Object.assign(new Error('Access Denied'), {
        name: 'AccessDenied',
        $metadata: { httpStatusCode: 403, requestId: 'retention-request' },
      });
    }
    if (command instanceof DeleteObjectCommand) {
      if (deleteSucceeds) return {};
      throw Object.assign(new Error('Access Denied'), {
        name: 'AccessDenied',
        $metadata: { httpStatusCode: 403, requestId: 'deletion-request' },
      });
    }
    throw new Error('unexpected command');
  });
  const client = { send } as unknown as S3Client;
  Object.defineProperty(client, 'headCalls', { get: () => headCalls });
  return client;
}

describe('Object Lock production drill', () => {
  it('matches an approved IAM role to its temporary STS role session', () => {
    expect(awsPrincipalMatches(
      'arn:aws:sts::123456789012:assumed-role/otto-object-lock-drill/session-42',
      drillPrincipal,
    )).toBe(true);
    expect(awsPrincipalMatches(
      'arn:aws:sts::999999999999:assumed-role/otto-object-lock-drill/session-42',
      drillPrincipal,
    )).toBe(false);
  });

  it('proves deletion is denied and the exact encrypted version remains intact', async () => {
    const client = fixtureClient();
    await expect(runObjectLockDrill({
      bucket: 'otto-audit-evidence',
      key: 'witness/primary/42.json',
      versionId: 'version-42',
      expectedSha256: sha256,
      minimumRetentionDays: 30,
      actualPrincipalArn: 'arn:aws:sts::123456789012:assumed-role/otto-object-lock-drill/session-42',
      expectedPrincipalArn: drillPrincipal,
      now: () => Date.parse('2026-08-03T00:00:00.000Z'),
    }, client)).resolves.toMatchObject({
      result: 'passed',
      objectLockMode: 'COMPLIANCE',
      serverSideEncryption: 'aws:kms',
      bucketPolicyEvidence: {
        deleteObjectVersionAllowed: true,
        putObjectRetentionAllowed: true,
      },
      retentionReductionDenied: true,
      deletionDenied: true,
      retentionReductionDenial: { requestId: 'retention-request' },
      deletionDenial: { requestId: 'deletion-request' },
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
      actualPrincipalArn: drillPrincipal,
      expectedPrincipalArn: drillPrincipal,
      now: () => Date.parse('2026-08-03T00:00:00.000Z'),
    }, fixtureClient(true))).rejects.toThrow('deletion unexpectedly succeeded');
  });

  it('fails the drill if COMPLIANCE retention can be shortened', async () => {
    await expect(runObjectLockDrill({
      bucket: 'otto-audit-evidence',
      key: 'witness/primary/42.json',
      versionId: 'version-42',
      expectedSha256: sha256,
      minimumRetentionDays: 30,
      actualPrincipalArn: drillPrincipal,
      expectedPrincipalArn: drillPrincipal,
      now: () => Date.parse('2026-08-03T00:00:00.000Z'),
    }, fixtureClient(false, true))).rejects.toThrow('retention reduction unexpectedly succeeded');
  });

  it('rejects an ordinary IAM denial that lacks destructive bucket-policy permission', async () => {
    await expect(runObjectLockDrill({
      bucket: 'otto-audit-evidence',
      key: 'witness/primary/42.json',
      versionId: 'version-42',
      expectedSha256: sha256,
      minimumRetentionDays: 30,
      actualPrincipalArn: drillPrincipal,
      expectedPrincipalArn: drillPrincipal,
      now: () => Date.parse('2026-08-03T00:00:00.000Z'),
    }, fixtureClient(false, false, false))).rejects.toThrow(
      'bucket policy does not grant the drill principal destructive test actions',
    );
  });
});

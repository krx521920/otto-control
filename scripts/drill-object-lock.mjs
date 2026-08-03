import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  DeleteObjectCommand,
  GetBucketVersioningCommand,
  GetBucketPolicyCommand,
  GetObjectCommand,
  GetObjectLockConfigurationCommand,
  GetObjectRetentionCommand,
  HeadObjectCommand,
  PutObjectRetentionCommand,
  S3Client,
} from '@aws-sdk/client-s3';
import { GetCallerIdentityCommand, STSClient } from '@aws-sdk/client-sts';

function argumentsMap(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 1) {
    const entry = argv[index];
    if (!entry?.startsWith('--')) throw new Error(`unexpected argument: ${entry}`);
    const [name, inlineValue] = entry.slice(2).split('=', 2);
    const value = inlineValue ?? argv[index + 1];
    if (!name || !value || value.startsWith('--')) throw new Error(`--${name} requires a value`);
    values.set(name, value);
    if (inlineValue === undefined) index += 1;
  }
  return values;
}

function required(values, name) {
  const value = values.get(name)?.trim();
  if (!value) throw new Error(`--${name} is required`);
  return value;
}

function checksumHex(base64) {
  if (!base64) return '';
  const value = Buffer.from(base64, 'base64');
  return value.length === 32 ? value.toString('hex') : '';
}

function deletionDenied(error) {
  const status = error?.$metadata?.httpStatusCode;
  return status === 403 || status === 409
    || error?.name === 'AccessDenied'
    || error?.name === 'InvalidRequest';
}

function values(value) {
  return Array.isArray(value) ? value : [value];
}

function policyAllows(policy, input, action) {
  const objectArn = `arn:${input.partition}:s3:::${input.bucket}/*`;
  return values(policy.Statement ?? []).some((statement) => {
    const principals = values(statement?.Principal?.AWS ?? statement?.Principal);
    const actions = values(statement?.Action);
    const resources = values(statement?.Resource);
    return statement?.Effect === 'Allow'
      && principals.includes(input.expectedPrincipalArn)
      && actions.some((entry) => entry === action || entry === 's3:*' || entry === '*')
      && resources.some((entry) => entry === objectArn || entry === '*');
  });
}

function bucketPolicyEvidence(raw, input) {
  let policy;
  try {
    policy = JSON.parse(raw);
  } catch {
    throw new Error('bucket policy is missing or invalid JSON');
  }
  const deleteObjectVersionAllowed = policyAllows(policy, input, 's3:DeleteObjectVersion');
  const putObjectRetentionAllowed = policyAllows(policy, input, 's3:PutObjectRetention');
  if (!deleteObjectVersionAllowed || !putObjectRetentionAllowed) {
    throw new Error('bucket policy does not grant the drill principal destructive test actions');
  }
  return { deleteObjectVersionAllowed, putObjectRetentionAllowed };
}

function denialEvidence(error) {
  if (!deletionDenied(error)) return null;
  return {
    code: typeof error?.name === 'string' ? error.name : 'Unknown',
    httpStatusCode: Number(error?.$metadata?.httpStatusCode ?? 0),
    requestId: typeof error?.$metadata?.requestId === 'string'
      ? error.$metadata.requestId
      : null,
    extendedRequestId: typeof error?.$metadata?.extendedRequestId === 'string'
      ? error.$metadata.extendedRequestId
      : null,
  };
}

export function awsPrincipalMatches(actualArn, expectedArn) {
  if (actualArn === expectedArn) return true;
  const expected = expectedArn.match(
    /^arn:(aws(?:-[a-z]+)?):iam::([0-9]{12}):role\/(.+)$/u,
  );
  if (!expected) return false;
  const [, partition, accountId, expectedPath] = expected;
  const roleName = expectedPath.split('/').at(-1);
  const actual = actualArn.match(
    /^arn:(aws(?:-[a-z]+)?):sts::([0-9]{12}):assumed-role\/([^/]+)\/[^/]+$/u,
  );
  return actual?.[1] === partition && actual[2] === accountId && actual[3] === roleName;
}

async function readVersion(client, input) {
  const response = await client.send(new GetObjectCommand({
    Bucket: input.bucket,
    Key: input.key,
    VersionId: input.versionId,
    ChecksumMode: 'ENABLED',
  }));
  if (!response.Body) throw new Error('WORM object returned an empty body');
  const bytes = await response.Body.transformToByteArray();
  return {
    bytes,
    sha256: createHash('sha256').update(bytes).digest('hex'),
  };
}

export async function runObjectLockDrill(input, client) {
  const startedAt = new Date(input.now()).toISOString();
  if (!awsPrincipalMatches(input.actualPrincipalArn, input.expectedPrincipalArn)) {
    throw new Error('AWS caller identity does not match the approved drill principal');
  }
  const partition = input.expectedPrincipalArn.split(':')[1];
  const [versioning, lockConfiguration, bucketPolicy] = await Promise.all([
    client.send(new GetBucketVersioningCommand({ Bucket: input.bucket })),
    client.send(new GetObjectLockConfigurationCommand({ Bucket: input.bucket })),
    client.send(new GetBucketPolicyCommand({ Bucket: input.bucket })),
  ]);
  if (versioning.Status !== 'Enabled') throw new Error('bucket versioning is not enabled');
  if (lockConfiguration.ObjectLockConfiguration?.ObjectLockEnabled !== 'Enabled') {
    throw new Error('bucket Object Lock is not enabled');
  }
  const policyEvidence = bucketPolicyEvidence(bucketPolicy.Policy ?? '', {
    bucket: input.bucket,
    partition,
    expectedPrincipalArn: input.expectedPrincipalArn,
  });

  const headInput = {
    Bucket: input.bucket,
    Key: input.key,
    VersionId: input.versionId,
    ChecksumMode: 'ENABLED',
  };
  const before = await client.send(new HeadObjectCommand(headInput));
  if (before.VersionId !== input.versionId) throw new Error('S3 returned a different object version');
  if (before.ObjectLockMode !== 'COMPLIANCE') throw new Error('object is not in COMPLIANCE mode');
  if (before.ServerSideEncryption !== 'aws:kms' || !before.SSEKMSKeyId) {
    throw new Error('object is not protected by SSE-KMS');
  }
  const retainUntil = before.ObjectLockRetainUntilDate?.getTime() ?? 0;
  const minimumRetainUntil = input.now() + input.minimumRetentionDays * 86_400_000;
  if (retainUntil < minimumRetainUntil) {
    throw new Error('object retention does not meet the required future retention window');
  }
  const metadataChecksum = checksumHex(before.ChecksumSHA256) || before.Metadata?.sha256 || '';
  if (metadataChecksum !== input.expectedSha256) {
    throw new Error('object metadata checksum does not match the expected evidence checksum');
  }
  const contentBefore = await readVersion(client, input);
  if (contentBefore.sha256 !== input.expectedSha256) {
    throw new Error('object bytes do not match the expected evidence checksum');
  }

  const retentionBefore = await client.send(new GetObjectRetentionCommand({
    Bucket: input.bucket,
    Key: input.key,
    VersionId: input.versionId,
  }));
  if (retentionBefore.Retention?.Mode !== 'COMPLIANCE'
    || retentionBefore.Retention.RetainUntilDate?.getTime() !== retainUntil) {
    throw new Error('explicit object retention does not match the immutable version metadata');
  }

  let retentionDenial = null;
  try {
    await client.send(new PutObjectRetentionCommand({
      Bucket: input.bucket,
      Key: input.key,
      VersionId: input.versionId,
      Retention: {
        Mode: 'COMPLIANCE',
        RetainUntilDate: new Date(input.now() + 60_000),
      },
    }));
  } catch (error) {
    retentionDenial = denialEvidence(error);
    if (!retentionDenial) throw error;
  }
  if (!retentionDenial) throw new Error('COMPLIANCE retention reduction unexpectedly succeeded');

  let deletionDenial = null;
  try {
    await client.send(new DeleteObjectCommand({
      Bucket: input.bucket,
      Key: input.key,
      VersionId: input.versionId,
    }));
  } catch (error) {
    deletionDenial = denialEvidence(error);
    if (!deletionDenial) throw error;
  }
  if (!deletionDenial) throw new Error('COMPLIANCE object deletion unexpectedly succeeded');

  const after = await client.send(new HeadObjectCommand(headInput));
  if (after.VersionId !== input.versionId || after.ObjectLockMode !== 'COMPLIANCE') {
    throw new Error('object version or retention changed after the deletion attempt');
  }
  const contentAfter = await readVersion(client, input);
  if (contentAfter.sha256 !== input.expectedSha256) {
    throw new Error('object bytes changed after the deletion attempt');
  }
  const retentionAfter = await client.send(new GetObjectRetentionCommand({
    Bucket: input.bucket,
    Key: input.key,
    VersionId: input.versionId,
  }));
  if (retentionAfter.Retention?.Mode !== 'COMPLIANCE'
    || retentionAfter.Retention.RetainUntilDate?.getTime() !== retainUntil) {
    throw new Error('object retention changed after the destructive attempts');
  }

  return {
    version: 1,
    drill: 's3_object_lock_compliance',
    startedAt,
    completedAt: new Date(input.now()).toISOString(),
    result: 'passed',
    bucket: input.bucket,
    key: input.key,
    versionId: input.versionId,
    sha256: input.expectedSha256,
    objectLockMode: before.ObjectLockMode,
    retainUntil: before.ObjectLockRetainUntilDate.toISOString(),
    serverSideEncryption: before.ServerSideEncryption,
    kmsKeyId: before.SSEKMSKeyId,
    callerIdentity: input.actualPrincipalArn,
    expectedDrillPrincipal: input.expectedPrincipalArn,
    bucketPolicyEvidence: policyEvidence,
    retentionReductionDenial: retentionDenial,
    deletionDenial,
    retentionReductionDenied: true,
    deletionDenied: true,
    objectIntactAfterDeletionAttempt: true,
  };
}

async function main() {
  const values = argumentsMap(process.argv.slice(2));
  if (required(values, 'confirm') !== 'DELETE_LOCKED_AUDIT_EVIDENCE') {
    throw new Error('--confirm=DELETE_LOCKED_AUDIT_EVIDENCE is required');
  }
  const expectedPrincipalArn = required(values, 'expected-drill-principal-arn');
  if (!/^arn:aws(?:-[a-z]+)?:iam::[0-9]{12}:(?:role|user)\/.+$/u.test(expectedPrincipalArn)) {
    throw new Error('--expected-drill-principal-arn must be an IAM role or user ARN');
  }
  const expectedSha256 = required(values, 'expected-sha256').toLowerCase();
  if (!/^[a-f0-9]{64}$/u.test(expectedSha256)) {
    throw new Error('--expected-sha256 must be a lowercase SHA-256 digest');
  }
  const minimumRetentionDays = Number(values.get('minimum-retention-days') ?? '1');
  if (!Number.isInteger(minimumRetentionDays)
    || minimumRetentionDays < 1 || minimumRetentionDays > 3_650) {
    throw new Error('--minimum-retention-days must be between 1 and 3650');
  }
  const bucket = required(values, 'bucket');
  const key = required(values, 'key');
  const versionId = required(values, 'version-id');
  if (!/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/u.test(bucket)) {
    throw new Error('--bucket is invalid');
  }
  if (key.length > 1_024 || /[\u0000-\u001f\u007f]/u.test(key)) throw new Error('--key is invalid');
  if (versionId.length > 1_024 || /[\u0000-\u001f\u007f]/u.test(versionId)) {
    throw new Error('--version-id is invalid');
  }
  const endpoint = values.get('endpoint')?.trim();
  if (endpoint) {
    const url = new URL(endpoint);
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) {
      throw new Error('--endpoint must be a credential-free HTTPS origin');
    }
  }
  const region = values.get('region')?.trim() || process.env.AWS_REGION || 'us-east-1';
  const client = new S3Client({
    region,
    endpoint: endpoint || undefined,
    forcePathStyle: values.get('force-path-style') === 'true',
  });
  const identity = await new STSClient({ region }).send(new GetCallerIdentityCommand({}));
  if (!identity.Arn || !awsPrincipalMatches(identity.Arn, expectedPrincipalArn)) {
    throw new Error('current AWS identity is not the approved drill principal');
  }
  const report = await runObjectLockDrill({
    bucket,
    key,
    versionId,
    expectedSha256,
    minimumRetentionDays,
    actualPrincipalArn: identity.Arn,
    expectedPrincipalArn,
    now: Date.now,
  }, client);
  const output = resolve(required(values, 'output'));
  writeFileSync(output, `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  process.stdout.write(`Object Lock deletion drill passed; report written to ${output}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}

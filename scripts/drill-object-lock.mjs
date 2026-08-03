import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  DeleteObjectCommand,
  GetBucketVersioningCommand,
  GetObjectCommand,
  GetObjectLockConfigurationCommand,
  HeadObjectCommand,
  S3Client,
} from '@aws-sdk/client-s3';

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
  const [versioning, lockConfiguration] = await Promise.all([
    client.send(new GetBucketVersioningCommand({ Bucket: input.bucket })),
    client.send(new GetObjectLockConfigurationCommand({ Bucket: input.bucket })),
  ]);
  if (versioning.Status !== 'Enabled') throw new Error('bucket versioning is not enabled');
  if (lockConfiguration.ObjectLockConfiguration?.ObjectLockEnabled !== 'Enabled') {
    throw new Error('bucket Object Lock is not enabled');
  }

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

  let denied = false;
  try {
    await client.send(new DeleteObjectCommand({
      Bucket: input.bucket,
      Key: input.key,
      VersionId: input.versionId,
    }));
  } catch (error) {
    if (!deletionDenied(error)) throw error;
    denied = true;
  }
  if (!denied) throw new Error('COMPLIANCE object deletion unexpectedly succeeded');

  const after = await client.send(new HeadObjectCommand(headInput));
  if (after.VersionId !== input.versionId || after.ObjectLockMode !== 'COMPLIANCE') {
    throw new Error('object version or retention changed after the deletion attempt');
  }
  const contentAfter = await readVersion(client, input);
  if (contentAfter.sha256 !== input.expectedSha256) {
    throw new Error('object bytes changed after the deletion attempt');
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
    deleteCapablePrincipalAttested: true,
    deletionDenied: true,
    objectIntactAfterDeletionAttempt: true,
  };
}

async function main() {
  const values = argumentsMap(process.argv.slice(2));
  if (required(values, 'confirm') !== 'DELETE_LOCKED_AUDIT_EVIDENCE') {
    throw new Error('--confirm=DELETE_LOCKED_AUDIT_EVIDENCE is required');
  }
  if (required(values, 'delete-capable-principal') !== 'true') {
    throw new Error('--delete-capable-principal=true is required');
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
  const client = new S3Client({
    region: values.get('region')?.trim() || process.env.AWS_REGION || 'us-east-1',
    endpoint: endpoint || undefined,
    forcePathStyle: values.get('force-path-style') === 'true',
  });
  const report = await runObjectLockDrill({
    bucket,
    key,
    versionId,
    expectedSha256,
    minimumRetentionDays,
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

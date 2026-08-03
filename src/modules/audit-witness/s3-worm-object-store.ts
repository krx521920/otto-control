import { createHash } from 'node:crypto';

import {
  GetObjectCommand,
  GetObjectLockConfigurationCommand,
  GetBucketVersioningCommand,
  HeadObjectCommand,
  ListObjectsV2Command,
  PutObjectCommand,
  S3Client,
  type ObjectLockMode,
  type ServerSideEncryption,
} from '@aws-sdk/client-s3';

import { conflict, notFound } from '../../errors.js';
import type { AuditWitnessWormStorageConfig } from './worm-storage-config.js';
import type {
  AuditWitnessWormObject,
  AuditWitnessWormObjectStore,
} from './worm-object-store.js';

function checksumBase64(sha256: string): string {
  return Buffer.from(sha256, 'hex').toString('base64');
}

function checksumHex(base64: string | undefined): string {
  if (!base64) return '';
  const value = Buffer.from(base64, 'base64');
  return value.length === 32 ? value.toString('hex') : '';
}

function missingObject(error: unknown): boolean {
  return (error as { $metadata?: { httpStatusCode?: number } }).$metadata?.httpStatusCode === 404;
}

function conditionalConflict(error: unknown): boolean {
  const status = (error as { $metadata?: { httpStatusCode?: number } }).$metadata?.httpStatusCode;
  return status === 409 || status === 412;
}

export class S3AuditWitnessWormObjectStore implements AuditWitnessWormObjectStore {
  readonly prefix: string;
  readonly requiredLockMode: 'COMPLIANCE' | 'GOVERNANCE';
  readonly requiredEncryption: 'AES256' | 'aws:kms';
  readonly #config: AuditWitnessWormStorageConfig;
  readonly #client: S3Client;

  constructor(config: AuditWitnessWormStorageConfig, options: { client?: S3Client } = {}) {
    this.#config = config;
    this.prefix = config.prefix;
    this.requiredLockMode = config.objectLockMode;
    this.requiredEncryption = config.serverSideEncryption;
    const credentials = config.accessKeyId && config.secretAccessKey ? {
      accessKeyId: config.accessKeyId,
      secretAccessKey: config.secretAccessKey,
      sessionToken: config.sessionToken ?? undefined,
    } : null;
    this.#client = options.client ?? new S3Client({
      endpoint: config.endpoint,
      region: config.region,
      forcePathStyle: config.forcePathStyle,
      ...(credentials ? { credentials } : {}),
    });
  }

  objectKey(sourceId: string, chainSequence: number): string {
    if (!/^[a-z][a-z0-9_-]{1,63}$/u.test(sourceId) || !Number.isSafeInteger(chainSequence)
      || chainSequence < 0) {
      throw new Error('audit WORM object identity is invalid');
    }
    return `${this.prefix}/${sourceId}/${String(chainSequence).padStart(20, '0')}.json`;
  }

  async assertReady(): Promise<void> {
    const [versioning, objectLock] = await Promise.all([
      this.#client.send(new GetBucketVersioningCommand({ Bucket: this.#config.bucket })),
      this.#client.send(new GetObjectLockConfigurationCommand({ Bucket: this.#config.bucket })),
    ]);
    if (versioning.Status !== 'Enabled') {
      throw new Error('audit WORM bucket versioning is not enabled');
    }
    if (objectLock.ObjectLockConfiguration?.ObjectLockEnabled !== 'Enabled') {
      throw new Error('audit WORM bucket Object Lock is not enabled');
    }
  }

  async put(input: {
    objectKey: string;
    body: Uint8Array;
    sha256: string;
    retainUntil: Date;
  }): Promise<AuditWitnessWormObject> {
    try {
      await this.#client.send(new PutObjectCommand({
        Bucket: this.#config.bucket,
        Key: input.objectKey,
        Body: input.body,
        ContentLength: input.body.byteLength,
        ContentType: 'application/vnd.otto.audit-witness-evidence+json',
        ChecksumSHA256: checksumBase64(input.sha256),
        Metadata: { sha256: input.sha256, schema: 'otto-audit-witness-v1' },
        ServerSideEncryption: this.#config.serverSideEncryption as ServerSideEncryption,
        SSEKMSKeyId: this.#config.kmsKeyId ?? undefined,
        ObjectLockMode: this.#config.objectLockMode as ObjectLockMode,
        ObjectLockRetainUntilDate: input.retainUntil,
        IfNoneMatch: '*',
      }));
    } catch (error) {
      if (!conditionalConflict(error)) throw error;
      const existing = await this.inspect(input.objectKey);
      const body = await this.read(input.objectKey);
      const actual = createHash('sha256').update(body).digest('hex');
      if (existing.checksumSha256 !== input.sha256 || actual !== input.sha256
        || existing.sizeBytes !== input.body.byteLength) {
        throw conflict('audit WORM evidence slot already contains different bytes');
      }
      return existing;
    }
    return this.inspect(input.objectKey);
  }

  async inspect(objectKey: string): Promise<AuditWitnessWormObject> {
    let result;
    try {
      result = await this.#client.send(new HeadObjectCommand({
        Bucket: this.#config.bucket,
        Key: objectKey,
        ChecksumMode: 'ENABLED',
      }));
    } catch (error) {
      if (missingObject(error)) throw notFound('audit WORM evidence object does not exist');
      throw error;
    }
    const checksumSha256 = checksumHex(result.ChecksumSHA256) || result.Metadata?.sha256 || '';
    if (!/^[a-f0-9]{64}$/u.test(checksumSha256)) {
      throw conflict('audit WORM evidence has no verifiable SHA-256 checksum');
    }
    return {
      objectKey,
      sizeBytes: Number(result.ContentLength),
      checksumSha256,
      versionId: result.VersionId ?? null,
      serverSideEncryption: result.ServerSideEncryption ?? null,
      objectLockMode: result.ObjectLockMode ?? null,
      objectLockRetainUntil: result.ObjectLockRetainUntilDate?.toISOString() ?? null,
    };
  }

  async read(objectKey: string): Promise<Uint8Array> {
    let result;
    try {
      result = await this.#client.send(new GetObjectCommand({
        Bucket: this.#config.bucket,
        Key: objectKey,
        ChecksumMode: 'ENABLED',
      }));
    } catch (error) {
      if (missingObject(error)) throw notFound('audit WORM evidence object does not exist');
      throw error;
    }
    if (!result.Body) throw conflict('audit WORM evidence object has an empty response body');
    return result.Body.transformToByteArray();
  }

  async list(input: {
    continuationToken?: string;
    limit: number;
  }): Promise<{ objectKeys: string[]; continuationToken: string | null }> {
    const result = await this.#client.send(new ListObjectsV2Command({
      Bucket: this.#config.bucket,
      Prefix: `${this.prefix}/`,
      ContinuationToken: input.continuationToken,
      MaxKeys: input.limit,
    }));
    return {
      objectKeys: (result.Contents ?? [])
        .map((item) => item.Key)
        .filter((key): key is string => Boolean(key))
        .sort(),
      continuationToken: result.IsTruncated ? result.NextContinuationToken ?? null : null,
    };
  }
}

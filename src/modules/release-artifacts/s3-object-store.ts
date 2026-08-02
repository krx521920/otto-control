import {
  GetObjectCommand,
  HeadObjectCommand,
  PutObjectCommand,
  S3Client,
  type ObjectCannedACL,
  type ObjectLockMode,
  type ServerSideEncryption,
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';

import type {
  ArtifactObjectIdentity,
  ArtifactObjectStore,
  ArtifactUploadTarget,
  StoredArtifactObject,
} from './object-store.js';
import type { ArtifactStorageConfig } from './storage-config.js';
import { conflict, notFound } from '../../errors.js';

function safeSegment(value: string): string {
  const normalized = value.toLowerCase().replace(/[^a-z0-9._-]+/gu, '-').replace(/^-+|-+$/gu, '');
  if (!normalized || normalized === '.' || normalized === '..') throw new Error('artifact object key segment is invalid');
  return normalized;
}

function checksumBase64(sha256: string): string {
  return Buffer.from(sha256, 'hex').toString('base64');
}

function checksumHex(base64: string | undefined): string {
  if (!base64) return '';
  const bytes = Buffer.from(base64, 'base64');
  return bytes.length === 32 ? bytes.toString('hex') : '';
}

function encodedKey(key: string): string {
  return key.split('/').map(encodeURIComponent).join('/');
}

export class S3ArtifactObjectStore implements ArtifactObjectStore {
  readonly managed = true as const;
  readonly #config: ArtifactStorageConfig;
  readonly #client: S3Client;
  readonly #presign: typeof getSignedUrl;

  constructor(config: ArtifactStorageConfig, options: {
    client?: S3Client;
    presign?: typeof getSignedUrl;
  } = {}) {
    this.#config = config;
    this.#client = options.client ?? new S3Client({
      endpoint: config.endpoint,
      region: config.region,
      forcePathStyle: config.forcePathStyle,
      credentials: {
        accessKeyId: config.accessKeyId,
        secretAccessKey: config.secretAccessKey,
        sessionToken: config.sessionToken ?? undefined,
      },
    });
    this.#presign = options.presign ?? getSignedUrl;
  }

  objectKey(identity: ArtifactObjectIdentity): string {
    return [
      this.#config.prefix,
      safeSegment(identity.releaseId),
      safeSegment(identity.version),
      safeSegment(identity.platform),
      `${safeSegment(identity.kind)}-${identity.sha256}`,
    ].join('/');
  }

  async createUpload(input: {
    objectKey: string;
    sha256: string;
    sizeBytes: number;
    contentType: string;
    expiresAt: Date;
  }): Promise<ArtifactUploadTarget> {
    const checksum = checksumBase64(input.sha256);
    const retainUntil = this.#config.objectLockRequired
      ? new Date(Date.now() + this.#config.retentionDays * 24 * 60 * 60_000)
      : undefined;
    const command = new PutObjectCommand({
      Bucket: this.#config.bucket,
      Key: input.objectKey,
      ContentLength: input.sizeBytes,
      ContentType: input.contentType,
      ChecksumSHA256: checksum,
      Metadata: { sha256: input.sha256 },
      ServerSideEncryption: this.#config.serverSideEncryption as ServerSideEncryption,
      SSEKMSKeyId: this.#config.kmsKeyId ?? undefined,
      ObjectLockMode: this.#config.objectLockRequired ? 'COMPLIANCE' as ObjectLockMode : undefined,
      ObjectLockRetainUntilDate: retainUntil,
      ACL: undefined as ObjectCannedACL | undefined,
    });
    const expiresIn = Math.max(1, Math.floor((input.expiresAt.getTime() - Date.now()) / 1000));
    const url = await this.#presign(this.#client, command, {
      expiresIn,
      unhoistableHeaders: new Set([
        'content-length',
        'content-type',
        'x-amz-checksum-sha256',
        'x-amz-meta-sha256',
        'x-amz-server-side-encryption',
        'x-amz-server-side-encryption-aws-kms-key-id',
        'x-amz-object-lock-mode',
        'x-amz-object-lock-retain-until-date',
      ]),
    });
    const headers: Record<string, string> = {
      'content-length': String(input.sizeBytes),
      'content-type': input.contentType,
      'x-amz-checksum-sha256': checksum,
      'x-amz-meta-sha256': input.sha256,
      'x-amz-server-side-encryption': this.#config.serverSideEncryption,
    };
    if (this.#config.kmsKeyId) headers['x-amz-server-side-encryption-aws-kms-key-id'] = this.#config.kmsKeyId;
    if (retainUntil) {
      headers['x-amz-object-lock-mode'] = 'COMPLIANCE';
      headers['x-amz-object-lock-retain-until-date'] = retainUntil.toISOString();
    }
    return { method: 'PUT', url, headers, expiresAt: input.expiresAt.toISOString() };
  }

  async inspect(objectKey: string): Promise<StoredArtifactObject> {
    let result;
    try {
      result = await this.#client.send(new HeadObjectCommand({
        Bucket: this.#config.bucket,
        Key: objectKey,
        ChecksumMode: 'ENABLED',
      }));
    } catch (error) {
      const status = (error as { $metadata?: { httpStatusCode?: number } }).$metadata?.httpStatusCode;
      if (status === 404) throw notFound('stored release artifact does not exist');
      throw error;
    }
    const checksum = checksumHex(result.ChecksumSHA256) || result.Metadata?.sha256 || '';
    if (!/^[a-f0-9]{64}$/u.test(checksum)) {
      throw conflict('stored release artifact has no verifiable SHA-256 checksum');
    }
    return {
      objectKey,
      sizeBytes: Number(result.ContentLength),
      checksumSha256: checksum,
      versionId: result.VersionId ?? null,
      serverSideEncryption: result.ServerSideEncryption ?? null,
      objectLockMode: result.ObjectLockMode ?? null,
      objectLockRetainUntil: result.ObjectLockRetainUntilDate?.toISOString() ?? null,
    };
  }

  async createDownloadUrl(objectKey: string, expiresAt: Date): Promise<string> {
    if (this.#config.cdnBaseUrl) {
      return `${this.#config.cdnBaseUrl}/${encodedKey(objectKey)}`;
    }
    const expiresIn = Math.max(1, Math.floor((expiresAt.getTime() - Date.now()) / 1000));
    return this.#presign(this.#client, new GetObjectCommand({
      Bucket: this.#config.bucket,
      Key: objectKey,
    }), { expiresIn });
  }
}

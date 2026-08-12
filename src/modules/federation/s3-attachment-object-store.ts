import {
  DeleteObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
  PutObjectCommand,
  S3Client,
  type ServerSideEncryption,
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';

import { conflict, notFound } from '../../errors.js';
import type { FederationAttachmentObjectStore } from './attachment-object-store.js';
import type { FederationAttachmentStorageConfig } from './attachment-storage-config.js';

function checksumBase64(sha256: string): string {
  return Buffer.from(sha256, 'hex').toString('base64');
}

function checksumHex(value: string | undefined): string {
  if (!value) return '';
  const bytes = Buffer.from(value, 'base64');
  return bytes.length === 32 ? bytes.toString('hex') : '';
}

export class S3FederationAttachmentObjectStore implements FederationAttachmentObjectStore {
  readonly #config: FederationAttachmentStorageConfig;
  readonly #client: S3Client;
  readonly #presign: typeof getSignedUrl;

  constructor(config: FederationAttachmentStorageConfig, options: {
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

  objectKey(attachmentId: string): string {
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$/u.test(attachmentId)) {
      throw new Error('federation attachment id is invalid');
    }
    return `${this.#config.prefix}/${attachmentId.slice(0, 2).toLowerCase()}/${attachmentId}`;
  }

  async createUpload(input: {
    objectKey: string;
    sha256: string;
    sizeBytes: number;
    expiresAt: Date;
  }) {
    const checksum = checksumBase64(input.sha256);
    const command = new PutObjectCommand({
      Bucket: this.#config.bucket,
      Key: input.objectKey,
      ContentLength: input.sizeBytes,
      ContentType: 'application/otto-e2ee-attachment',
      ChecksumSHA256: checksum,
      Metadata: { sha256: input.sha256 },
      ServerSideEncryption: this.#config.serverSideEncryption as ServerSideEncryption,
      SSEKMSKeyId: this.#config.kmsKeyId ?? undefined,
    });
    const url = await this.#presign(this.#client, command, {
      expiresIn: Math.max(1, Math.floor((input.expiresAt.getTime() - Date.now()) / 1000)),
      unhoistableHeaders: new Set([
        'content-length',
        'content-type',
        'x-amz-checksum-sha256',
        'x-amz-meta-sha256',
        'x-amz-server-side-encryption',
        'x-amz-server-side-encryption-aws-kms-key-id',
      ]),
    });
    const headers: Record<string, string> = {
      'content-length': String(input.sizeBytes),
      'content-type': 'application/otto-e2ee-attachment',
      'x-amz-checksum-sha256': checksum,
      'x-amz-meta-sha256': input.sha256,
      'x-amz-server-side-encryption': this.#config.serverSideEncryption,
    };
    if (this.#config.kmsKeyId) {
      headers['x-amz-server-side-encryption-aws-kms-key-id'] = this.#config.kmsKeyId;
    }
    return { method: 'PUT' as const, url, headers, expiresAt: input.expiresAt.toISOString() };
  }

  async inspect(objectKey: string) {
    let result;
    try {
      result = await this.#client.send(new HeadObjectCommand({
        Bucket: this.#config.bucket,
        Key: objectKey,
        ChecksumMode: 'ENABLED',
      }));
    } catch (error) {
      const status = (error as { $metadata?: { httpStatusCode?: number } }).$metadata?.httpStatusCode;
      if (status === 404) throw notFound('federation attachment object does not exist');
      throw error;
    }
    const checksum = checksumHex(result.ChecksumSHA256) || result.Metadata?.sha256 || '';
    if (!/^[a-f0-9]{64}$/u.test(checksum)) {
      throw conflict('federation attachment has no verifiable SHA-256 checksum');
    }
    return { objectKey, sizeBytes: Number(result.ContentLength), checksumSha256: checksum };
  }

  async createDownload(input: { objectKey: string; expiresAt: Date }) {
    const url = await this.#presign(this.#client, new GetObjectCommand({
      Bucket: this.#config.bucket,
      Key: input.objectKey,
    }), { expiresIn: Math.max(1, Math.floor((input.expiresAt.getTime() - Date.now()) / 1000)) });
    return {
      method: 'GET' as const,
      url,
      headers: {},
      expiresAt: input.expiresAt.toISOString(),
    };
  }

  async remove(objectKey: string): Promise<void> {
    await this.#client.send(new DeleteObjectCommand({
      Bucket: this.#config.bucket,
      Key: objectKey,
    }));
  }
}

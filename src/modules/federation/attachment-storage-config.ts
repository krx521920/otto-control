import { readFileSync } from 'node:fs';

export interface FederationAttachmentStorageConfig {
  endpoint: string;
  bucket: string;
  region: string;
  prefix: string;
  forcePathStyle: boolean;
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string | null;
  serverSideEncryption: 'AES256' | 'aws:kms';
  kmsKeyId: string | null;
  uploadTtlSeconds: number;
  downloadTtlSeconds: number;
}

function secretFile(env: NodeJS.ProcessEnv, name: string): string {
  const path = env[name]?.trim();
  if (!path) throw new Error(`${name} is required`);
  try {
    const value = readFileSync(path, 'utf8').trim();
    if (!value) throw new Error('empty');
    return value;
  } catch {
    throw new Error(`${name} could not be read`);
  }
}

function integer(value: string | undefined, fallback: number, minimum: number, maximum: number, name: string): number {
  const normalized = value?.trim() || String(fallback);
  if (!/^\d+$/u.test(normalized)) throw new Error(`${name} must be an integer`);
  const parsed = Number(normalized);
  if (parsed < minimum || parsed > maximum) throw new Error(`${name} must be between ${minimum} and ${maximum}`);
  return parsed;
}

function boolean(value: string | undefined, fallback: boolean, name: string): boolean {
  if (!value?.trim()) return fallback;
  if (value === 'true') return true;
  if (value === 'false') return false;
  throw new Error(`${name} must be true or false`);
}

export function loadFederationAttachmentStorageConfig(
  env: NodeJS.ProcessEnv,
  production: boolean,
): FederationAttachmentStorageConfig | null {
  const endpoint = env.FEDERATION_ATTACHMENT_S3_ENDPOINT?.trim();
  const required = boolean(
    env.FEDERATION_ATTACHMENT_STORAGE_REQUIRED,
    false,
    'FEDERATION_ATTACHMENT_STORAGE_REQUIRED',
  );
  if (!endpoint) {
    if (required) throw new Error('FEDERATION_ATTACHMENT_S3_ENDPOINT is required');
    return null;
  }
  const url = new URL(endpoint);
  if ((production && url.protocol !== 'https:') || !['http:', 'https:'].includes(url.protocol)) {
    throw new Error('FEDERATION_ATTACHMENT_S3_ENDPOINT must use HTTPS in production');
  }
  const bucket = env.FEDERATION_ATTACHMENT_S3_BUCKET?.trim() || '';
  if (!/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/u.test(bucket)) {
    throw new Error('FEDERATION_ATTACHMENT_S3_BUCKET is invalid');
  }
  const prefix = (env.FEDERATION_ATTACHMENT_S3_PREFIX?.trim() || 'otto-federation-attachments')
    .replace(/^\/+|\/+$/gu, '');
  if (!prefix || prefix.includes('..') || !/^[A-Za-z0-9._/-]{1,200}$/u.test(prefix)) {
    throw new Error('FEDERATION_ATTACHMENT_S3_PREFIX is invalid');
  }
  const encryption = env.FEDERATION_ATTACHMENT_S3_ENCRYPTION?.trim() || 'AES256';
  if (encryption !== 'AES256' && encryption !== 'aws:kms') {
    throw new Error('FEDERATION_ATTACHMENT_S3_ENCRYPTION must be AES256 or aws:kms');
  }
  const kmsKeyId = env.FEDERATION_ATTACHMENT_S3_KMS_KEY_ID?.trim() || null;
  if (encryption === 'aws:kms' && !kmsKeyId) {
    throw new Error('FEDERATION_ATTACHMENT_S3_KMS_KEY_ID is required for aws:kms');
  }
  return {
    endpoint: url.toString().replace(/\/$/u, ''),
    bucket,
    region: env.FEDERATION_ATTACHMENT_S3_REGION?.trim() || 'us-east-1',
    prefix,
    forcePathStyle: boolean(env.FEDERATION_ATTACHMENT_S3_FORCE_PATH_STYLE, true, 'FEDERATION_ATTACHMENT_S3_FORCE_PATH_STYLE'),
    accessKeyId: secretFile(env, 'FEDERATION_ATTACHMENT_S3_ACCESS_KEY_ID_FILE'),
    secretAccessKey: secretFile(env, 'FEDERATION_ATTACHMENT_S3_SECRET_ACCESS_KEY_FILE'),
    sessionToken: env.FEDERATION_ATTACHMENT_S3_SESSION_TOKEN_FILE?.trim()
      ? secretFile(env, 'FEDERATION_ATTACHMENT_S3_SESSION_TOKEN_FILE')
      : null,
    serverSideEncryption: encryption,
    kmsKeyId,
    uploadTtlSeconds: integer(env.FEDERATION_ATTACHMENT_UPLOAD_TTL_SECONDS, 900, 60, 3_600, 'FEDERATION_ATTACHMENT_UPLOAD_TTL_SECONDS'),
    downloadTtlSeconds: integer(env.FEDERATION_ATTACHMENT_DOWNLOAD_TTL_SECONDS, 300, 30, 3_600, 'FEDERATION_ATTACHMENT_DOWNLOAD_TTL_SECONDS'),
  };
}

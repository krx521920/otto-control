import { readFileSync } from 'node:fs';

import type { ControlEnvironment } from '../../config.js';

export interface ArtifactStorageConfig {
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
  objectLockRequired: boolean;
  retentionDays: number;
  uploadTtlSeconds: number;
  downloadTtlSeconds: number;
  cdnBaseUrl: string | null;
}

function requiredFile(env: NodeJS.ProcessEnv, name: string): string {
  const path = env[name]?.trim();
  if (!path) throw new Error(`${name} is required when artifact storage is enabled`);
  let value = '';
  try {
    value = readFileSync(path, 'utf8').trim();
  } catch {
    throw new Error(`${name} could not be read`);
  }
  if (!value) throw new Error(`${name} must not be empty`);
  return value;
}

function boundedInteger(
  value: string | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
  name: string,
): number {
  const normalized = value?.trim() || String(fallback);
  if (!/^\d+$/u.test(normalized)) throw new Error(`${name} must be an integer`);
  const parsed = Number(normalized);
  if (parsed < minimum || parsed > maximum) {
    throw new Error(`${name} must be between ${minimum} and ${maximum}`);
  }
  return parsed;
}

function booleanValue(value: string | undefined, fallback: boolean, name: string): boolean {
  if (!value?.trim()) return fallback;
  if (value === 'true') return true;
  if (value === 'false') return false;
  throw new Error(`${name} must be true or false`);
}

function httpsOrigin(value: string, name: string, environment: ControlEnvironment): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${name} must be an absolute URL`);
  }
  if ((environment === 'production' && url.protocol !== 'https:')
    || (url.protocol !== 'https:' && url.protocol !== 'http:')
    || url.username
    || url.password
    || url.search
    || url.hash) {
    throw new Error(`${name} must be a credential-free ${environment === 'production' ? 'HTTPS ' : ''}origin`);
  }
  return url.toString().replace(/\/$/u, '');
}

export function loadArtifactStorageConfig(
  env: NodeJS.ProcessEnv,
  environment: ControlEnvironment,
): ArtifactStorageConfig | null {
  const isProductionDeployment = environment === 'production'
    && env.OTTO_CONTROL_DEPLOYMENT_ENVIRONMENT?.trim() !== 'staging';
  const endpoint = env.CONTROL_ARTIFACT_S3_ENDPOINT?.trim();
  const required = booleanValue(
    env.CONTROL_ARTIFACT_STORAGE_REQUIRED,
    isProductionDeployment,
    'CONTROL_ARTIFACT_STORAGE_REQUIRED',
  );
  if (!endpoint) {
    if (required) throw new Error('artifact storage is required but CONTROL_ARTIFACT_S3_ENDPOINT is missing');
    return null;
  }
  const bucket = env.CONTROL_ARTIFACT_S3_BUCKET?.trim();
  if (!bucket || !/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/u.test(bucket)) {
    throw new Error('CONTROL_ARTIFACT_S3_BUCKET is invalid');
  }
  const region = env.CONTROL_ARTIFACT_S3_REGION?.trim() || 'us-east-1';
  if (!/^[a-z0-9-]{3,40}$/u.test(region)) throw new Error('CONTROL_ARTIFACT_S3_REGION is invalid');
  const prefix = (env.CONTROL_ARTIFACT_S3_PREFIX?.trim() || 'otto-releases')
    .replace(/^\/+|\/+$/gu, '');
  if (!prefix || !/^[a-zA-Z0-9._/-]{1,200}$/u.test(prefix) || prefix.includes('..')) {
    throw new Error('CONTROL_ARTIFACT_S3_PREFIX is invalid');
  }
  const serverSideEncryption = env.CONTROL_ARTIFACT_S3_ENCRYPTION?.trim() || 'AES256';
  if (serverSideEncryption !== 'AES256' && serverSideEncryption !== 'aws:kms') {
    throw new Error('CONTROL_ARTIFACT_S3_ENCRYPTION must be AES256 or aws:kms');
  }
  const kmsKeyId = env.CONTROL_ARTIFACT_S3_KMS_KEY_ID?.trim() || null;
  if (serverSideEncryption === 'aws:kms' && !kmsKeyId) {
    throw new Error('CONTROL_ARTIFACT_S3_KMS_KEY_ID is required for aws:kms encryption');
  }
  const cdnValue = env.CONTROL_ARTIFACT_CDN_BASE_URL?.trim();
  return {
    endpoint: httpsOrigin(endpoint, 'CONTROL_ARTIFACT_S3_ENDPOINT', environment),
    bucket,
    region,
    prefix,
    forcePathStyle: booleanValue(
      env.CONTROL_ARTIFACT_S3_FORCE_PATH_STYLE,
      true,
      'CONTROL_ARTIFACT_S3_FORCE_PATH_STYLE',
    ),
    accessKeyId: requiredFile(env, 'CONTROL_ARTIFACT_S3_ACCESS_KEY_ID_FILE'),
    secretAccessKey: requiredFile(env, 'CONTROL_ARTIFACT_S3_SECRET_ACCESS_KEY_FILE'),
    sessionToken: env.CONTROL_ARTIFACT_S3_SESSION_TOKEN_FILE?.trim()
      ? requiredFile(env, 'CONTROL_ARTIFACT_S3_SESSION_TOKEN_FILE')
      : null,
    serverSideEncryption,
    kmsKeyId,
    objectLockRequired: booleanValue(
      env.CONTROL_ARTIFACT_S3_OBJECT_LOCK_REQUIRED,
      environment === 'production',
      'CONTROL_ARTIFACT_S3_OBJECT_LOCK_REQUIRED',
    ),
    retentionDays: boundedInteger(
      env.CONTROL_ARTIFACT_S3_RETENTION_DAYS,
      365,
      1,
      3_650,
      'CONTROL_ARTIFACT_S3_RETENTION_DAYS',
    ),
    uploadTtlSeconds: boundedInteger(
      env.CONTROL_ARTIFACT_UPLOAD_TTL_SECONDS,
      900,
      60,
      3_600,
      'CONTROL_ARTIFACT_UPLOAD_TTL_SECONDS',
    ),
    downloadTtlSeconds: boundedInteger(
      env.CONTROL_ARTIFACT_DOWNLOAD_TTL_SECONDS,
      300,
      30,
      3_600,
      'CONTROL_ARTIFACT_DOWNLOAD_TTL_SECONDS',
    ),
    cdnBaseUrl: cdnValue
      ? httpsOrigin(cdnValue, 'CONTROL_ARTIFACT_CDN_BASE_URL', environment)
      : null,
  };
}

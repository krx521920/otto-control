import { readFileSync } from 'node:fs';

import type { ControlEnvironment } from '../../config.js';

export interface AuditWitnessWormStorageConfig {
  endpoint: string;
  bucket: string;
  region: string;
  prefix: string;
  forcePathStyle: boolean;
  accessKeyId: string | null;
  secretAccessKey: string | null;
  sessionToken: string | null;
  serverSideEncryption: 'AES256' | 'aws:kms';
  kmsKeyId: string | null;
  objectLockMode: 'COMPLIANCE' | 'GOVERNANCE';
  retentionDays: number;
  pollIntervalMs: number;
  maxAttempts: number;
}

function booleanValue(value: string | undefined, fallback: boolean, name: string): boolean {
  if (!value?.trim()) return fallback;
  if (value === 'true') return true;
  if (value === 'false') return false;
  throw new Error(`${name} must be true or false`);
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

function requiredFile(env: NodeJS.ProcessEnv, name: string): string {
  const path = env[name]?.trim();
  if (!path) throw new Error(`${name} is required when audit WORM storage is enabled`);
  try {
    const value = readFileSync(path, 'utf8').trim();
    if (value) return value;
  } catch {
    // Replaced below with a stable configuration error.
  }
  throw new Error(`${name} could not be read or is empty`);
}

function endpointValue(value: string, environment: ControlEnvironment): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error('CONTROL_AUDIT_WORM_S3_ENDPOINT must be an absolute URL');
  }
  if ((environment === 'production' && url.protocol !== 'https:')
    || (url.protocol !== 'https:' && url.protocol !== 'http:')
    || url.username || url.password || url.search || url.hash) {
    throw new Error('CONTROL_AUDIT_WORM_S3_ENDPOINT must be a credential-free HTTPS origin in production');
  }
  return url.toString().replace(/\/$/u, '');
}

export function loadAuditWitnessWormStorageConfig(
  env: NodeJS.ProcessEnv,
  environment: ControlEnvironment,
): { config: AuditWitnessWormStorageConfig | null; required: boolean } {
  const required = booleanValue(
    env.CONTROL_AUDIT_WORM_REQUIRED,
    false,
    'CONTROL_AUDIT_WORM_REQUIRED',
  );
  const endpoint = env.CONTROL_AUDIT_WORM_S3_ENDPOINT?.trim();
  if (!endpoint) {
    if (required) {
      throw new Error('audit WORM storage is required but CONTROL_AUDIT_WORM_S3_ENDPOINT is missing');
    }
    return { config: null, required };
  }
  const bucket = env.CONTROL_AUDIT_WORM_S3_BUCKET?.trim();
  if (!bucket || !/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/u.test(bucket)) {
    throw new Error('CONTROL_AUDIT_WORM_S3_BUCKET is invalid');
  }
  const region = env.CONTROL_AUDIT_WORM_S3_REGION?.trim() || 'us-east-1';
  if (!/^[a-z0-9-]{3,40}$/u.test(region)) {
    throw new Error('CONTROL_AUDIT_WORM_S3_REGION is invalid');
  }
  const prefix = (env.CONTROL_AUDIT_WORM_S3_PREFIX?.trim() || 'otto-audit-witness')
    .replace(/^\/+|\/+$/gu, '');
  if (!prefix || !/^[a-zA-Z0-9._/-]{1,200}$/u.test(prefix) || prefix.includes('..')) {
    throw new Error('CONTROL_AUDIT_WORM_S3_PREFIX is invalid');
  }
  const encryption = env.CONTROL_AUDIT_WORM_S3_ENCRYPTION?.trim() || 'AES256';
  if (encryption !== 'AES256' && encryption !== 'aws:kms') {
    throw new Error('CONTROL_AUDIT_WORM_S3_ENCRYPTION must be AES256 or aws:kms');
  }
  const kmsKeyId = env.CONTROL_AUDIT_WORM_S3_KMS_KEY_ID?.trim() || null;
  if (encryption === 'aws:kms' && !kmsKeyId) {
    throw new Error('CONTROL_AUDIT_WORM_S3_KMS_KEY_ID is required for aws:kms encryption');
  }
  const lockMode = env.CONTROL_AUDIT_WORM_S3_LOCK_MODE?.trim() || 'COMPLIANCE';
  if (lockMode !== 'COMPLIANCE' && lockMode !== 'GOVERNANCE') {
    throw new Error('CONTROL_AUDIT_WORM_S3_LOCK_MODE must be COMPLIANCE or GOVERNANCE');
  }
  if (environment === 'production' && required && lockMode !== 'COMPLIANCE') {
    throw new Error('required production audit WORM storage must use COMPLIANCE lock mode');
  }
  const accessKeyFile = env.CONTROL_AUDIT_WORM_S3_ACCESS_KEY_ID_FILE?.trim();
  const secretAccessKeyFile = env.CONTROL_AUDIT_WORM_S3_SECRET_ACCESS_KEY_FILE?.trim();
  const sessionTokenFile = env.CONTROL_AUDIT_WORM_S3_SESSION_TOKEN_FILE?.trim();
  if (Boolean(accessKeyFile) !== Boolean(secretAccessKeyFile)) {
    throw new Error(
      'CONTROL_AUDIT_WORM_S3_ACCESS_KEY_ID_FILE and '
      + 'CONTROL_AUDIT_WORM_S3_SECRET_ACCESS_KEY_FILE must be configured together',
    );
  }
  if (sessionTokenFile && !accessKeyFile) {
    throw new Error('CONTROL_AUDIT_WORM_S3_SESSION_TOKEN_FILE requires static access key files');
  }
  return {
    required,
    config: {
      endpoint: endpointValue(endpoint, environment),
      bucket,
      region,
      prefix,
      forcePathStyle: booleanValue(
        env.CONTROL_AUDIT_WORM_S3_FORCE_PATH_STYLE,
        true,
        'CONTROL_AUDIT_WORM_S3_FORCE_PATH_STYLE',
      ),
      accessKeyId: accessKeyFile
        ? requiredFile(env, 'CONTROL_AUDIT_WORM_S3_ACCESS_KEY_ID_FILE')
        : null,
      secretAccessKey: secretAccessKeyFile
        ? requiredFile(env, 'CONTROL_AUDIT_WORM_S3_SECRET_ACCESS_KEY_FILE')
        : null,
      sessionToken: sessionTokenFile
        ? requiredFile(env, 'CONTROL_AUDIT_WORM_S3_SESSION_TOKEN_FILE')
        : null,
      serverSideEncryption: encryption,
      kmsKeyId,
      objectLockMode: lockMode,
      retentionDays: boundedInteger(
        env.CONTROL_AUDIT_WORM_RETENTION_DAYS,
        2_555,
        30,
        3_650,
        'CONTROL_AUDIT_WORM_RETENTION_DAYS',
      ),
      pollIntervalMs: boundedInteger(
        env.CONTROL_AUDIT_WORM_POLL_INTERVAL_MS,
        30_000,
        5_000,
        3_600_000,
        'CONTROL_AUDIT_WORM_POLL_INTERVAL_MS',
      ),
      maxAttempts: boundedInteger(
        env.CONTROL_AUDIT_WORM_MAX_ATTEMPTS,
        20,
        1,
        100,
        'CONTROL_AUDIT_WORM_MAX_ATTEMPTS',
      ),
    },
  };
}

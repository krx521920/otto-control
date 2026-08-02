import { readFileSync } from 'node:fs';

export interface FederationConfig {
  environment: 'development' | 'test' | 'production';
  host: string;
  port: number;
  logLevel: 'fatal' | 'error' | 'warn' | 'info' | 'debug' | 'trace' | 'silent';
  trustProxy: boolean;
  publicBaseUrl: string | null;
  databaseUrl: string | null;
  databaseSsl: boolean;
  adminToken: string | null;
  metricsToken: string | null;
  maximumCiphertextBytes: number;
  maximumClaimBytes: number;
  maximumEnvelopeTtlMs: number;
  maximumClockSkewMs: number;
  claimTtlMs: number;
  cleanupIntervalMs: number;
  deliveredRetentionMs: number;
}

function requiredSecret(
  env: NodeJS.ProcessEnv,
  valueName: string,
  fileName: string,
): string | null {
  const direct = env[valueName]?.trim();
  const path = env[fileName]?.trim();
  if (direct && path) throw new Error(`${valueName} and ${fileName} cannot both be set`);
  let value = direct;
  if (path) {
    try {
      value = readFileSync(path, 'utf8').trim();
    } catch {
      throw new Error(`${fileName} could not be read`);
    }
  }
  if (!value) return null;
  if (Buffer.byteLength(value, 'utf8') < 32) throw new Error(`${valueName} must contain at least 32 bytes`);
  return value;
}

function databaseUrl(env: NodeJS.ProcessEnv): string | null {
  const direct = env.FEDERATION_DATABASE_URL?.trim() || env.CONTROL_DATABASE_URL?.trim();
  const host = env.FEDERATION_DATABASE_HOST?.trim() || env.CONTROL_DATABASE_HOST?.trim();
  const database = env.FEDERATION_DATABASE_NAME?.trim() || env.CONTROL_DATABASE_NAME?.trim();
  const user = env.FEDERATION_DATABASE_USER?.trim() || env.CONTROL_DATABASE_USER?.trim();
  const passwordFile = env.FEDERATION_DATABASE_PASSWORD_FILE?.trim()
    || env.CONTROL_DATABASE_PASSWORD_FILE?.trim();
  const passwordValue = env.FEDERATION_DATABASE_PASSWORD?.trim()
    || env.CONTROL_DATABASE_PASSWORD?.trim();
  if (direct && (host || database || user || passwordFile || passwordValue)) {
    throw new Error('FEDERATION_DATABASE_URL cannot be combined with database component settings');
  }
  if (direct) return direct;
  if (!host && !database && !user && !passwordFile && !passwordValue) return null;
  if (!host || !database || !user) {
    throw new Error('FEDERATION_DATABASE_HOST, FEDERATION_DATABASE_NAME, and FEDERATION_DATABASE_USER are required together');
  }
  if (passwordFile && passwordValue) {
    throw new Error('FEDERATION_DATABASE_PASSWORD and FEDERATION_DATABASE_PASSWORD_FILE cannot both be set');
  }
  let password = passwordValue;
  if (passwordFile) {
    try {
      password = readFileSync(passwordFile, 'utf8').trim();
    } catch {
      throw new Error('FEDERATION_DATABASE_PASSWORD_FILE could not be read');
    }
  }
  if (!password) throw new Error('federation database password is required');
  const url = new URL('postgresql://localhost');
  url.hostname = host;
  url.port = env.FEDERATION_DATABASE_PORT?.trim() || env.CONTROL_DATABASE_PORT?.trim() || '5432';
  url.username = user;
  url.password = password;
  url.pathname = `/${database}`;
  return url.toString();
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
  if (parsed < minimum || parsed > maximum) throw new Error(`${name} must be between ${minimum} and ${maximum}`);
  return parsed;
}

function boolean(value: string | undefined, fallback: boolean, name: string): boolean {
  if (value === undefined || value.trim() === '') return fallback;
  if (value === 'true') return true;
  if (value === 'false') return false;
  throw new Error(`${name} must be true or false`);
}

function baseUrl(value: string | undefined, production: boolean): string | null {
  const normalized = value?.trim();
  if (!normalized) return null;
  let url: URL;
  try {
    url = new URL(normalized);
  } catch {
    throw new Error('FEDERATION_PUBLIC_BASE_URL must be an absolute URL');
  }
  if (production && url.protocol !== 'https:') throw new Error('FEDERATION_PUBLIC_BASE_URL must use HTTPS in production');
  return url.toString().replace(/\/$/u, '');
}

export function loadFederationConfig(env: NodeJS.ProcessEnv = process.env): Readonly<FederationConfig> {
  const environment = env.NODE_ENV?.trim() || 'development';
  if (environment !== 'development' && environment !== 'test' && environment !== 'production') {
    throw new Error('NODE_ENV must be development, test, or production');
  }
  const logLevel = env.FEDERATION_LOG_LEVEL?.trim() || 'info';
  if (!['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent'].includes(logLevel)) {
    throw new Error('FEDERATION_LOG_LEVEL is invalid');
  }
  const resolvedDatabaseUrl = databaseUrl(env);
  if (resolvedDatabaseUrl) {
    const url = new URL(resolvedDatabaseUrl);
    if (url.protocol !== 'postgres:' && url.protocol !== 'postgresql:') {
      throw new Error('FEDERATION_DATABASE_URL must use PostgreSQL');
    }
  }
  const maximumCiphertextBytes = boundedInteger(
    env.FEDERATION_MAX_CIPHERTEXT_BYTES,
    1024 * 1024,
    4096,
    10 * 1024 * 1024,
    'FEDERATION_MAX_CIPHERTEXT_BYTES',
  );
  const maximumClaimBytes = boundedInteger(
    env.FEDERATION_MAX_CLAIM_BYTES,
    Math.max(maximumCiphertextBytes, 4 * 1024 * 1024),
    4096,
    100 * 1024 * 1024,
    'FEDERATION_MAX_CLAIM_BYTES',
  );
  if (maximumClaimBytes < maximumCiphertextBytes) {
    throw new Error('FEDERATION_MAX_CLAIM_BYTES must be at least FEDERATION_MAX_CIPHERTEXT_BYTES');
  }
  const config: FederationConfig = {
    environment,
    host: env.FEDERATION_HOST?.trim() || '127.0.0.1',
    port: boundedInteger(env.FEDERATION_PORT, 7790, 1, 65_535, 'FEDERATION_PORT'),
    logLevel: logLevel as FederationConfig['logLevel'],
    trustProxy: boolean(env.FEDERATION_TRUST_PROXY, environment === 'production', 'FEDERATION_TRUST_PROXY'),
    publicBaseUrl: baseUrl(env.FEDERATION_PUBLIC_BASE_URL, environment === 'production'),
    databaseUrl: resolvedDatabaseUrl,
    databaseSsl: boolean(env.FEDERATION_DATABASE_SSL, environment === 'production', 'FEDERATION_DATABASE_SSL'),
    adminToken: requiredSecret(env, 'FEDERATION_ADMIN_TOKEN', 'FEDERATION_ADMIN_TOKEN_FILE'),
    metricsToken: requiredSecret(env, 'FEDERATION_METRICS_TOKEN', 'FEDERATION_METRICS_TOKEN_FILE'),
    maximumCiphertextBytes,
    maximumClaimBytes,
    maximumEnvelopeTtlMs: boundedInteger(
      env.FEDERATION_MAX_ENVELOPE_TTL_MS,
      7 * 24 * 60 * 60_000,
      60_000,
      30 * 24 * 60 * 60_000,
      'FEDERATION_MAX_ENVELOPE_TTL_MS',
    ),
    maximumClockSkewMs: boundedInteger(
      env.FEDERATION_MAX_CLOCK_SKEW_MS,
      5 * 60_000,
      30_000,
      15 * 60_000,
      'FEDERATION_MAX_CLOCK_SKEW_MS',
    ),
    claimTtlMs: boundedInteger(env.FEDERATION_CLAIM_TTL_MS, 60_000, 10_000, 10 * 60_000, 'FEDERATION_CLAIM_TTL_MS'),
    cleanupIntervalMs: boundedInteger(
      env.FEDERATION_CLEANUP_INTERVAL_MS,
      60_000,
      10_000,
      60 * 60_000,
      'FEDERATION_CLEANUP_INTERVAL_MS',
    ),
    deliveredRetentionMs: boundedInteger(
      env.FEDERATION_DELIVERED_RETENTION_MS,
      7 * 24 * 60 * 60_000,
      60 * 60_000,
      90 * 24 * 60 * 60_000,
      'FEDERATION_DELIVERED_RETENTION_MS',
    ),
  };
  if (environment === 'production') {
    const missing = [
      !config.publicBaseUrl && 'FEDERATION_PUBLIC_BASE_URL',
      !config.databaseUrl && 'FEDERATION_DATABASE_URL',
      !config.adminToken && 'FEDERATION_ADMIN_TOKEN',
      !config.metricsToken && 'FEDERATION_METRICS_TOKEN',
    ].filter(Boolean);
    if (missing.length) throw new Error(`federation configuration is incomplete: ${missing.join(', ')}`);
  }
  return config;
}

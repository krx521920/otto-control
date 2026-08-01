import { readFileSync } from 'node:fs';

export type ControlEnvironment = 'development' | 'test' | 'production';
export type ControlLogLevel = 'fatal' | 'error' | 'warn' | 'info' | 'debug' | 'trace' | 'silent';

export interface ControlConfig {
  environment: ControlEnvironment;
  host: string;
  port: number;
  logLevel: ControlLogLevel;
  trustProxy: boolean;
  publicBaseUrl: string | null;
  version: string;
  databaseUrl: string | null;
  databaseSsl: boolean;
  adminToken: string | null;
  tokenSecret: string | null;
  signerPrivateKeyFile: string | null;
  signerKeyringFile: string | null;
  leaseDurationMs: number;
  telemetryRetentionDays: number;
  updatePolicyDurationMs: number;
  backupReportDirectory: string | null;
  backupStatusMaximumAgeHours: number;
  alertChannelsFile: string | null;
  alertWebhookUrl: string | null;
  alertWebhookSecretFile: string | null;
  alertPollIntervalMs: number;
  alertWebhookTimeoutMs: number;
  alertWebhookMaxAttempts: number;
  alertRetentionDays: number;
}

const LOG_LEVELS = new Set<ControlLogLevel>([
  'fatal',
  'error',
  'warn',
  'info',
  'debug',
  'trace',
  'silent',
]);

function parseEnvironment(value: string | undefined): ControlEnvironment {
  const normalized = value?.trim() || 'development';
  if (normalized === 'development' || normalized === 'test' || normalized === 'production') {
    return normalized;
  }
  throw new Error('NODE_ENV must be development, test, or production');
}

function parsePort(value: string | undefined): number {
  const normalized = value?.trim() || '7788';
  if (!/^\d{1,5}$/u.test(normalized)) throw new Error('CONTROL_PORT must be an integer');
  const port = Number(normalized);
  if (port < 1 || port > 65_535) throw new Error('CONTROL_PORT must be between 1 and 65535');
  return port;
}

function parseBoolean(value: string | undefined, fallback: boolean, name: string): boolean {
  if (value === undefined || value.trim() === '') return fallback;
  if (value === 'true') return true;
  if (value === 'false') return false;
  throw new Error(`${name} must be true or false`);
}

function optionalSecret(value: string | undefined, name: string): string | null {
  const normalized = value?.trim();
  if (!normalized) return null;
  if (Buffer.byteLength(normalized, 'utf8') < 32) {
    throw new Error(`${name} must contain at least 32 bytes`);
  }
  return normalized;
}

function secretFromEnvironment(
  env: NodeJS.ProcessEnv,
  valueName: string,
  fileName: string,
): string | null {
  const direct = env[valueName]?.trim();
  const path = env[fileName]?.trim();
  if (direct && path) throw new Error(`${valueName} and ${fileName} cannot both be set`);
  if (!path) return optionalSecret(direct, valueName);

  let value: string;
  try {
    value = readFileSync(path, 'utf8').trim();
  } catch {
    throw new Error(`${fileName} could not be read`);
  }
  return optionalSecret(value, fileName);
}

function databaseUrlFromEnvironment(env: NodeJS.ProcessEnv): string | undefined {
  const direct = env.CONTROL_DATABASE_URL?.trim();
  const componentNames = [
    'CONTROL_DATABASE_HOST',
    'CONTROL_DATABASE_PORT',
    'CONTROL_DATABASE_NAME',
    'CONTROL_DATABASE_USER',
    'CONTROL_DATABASE_PASSWORD',
    'CONTROL_DATABASE_PASSWORD_FILE',
  ] as const;
  const hasComponents = componentNames.some((name) => Boolean(env[name]?.trim()));
  if (direct && hasComponents) {
    throw new Error('CONTROL_DATABASE_URL cannot be combined with database component settings');
  }
  if (!hasComponents) return direct;

  const host = env.CONTROL_DATABASE_HOST?.trim();
  const database = env.CONTROL_DATABASE_NAME?.trim();
  const user = env.CONTROL_DATABASE_USER?.trim();
  if (!host || !database || !user) {
    throw new Error(
      'CONTROL_DATABASE_HOST, CONTROL_DATABASE_NAME, and CONTROL_DATABASE_USER are required together',
    );
  }
  const password = secretFromEnvironment(
    env,
    'CONTROL_DATABASE_PASSWORD',
    'CONTROL_DATABASE_PASSWORD_FILE',
  );
  if (!password) throw new Error('CONTROL_DATABASE_PASSWORD or CONTROL_DATABASE_PASSWORD_FILE is required');

  const port = env.CONTROL_DATABASE_PORT?.trim() || '5432';
  if (!/^\d{1,5}$/u.test(port) || Number(port) < 1 || Number(port) > 65_535) {
    throw new Error('CONTROL_DATABASE_PORT must be between 1 and 65535');
  }
  const url = new URL('postgresql://localhost');
  url.hostname = host;
  url.port = port;
  url.username = user;
  url.password = password;
  url.pathname = `/${database}`;
  return url.toString();
}

function parseDatabaseUrl(value: string | undefined): string | null {
  const normalized = value?.trim();
  if (!normalized) return null;
  let url: URL;
  try {
    url = new URL(normalized);
  } catch {
    throw new Error('CONTROL_DATABASE_URL must be an absolute PostgreSQL URL');
  }
  if (url.protocol !== 'postgres:' && url.protocol !== 'postgresql:') {
    throw new Error('CONTROL_DATABASE_URL must use postgres:// or postgresql://');
  }
  return normalized;
}

function parseLeaseDuration(value: string | undefined): number {
  const normalized = value?.trim() || '600000';
  if (!/^\d+$/u.test(normalized)) {
    throw new Error('CONTROL_LEASE_DURATION_MS must be an integer');
  }
  const duration = Number(normalized);
  if (duration < 120_000 || duration > 86_400_000) {
    throw new Error('CONTROL_LEASE_DURATION_MS must be between 120000 and 86400000');
  }
  return duration;
}

function parseRetentionDays(value: string | undefined): number {
  const normalized = value?.trim() || '90';
  if (!/^\d+$/u.test(normalized)) {
    throw new Error('CONTROL_TELEMETRY_RETENTION_DAYS must be an integer');
  }
  const days = Number(normalized);
  if (days < 1 || days > 3650) {
    throw new Error('CONTROL_TELEMETRY_RETENTION_DAYS must be between 1 and 3650');
  }
  return days;
}

function parseUpdatePolicyDuration(value: string | undefined): number {
  const normalized = value?.trim() || '300000';
  if (!/^\d+$/u.test(normalized)) {
    throw new Error('CONTROL_UPDATE_POLICY_DURATION_MS must be an integer');
  }
  const duration = Number(normalized);
  if (duration < 60_000 || duration > 3_600_000) {
    throw new Error('CONTROL_UPDATE_POLICY_DURATION_MS must be between 60000 and 3600000');
  }
  return duration;
}

function parseBackupStatusMaximumAgeHours(value: string | undefined): number {
  const normalized = value?.trim() || '48';
  if (!/^\d+$/u.test(normalized)) {
    throw new Error('CONTROL_BACKUP_STATUS_MAX_AGE_HOURS must be an integer');
  }
  const hours = Number(normalized);
  if (hours < 1 || hours > 720) {
    throw new Error('CONTROL_BACKUP_STATUS_MAX_AGE_HOURS must be between 1 and 720');
  }
  return hours;
}

function parseBoundedInteger(
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

function parseAlertWebhookUrl(value: string | undefined): string | null {
  const normalized = value?.trim();
  if (!normalized) return null;
  let url: URL;
  try {
    url = new URL(normalized);
  } catch {
    throw new Error('CONTROL_ALERT_WEBHOOK_URL must be an absolute HTTPS URL');
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) {
    throw new Error('CONTROL_ALERT_WEBHOOK_URL must use HTTPS without credentials or fragments');
  }
  return url.toString();
}

function parseLogLevel(value: string | undefined): ControlLogLevel {
  const normalized = (value?.trim() || 'info') as ControlLogLevel;
  if (!LOG_LEVELS.has(normalized)) throw new Error('CONTROL_LOG_LEVEL is invalid');
  return normalized;
}

function parsePublicBaseUrl(value: string | undefined, environment: ControlEnvironment): string | null {
  const normalized = value?.trim();
  if (!normalized) return null;
  let url: URL;
  try {
    url = new URL(normalized);
  } catch {
    throw new Error('CONTROL_PUBLIC_BASE_URL must be an absolute URL');
  }
  if (environment === 'production' && url.protocol !== 'https:') {
    throw new Error('CONTROL_PUBLIC_BASE_URL must use HTTPS in production');
  }
  return url.toString().replace(/\/$/u, '');
}

export function loadControlConfig(
  env: NodeJS.ProcessEnv = process.env,
): Readonly<ControlConfig> {
  const environment = parseEnvironment(env.NODE_ENV);
  const signerPrivateKeyFile = env.CONTROL_SIGNER_PRIVATE_KEY_FILE?.trim() || null;
  const signerKeyringFile = env.CONTROL_SIGNER_KEYRING_FILE?.trim() || null;
  const alertWebhookUrl = parseAlertWebhookUrl(env.CONTROL_ALERT_WEBHOOK_URL);
  const alertWebhookSecretFile = env.CONTROL_ALERT_WEBHOOK_SECRET_FILE?.trim() || null;
  const alertChannelsFile = env.CONTROL_ALERT_CHANNELS_FILE?.trim() || null;
  if (signerPrivateKeyFile && signerKeyringFile) {
    throw new Error('CONTROL_SIGNER_PRIVATE_KEY_FILE and CONTROL_SIGNER_KEYRING_FILE cannot both be set');
  }
  if (alertWebhookUrl && !alertWebhookSecretFile) {
    throw new Error('CONTROL_ALERT_WEBHOOK_SECRET_FILE is required with CONTROL_ALERT_WEBHOOK_URL');
  }
  if (alertChannelsFile && (alertWebhookUrl || alertWebhookSecretFile)) {
    throw new Error('CONTROL_ALERT_CHANNELS_FILE cannot be combined with legacy alert webhook settings');
  }
  return Object.freeze({
    environment,
    host: env.CONTROL_HOST?.trim() || '127.0.0.1',
    port: parsePort(env.CONTROL_PORT),
    logLevel: parseLogLevel(env.CONTROL_LOG_LEVEL),
    trustProxy: parseBoolean(env.CONTROL_TRUST_PROXY, false, 'CONTROL_TRUST_PROXY'),
    publicBaseUrl: parsePublicBaseUrl(env.CONTROL_PUBLIC_BASE_URL, environment),
    version: env.OTTO_CONTROL_VERSION?.trim() || '0.18.0',
    databaseUrl: parseDatabaseUrl(databaseUrlFromEnvironment(env)),
    databaseSsl: parseBoolean(
      env.CONTROL_DATABASE_SSL,
      environment === 'production',
      'CONTROL_DATABASE_SSL',
    ),
    adminToken: secretFromEnvironment(env, 'CONTROL_ADMIN_TOKEN', 'CONTROL_ADMIN_TOKEN_FILE'),
    tokenSecret: secretFromEnvironment(env, 'CONTROL_TOKEN_SECRET', 'CONTROL_TOKEN_SECRET_FILE'),
    signerPrivateKeyFile,
    signerKeyringFile,
    leaseDurationMs: parseLeaseDuration(env.CONTROL_LEASE_DURATION_MS),
    telemetryRetentionDays: parseRetentionDays(env.CONTROL_TELEMETRY_RETENTION_DAYS),
    updatePolicyDurationMs: parseUpdatePolicyDuration(env.CONTROL_UPDATE_POLICY_DURATION_MS),
    backupReportDirectory: env.CONTROL_BACKUP_REPORT_DIR?.trim() || null,
    backupStatusMaximumAgeHours: parseBackupStatusMaximumAgeHours(
      env.CONTROL_BACKUP_STATUS_MAX_AGE_HOURS,
    ),
    alertChannelsFile,
    alertWebhookUrl,
    alertWebhookSecretFile,
    alertPollIntervalMs: parseBoundedInteger(
      env.CONTROL_ALERT_POLL_INTERVAL_MS,
      60_000,
      5_000,
      3_600_000,
      'CONTROL_ALERT_POLL_INTERVAL_MS',
    ),
    alertWebhookTimeoutMs: parseBoundedInteger(
      env.CONTROL_ALERT_WEBHOOK_TIMEOUT_MS,
      10_000,
      500,
      30_000,
      'CONTROL_ALERT_WEBHOOK_TIMEOUT_MS',
    ),
    alertWebhookMaxAttempts: parseBoundedInteger(
      env.CONTROL_ALERT_WEBHOOK_MAX_ATTEMPTS,
      8,
      1,
      20,
      'CONTROL_ALERT_WEBHOOK_MAX_ATTEMPTS',
    ),
    alertRetentionDays: parseBoundedInteger(
      env.CONTROL_ALERT_RETENTION_DAYS,
      365,
      30,
      3_650,
      'CONTROL_ALERT_RETENTION_DAYS',
    ),
  });
}

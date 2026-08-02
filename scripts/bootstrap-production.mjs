import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

function option(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function requiredPublicUrl() {
  const raw = option('--public-url');
  if (!raw) throw new Error('usage: npm run bootstrap:production -- --public-url https://control.example.com');
  const url = new URL(raw);
  if (url.protocol !== 'https:' || url.pathname !== '/' || url.search || url.hash) {
    throw new Error('--public-url must be an HTTPS origin without a path, query, or fragment');
  }
  return url;
}

function writeSecret(path, value) {
  writeFileSync(path, `${value}\n`, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
}

function main() {
  const publicUrl = requiredPublicUrl();
  const root = resolve(option('--output') ?? '.');
  const secretDirectory = resolve(root, 'secrets');
  const targets = [
    resolve(root, '.env.production'),
    resolve(secretDirectory, 'control_signer_private_key.pem'),
    resolve(secretDirectory, 'control_signer_keyring.json'),
    resolve(secretDirectory, 'control_admin_token'),
    resolve(secretDirectory, 'control_token_secret'),
    resolve(secretDirectory, 'control_metrics_token'),
    resolve(secretDirectory, 'postgres_password'),
    resolve(secretDirectory, 'postgres_superuser_password'),
    resolve(secretDirectory, 'postgres_replication_password'),
    resolve(secretDirectory, 'pgbackrest_cipher_pass'),
    resolve(secretDirectory, 'backup_encryption_key'),
    resolve(secretDirectory, 'alert_webhook_secret'),
    resolve(secretDirectory, 'audit_anchor_token'),
  ];
  const existing = targets.find(existsSync);
  if (existing) throw new Error(`refusing to overwrite existing production identity file: ${existing}`);
  mkdirSync(secretDirectory, { recursive: true, mode: 0o700 });
  mkdirSync(resolve(root, 'backups'), { recursive: true, mode: 0o700 });
  const backupReportDirectory = resolve(root, 'backups', 'reports');
  mkdirSync(backupReportDirectory, { recursive: true, mode: 0o755 });
  chmodSync(backupReportDirectory, 0o755);

  const { privateKey } = generateKeyPairSync('ed25519');
  writeSecret(
    resolve(secretDirectory, 'control_signer_private_key.pem'),
    privateKey.export({ type: 'pkcs8', format: 'pem' }),
  );
  writeSecret(
    resolve(secretDirectory, 'control_signer_keyring.json'),
    JSON.stringify({
      version: 1,
      keys: [{
        provider: 'local',
        privateKeyFile: 'control_signer_private_key.pem',
      }],
    }, null, 2),
  );
  writeSecret(resolve(secretDirectory, 'control_admin_token'), randomBytes(48).toString('base64url'));
  writeSecret(resolve(secretDirectory, 'control_token_secret'), randomBytes(48).toString('base64url'));
  writeSecret(resolve(secretDirectory, 'control_metrics_token'), randomBytes(48).toString('base64url'));
  writeSecret(resolve(secretDirectory, 'postgres_password'), randomBytes(48).toString('base64url'));
  writeSecret(
    resolve(secretDirectory, 'postgres_superuser_password'),
    randomBytes(48).toString('base64url'),
  );
  writeSecret(
    resolve(secretDirectory, 'postgres_replication_password'),
    randomBytes(48).toString('base64url'),
  );
  writeSecret(
    resolve(secretDirectory, 'pgbackrest_cipher_pass'),
    randomBytes(48).toString('base64url'),
  );
  writeSecret(resolve(secretDirectory, 'backup_encryption_key'), randomBytes(48).toString('base64url'));
  writeSecret(resolve(secretDirectory, 'alert_webhook_secret'), randomBytes(48).toString('base64url'));
  writeSecret(resolve(secretDirectory, 'audit_anchor_token'), randomBytes(48).toString('base64url'));

  const environment = [
    'NODE_ENV=production',
    'OTTO_CONTROL_VERSION=0.25.0',
    'CONTROL_HOST=0.0.0.0',
    'CONTROL_PORT=7788',
    'CONTROL_LOG_LEVEL=info',
    'CONTROL_TRUST_PROXY=true',
    `CONTROL_PUBLIC_BASE_URL=${publicUrl.origin}`,
    `CONTROL_DOMAIN=${publicUrl.hostname}`,
    'CONTROL_DATABASE_HOST=postgres-router',
    'CONTROL_DATABASE_PORT=5432',
    'CONTROL_DATABASE_NAME=otto_control',
    'CONTROL_DATABASE_USER=otto_control',
    'CONTROL_DATABASE_PASSWORD_FILE=/run/secrets/postgres_password',
    'CONTROL_DATABASE_SSL=false',
    'CONTROL_ADMIN_TOKEN_FILE=/run/secrets/control_admin_token',
    'CONTROL_TOKEN_SECRET_FILE=/run/secrets/control_token_secret',
    'CONTROL_METRICS_TOKEN_FILE=/run/secrets/control_metrics_token',
    'CONTROL_SIGNER_KEYRING_FILE=/run/otto-secrets/control_signer_keyring.json',
    'CONTROL_LEASE_DURATION_MS=600000',
    'CONTROL_TELEMETRY_RETENTION_DAYS=90',
    'CONTROL_UPDATE_POLICY_DURATION_MS=300000',
    `CONTROL_DATA_REGION=${process.env.CONTROL_DATA_REGION?.trim() || 'CN-BJ'}`,
    `CONTROL_ALLOWED_DATA_REGIONS=${process.env.CONTROL_ALLOWED_DATA_REGIONS?.trim() || process.env.CONTROL_DATA_REGION?.trim() || 'CN-BJ'}`,
    'CONTROL_CROSS_BORDER_ENABLED=false',
    'CONTROL_CROSS_BORDER_ASSESSMENT_ID=',
    'CONTROL_PRIVACY_POLICY_VERSION=2026-08-01',
    'CONTROL_PRIVACY_POLICY_EFFECTIVE_AT=2026-08-01T00:00:00.000Z',
    `CONTROL_PRIVACY_CONTROLLER=${process.env.CONTROL_PRIVACY_CONTROLLER?.trim() || publicUrl.hostname}`,
    `CONTROL_PRIVACY_CONTACT=${process.env.CONTROL_PRIVACY_CONTACT?.trim() || `privacy@${publicUrl.hostname}`}`,
    'CONTROL_CUSTOMER_ERASURE_GRACE_DAYS=14',
    'CONTROL_BILLING_RETENTION_DAYS=1095',
    'CONTROL_GOVERNANCE_AUDIT_RETENTION_DAYS=2555',
    'CONTROL_DATA_EXPORT_RECORD_RETENTION_DAYS=30',
    'CONTROL_DATA_RETENTION_POLL_INTERVAL_HOURS=24',
    'CONTROL_ARTIFACT_STORAGE_REQUIRED=false',
    'CONTROL_ARTIFACT_S3_ENDPOINT=',
    'CONTROL_ARTIFACT_S3_BUCKET=',
    'CONTROL_ARTIFACT_S3_REGION=us-east-1',
    'CONTROL_ARTIFACT_S3_PREFIX=otto-releases',
    'CONTROL_ARTIFACT_S3_FORCE_PATH_STYLE=true',
    'CONTROL_ARTIFACT_S3_ACCESS_KEY_ID_FILE=',
    'CONTROL_ARTIFACT_S3_SECRET_ACCESS_KEY_FILE=',
    'CONTROL_ARTIFACT_S3_SESSION_TOKEN_FILE=',
    'CONTROL_ARTIFACT_S3_ENCRYPTION=AES256',
    'CONTROL_ARTIFACT_S3_KMS_KEY_ID=',
    'CONTROL_ARTIFACT_S3_OBJECT_LOCK_REQUIRED=true',
    'CONTROL_ARTIFACT_S3_RETENTION_DAYS=365',
    'CONTROL_ARTIFACT_UPLOAD_TTL_SECONDS=900',
    'CONTROL_ARTIFACT_DOWNLOAD_TTL_SECONDS=300',
    'CONTROL_ARTIFACT_CDN_BASE_URL=',
    'CONTROL_ARTIFACT_ATTESTATION_KEYS_FILE=',
    'CONTROL_BACKUP_RETENTION_DAYS=30',
    'CONTROL_BACKUP_REPORT_DIR=/var/lib/otto-control/backup-reports',
    'CONTROL_BACKUP_STATUS_MAX_AGE_HOURS=48',
    'CONTROL_ALERT_WEBHOOK_URL=',
    'CONTROL_ALERT_WEBHOOK_SECRET_FILE=',
    'CONTROL_ALERT_POLL_INTERVAL_MS=60000',
    'CONTROL_ALERT_WEBHOOK_TIMEOUT_MS=10000',
    'CONTROL_ALERT_WEBHOOK_MAX_ATTEMPTS=8',
    'CONTROL_ALERT_RETENTION_DAYS=365',
    'CONTROL_AUDIT_ANCHOR_URL=',
    'CONTROL_AUDIT_ANCHOR_TOKEN_FILE=',
    'CONTROL_AUDIT_ANCHOR_INTERVAL_MS=900000',
    'CONTROL_AUDIT_ANCHOR_POLL_INTERVAL_MS=60000',
    'CONTROL_AUDIT_ANCHOR_TIMEOUT_MS=10000',
    'CONTROL_AUDIT_ANCHOR_MAX_ATTEMPTS=8',
    'CONTROL_AUDIT_WITNESS_SOURCES_FILE=',
    'CONTROL_AUDIT_WORM_REQUIRED=false',
    'CONTROL_AUDIT_WORM_S3_ENDPOINT=',
    'CONTROL_AUDIT_WORM_S3_BUCKET=',
    'CONTROL_AUDIT_WORM_S3_REGION=us-east-1',
    'CONTROL_AUDIT_WORM_S3_PREFIX=otto-audit-witness',
    'CONTROL_AUDIT_WORM_S3_FORCE_PATH_STYLE=true',
    'CONTROL_AUDIT_WORM_S3_ACCESS_KEY_ID_FILE=',
    'CONTROL_AUDIT_WORM_S3_SECRET_ACCESS_KEY_FILE=',
    'CONTROL_AUDIT_WORM_S3_SESSION_TOKEN_FILE=',
    'CONTROL_AUDIT_WORM_S3_ENCRYPTION=AES256',
    'CONTROL_AUDIT_WORM_S3_KMS_KEY_ID=',
    'CONTROL_AUDIT_WORM_S3_LOCK_MODE=COMPLIANCE',
    'CONTROL_AUDIT_WORM_RETENTION_DAYS=2555',
    'CONTROL_AUDIT_WORM_POLL_INTERVAL_MS=30000',
    'CONTROL_AUDIT_WORM_MAX_ATTEMPTS=20',
    'CONTROL_SLOW_REQUEST_THRESHOLD_MS=1000',
    'CONTROL_CAPACITY_SAMPLE_INTERVAL_MS=60000',
    'CONTROL_SLO_AVAILABILITY_TARGET=0.999',
    'CONTROL_SLO_LATENCY_TARGET_MS=500',
    'CONTROL_OTLP_TRACE_ENDPOINT=',
    'CONTROL_OTLP_HEADERS_FILE=',
    'CONTROL_TRACE_SAMPLE_RATIO=0.1',
    'CONTROL_BACKUP_OFFSITE_REQUIRED=false',
    'CONTROL_BACKUP_S3_ENDPOINT=',
    'CONTROL_BACKUP_S3_BUCKET=',
    'CONTROL_BACKUP_S3_REGION=us-east-1',
    'CONTROL_BACKUP_S3_PREFIX=otto-control',
    'CONTROL_BACKUP_S3_ADDRESSING_STYLE=path',
    'CONTROL_BACKUP_S3_ACCESS_KEY_ID_FILE=',
    'CONTROL_BACKUP_S3_SECRET_ACCESS_KEY_FILE=',
    'CONTROL_BACKUP_S3_SESSION_TOKEN_FILE=',
    'CONTROL_BACKUP_S3_MAX_ATTEMPTS=4',
    'CONTROL_BACKUP_S3_TIMEOUT_MS=120000',
    'CONTROL_DRILL_REPORT_RETENTION_DAYS=180',
    'CONTROL_DRILL_MAX_BACKUP_AGE_HOURS=48',
    'CONTROL_PITR_REPORT_RETENTION_DAYS=180',
    'CONTROL_PITR_MAX_BACKUP_AGE_HOURS=24',
    'OTTO_CONTROL_BACKUP_KEY_FILE=./secrets/backup_encryption_key',
    'POSTGRES_DB=otto_control',
    'POSTGRES_USER=otto_control',
    'ETCD_IMAGE=quay.io/coreos/etcd:v3.5.21',
    'PROMETHEUS_IMAGE=prom/prometheus:v3.13.0-distroless',
    'PROMETHEUS_RETENTION=30d',
    '',
  ].join('\n');
  writeFileSync(targets[0], environment, {
    encoding: 'utf8',
    flag: 'wx',
    mode: 0o600,
  });

  process.stdout.write(
    `Production secrets created under ${secretDirectory}. Back them up securely before deployment.\n`,
  );
}

try {
  main();
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}

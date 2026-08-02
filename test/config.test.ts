import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { loadControlConfig } from '../src/config.js';

describe('control configuration', () => {
  it('uses a loopback-only development default', () => {
    expect(loadControlConfig({})).toMatchObject({
      environment: 'development',
      host: '127.0.0.1',
      port: 7788,
      trustProxy: false,
      backupReportDirectory: null,
      backupStatusMaximumAgeHours: 48,
      alertChannelsFile: null,
      alertWebhookUrl: null,
      alertWebhookSecretFile: null,
      alertPollIntervalMs: 60_000,
      alertWebhookTimeoutMs: 10_000,
      alertWebhookMaxAttempts: 8,
      alertRetentionDays: 365,
      auditAnchorUrl: null,
      auditAnchorTokenFile: null,
      auditAnchorIntervalMs: 900_000,
      auditAnchorPollIntervalMs: 60_000,
      auditAnchorTimeoutMs: 10_000,
      auditAnchorMaxAttempts: 8,
      auditWitnessSourcesFile: null,
      metricsToken: null,
      slowRequestThresholdMs: 1_000,
      capacitySampleIntervalMs: 60_000,
      sloAvailabilityTarget: 0.999,
      sloLatencyTargetMs: 500,
      artifactStorage: null,
      artifactStorageRequired: false,
      artifactAttestationKeysFile: null,
    });
  });

  it('rejects invalid ports and ambiguous booleans', () => {
    expect(() => loadControlConfig({ CONTROL_PORT: '70000' })).toThrow(
      'CONTROL_PORT must be between 1 and 65535',
    );
    expect(() => loadControlConfig({ CONTROL_TRUST_PROXY: 'yes' })).toThrow(
      'CONTROL_TRUST_PROXY must be true or false',
    );
    expect(() => loadControlConfig({ CONTROL_ADMIN_TOKEN: 'short' })).toThrow(
      'CONTROL_ADMIN_TOKEN must contain at least 32 bytes',
    );
    expect(() => loadControlConfig({ CONTROL_TELEMETRY_RETENTION_DAYS: '0' })).toThrow(
      'CONTROL_TELEMETRY_RETENTION_DAYS must be between 1 and 3650',
    );
    expect(() => loadControlConfig({ CONTROL_UPDATE_POLICY_DURATION_MS: '1000' })).toThrow(
      'CONTROL_UPDATE_POLICY_DURATION_MS must be between 60000 and 3600000',
    );
    expect(() => loadControlConfig({ CONTROL_BACKUP_STATUS_MAX_AGE_HOURS: '0' })).toThrow(
      'CONTROL_BACKUP_STATUS_MAX_AGE_HOURS must be between 1 and 720',
    );
    expect(() => loadControlConfig({ CONTROL_BACKUP_STATUS_MAX_AGE_HOURS: '721' })).toThrow(
      'CONTROL_BACKUP_STATUS_MAX_AGE_HOURS must be between 1 and 720',
    );
    expect(() => loadControlConfig({ CONTROL_ALERT_WEBHOOK_URL: 'http://alerts.test' })).toThrow(
      'CONTROL_ALERT_WEBHOOK_URL must use HTTPS',
    );
    expect(() => loadControlConfig({
      CONTROL_ALERT_WEBHOOK_URL: 'https://alerts.example.test/hooks/otto',
    })).toThrow('CONTROL_ALERT_WEBHOOK_URL and CONTROL_ALERT_WEBHOOK_SECRET_FILE');
    expect(() => loadControlConfig({
      CONTROL_ALERT_WEBHOOK_SECRET_FILE: 'secret',
    })).toThrow('CONTROL_ALERT_WEBHOOK_URL and CONTROL_ALERT_WEBHOOK_SECRET_FILE');
    expect(() => loadControlConfig({
      CONTROL_ALERT_CHANNELS_FILE: 'channels.json',
      CONTROL_ALERT_WEBHOOK_URL: 'https://alerts.example.test/hooks/otto',
      CONTROL_ALERT_WEBHOOK_SECRET_FILE: 'secret',
    })).toThrow('CONTROL_ALERT_CHANNELS_FILE cannot be combined');
    expect(() => loadControlConfig({ CONTROL_ALERT_WEBHOOK_MAX_ATTEMPTS: '21' })).toThrow(
      'CONTROL_ALERT_WEBHOOK_MAX_ATTEMPTS must be between 1 and 20',
    );
    expect(() => loadControlConfig({ CONTROL_ALERT_RETENTION_DAYS: '29' })).toThrow(
      'CONTROL_ALERT_RETENTION_DAYS must be between 30 and 3650',
    );
    expect(() => loadControlConfig({ CONTROL_AUDIT_ANCHOR_URL: 'http://audit.test' })).toThrow(
      'CONTROL_AUDIT_ANCHOR_URL must use HTTPS',
    );
    expect(() => loadControlConfig({
      CONTROL_AUDIT_ANCHOR_URL: 'https://audit.example.test/anchors',
    })).toThrow('CONTROL_AUDIT_ANCHOR_URL and CONTROL_AUDIT_ANCHOR_TOKEN_FILE');
    expect(() => loadControlConfig({
      CONTROL_AUDIT_ANCHOR_TOKEN_FILE: 'token',
    })).toThrow('CONTROL_AUDIT_ANCHOR_URL and CONTROL_AUDIT_ANCHOR_TOKEN_FILE');
    expect(() => loadControlConfig({ CONTROL_AUDIT_ANCHOR_MAX_ATTEMPTS: '21' })).toThrow(
      'CONTROL_AUDIT_ANCHOR_MAX_ATTEMPTS must be between 1 and 20',
    );
    expect(() => loadControlConfig({ CONTROL_SLOW_REQUEST_THRESHOLD_MS: '99' })).toThrow(
      'CONTROL_SLOW_REQUEST_THRESHOLD_MS must be between 100 and 30000',
    );
    expect(() => loadControlConfig({ CONTROL_SLO_AVAILABILITY_TARGET: '0.5' })).toThrow(
      'CONTROL_SLO_AVAILABILITY_TARGET must be between 0.9 and 0.99999',
    );
  });

  it('requires an HTTPS public URL in production', () => {
    expect(() => loadControlConfig({
      NODE_ENV: 'production',
      CONTROL_PUBLIC_BASE_URL: 'http://control.example.test',
      CONTROL_METRICS_TOKEN: 'm'.repeat(48),
    })).toThrow('CONTROL_PUBLIC_BASE_URL must use HTTPS in production');

    expect(loadControlConfig({
      NODE_ENV: 'production',
      CONTROL_PUBLIC_BASE_URL: 'https://control.example.test/',
      CONTROL_METRICS_TOKEN: 'm'.repeat(48),
    }).publicBaseUrl).toBe('https://control.example.test');
  });

  it('loads managed S3 artifact storage only from file-backed credentials', () => {
    const directory = mkdtempSync(join(tmpdir(), 'otto-artifact-storage-config-'));
    try {
      const accessKeyFile = join(directory, 'access-key');
      const secretKeyFile = join(directory, 'secret-key');
      writeFileSync(accessKeyFile, 'fixture-access-key');
      writeFileSync(secretKeyFile, 'fixture-secret-key');
      expect(() => loadControlConfig({
        CONTROL_ARTIFACT_S3_ENDPOINT: 'http://127.0.0.1:9000',
        CONTROL_ARTIFACT_S3_BUCKET: 'otto-release-fixtures',
        CONTROL_ARTIFACT_S3_ACCESS_KEY_ID_FILE: accessKeyFile,
        CONTROL_ARTIFACT_S3_SECRET_ACCESS_KEY_FILE: secretKeyFile,
      })).toThrow('CONTROL_ARTIFACT_ATTESTATION_KEYS_FILE is required');
      const config = loadControlConfig({
        CONTROL_ARTIFACT_STORAGE_REQUIRED: 'true',
        CONTROL_ARTIFACT_S3_ENDPOINT: 'http://127.0.0.1:9000',
        CONTROL_ARTIFACT_S3_BUCKET: 'otto-release-fixtures',
        CONTROL_ARTIFACT_S3_ACCESS_KEY_ID_FILE: accessKeyFile,
        CONTROL_ARTIFACT_S3_SECRET_ACCESS_KEY_FILE: secretKeyFile,
        CONTROL_ARTIFACT_ATTESTATION_KEYS_FILE: join(directory, 'trusted-keys.json'),
      });

      expect(config.artifactStorageRequired).toBe(true);
      expect(config.artifactStorage).toMatchObject({
        endpoint: 'http://127.0.0.1:9000',
        bucket: 'otto-release-fixtures',
        accessKeyId: 'fixture-access-key',
        secretAccessKey: 'fixture-secret-key',
        objectLockRequired: false,
        uploadTtlSeconds: 900,
        downloadTtlSeconds: 300,
      });
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('fails closed when required artifact storage is incomplete or insecure', () => {
    expect(() => loadControlConfig({
      CONTROL_ARTIFACT_STORAGE_REQUIRED: 'true',
    })).toThrow('CONTROL_ARTIFACT_S3_ENDPOINT is missing');

    expect(() => loadControlConfig({
      NODE_ENV: 'production',
      CONTROL_METRICS_TOKEN: 'm'.repeat(48),
      CONTROL_ARTIFACT_S3_ENDPOINT: 'http://storage.example.test',
      CONTROL_ARTIFACT_S3_BUCKET: 'otto-releases',
    })).toThrow('CONTROL_ARTIFACT_S3_ENDPOINT must be a credential-free HTTPS origin');
  });

  it('fails closed without a metrics credential in production', () => {
    expect(() => loadControlConfig({ NODE_ENV: 'production' })).toThrow(
      'CONTROL_METRICS_TOKEN or CONTROL_METRICS_TOKEN_FILE is required in production',
    );
  });

  it('loads production secrets and database credentials from mounted files', () => {
    const directory = mkdtempSync(join(tmpdir(), 'otto-control-config-'));
    try {
      const adminTokenFile = join(directory, 'admin-token');
      const tokenSecretFile = join(directory, 'token-secret');
      const databasePasswordFile = join(directory, 'database-password');
      const metricsTokenFile = join(directory, 'metrics-token');
      writeFileSync(adminTokenFile, 'a'.repeat(48));
      writeFileSync(tokenSecretFile, 'b'.repeat(48));
      writeFileSync(databasePasswordFile, 'p'.repeat(48));
      writeFileSync(metricsTokenFile, 'm'.repeat(48));

      const config = loadControlConfig({
        CONTROL_ADMIN_TOKEN_FILE: adminTokenFile,
        CONTROL_TOKEN_SECRET_FILE: tokenSecretFile,
        CONTROL_DATABASE_HOST: 'postgres',
        CONTROL_DATABASE_PORT: '5433',
        CONTROL_DATABASE_NAME: 'otto_control',
        CONTROL_DATABASE_USER: 'otto_control',
        CONTROL_DATABASE_PASSWORD_FILE: databasePasswordFile,
        CONTROL_METRICS_TOKEN_FILE: metricsTokenFile,
      });

      expect(config.adminToken).toBe('a'.repeat(48));
      expect(config.tokenSecret).toBe('b'.repeat(48));
      expect(config.metricsToken).toBe('m'.repeat(48));
      expect(config.databaseUrl).toBe(
        `postgresql://otto_control:${'p'.repeat(48)}@postgres:5433/otto_control`,
      );
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('rejects ambiguous direct and file-backed secrets', () => {
    expect(() => loadControlConfig({
      CONTROL_ADMIN_TOKEN: 'a'.repeat(48),
      CONTROL_ADMIN_TOKEN_FILE: 'admin-token',
    })).toThrow('CONTROL_ADMIN_TOKEN and CONTROL_ADMIN_TOKEN_FILE cannot both be set');
    expect(() => loadControlConfig({
      CONTROL_DATABASE_URL: 'postgresql://otto:secret@localhost/otto',
      CONTROL_DATABASE_HOST: 'postgres',
    })).toThrow('CONTROL_DATABASE_URL cannot be combined with database component settings');
    expect(() => loadControlConfig({
      CONTROL_SIGNER_PRIVATE_KEY_FILE: 'current.pem',
      CONTROL_SIGNER_KEYRING_FILE: 'keyring.json',
    })).toThrow(
      'CONTROL_SIGNER_PRIVATE_KEY_FILE and CONTROL_SIGNER_KEYRING_FILE cannot both be set',
    );
  });
});

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
      alertWebhookUrl: null,
      alertWebhookSecretFile: null,
      alertPollIntervalMs: 60_000,
      alertWebhookTimeoutMs: 10_000,
      alertWebhookMaxAttempts: 8,
      alertRetentionDays: 365,
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
    })).toThrow('CONTROL_ALERT_WEBHOOK_SECRET_FILE is required');
    expect(() => loadControlConfig({ CONTROL_ALERT_WEBHOOK_MAX_ATTEMPTS: '21' })).toThrow(
      'CONTROL_ALERT_WEBHOOK_MAX_ATTEMPTS must be between 1 and 20',
    );
    expect(() => loadControlConfig({ CONTROL_ALERT_RETENTION_DAYS: '29' })).toThrow(
      'CONTROL_ALERT_RETENTION_DAYS must be between 30 and 3650',
    );
  });

  it('requires an HTTPS public URL in production', () => {
    expect(() => loadControlConfig({
      NODE_ENV: 'production',
      CONTROL_PUBLIC_BASE_URL: 'http://control.example.test',
    })).toThrow('CONTROL_PUBLIC_BASE_URL must use HTTPS in production');

    expect(loadControlConfig({
      NODE_ENV: 'production',
      CONTROL_PUBLIC_BASE_URL: 'https://control.example.test/',
    }).publicBaseUrl).toBe('https://control.example.test');
  });

  it('loads production secrets and database credentials from mounted files', () => {
    const directory = mkdtempSync(join(tmpdir(), 'otto-control-config-'));
    try {
      const adminTokenFile = join(directory, 'admin-token');
      const tokenSecretFile = join(directory, 'token-secret');
      const databasePasswordFile = join(directory, 'database-password');
      writeFileSync(adminTokenFile, 'a'.repeat(48));
      writeFileSync(tokenSecretFile, 'b'.repeat(48));
      writeFileSync(databasePasswordFile, 'p'.repeat(48));

      const config = loadControlConfig({
        CONTROL_ADMIN_TOKEN_FILE: adminTokenFile,
        CONTROL_TOKEN_SECRET_FILE: tokenSecretFile,
        CONTROL_DATABASE_HOST: 'postgres',
        CONTROL_DATABASE_PORT: '5433',
        CONTROL_DATABASE_NAME: 'otto_control',
        CONTROL_DATABASE_USER: 'otto_control',
        CONTROL_DATABASE_PASSWORD_FILE: databasePasswordFile,
      });

      expect(config.adminToken).toBe('a'.repeat(48));
      expect(config.tokenSecret).toBe('b'.repeat(48));
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

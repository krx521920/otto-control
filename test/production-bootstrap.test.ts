import { X509Certificate } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

describe('production bootstrap', () => {
  it('creates file-backed secrets without writing them into the environment file', () => {
    const output = mkdtempSync(join(tmpdir(), 'otto-control-bootstrap-'));
    try {
      const result = spawnSync(process.execPath, [
        'scripts/bootstrap-production.mjs',
        '--environment',
        'staging',
        '--public-url',
        'https://control.example.test',
        '--output',
        output,
      ], { cwd: process.cwd(), encoding: 'utf8' });
      expect(result.status, result.stderr).toBe(0);

      const environment = readFileSync(join(output, '.env.staging'), 'utf8');
      const adminToken = readFileSync(
        join(output, 'secrets-staging', 'control_admin_token'),
        'utf8',
      ).trim();
      const databasePassword = readFileSync(
        join(output, 'secrets-staging', 'postgres_password'),
        'utf8',
      ).trim();
      const superuserPassword = readFileSync(
        join(output, 'secrets-staging', 'postgres_superuser_password'),
        'utf8',
      ).trim();
      const replicationPassword = readFileSync(
        join(output, 'secrets-staging', 'postgres_replication_password'),
        'utf8',
      ).trim();
      const pgbackrestCipherPass = readFileSync(
        join(output, 'secrets-staging', 'pgbackrest_cipher_pass'),
        'utf8',
      ).trim();
      const backupKey = readFileSync(
        join(output, 'secrets-staging', 'backup_encryption_key'),
        'utf8',
      ).trim();
      const alertWebhookSecret = readFileSync(
        join(output, 'secrets-staging', 'alert_webhook_secret'),
        'utf8',
      ).trim();
      const auditAnchorToken = readFileSync(
        join(output, 'secrets-staging', 'audit_anchor_token'),
        'utf8',
      ).trim();
      const metricsToken = readFileSync(
        join(output, 'secrets-staging', 'control_metrics_token'),
        'utf8',
      ).trim();
      const signer = readFileSync(
        join(output, 'signing-staging', 'control_signer_private_key.pem'),
        'utf8',
      );
      const keyring = JSON.parse(readFileSync(
        join(output, 'signing-staging', 'control_signer_keyring.json'),
        'utf8',
      )) as { version: number; keys: Array<{ privateKeyFile: string }> };
      expect(environment).toContain('CONTROL_PUBLIC_BASE_URL=https://control.example.test');
      expect(environment).toContain('OTTO_CONTROL_DEPLOYMENT_ENVIRONMENT=staging');
      expect(environment).toContain('OTTO_CONTROL_STACK_NAME=otto-control-staging');
      expect(environment).toContain('CONTROL_DATABASE_SSL=true');
      expect(environment).toContain('FEDERATION_DATABASE_SSL=true');
      expect(environment).toContain('NODE_EXTRA_CA_CERTS=/run/secrets/postgres_tls_ca');
      expect(environment).toContain('CONTROL_DATABASE_HOST=postgres-router');
      expect(environment).toContain('ETCD_IMAGE=quay.io/coreos/etcd:v3.5.21');
      expect(environment).toContain('CONTROL_ADMIN_TOKEN_FILE=/run/secrets/control_admin_token');
      expect(environment).toContain(
        'CONTROL_SIGNER_KEYRING_FILE=/run/otto-runtime-secrets/control_signer_keyring.json',
      );
      expect(environment).toContain('CONTROL_BACKUP_OFFSITE_REQUIRED=false');
      expect(environment).toContain(
        'CONTROL_BACKUP_REPORT_DIR=/var/lib/otto-control/backup-reports',
      );
      expect(environment).toContain('CONTROL_BACKUP_STATUS_MAX_AGE_HOURS=48');
      expect(environment).toContain('CONTROL_ALERT_WEBHOOK_URL=');
      expect(environment).toContain('CONTROL_ALERT_WEBHOOK_SECRET_FILE=');
      expect(environment).toContain('CONTROL_AUDIT_ANCHOR_URL=');
      expect(environment).toContain('CONTROL_AUDIT_ANCHOR_TOKEN_FILE=');
      expect(environment).toContain('CONTROL_AUDIT_WITNESS_SOURCES_FILE=');
      expect(environment).toContain(
        'CONTROL_METRICS_TOKEN_FILE=/run/secrets/control_metrics_token',
      );
      expect(environment).toContain('CONTROL_SLO_AVAILABILITY_TARGET=0.999');
      expect(environment).toContain('CONTROL_OTLP_TRACE_ENDPOINT=');
      expect(environment).toContain('CONTROL_TRACE_SAMPLE_RATIO=0.1');
      expect(environment).toContain('PROMETHEUS_IMAGE=prom/prometheus:v3.13.0-distroless');
      expect(environment).toContain('CONTROL_BACKUP_S3_ADDRESSING_STYLE=path');
      expect(environment).toContain('CONTROL_PITR_REPORT_RETENTION_DAYS=180');
      expect(environment).toContain('CONTROL_PITR_MAX_BACKUP_AGE_HOURS=24');
      expect(environment).toContain('FEDERATION_MAX_CLAIM_BYTES=4194304');
      expect(environment).not.toMatch(/CONTROL_BACKUP_S3_SECRET_ACCESS_KEY=[^\n]+/u);
      expect(environment).not.toContain(adminToken);
      expect(environment).not.toContain(databasePassword);
      expect(environment).not.toContain(superuserPassword);
      expect(environment).not.toContain(replicationPassword);
      expect(environment).not.toContain(pgbackrestCipherPass);
      expect(environment).not.toContain(backupKey);
      expect(environment).not.toContain(alertWebhookSecret);
      expect(environment).not.toContain(auditAnchorToken);
      expect(environment).not.toContain(metricsToken);
      expect(signer).toContain('BEGIN PRIVATE KEY');
      expect(keyring).toEqual({
        version: 1,
        keys: [{ provider: 'local', privateKeyFile: 'control_signer_private_key.pem' }],
      });
      expect(existsSync(join(output, 'backups-staging', 'reports'))).toBe(true);
      const postgresCa = new X509Certificate(readFileSync(
        join(output, 'secrets-staging', 'postgres_tls_ca.pem'),
        'utf8',
      ));
      const postgresCertificate = new X509Certificate(readFileSync(
        join(output, 'secrets-staging', 'postgres_tls_cert.pem'),
        'utf8',
      ));
      expect(postgresCa.ca).toBe(true);
      expect(postgresCertificate.verify(postgresCa.publicKey)).toBe(true);
      expect(postgresCertificate.checkHost('postgres-router')).toBe('postgres-router');
      expect(postgresCertificate.checkHost('postgres-3')).toBe('postgres-3');
      expect(postgresCertificate.checkHost('localhost')).toBe('localhost');
      expect(postgresCertificate.checkIP('127.0.0.1')).toBe('127.0.0.1');
      expect(postgresCertificate.checkIP('::1')).toBe('::1');

      const repeated = spawnSync(process.execPath, [
        'scripts/bootstrap-production.mjs',
        '--environment',
        'staging',
        '--public-url',
        'https://control.example.test',
        '--output',
        output,
      ], { cwd: process.cwd(), encoding: 'utf8' });
      expect(repeated.status).toBe(1);
      expect(
        readFileSync(join(output, 'secrets-staging', 'control_admin_token'), 'utf8').trim(),
      ).toBe(adminToken);
    } finally {
      rmSync(output, { recursive: true, force: true });
    }
  });

  it('rejects placeholder production identity and missing legal metadata', () => {
    const result = spawnSync(process.execPath, [
      'scripts/bootstrap-production.mjs',
      '--environment',
      'production',
      '--public-url',
      'https://control.example.test',
    ], { cwd: process.cwd(), encoding: 'utf8' });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('reserved example/test domains');
  });

  it('rejects production bootstrap without a KMS signing identity', () => {
    const result = spawnSync(process.execPath, [
      'scripts/bootstrap-production.mjs',
      '--environment', 'production',
      '--public-url', 'https://control.otto.cn',
      '--federation-public-url', 'https://federation.otto.cn',
      '--acme-email', 'operations@otto.cn',
      '--privacy-controller', 'Otto Technology Co., Ltd.',
      '--privacy-contact', 'privacy@otto.cn',
      '--data-region', 'CN-BJ',
    ], { cwd: process.cwd(), encoding: 'utf8' });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('production requires --aws-kms-key-arns');
  });

  it('creates an explicit production identity with no development defaults', () => {
    const output = mkdtempSync(join(tmpdir(), 'otto-control-production-bootstrap-'));
    try {
      const result = spawnSync(process.execPath, [
        'scripts/bootstrap-production.mjs',
        '--environment',
        'production',
        '--public-url',
        'https://control.otto.cn',
        '--federation-public-url',
        'https://federation.otto.cn',
        '--acme-email',
        'operations@otto.cn',
        '--privacy-controller',
        'Otto Technology Co., Ltd.',
        '--privacy-contact',
        'privacy@otto.cn',
        '--data-region',
        'CN-BJ',
        '--allow-local-signing-for-test',
        '--output',
        output,
      ], { cwd: process.cwd(), encoding: 'utf8', env: { ...process.env, CI: 'true' } });
      expect(result.status, result.stderr).toBe(0);
      const environment = readFileSync(join(output, '.env.production'), 'utf8');
      expect(environment).toContain('ACME_EMAIL=operations@otto.cn');
      expect(environment).toContain('CONTROL_PRIVACY_CONTROLLER=Otto Technology Co., Ltd.');
      expect(environment).toContain('CONTROL_PRIVACY_REQUEST_SLA_DAYS=15');
      expect(environment).toContain('CONTROL_DATA_REGION=CN-BJ');
      expect(environment).not.toContain('staging operator');
    } finally {
      rmSync(output, { recursive: true, force: true });
    }
  });

  it('creates a KMS-only production identity without a local signing private key', () => {
    const output = mkdtempSync(join(tmpdir(), 'otto-control-production-kms-bootstrap-'));
    try {
      const keyArn = `arn:aws:kms:cn-north-1:111122223333:key/mrk-${'a'.repeat(32)}`;
      const result = spawnSync(process.execPath, [
        'scripts/bootstrap-production.mjs',
        '--environment', 'production',
        '--public-url', 'https://control.otto.cn',
        '--federation-public-url', 'https://federation.otto.cn',
        '--acme-email', 'operations@otto.cn',
        '--privacy-controller', 'Otto Technology Co., Ltd.',
        '--privacy-contact', 'privacy@otto.cn',
        '--data-region', 'CN-BJ',
        '--aws-kms-key-arns', keyArn,
        '--output', output,
      ], { cwd: process.cwd(), encoding: 'utf8' });
      expect(result.status, result.stderr).toBe(0);
      const environment = readFileSync(join(output, '.env.production'), 'utf8');
      const keyring = JSON.parse(readFileSync(
        join(output, 'signing', 'control_signer_keyring.json'),
        'utf8',
      )) as { keys: Array<Record<string, unknown>> };
      expect(environment).toContain('OTTO_CONTROL_SIGNING_DIR=./signing');
      expect(keyring.keys).toEqual([expect.objectContaining({
        provider: 'kms', backend: 'aws_kms', keyArns: [keyArn],
      })]);
      expect(existsSync(join(output, 'signing', 'control_signer_private_key.pem'))).toBe(false);
    } finally {
      rmSync(output, { recursive: true, force: true });
    }
  });
});

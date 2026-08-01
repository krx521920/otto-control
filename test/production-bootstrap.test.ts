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
        '--public-url',
        'https://control.example.test',
        '--output',
        output,
      ], { cwd: process.cwd(), encoding: 'utf8' });
      expect(result.status, result.stderr).toBe(0);

      const environment = readFileSync(join(output, '.env.production'), 'utf8');
      const adminToken = readFileSync(join(output, 'secrets', 'control_admin_token'), 'utf8').trim();
      const databasePassword = readFileSync(
        join(output, 'secrets', 'postgres_password'),
        'utf8',
      ).trim();
      const backupKey = readFileSync(
        join(output, 'secrets', 'backup_encryption_key'),
        'utf8',
      ).trim();
      const alertWebhookSecret = readFileSync(
        join(output, 'secrets', 'alert_webhook_secret'),
        'utf8',
      ).trim();
      const signer = readFileSync(
        join(output, 'secrets', 'control_signer_private_key.pem'),
        'utf8',
      );
      const keyring = JSON.parse(readFileSync(
        join(output, 'secrets', 'control_signer_keyring.json'),
        'utf8',
      )) as { version: number; keys: Array<{ privateKeyFile: string }> };
      expect(environment).toContain('CONTROL_PUBLIC_BASE_URL=https://control.example.test');
      expect(environment).toContain('CONTROL_ADMIN_TOKEN_FILE=/run/secrets/control_admin_token');
      expect(environment).toContain(
        'CONTROL_SIGNER_KEYRING_FILE=/run/otto-secrets/control_signer_keyring.json',
      );
      expect(environment).toContain('CONTROL_BACKUP_OFFSITE_REQUIRED=false');
      expect(environment).toContain(
        'CONTROL_BACKUP_REPORT_DIR=/var/lib/otto-control/backup-reports',
      );
      expect(environment).toContain('CONTROL_BACKUP_STATUS_MAX_AGE_HOURS=48');
      expect(environment).toContain('CONTROL_ALERT_WEBHOOK_URL=');
      expect(environment).toContain(
        'CONTROL_ALERT_WEBHOOK_SECRET_FILE=/run/secrets/alert_webhook_secret',
      );
      expect(environment).toContain('CONTROL_BACKUP_S3_ADDRESSING_STYLE=path');
      expect(environment).not.toMatch(/CONTROL_BACKUP_S3_SECRET_ACCESS_KEY=[^\n]+/u);
      expect(environment).not.toContain(adminToken);
      expect(environment).not.toContain(databasePassword);
      expect(environment).not.toContain(backupKey);
      expect(environment).not.toContain(alertWebhookSecret);
      expect(signer).toContain('BEGIN PRIVATE KEY');
      expect(keyring).toEqual({
        version: 1,
        keys: [{ provider: 'local', privateKeyFile: 'control_signer_private_key.pem' }],
      });
      expect(existsSync(join(output, 'backups', 'reports'))).toBe(true);

      const repeated = spawnSync(process.execPath, [
        'scripts/bootstrap-production.mjs',
        '--public-url',
        'https://control.example.test',
        '--output',
        output,
      ], { cwd: process.cwd(), encoding: 'utf8' });
      expect(repeated.status).toBe(1);
      expect(
        readFileSync(join(output, 'secrets', 'control_admin_token'), 'utf8').trim(),
      ).toBe(adminToken);
    } finally {
      rmSync(output, { recursive: true, force: true });
    }
  });
});

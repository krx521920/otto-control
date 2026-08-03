import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

function bootstrapStaging(output: string) {
  return spawnSync(process.execPath, [
    'scripts/bootstrap-production.mjs',
    '--environment',
    'staging',
    '--public-url',
    'https://control.example.test',
    '--output',
    output,
  ], { cwd: process.cwd(), encoding: 'utf8' });
}

function preflight(
  environmentFile: string,
  environment = 'staging',
  extraArguments: string[] = [],
  environmentVariables: NodeJS.ProcessEnv = process.env,
) {
  return spawnSync(process.execPath, [
    'scripts/preflight-deployment.mjs',
    '--environment',
    environment,
    '--env-file',
    environmentFile,
    '--skip-docker',
    '--skip-dns',
    ...extraArguments,
  ], { cwd: process.cwd(), encoding: 'utf8', env: environmentVariables });
}

describe('deployment preflight', () => {
  it('accepts a complete isolated staging identity', () => {
    const output = mkdtempSync(join(tmpdir(), 'otto-control-preflight-'));
    try {
      const bootstrap = bootstrapStaging(output);
      expect(bootstrap.status, bootstrap.stderr).toBe(0);
      const result = preflight(join(output, '.env.staging'));
      expect(result.status, result.stderr).toBe(0);
      expect(result.stdout).toContain('Deployment preflight passed for staging');
    } finally {
      rmSync(output, { recursive: true, force: true });
    }
  });

  it('fails closed when database TLS is disabled', () => {
    const output = mkdtempSync(join(tmpdir(), 'otto-control-preflight-tls-'));
    try {
      const bootstrap = bootstrapStaging(output);
      expect(bootstrap.status, bootstrap.stderr).toBe(0);
      const environmentFile = join(output, '.env.staging');
      const environment = readFileSync(environmentFile, 'utf8')
        .replace('CONTROL_DATABASE_SSL=true', 'CONTROL_DATABASE_SSL=false');
      writeFileSync(environmentFile, environment, 'utf8');
      const result = preflight(environmentFile);
      expect(result.status).toBe(1);
      expect(result.stderr).toContain('CONTROL_DATABASE_SSL must be true');
    } finally {
      rmSync(output, { recursive: true, force: true });
    }
  });

  it('accepts a production KMS-only signing identity', () => {
    const output = mkdtempSync(join(tmpdir(), 'otto-control-preflight-kms-'));
    try {
      const keyArn = `arn:aws:kms:cn-north-1:111122223333:key/mrk-${'b'.repeat(32)}`;
      const bootstrap = spawnSync(process.execPath, [
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
      expect(bootstrap.status, bootstrap.stderr).toBe(0);
      const result = preflight(join(output, '.env.production'), 'production');
      expect(result.status, result.stderr).toBe(0);
      expect(result.stdout).toContain('Deployment preflight passed for production');
    } finally {
      rmSync(output, { recursive: true, force: true });
    }
  });

  it('rejects unexpected local files in a production KMS-only signing directory', () => {
    const output = mkdtempSync(join(tmpdir(), 'otto-control-preflight-kms-mixed-'));
    try {
      const keyArn = `arn:aws:kms:cn-north-1:111122223333:key/mrk-${'c'.repeat(32)}`;
      const bootstrap = spawnSync(process.execPath, [
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
      expect(bootstrap.status, bootstrap.stderr).toBe(0);
      writeFileSync(join(output, 'signing', 'control_signer_private_key.pem'), 'forbidden', 'utf8');
      const result = preflight(join(output, '.env.production'), 'production');
      expect(result.status).toBe(1);
      expect(result.stderr).toContain(
        'AWS KMS-only signing directory contains unexpected files: control_signer_private_key.pem',
      );
    } finally {
      rmSync(output, { recursive: true, force: true });
    }
  });

  it('rejects a local signing private key in production without the CI escape hatch', () => {
    const output = mkdtempSync(join(tmpdir(), 'otto-control-preflight-local-signing-'));
    try {
      const bootstrap = spawnSync(process.execPath, [
        'scripts/bootstrap-production.mjs',
        '--environment', 'production',
        '--public-url', 'https://control.otto.cn',
        '--federation-public-url', 'https://federation.otto.cn',
        '--acme-email', 'operations@otto.cn',
        '--privacy-controller', 'Otto Technology Co., Ltd.',
        '--privacy-contact', 'privacy@otto.cn',
        '--data-region', 'CN-BJ',
        '--allow-local-signing-for-test',
        '--output', output,
      ], {
        cwd: process.cwd(),
        encoding: 'utf8',
        env: { ...process.env, CI: 'true' },
      });
      expect(bootstrap.status, bootstrap.stderr).toBe(0);
      const result = preflight(join(output, '.env.production'), 'production');
      expect(result.status).toBe(1);
      expect(result.stderr).toContain(
        'production signing keyring must not contain a local signing private key',
      );
    } finally {
      rmSync(output, { recursive: true, force: true });
    }
  });
});

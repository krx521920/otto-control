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

function preflight(environmentFile: string) {
  return spawnSync(process.execPath, [
    'scripts/preflight-deployment.mjs',
    '--environment',
    'staging',
    '--env-file',
    environmentFile,
    '--skip-docker',
    '--skip-dns',
  ], { cwd: process.cwd(), encoding: 'utf8' });
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
});

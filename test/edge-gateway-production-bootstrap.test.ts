import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const repositoryRoot = new URL('..', import.meta.url);

function run(arguments_: string[]) {
  return spawnSync(process.execPath, arguments_, {
    cwd: repositoryRoot,
    encoding: 'utf8',
  });
}

describe('Edge Gateway production bootstrap', () => {
  it('creates a fail-closed file-backed Edge identity and passes deployment preflight', () => {
    const output = mkdtempSync(join(tmpdir(), 'otto-edge-production-bootstrap-'));
    const base = run([
      'scripts/bootstrap-production.mjs',
      '--environment', 'staging',
      '--public-url', 'https://control.staging.otto.test',
      '--output', output,
    ]);
    expect(base.status, base.stderr).toBe(0);
    const inputs = join(output, 'inputs');
    mkdirSync(inputs, { recursive: true });
    const inputFiles = {
      publicKeys: join(inputs, 'control-public-keys.json'),
      origins: join(inputs, 'upstream-origins.json'),
      identity: join(inputs, 'deployment-identity.json'),
      lease: join(inputs, 'lease-token'),
      provider: join(inputs, 'provider-api-key'),
    };
    writeFileSync(inputFiles.publicKeys, JSON.stringify({ control: 'public-key' }));
    writeFileSync(inputFiles.origins, JSON.stringify({
      version: 2,
      allowedUpstreams: [{
        origin: 'https://api.openai.com',
        authentications: [{ type: 'bearer', secretBinding: 'OPENAI_API_KEY' }],
      }],
    }));
    writeFileSync(inputFiles.identity, JSON.stringify({
      licenseId: 'license_1',
      deploymentId: 'deployment_1',
      organizationId: 'organization_1',
      machineFingerprint: 'a'.repeat(64),
    }));
    writeFileSync(inputFiles.lease, 'lease-token-that-is-longer-than-thirty-two-characters');
    writeFileSync(inputFiles.provider, 'provider-secret-from-secure-input');

    const bootstrap = run([
      'scripts/bootstrap-edge-production.mjs',
      '--env-file', join(output, '.env.staging'),
      '--control-public-keys-file', inputFiles.publicKeys,
      '--upstream-origins-file', inputFiles.origins,
      '--deployment-identity-file', inputFiles.identity,
      '--lease-token-file', inputFiles.lease,
      '--provider-secret', `OPENAI_API_KEY=${inputFiles.provider}`,
    ]);
    expect(bootstrap.status, bootstrap.stderr).toBe(0);
    const environment = readFileSync(join(output, '.env.staging'), 'utf8');
    expect(environment).toContain('OTTO_EDGE_ENABLED=true');
    expect(environment).not.toContain('lease-token-that-is-longer');
    expect(environment).not.toContain('provider-secret-from-secure-input');
    expect(environment).toContain(
      'OPENAI_API_KEY_FILE=/run/otto-edge-provider-secrets/OPENAI_API_KEY',
    );
    for (const path of [
      'edge-config-staging/control_public_keys.json',
      'edge-config-staging/upstream_origins.json',
      'edge-config-staging/deployment_identity.json',
      'secrets-staging/edge_lease_token',
      'secrets-staging/edge_rate_limit_key',
      'secrets-staging/edge_redis_password',
      'secrets-staging/edge_redis_tls_ca.pem',
      'secrets-staging/edge_redis_tls_cert.pem',
      'secrets-staging/edge_redis_tls_key.pem',
      'secrets-staging/edge_execution_receipt_private_key.pem',
      'secrets-staging/edge_operations_token',
      'edge-provider-secrets-staging/OPENAI_API_KEY',
    ]) {
      expect(existsSync(join(output, path)), path).toBe(true);
    }

    const preflight = run([
      'scripts/preflight-deployment.mjs',
      '--environment', 'staging',
      '--env-file', join(output, '.env.staging'),
      '--skip-dns',
      '--skip-docker',
    ]);
    expect(preflight.status, preflight.stderr).toBe(0);
    expect(preflight.stdout).toContain('Edge Gateway edge.control.staging.otto.test');

    if (process.env.OTTO_VERIFY_DOCKER_COMPOSE === 'true') {
      const compose = spawnSync('docker', [
        'compose',
        '-f', fileURLToPath(new URL('../compose.production.yaml', import.meta.url)),
        '--project-directory', output,
        '--env-file', join(output, '.env.staging'),
        '--profile', 'edge',
        'config', '--quiet',
      ], { cwd: repositoryRoot, encoding: 'utf8' });
      expect(compose.status, compose.stderr).toBe(0);
    }

    const repeated = run([
      'scripts/bootstrap-edge-production.mjs',
      '--env-file', join(output, '.env.staging'),
      '--control-public-keys-file', inputFiles.publicKeys,
      '--upstream-origins-file', inputFiles.origins,
      '--deployment-identity-file', inputFiles.identity,
      '--lease-token-file', inputFiles.lease,
      '--provider-secret', `OPENAI_API_KEY=${inputFiles.provider}`,
    ]);
    expect(repeated.status).not.toBe(0);
    expect(repeated.stderr).toMatch(/refusing to overwrite|OTTO_EDGE_ENABLED=false/u);
  });
});

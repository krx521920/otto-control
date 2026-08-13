import { createHash, generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

import { validateAliyunEsaRelease } from '../scripts/preflight-aliyun-esa-iac.mjs';

function repositoryFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
}

function sha(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function fixture() {
  const publicKey = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' });
  const worker = { raw: 'export default { fetch: () => new Response("ok") };\n' };
  const policy = {
    raw: JSON.stringify({ policy: { routes: [{ authentication: { secretBinding: 'OPENAI_API_KEY' } }] } }),
    value: { policy: { routes: [{ authentication: { secretBinding: 'OPENAI_API_KEY' } }] } },
  };
  const keyringValue = { control: publicKey };
  const keyring = { raw: JSON.stringify(keyringValue), value: keyringValue };
  const secretsValue = {
    schemaVersion: 1,
    environment: 'production',
    bindings: [{
      binding: 'OPENAI_API_KEY',
      provider: 'external-secret-provider',
      secretRef: 'external-secret://otto-edge/openai/versions/v000001',
      readback: 'prohibited',
      terraformState: 'excluded',
    }],
  };
  const canaryValue = {
    drill: 'esa_canary_rollout',
    result: 'promoted',
    startedPercent: 5,
    completedPercent: 100,
    billingReady: true,
    rollbackDrill: 'passed',
  };
  const canary = { raw: JSON.stringify(canaryValue), value: canaryValue };
  const evidenceValue = {
    schemaVersion: 1,
    evidenceId: `esa-release-${'a'.repeat(32)}`,
    workerSha256: sha(worker.raw),
    policySha256: sha(policy.raw),
    keyringSha256: sha(keyring.raw),
    secretBindingsSha256: sha(JSON.stringify(secretsValue)),
    canaryReportSha256: sha(canary.raw),
    secretBindingRevision: 'secret-revision-000001',
    productionDeploymentId: 'deployment-000001',
    approvedBy: ['operator-a', 'operator-b'],
    approvedAt: '2026-08-13T00:00:00.000Z',
  };
  return {
    worker, policy, keyring,
    secrets: { raw: JSON.stringify(secretsValue), value: secretsValue }, canary,
    evidence: { raw: JSON.stringify(evidenceValue), value: evidenceValue },
  };
}

describe('Aliyun ESA production IaC', () => {
  it('uses only confirmed ESA resources and keeps the public route fail-closed', () => {
    const main = repositoryFile('deploy/aliyun-esa/terraform/main.tf');
    for (const resource of [
      'alicloud_esa_site', 'alicloud_esa_kv_namespace', 'alicloud_esa_kv',
      'alicloud_esa_routine',
      'alicloud_esa_certificate', 'alicloud_esa_https_basic_configuration',
      'alicloud_esa_routine_route',
    ]) expect(main).toContain(`resource "${resource}"`);
    expect(main).toContain('route_enable = var.activate_public_route ? "on" : "off"');
    expect(main).not.toMatch(/^\s*(?:code|code_description|deploy_env|fallback)\s*=/mu);
    expect(main).not.toContain('alicloud_esa_routine_related_record');
    expect(main).toContain('tls10             = "off"');
    expect(main).toContain('ciphersuite_group = "strict"');
    expect(main).not.toMatch(/access_key|secret_key|PRIVATE KEY/iu);
    expect(repositoryFile('deploy/aliyun-esa/terraform/variables.tf'))
      .toContain('default     = false');
  });

  it('accepts content-addressed, versioned and two-person release evidence', () => {
    expect(validateAliyunEsaRelease(fixture())).toMatchObject({
      evidenceId: `esa-release-${'a'.repeat(32)}`,
    });
  });

  it('rejects plaintext Secret material and release digest drift', () => {
    const plaintext = fixture();
    (plaintext.secrets.value.bindings[0] as Record<string, unknown>).value = 'do-not-store-this';
    expect(() => validateAliyunEsaRelease(plaintext)).toThrow('secret material field is forbidden');

    const drift = fixture();
    drift.worker.raw = 'modified';
    expect(() => validateAliyunEsaRelease(drift)).toThrow('workerSha256 does not match');

    const fakeCanary = fixture();
    fakeCanary.canary.value.result = 'rolled_back';
    expect(() => validateAliyunEsaRelease(fakeCanary)).toThrow(
      'Canary report does not prove a healthy promotion',
    );
  });

  it('ships credential-free examples and no generated state', () => {
    const directory = mkdtempSync(join(tmpdir(), 'otto-esa-iac-'));
    writeFileSync(join(directory, 'marker'), 'ok');
    const variables = repositoryFile('deploy/aliyun-esa/terraform/terraform.tfvars.example');
    expect(variables).toContain('activate_public_route = false');
    expect(variables).not.toMatch(/LTAI[A-Za-z0-9]{12,}|BEGIN PRIVATE KEY/u);
    expect(repositoryFile('.gitignore')).toContain('*.tfstate');
  });
});

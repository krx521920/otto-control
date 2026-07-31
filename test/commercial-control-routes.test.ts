import { generateKeyPairSync } from 'node:crypto';

import type { FastifyInstance } from 'fastify';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { buildControlApp } from '../src/app.js';
import type { ControlConfig } from '../src/config.js';
import { LocalEd25519Signer } from '../src/crypto/signed-envelope.js';
import { CommercialControlService } from '../src/modules/commercial-control/service.js';
import { ControlTokenIssuer } from '../src/modules/commercial-control/token-issuer.js';
import { MemoryControlStore } from './helpers/memory-store.js';

const ADMIN_TOKEN = 'test-admin-token-that-is-at-least-32-bytes';
const config: Readonly<ControlConfig> = {
  environment: 'test',
  host: '127.0.0.1',
  port: 7788,
  logLevel: 'silent',
  trustProxy: false,
  publicBaseUrl: 'https://control.otto.test',
  version: '0.2.0-test',
  databaseUrl: null,
  databaseSsl: false,
  adminToken: ADMIN_TOKEN,
  tokenSecret: 'test-control-token-secret-that-is-long-enough',
  signerPrivateKeyFile: null,
  leaseDurationMs: 600_000,
};

describe('commercial control HTTP routes', () => {
  let app: FastifyInstance;

  beforeEach(async () => {
    const keys = generateKeyPairSync('ed25519');
    const service = new CommercialControlService({
      store: new MemoryControlStore(),
      signer: new LocalEd25519Signer(
        keys.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
      ),
      tokenIssuer: new ControlTokenIssuer(config.tokenSecret!),
      publicBaseUrl: config.publicBaseUrl!,
    });
    app = await buildControlApp({
      config,
      logger: false,
      commercialControl: { adminToken: ADMIN_TOKEN, service },
    });
  });

  afterEach(async () => app.close());

  it('protects administrator routes and reports enabled capabilities', async () => {
    const rejected = await app.inject({
      method: 'POST',
      url: '/v1/admin/customers',
      payload: { name: 'Acme' },
    });
    expect(rejected.statusCode).toBe(401);
    expect(rejected.json()).toMatchObject({ error: { code: 'UNAUTHORIZED' } });

    const platform = await app.inject({ method: 'GET', url: '/v1' });
    expect(platform.json().capabilities).toEqual([
      'health',
      'customer_deployment',
      'license_authority',
      'lease_revocation',
    ]);

    const signingKey = await app.inject({
      method: 'GET',
      url: '/v1/admin/signing-key',
      headers: { authorization: `Bearer ${ADMIN_TOKEN}` },
    });
    expect(signingKey.statusCode).toBe(200);
    expect(signingKey.json().signingKey).toMatchObject({ algorithm: 'ed25519' });
    expect(signingKey.json().signingKey.publicKeyPem).toContain('BEGIN PUBLIC KEY');
  });

  it('creates a deployment, issues a License, and serves Otto lease refreshes', async () => {
    const authorization = { authorization: `Bearer ${ADMIN_TOKEN}` };
    const customerResponse = await app.inject({
      method: 'POST',
      url: '/v1/admin/customers',
      headers: authorization,
      payload: { name: 'Acme Park' },
    });
    expect(customerResponse.statusCode).toBe(201);
    const customerId = customerResponse.json().customer.id as string;

    const deploymentResponse = await app.inject({
      method: 'POST',
      url: '/v1/admin/deployments',
      headers: authorization,
      payload: {
        deploymentId: 'dep_1234567890abcdef',
        customerId,
        organizationId: 'org_acme',
        machineFingerprint: 'b'.repeat(64),
        name: 'Acme server',
      },
    });
    expect(deploymentResponse.statusCode).toBe(201);

    const licenseResponse = await app.inject({
      method: 'POST',
      url: '/v1/admin/licenses',
      headers: authorization,
      payload: {
        deploymentId: 'dep_1234567890abcdef',
        plan: 'enterprise',
        expiresAt: '2030-01-01T00:00:00.000Z',
        seatLimit: 100,
        modules: ['enterprise_tree', 'direct_messages'],
      },
    });
    expect(licenseResponse.statusCode).toBe(201);
    const license = licenseResponse.json().license as Record<string, unknown>;

    const leaseResponse = await app.inject({
      method: 'POST',
      url: `/v1/licenses/${license.id as string}/lease`,
      headers: { authorization: `Bearer ${license.leaseToken as string}` },
      payload: {
        version: 1,
        licenseId: license.id,
        deploymentId: license.deploymentId,
        organizationId: license.organizationId,
        machineFingerprint: license.machineFingerprint,
        nonce: 'nonce_1234567890abcdef',
      },
    });
    expect(leaseResponse.statusCode).toBe(200);
    expect(leaseResponse.json()).toMatchObject({
      lease: {
        licenseId: license.id,
        deploymentId: license.deploymentId,
      },
    });
  });
});

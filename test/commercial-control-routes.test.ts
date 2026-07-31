import { generateKeyPairSync } from 'node:crypto';

import type { FastifyInstance } from 'fastify';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { buildControlApp } from '../src/app.js';
import type { ControlConfig } from '../src/config.js';
import { LocalEd25519Signer } from '../src/crypto/signed-envelope.js';
import { ManagedSigningKeyring } from '../src/crypto/signing-keyring.js';
import {
  signTelemetryRequest,
  telemetryIntegrityHash,
} from '../src/crypto/telemetry-request.js';
import { generateTotpCode } from '../src/modules/admin-identity/crypto.js';
import { AdminIdentityService } from '../src/modules/admin-identity/service.js';
import { CommercialControlService } from '../src/modules/commercial-control/service.js';
import { ControlTokenIssuer } from '../src/modules/commercial-control/token-issuer.js';
import { BillingService } from '../src/modules/billing/service.js';
import { UpdatePolicyService } from '../src/modules/update-policy/service.js';
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
  signerKeyringFile: null,
  leaseDurationMs: 600_000,
  telemetryRetentionDays: 90,
  updatePolicyDurationMs: 300_000,
};

describe('commercial control HTTP routes', () => {
  let app: FastifyInstance;
  let activeKeyId: string;
  let standbyKeyId: string;
  let adminSessionToken: string;
  let securitySessionToken: string;

  beforeEach(async () => {
    const keys = generateKeyPairSync('ed25519');
    const store = new MemoryControlStore();
    const signer = new LocalEd25519Signer(
      keys.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    );
    const standbyKeys = generateKeyPairSync('ed25519');
    const standbySigner = new LocalEd25519Signer(
      standbyKeys.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    );
    activeKeyId = signer.keyId;
    standbyKeyId = standbySigner.keyId;
    const keyring = await ManagedSigningKeyring.create({
      store,
      providers: [
        { signer, provider: 'local' },
        { signer: standbySigner, provider: 'local' },
      ],
    });
    const tokenIssuer = new ControlTokenIssuer(config.tokenSecret!);
    const identity = new AdminIdentityService({
      store,
      controlSecret: config.tokenSecret!,
    });
    const enrollment = await identity.bootstrap({
      username: 'route.admin',
      displayName: 'Route Admin',
      password: 'SecureControl2026',
    });
    const adminSession = await identity.confirmEnrollment({
      accountId: enrollment.account.id,
      enrollmentToken: enrollment.enrollmentToken,
      totpCode: generateTotpCode(enrollment.mfaSecret),
    });
    adminSessionToken = adminSession.token;
    const securityEnrollment = await identity.createAccount(adminSession.principal, {
      username: 'security.admin',
      displayName: 'Security Admin',
      password: 'SecureControl2026',
      roleIds: ['security_admin'],
    });
    securitySessionToken = (await identity.confirmEnrollment({
      accountId: securityEnrollment.account.id,
      enrollmentToken: securityEnrollment.enrollmentToken,
      totpCode: generateTotpCode(securityEnrollment.mfaSecret),
    })).token;
    const service = new CommercialControlService({
      store,
      signer: keyring,
      keyring,
      tokenIssuer,
      publicBaseUrl: config.publicBaseUrl!,
    });
    app = await buildControlApp({
      config,
      logger: false,
      commercialControl: {
        adminToken: ADMIN_TOKEN,
        identity,
        service,
        billing: new BillingService({ store, tokenIssuer }),
        updatePolicy: new UpdatePolicyService({ store, signer: keyring, tokenIssuer }),
      },
    });
  });

  async function approvedOperation(
    operation: string,
    targetType: string,
    targetId: string,
    request: unknown = {},
  ): Promise<string> {
    const requested = await app.inject({
      method: 'POST',
      url: '/v1/admin/approvals',
      headers: { authorization: `Bearer ${adminSessionToken}` },
      payload: { operation, targetType, targetId, request },
    });
    expect(requested.statusCode).toBe(201);
    const approvalId = requested.json().approval.id as string;
    const decided = await app.inject({
      method: 'POST',
      url: `/v1/admin/approvals/${approvalId}/decide`,
      headers: { authorization: `Bearer ${securitySessionToken}` },
      payload: { decision: 'approve', reason: 'test review' },
    });
    expect(decided.statusCode).toBe(200);
    return approvalId;
  }

  it('activates, retires, and revokes signing keys through audited admin routes', async () => {
    const headers = {
      authorization: `Bearer ${adminSessionToken}`,
      'x-otto-actor': 'security-operator',
    };
    const activationApproval = await approvedOperation(
      'signing_key.activate',
      'signing_key',
      standbyKeyId,
    );
    const activated = await app.inject({
      method: 'POST',
      url: `/v1/admin/signing-keys/${standbyKeyId}/activate`,
      headers: { ...headers, 'x-otto-approval-id': activationApproval },
    });
    expect(activated.statusCode).toBe(200);
    expect(activated.json().signingKeys).toEqual(expect.arrayContaining([
      expect.objectContaining({ keyId: activeKeyId, state: 'retired' }),
      expect.objectContaining({ keyId: standbyKeyId, state: 'active' }),
    ]));

    const revokeRequest = { reason: 'confirmed key exposure' };
    const revocationApproval = await approvedOperation(
      'signing_key.revoke',
      'signing_key',
      activeKeyId,
      revokeRequest,
    );
    const revoked = await app.inject({
      method: 'POST',
      url: `/v1/admin/signing-keys/${activeKeyId}/revoke`,
      headers: { ...headers, 'x-otto-approval-id': revocationApproval },
      payload: revokeRequest,
    });
    expect(revoked.statusCode).toBe(200);
    expect(revoked.json().signingKeys).toEqual(expect.arrayContaining([
      expect.objectContaining({ keyId: activeKeyId, state: 'revoked' }),
      expect.objectContaining({ keyId: standbyKeyId, state: 'active' }),
    ]));
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
      'signing_key_rotation',
      'lease_revocation',
      'telemetry_health',
      'update_policy',
      'admin_identity',
      'admin_rbac',
      'admin_mfa',
      'dual_control_approval',
      'credit_billing',
      'billing_statement_export',
    ]);

    const signingKey = await app.inject({
      method: 'GET',
      url: '/v1/admin/signing-key',
      headers: { authorization: `Bearer ${adminSessionToken}` },
    });
    expect(signingKey.statusCode).toBe(200);
    expect(signingKey.json().signingKey).toMatchObject({ algorithm: 'ed25519' });
    expect(signingKey.json().signingKey.publicKeyPem).toContain('BEGIN PUBLIC KEY');

    const keyring = await app.inject({ method: 'GET', url: '/v1/signing-keyring' });
    expect(keyring.statusCode).toBe(200);
    expect(keyring.json()).toMatchObject({
      keyring: { version: 1, activeKeyId: signingKey.json().signingKey.keyId },
      signingKeyId: signingKey.json().signingKey.keyId,
    });
  });

  it('runs approved top-up, central pricing, idempotent usage, and CSV export', async () => {
    const authorization = { authorization: `Bearer ${adminSessionToken}` };
    const customerResponse = await app.inject({
      method: 'POST',
      url: '/v1/admin/customers',
      headers: authorization,
      payload: { name: 'Billing Route Customer' },
    });
    expect(customerResponse.statusCode).toBe(201);
    const customerId = customerResponse.json().customer.id as string;
    const deploymentId = 'dep_billingroute0001';
    const fingerprint = 'c'.repeat(64);
    await app.inject({
      method: 'POST',
      url: '/v1/admin/deployments',
      headers: authorization,
      payload: {
        deploymentId,
        customerId,
        organizationId: 'org_billing_route',
        machineFingerprint: fingerprint,
        name: 'Billing route deployment',
      },
    });
    const licenseResponse = await app.inject({
      method: 'POST',
      url: '/v1/admin/licenses',
      headers: authorization,
      payload: {
        deploymentId,
        plan: 'enterprise',
        expiresAt: '2028-07-31T00:00:00.000Z',
        seatLimit: 20,
        modules: ['enterprise_tree'],
      },
    });
    expect(licenseResponse.statusCode).toBe(201);
    const license = licenseResponse.json().license as Record<string, unknown>;

    const rateRequest = { module: 'model_gateway', unitSize: 1_000, creditsPerUnit: 2 };
    const rateApproval = await approvedOperation(
      'billing.rate.set', 'customer', customerId, rateRequest,
    );
    const rateResponse = await app.inject({
      method: 'PUT',
      url: `/v1/admin/billing/customers/${customerId}/rates/model_gateway`,
      headers: { ...authorization, 'x-otto-approval-id': rateApproval },
      payload: { unitSize: 1_000, creditsPerUnit: 2 },
    });
    expect(rateResponse.statusCode).toBe(200);

    const topupRequest = {
      amount: 50,
      idempotencyKey: 'topup:route-1',
      referenceId: 'invoice-route-1',
    };
    const topupApproval = await approvedOperation(
      'billing.topup', 'customer', customerId, topupRequest,
    );
    const topupResponse = await app.inject({
      method: 'POST',
      url: `/v1/admin/billing/customers/${customerId}/topups`,
      headers: { ...authorization, 'x-otto-approval-id': topupApproval },
      payload: topupRequest,
    });
    expect(topupResponse.statusCode).toBe(201);

    const usageRequest = {
      version: 1,
      licenseId: license.id,
      deploymentId,
      organizationId: 'org_billing_route',
      machineFingerprint: fingerprint,
      module: 'model_gateway',
      units: 1_001,
      referenceId: 'usage_route_1',
      idempotencyKey: 'usage:route-1',
    };
    const usageResponse = await app.inject({
      method: 'POST',
      url: '/v1/billing/usage/consume',
      headers: { authorization: `Bearer ${license.leaseToken as string}` },
      payload: usageRequest,
    });
    expect(usageResponse.statusCode).toBe(201);
    expect(usageResponse.json()).toMatchObject({
      account: { availableBalance: 46 },
      transaction: { billedAmount: 4, module: 'model_gateway' },
      replayed: false,
    });
    const replay = await app.inject({
      method: 'POST',
      url: '/v1/billing/usage/consume',
      headers: { authorization: `Bearer ${license.leaseToken as string}` },
      payload: usageRequest,
    });
    expect(replay.statusCode).toBe(200);
    expect(replay.json().replayed).toBe(true);

    const exported = await app.inject({
      method: 'GET',
      url: `/v1/admin/billing/customers/${customerId}/export.csv`,
      headers: authorization,
    });
    expect(exported.statusCode).toBe(200);
    expect(exported.headers['content-type']).toContain('text/csv');
    expect(exported.body).toContain('usage:route-1');
  });

  it('creates a deployment, issues a License, and serves Otto lease refreshes', async () => {
    const authorization = { authorization: `Bearer ${adminSessionToken}` };
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
    expect(licenseResponse.json().signingKeyId).toMatch(/^[a-f0-9]{16}$/u);
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
        activeSeatCount: 80,
      },
    });
    expect(leaseResponse.statusCode).toBe(200);
    expect(leaseResponse.json()).toMatchObject({
      lease: {
        licenseId: license.id,
        deploymentId: license.deploymentId,
      },
    });

    const seatResponse = await app.inject({
      method: 'GET',
      url: `/v1/admin/licenses/${license.id as string}/seats`,
      headers: authorization,
    });
    expect(seatResponse.statusCode).toBe(200);
    expect(seatResponse.json().usage).toMatchObject({
      activeSeats: 80,
      seatLimit: 100,
      status: 'within_limit',
    });

    const renewalResponse = await app.inject({
      method: 'POST',
      url: `/v1/admin/licenses/${license.id as string}/renew`,
      headers: authorization,
      payload: { expiresAt: '2031-01-01T00:00:00.000Z' },
    });
    expect(renewalResponse.statusCode).toBe(200);
    expect(renewalResponse.json().license).toMatchObject({ revision: 2 });

    const resizeResponse = await app.inject({
      method: 'POST',
      url: `/v1/admin/licenses/${license.id as string}/resize`,
      headers: authorization,
      payload: { seatLimit: 50, seatEnforcement: 'monitor' },
    });
    expect(resizeResponse.statusCode).toBe(200);
    expect(resizeResponse.json().license).toMatchObject({ revision: 3, seatLimit: 50 });

    const lifecycleResponse = await app.inject({
      method: 'GET',
      url: `/v1/admin/licenses/${license.id as string}/lifecycle`,
      headers: authorization,
    });
    expect(lifecycleResponse.statusCode).toBe(200);
    expect(lifecycleResponse.json().events).toMatchObject([
      { revision: 3, changeType: 'downgraded' },
      { revision: 2, changeType: 'renewed' },
    ]);
  });

  it('ingests authenticated operational telemetry and exposes deployment health', async () => {
    const authorization = { authorization: `Bearer ${adminSessionToken}` };
    const customerResponse = await app.inject({
      method: 'POST',
      url: '/v1/admin/customers',
      headers: authorization,
      payload: { name: 'Telemetry customer' },
    });
    const customerId = customerResponse.json().customer.id as string;
    const deploymentId = 'dep_abcdef1234567890';
    const machineFingerprint = 'c'.repeat(64);
    await app.inject({
      method: 'POST',
      url: '/v1/admin/deployments',
      headers: authorization,
      payload: {
        deploymentId,
        customerId,
        organizationId: 'org_telemetry',
        machineFingerprint,
        name: 'Telemetry server',
      },
    });
    const licenseResponse = await app.inject({
      method: 'POST',
      url: '/v1/admin/licenses',
      headers: authorization,
      payload: {
        deploymentId,
        plan: 'enterprise',
        expiresAt: '2030-01-01T00:00:00.000Z',
        seatLimit: 100,
        modules: ['enterprise_tree'],
      },
    });
    const license = licenseResponse.json().license as Record<string, unknown>;
    const createdAtMs = Date.now();
    const eventPayload = {
      deploymentId,
      organizationId: null,
      eventType: 'runtime_health',
      createdAtMs,
      payload: {
        uptimeSec: 3600,
        memoryRssMb: 180,
        successRate: 0.98,
        licenseStatus: 'active',
      },
    };
    const event = {
      id: 'tel_1234567890abcdef1234567890abcdef',
      organizationId: null,
      eventType: 'runtime_health',
      createdAtMs,
      payload: eventPayload,
      integrity: telemetryIntegrityHash(eventPayload),
    };
    const body = {
      version: 1,
      deploymentId,
      machineFingerprint,
      licenseId: license.id,
      events: [event],
    };
    const timestamp = Date.now();
    const nonce = 'telemetry_nonce_1234567890';
    const telemetryHeaders = {
      authorization: `Bearer ${license.telemetryToken as string}`,
      'x-otto-timestamp': String(timestamp),
      'x-otto-nonce': nonce,
      'x-otto-signature': signTelemetryRequest({
        token: license.telemetryToken as string,
        timestamp,
        nonce,
        body,
      }),
    };
    const invalidSignature = await app.inject({
      method: 'POST',
      url: '/v1/telemetry/ingest',
      headers: {
        ...telemetryHeaders,
        'x-otto-signature': 'hmac-sha256:invalid',
      },
      payload: body,
    });
    expect(invalidSignature.statusCode).toBe(401);

    const accepted = await app.inject({
      method: 'POST',
      url: '/v1/telemetry/ingest',
      headers: telemetryHeaders,
      payload: body,
    });
    expect(accepted.statusCode).toBe(202);
    expect(accepted.json()).toEqual({ accepted: 1, duplicates: 0 });

    const replay = await app.inject({
      method: 'POST',
      url: '/v1/telemetry/ingest',
      headers: telemetryHeaders,
      payload: body,
    });
    expect(replay.statusCode).toBe(409);
    expect(replay.json()).toMatchObject({ error: { code: 'CONFLICT' } });

    const duplicateNonce = 'telemetry_nonce_abcdef123456';
    const duplicate = await app.inject({
      method: 'POST',
      url: '/v1/telemetry/ingest',
      headers: {
        ...telemetryHeaders,
        'x-otto-nonce': duplicateNonce,
        'x-otto-signature': signTelemetryRequest({
          token: license.telemetryToken as string,
          timestamp,
          nonce: duplicateNonce,
          body,
        }),
      },
      payload: body,
    });
    expect(duplicate.json()).toEqual({ accepted: 0, duplicates: 1 });

    const forbiddenPayload = {
      ...eventPayload,
      payload: { prompt: 'must never leave the customer server' },
    };
    const forbiddenBody = {
      ...body,
      events: [{
        ...event,
        id: 'tel_abcdef1234567890abcdef1234567890',
        payload: forbiddenPayload,
        integrity: telemetryIntegrityHash(forbiddenPayload),
      }],
    };
    const forbiddenNonce = 'telemetry_nonce_forbidden_01';
    const forbidden = await app.inject({
      method: 'POST',
      url: '/v1/telemetry/ingest',
      headers: {
        authorization: telemetryHeaders.authorization,
        'x-otto-timestamp': String(timestamp),
        'x-otto-nonce': forbiddenNonce,
        'x-otto-signature': signTelemetryRequest({
          token: license.telemetryToken as string,
          timestamp,
          nonce: forbiddenNonce,
          body: forbiddenBody,
        }),
      },
      payload: forbiddenBody,
    });
    expect(forbidden.statusCode).toBe(400);
    expect(forbidden.json()).toMatchObject({ error: { code: 'INVALID_REQUEST' } });

    const health = await app.inject({
      method: 'GET',
      url: `/v1/admin/deployments/${deploymentId}/health?hours=24`,
      headers: authorization,
    });
    expect(health.statusCode).toBe(200);
    expect(health.json().health).toMatchObject({
      deploymentId,
      totalEvents: 1,
      eventCounts: { runtime_health: 1 },
      latestRuntimeHealth: {
        payload: eventPayload,
      },
    });
  });

  it('publishes and resolves an authenticated distribution-specific update policy', async () => {
    const authorization = { authorization: `Bearer ${adminSessionToken}` };
    const customer = await app.inject({
      method: 'POST',
      url: '/v1/admin/customers',
      headers: authorization,
      payload: { name: 'Update customer' },
    });
    const customerId = customer.json().customer.id as string;
    const deploymentId = 'dep_update1234567890';
    const machineFingerprint = 'd'.repeat(64);
    await app.inject({
      method: 'POST',
      url: '/v1/admin/deployments',
      headers: authorization,
      payload: {
        deploymentId,
        customerId,
        organizationId: 'org_update',
        machineFingerprint,
        name: 'Update server',
      },
    });
    const distribution = await app.inject({
      method: 'POST',
      url: '/v1/admin/update-distributions',
      headers: authorization,
      payload: { id: 'otto-green', name: 'Otto Green' },
    });
    expect(distribution.statusCode).toBe(201);
    const assignment = await app.inject({
      method: 'PUT',
      url: `/v1/admin/deployments/${deploymentId}/update-distribution`,
      headers: authorization,
      payload: { distributionId: 'otto-green' },
    });
    expect(assignment.statusCode).toBe(200);
    const releaseResponse = await app.inject({
      method: 'POST',
      url: '/v1/admin/update-releases',
      headers: authorization,
      payload: {
        distributionId: 'otto-green',
        version: '1.9.11',
        sourceCommit: 'abcdef1234567',
        channel: 'stable',
        fullManifest: {
          url: 'https://updates.example.test/otto-green/latest.json',
          sha256: 'e'.repeat(64),
        },
      },
    });
    expect(releaseResponse.statusCode).toBe(201);
    const releaseId = releaseResponse.json().release.id as string;
    const activationApproval = await approvedOperation(
      'update_release.activate',
      'update_release',
      releaseId,
    );
    const activated = await app.inject({
      method: 'POST',
      url: `/v1/admin/update-releases/${releaseId}/activate`,
      headers: { ...authorization, 'x-otto-approval-id': activationApproval },
    });
    expect(activated.statusCode).toBe(200);
    const licenseResponse = await app.inject({
      method: 'POST',
      url: '/v1/admin/licenses',
      headers: authorization,
      payload: {
        deploymentId,
        plan: 'enterprise',
        expiresAt: '2030-01-01T00:00:00.000Z',
        seatLimit: 100,
        modules: ['enterprise_tree'],
      },
    });
    const license = licenseResponse.json().license as Record<string, unknown>;
    const body = {
      version: 1,
      licenseId: license.id,
      deploymentId,
      machineFingerprint,
      distributionId: 'otto-green',
      currentVersion: '1.9.10',
    };
    const timestamp = Date.now();
    const nonce = 'update_route_nonce_123456';
    const resolved = await app.inject({
      method: 'POST',
      url: '/v1/update-policy/resolve',
      headers: {
        authorization: `Bearer ${license.leaseToken as string}`,
        'x-otto-timestamp': String(timestamp),
        'x-otto-nonce': nonce,
        'x-otto-signature': signTelemetryRequest({
          token: license.leaseToken as string,
          timestamp,
          nonce,
          body,
        }),
      },
      payload: body,
    });
    expect(resolved.statusCode).toBe(200);
    expect(resolved.json()).toMatchObject({
      policy: {
        decision: 'update',
        distributionId: 'otto-green',
        release: { id: releaseId, version: '1.9.11' },
      },
    });
    expect(resolved.json().signature).toMatch(/^ed25519:/u);
  });
});

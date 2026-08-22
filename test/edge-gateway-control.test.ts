import { generateKeyPairSync } from 'node:crypto';

import Fastify, { type FastifyInstance } from 'fastify';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import type { AdminPrincipal } from '../src/contracts/admin-identity.js';
import type { EdgeGatewayLimitsV1, EdgeModelRouteV1 } from '../src/contracts/edge-gateway.js';
import { signTelemetryRequest } from '../src/crypto/telemetry-request.js';
import { LocalEd25519Signer } from '../src/crypto/signed-envelope.js';
import { ControlPlaneError } from '../src/errors.js';
import type { AdminIdentityService } from '../src/modules/admin-identity/service.js';
import { ControlTokenIssuer } from '../src/modules/commercial-control/token-issuer.js';
import {
  EdgeGatewayControlService,
  type EdgeGatewayRequestAuthentication,
} from '../src/modules/edge-gateway/service.js';
import { registerEdgeGatewayRoutes } from '../src/routes/edge-gateway.js';
import { MemoryControlStore } from './helpers/memory-store.js';

const NOW = Date.parse('2026-08-11T10:00:00.000Z');
const DEPLOYMENT_ID = 'dep_edge_control';
const LICENSE_ID = 'lic_edge_control';
const ORGANIZATION_ID = 'org_edge_control';
const CUSTOMER_ID = 'cus_edge_control';
const FINGERPRINT = 'a'.repeat(64);
const TOKEN_SECRET = 'edge-control-test-token-secret-is-long-enough';

const limits: EdgeGatewayLimitsV1 = {
  maxRequestBytes: 65_536,
  requestsPerMinute: 120,
  upstreamConnectTimeoutMs: 5_000,
  upstreamIdleTimeoutMs: 30_000,
  maxRouteAttempts: 2,
};

const route: EdgeModelRouteV1 = {
  id: 'route_edge_primary',
  endpoint: 'chat_completions',
  publicModel: 'otto-fast',
  upstreamModel: 'provider-fast-v2',
  upstreamUrl: 'https://provider.test/v1/chat/completions',
  priority: 10,
  authentication: { type: 'bearer', secretBinding: 'PROVIDER_API_KEY' },
};

describe('edge gateway Control plane', () => {
  let store: MemoryControlStore;
  let tokens: ControlTokenIssuer;
  let service: EdgeGatewayControlService;
  let leaseToken: string;
  let nonceSequence: number;
  const apps: FastifyInstance[] = [];

  beforeEach(async () => {
    store = new MemoryControlStore();
    tokens = new ControlTokenIssuer(TOKEN_SECRET);
    const { privateKey } = generateKeyPairSync('ed25519');
    service = new EdgeGatewayControlService({
      store,
      tokenIssuer: tokens,
      signer: new LocalEd25519Signer(
        privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
      ),
      now: () => NOW,
      id: () => 'control_fixture',
    });
    await store.createCustomer({ id: CUSTOMER_ID, name: 'Edge Customer' });
    await store.createDeployment({
      id: DEPLOYMENT_ID,
      customerId: CUSTOMER_ID,
      organizationId: ORGANIZATION_ID,
      machineFingerprint: FINGERPRINT,
      name: 'Edge production',
    });
    await store.createLicense({
      id: LICENSE_ID,
      revision: 1,
      deploymentId: DEPLOYMENT_ID,
      customerName: 'Edge Customer',
      organizationId: ORGANIZATION_ID,
      machineFingerprint: FINGERPRINT,
      plan: 'enterprise',
      issuedAtMs: NOW - 60_000,
      expiresAtMs: NOW + 86_400_000,
      seatLimit: 100,
      gracePeriodMs: 0,
      seatEnforcement: 'monitor',
      billingEnforcement: 'enforce',
      modules: [],
      offline: false,
      telemetryAllowed: false,
      leaseEndpoint: 'https://control.otto.test/v1/licenses/lease',
      tokenVersion: 1,
      signature: 'fixture-signature',
      signingKeyId: 'fixture-signing-key',
      revokedAtMs: null,
    });
    store.creditAccounts.set(`${CUSTOMER_ID}\0${ORGANIZATION_ID}`, {
      customerId: CUSTOMER_ID,
      organizationId: ORGANIZATION_ID,
      availableBalance: 100,
      frozenBalance: 0,
      totalToppedUp: 100,
      totalConsumed: 0,
      totalRefunded: 0,
      version: 1,
      createdAt: new Date(NOW),
      updatedAt: new Date(NOW),
    });
    leaseToken = tokens.issue({
      purpose: 'lease',
      licenseId: LICENSE_ID,
      deploymentId: DEPLOYMENT_ID,
      version: 1,
    });
    nonceSequence = 0;
  });

  afterEach(async () => {
    await Promise.all(apps.splice(0).map((app) => app.close()));
  });

  const policyBody = () => ({
    organizationId: ORGANIZATION_ID,
    policyVersion: 'edge-policy-v1',
    routes: [route],
    limits,
    status: 'active',
  });

  function signedAuthentication(
    body: Record<string, unknown>,
    overrides: Partial<EdgeGatewayRequestAuthentication> = {},
  ): EdgeGatewayRequestAuthentication {
    const timestamp = NOW;
    const nonce = `edge_control_nonce_${++nonceSequence}`;
    return {
      authorization: `Bearer ${leaseToken}`,
      timestamp: String(timestamp),
      nonce,
      signature: signTelemetryRequest({ token: leaseToken, timestamp, nonce, body }),
      ...overrides,
    };
  }

  function authenticationAt(
    body: Record<string, unknown>,
    timestamp: number,
    nonce: string,
    authorization = `Bearer ${leaseToken}`,
  ): EdgeGatewayRequestAuthentication {
    return {
      authorization,
      timestamp: String(timestamp),
      nonce,
      signature: signTelemetryRequest({ token: leaseToken, timestamp, nonce, body }),
    };
  }

  const binding = () => ({
    licenseId: LICENSE_ID,
    deploymentId: DEPLOYMENT_ID,
    organizationId: ORGANIZATION_ID,
    machineFingerprint: FINGERPRINT,
  });

  it('persists a normalized policy and audits only content-free metadata', async () => {
    const configured = await service.configurePolicy(
      DEPLOYMENT_ID,
      policyBody(),
      'admin_edge',
    );
    expect(configured).toMatchObject({
      deploymentId: DEPLOYMENT_ID,
      organizationId: ORGANIZATION_ID,
      policyVersion: 'edge-policy-v1',
      status: 'active',
      routes: [{ upstreamUrl: 'https://provider.test/v1/chat/completions' }],
    });
    await expect(service.policy(DEPLOYMENT_ID)).resolves.toEqual(configured);
    expect(store.audits).toEqual([
      expect.objectContaining({
        action: 'edge_gateway.policy.configured',
        detail: expect.objectContaining({
          routeCount: 1,
          publicModels: ['otto-fast'],
        }),
      }),
    ]);
    const auditJson = JSON.stringify(store.audits);
    expect(auditJson).not.toContain('PROVIDER_API_KEY');
    expect(auditJson).not.toContain('provider.test');
  });

  it('validates configuration shape, deployment state, defaults, and audit ordering', async () => {
    for (const invalidBody of [null, undefined, [], 'policy']) {
      await expect(service.configurePolicy(DEPLOYMENT_ID, invalidBody, 'admin_edge'))
        .rejects.toMatchObject({ statusCode: 400, code: 'INVALID_REQUEST' });
    }
    await expect(service.configurePolicy('bad deployment id', policyBody(), 'admin_edge'))
      .rejects.toMatchObject({ statusCode: 400, code: 'INVALID_REQUEST' });
    await expect(service.configurePolicy('dep_not_present', policyBody(), 'admin_edge'))
      .rejects.toMatchObject({ statusCode: 404, code: 'NOT_FOUND' });
    const deployment = store.deployments.get(DEPLOYMENT_ID)!;
    store.deployments.set(DEPLOYMENT_ID, { ...deployment, status: 'suspended' });
    await expect(service.configurePolicy(DEPLOYMENT_ID, policyBody(), 'admin_edge'))
      .rejects.toMatchObject({ statusCode: 409, code: 'CONFLICT' });
    store.deployments.set(DEPLOYMENT_ID, deployment);

    await expect(service.configurePolicy(DEPLOYMENT_ID, {
      ...policyBody(),
      unsupported: true,
    }, 'admin_edge')).rejects.toMatchObject({ statusCode: 400, code: 'INVALID_REQUEST' });
    await expect(service.configurePolicy(DEPLOYMENT_ID, {
      ...policyBody(),
      status: 'unknown',
    }, 'admin_edge')).rejects.toMatchObject({ statusCode: 400, code: 'INVALID_REQUEST' });
    await expect(service.configurePolicy(DEPLOYMENT_ID, {
      ...policyBody(),
      policyVersion: 'bad policy version',
    }, 'admin_edge')).rejects.toMatchObject({ statusCode: 400, code: 'INVALID_REQUEST' });

    const secondRoute: EdgeModelRouteV1 = {
      ...route,
      id: 'route_edge_second',
      publicModel: 'alpha-model',
      priority: 20,
    };
    const withoutStatus = policyBody() as Record<string, unknown>;
    delete withoutStatus.status;
    withoutStatus.routes = [route, secondRoute, { ...secondRoute, id: 'route_edge_third' }];
    const configured = await service.configurePolicy(
      DEPLOYMENT_ID,
      withoutStatus,
      'admin_edge',
    );
    expect(configured.status).toBe('active');
    expect(store.audits.at(-1)?.detail).toEqual(expect.objectContaining({
      routeCount: 3,
      publicModels: ['alpha-model', 'otto-fast'],
      status: 'active',
    }));
  });

  it('resolves signed policy and issues a short-lived model-bound token', async () => {
    await service.configurePolicy(DEPLOYMENT_ID, policyBody(), 'admin_edge');
    const policyRequest = binding();
    const policy = await service.resolvePolicy(
      policyRequest,
      signedAuthentication(policyRequest),
    );
    expect(policy.policy).toMatchObject({
      deploymentId: DEPLOYMENT_ID,
      policyVersion: 'edge-policy-v1',
    });

    const tokenRequest = {
      ...binding(),
      subjectId: 'account_edge_user',
      allowedModels: ['otto-fast'],
    };
    const result = await service.issueDeploymentAccessToken(
      tokenRequest,
      signedAuthentication(tokenRequest),
    );
    expect(result.envelope.token).toMatchObject({
      deploymentId: DEPLOYMENT_ID,
      organizationId: ORGANIZATION_ID,
      subjectId: 'account_edge_user',
      allowedModels: ['otto-fast'],
      policyVersion: 'edge-policy-v1',
    });
    expect(result.envelope.token.expiresAtMs - result.envelope.token.issuedAtMs).toBe(300_000);
    expect(result.encodedToken).toMatch(/^[a-zA-Z0-9_-]+$/u);
    expect(store.audits.at(-1)).toMatchObject({
      action: 'edge_gateway.access_token.issued',
      detail: expect.not.objectContaining({ prompt: expect.anything() }),
    });
  });

  it('rejects replay, HMAC tampering, cross-tenant models, and content fields', async () => {
    await service.configurePolicy(DEPLOYMENT_ID, policyBody(), 'admin_edge');
    const validBody = {
      ...binding(),
      subjectId: 'account_edge_user',
      allowedModels: ['otto-fast'],
    };
    const authentication = signedAuthentication(validBody);
    await service.issueDeploymentAccessToken(validBody, authentication);
    await expect(service.issueDeploymentAccessToken(validBody, authentication))
      .rejects.toMatchObject({ statusCode: 409, code: 'CONFLICT' });

    const tamperedBody = { ...validBody, subjectId: 'account_attacker' };
    await expect(service.issueDeploymentAccessToken(
      tamperedBody,
      signedAuthentication(validBody),
    )).rejects.toMatchObject({ statusCode: 401, code: 'UNAUTHORIZED' });

    const forbiddenModel = { ...validBody, allowedModels: ['unconfigured-model'] };
    await expect(service.issueDeploymentAccessToken(
      forbiddenModel,
      signedAuthentication(forbiddenModel),
    )).rejects.toMatchObject({ statusCode: 403, code: 'FORBIDDEN' });

    const contentBody = { ...validBody, messages: [{ role: 'user', content: 'must not enter Control' }] };
    await expect(service.issueDeploymentAccessToken(
      contentBody,
      signedAuthentication(contentBody),
    )).rejects.toMatchObject({ statusCode: 400, code: 'INVALID_REQUEST' });
    expect(JSON.stringify(store.audits)).not.toContain('must not enter Control');
  });

  it('fails closed for enforced billing without credits and for revoked licenses', async () => {
    await service.configurePolicy(DEPLOYMENT_ID, policyBody(), 'admin_edge');
    store.creditAccounts.delete(`${CUSTOMER_ID}\0${ORGANIZATION_ID}`);
    const request = binding();
    await expect(service.resolvePolicy(request, signedAuthentication(request)))
      .rejects.toMatchObject({ statusCode: 403, code: 'FORBIDDEN' });

    store.creditAccounts.set(`${CUSTOMER_ID}\0${ORGANIZATION_ID}`, {
      customerId: CUSTOMER_ID,
      organizationId: ORGANIZATION_ID,
      availableBalance: 1,
      frozenBalance: 0,
      totalToppedUp: 1,
      totalConsumed: 0,
      totalRefunded: 0,
      version: 1,
      createdAt: new Date(NOW),
      updatedAt: new Date(NOW),
    });
    await expect(service.resolvePolicy(request, signedAuthentication(request)))
      .resolves.toHaveProperty('policy.policyVersion', 'edge-policy-v1');

    store.licenses.set(LICENSE_ID, {
      ...store.licenses.get(LICENSE_ID)!,
      revokedAtMs: NOW,
    });
    await expect(service.resolvePolicy(request, signedAuthentication(request)))
      .rejects.toMatchObject({ statusCode: 401, code: 'UNAUTHORIZED' });
  });

  it('rejects model access when the License does not enforce billing', async () => {
    await service.configurePolicy(DEPLOYMENT_ID, policyBody(), 'admin_edge');
    store.licenses.set(LICENSE_ID, {
      ...store.licenses.get(LICENSE_ID)!,
      billingEnforcement: 'disabled',
    });
    const request = binding();
    const tokenRequest = {
      ...request,
      subjectId: 'account_edge_disabled_billing',
      allowedModels: ['otto-business'],
    };

    await expect(service.resolvePolicy(request, signedAuthentication(request)))
      .rejects.toMatchObject({ statusCode: 403, code: 'FORBIDDEN' });
    await expect(service.issueDeploymentAccessToken(
      tokenRequest,
      signedAuthentication(tokenRequest),
    )).rejects.toMatchObject({ statusCode: 403, code: 'FORBIDDEN' });
  });

  it('enforces timestamp, nonce, policy-state, tenant, and model-list boundaries', async () => {
    await expect(service.configurePolicy(DEPLOYMENT_ID, {
      ...policyBody(),
      organizationId: 'org_other_tenant',
    }, 'admin_edge')).rejects.toMatchObject({ statusCode: 403, code: 'FORBIDDEN' });
    await service.configurePolicy(DEPLOYMENT_ID, policyBody(), 'admin_edge');

    const request = binding();
    const oldTimestamp = NOW - 5 * 60 * 1000 - 1;
    const oldNonce = 'edge_control_old_timestamp';
    await expect(service.resolvePolicy(request, {
      authorization: `Bearer ${leaseToken}`,
      timestamp: String(oldTimestamp),
      nonce: oldNonce,
      signature: signTelemetryRequest({
        token: leaseToken,
        timestamp: oldTimestamp,
        nonce: oldNonce,
        body: request,
      }),
    })).rejects.toMatchObject({ statusCode: 401, code: 'UNAUTHORIZED' });

    const shortNonce = 'too-short';
    await expect(service.resolvePolicy(request, {
      authorization: `Bearer ${leaseToken}`,
      timestamp: String(NOW),
      nonce: shortNonce,
      signature: signTelemetryRequest({
        token: leaseToken,
        timestamp: NOW,
        nonce: shortNonce,
        body: request,
      }),
    })).rejects.toMatchObject({ statusCode: 400, code: 'INVALID_REQUEST' });

    const nearBoundaryTimestamp = NOW - 1_000;
    const nearBoundaryNonce = 'edge_control_near_boundary';
    await expect(service.resolvePolicy(
      request,
      authenticationAt(request, nearBoundaryTimestamp, nearBoundaryNonce),
    )).resolves.toHaveProperty('policy.policyVersion', 'edge-policy-v1');
    expect(store.edgeGatewayNonces.get(`${DEPLOYMENT_ID}\0${nearBoundaryNonce}`))
      .toBe(NOW + 10 * 60 * 1000);

    const exactBoundaryTimestamp = NOW - 5 * 60 * 1000;
    const exactBoundaryNonce = 'edge_control_exact_boundary';
    await expect(service.resolvePolicy(
      request,
      authenticationAt(request, exactBoundaryTimestamp, exactBoundaryNonce),
    )).resolves.toHaveProperty('policy.policyVersion', 'edge-policy-v1');

    for (const nonce of [
      'x'.repeat(129),
      `${'x'.repeat(16)}!`,
      `!${'x'.repeat(16)}`,
    ]) {
      await expect(service.resolvePolicy(
        request,
        authenticationAt(request, NOW, nonce),
      )).rejects.toMatchObject({ statusCode: 400, code: 'INVALID_REQUEST' });
    }

    await expect(service.resolvePolicy(request, {
      ...signedAuthentication(request),
      authorization: `Basic ${leaseToken}`,
    })).rejects.toMatchObject({ statusCode: 401, code: 'UNAUTHORIZED' });
    await expect(service.resolvePolicy(request, {
      ...signedAuthentication(request),
      authorization: `xBearer ${leaseToken}`,
    })).rejects.toMatchObject({ statusCode: 401, code: 'UNAUTHORIZED' });

    const duplicateModels = {
      ...binding(),
      subjectId: 'account_edge_user',
      allowedModels: ['otto-fast', 'otto-fast'],
    };
    await expect(service.issueDeploymentAccessToken(
      duplicateModels,
      signedAuthentication(duplicateModels),
    )).rejects.toMatchObject({ statusCode: 400, code: 'INVALID_REQUEST' });

    for (const allowedModels of [
      [],
      'otto-fast',
      Array.from({ length: 65 }, (_, index) => `model-${index}`),
      [7],
      ['   '],
      ['x'.repeat(161)],
    ]) {
      const malformedModels = {
        ...binding(),
        subjectId: 'account_edge_user',
        allowedModels,
      };
      await expect(service.issueDeploymentAccessToken(
        malformedModels,
        signedAuthentication(malformedModels),
      )).rejects.toMatchObject({ statusCode: 400, code: 'INVALID_REQUEST' });
    }

    const invalidSubject = {
      ...binding(),
      subjectId: 'bad subject',
      allowedModels: ['otto-fast'],
    };
    await expect(service.issueDeploymentAccessToken(
      invalidSubject,
      signedAuthentication(invalidSubject),
    )).rejects.toMatchObject({ statusCode: 400, code: 'INVALID_REQUEST' });

    const partlyAllowed = {
      ...binding(),
      subjectId: 'account_edge_user',
      allowedModels: ['otto-fast', 'not-configured'],
    };
    await expect(service.issueDeploymentAccessToken(
      partlyAllowed,
      signedAuthentication(partlyAllowed),
    )).resolves.toMatchObject({
      envelope: { token: { allowedModels: ['otto-fast'] } },
    });

    const persisted = store.edgeGatewayPolicies.get(DEPLOYMENT_ID)!;
    store.edgeGatewayPolicies.set(DEPLOYMENT_ID, { ...persisted, status: 'suspended' });
    await expect(service.resolvePolicy(request, signedAuthentication(request)))
      .rejects.toMatchObject({ statusCode: 403, code: 'FORBIDDEN' });
    store.edgeGatewayPolicies.set(DEPLOYMENT_ID, {
      ...persisted,
      organizationId: 'org_other_tenant',
    });
    await expect(service.resolvePolicy(request, signedAuthentication(request)))
      .rejects.toMatchObject({ statusCode: 403, code: 'FORBIDDEN' });
  });

  it('treats an existing zero-balance account as exhausted', async () => {
    await service.configurePolicy(DEPLOYMENT_ID, policyBody(), 'admin_edge');
    store.licenses.set(LICENSE_ID, {
      ...store.licenses.get(LICENSE_ID)!,
      billingEnforcement: 'enforce',
    });
    store.creditAccounts.set(`${CUSTOMER_ID}\0${ORGANIZATION_ID}`, {
      customerId: CUSTOMER_ID,
      organizationId: ORGANIZATION_ID,
      availableBalance: 0,
      frozenBalance: 10,
      totalToppedUp: 10,
      totalConsumed: 0,
      totalRefunded: 0,
      version: 1,
      createdAt: new Date(NOW),
      updatedAt: new Date(NOW),
    });
    const request = binding();
    await expect(service.resolvePolicy(request, signedAuthentication(request)))
      .rejects.toMatchObject({ statusCode: 403, code: 'FORBIDDEN' });
  });

  it('fails closed when Control dependencies or policies are absent', async () => {
    const { privateKey } = generateKeyPairSync('ed25519');
    const signer = new LocalEd25519Signer(
      privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    );
    const noStore = new EdgeGatewayControlService({ signer, tokenIssuer: tokens, now: () => NOW });
    await expect(noStore.configurePolicy(DEPLOYMENT_ID, policyBody(), 'admin_edge'))
      .rejects.toThrow('Control store is not configured');
    const noTokens = new EdgeGatewayControlService({ signer, store, now: () => NOW });
    await expect(noTokens.resolvePolicy(binding(), signedAuthentication(binding())))
      .rejects.toThrow('token issuer is not configured');
    await expect(service.policy(DEPLOYMENT_ID))
      .rejects.toMatchObject({ statusCode: 404, code: 'NOT_FOUND' });

    const defaultIssuer = new EdgeGatewayControlService({ signer, now: () => NOW });
    const first = await defaultIssuer.issuePolicy({
      deploymentId: DEPLOYMENT_ID,
      organizationId: ORGANIZATION_ID,
      policyVersion: 'edge-policy-v1',
      routes: [route],
      limits,
    });
    const second = await defaultIssuer.issuePolicy({
      deploymentId: DEPLOYMENT_ID,
      organizationId: ORGANIZATION_ID,
      policyVersion: 'edge-policy-v1',
      routes: [route],
      limits,
    });
    expect(first.policy.policyId).not.toBe(second.policy.policyId);
    expect(first.policy.expiresAtMs - first.policy.issuedAtMs).toBe(15 * 60 * 1000);
  });

  it('exposes admin configuration and authenticated issuance HTTP routes', async () => {
    const app = Fastify({ logger: false });
    app.setErrorHandler(async (error, _request, reply) => {
      const controlled = error instanceof ControlPlaneError ? error : null;
      await reply.code(controlled?.statusCode ?? 500).send({
        error: {
          code: controlled?.code ?? 'REQUEST_FAILED',
          message: error instanceof Error ? error.message : 'request failed',
        },
      });
    });
    const principal: AdminPrincipal = {
      accountId: 'admin_edge',
      sessionId: 'session_edge',
      username: 'edge.admin',
      displayName: 'Edge Admin',
      roles: ['super_admin'],
      permissions: ['edge_gateway.read', 'edge_gateway.manage'],
      mfaVerifiedAt: new Date(NOW),
    };
    const identity = {
      authenticate: async () => principal,
    } as unknown as AdminIdentityService;
    await registerEdgeGatewayRoutes(app, { service, identity });
    apps.push(app);

    const configured = await app.inject({
      method: 'PUT',
      url: `/v1/admin/deployments/${DEPLOYMENT_ID}/edge-gateway-policy`,
      headers: { authorization: 'Bearer admin-session' },
      payload: policyBody(),
    });
    expect(configured.statusCode).toBe(200);

    const tokenBody = {
      ...binding(),
      subjectId: 'account_http_user',
      allowedModels: ['otto-fast'],
    };
    const authentication = signedAuthentication(tokenBody);
    const issued = await app.inject({
      method: 'POST',
      url: '/v1/edge-gateway/access-tokens',
      headers: {
        authorization: authentication.authorization!,
        'x-otto-timestamp': authentication.timestamp!,
        'x-otto-nonce': authentication.nonce!,
        'x-otto-signature': authentication.signature!,
      },
      payload: tokenBody,
    });
    expect(issued.statusCode).toBe(201);
    expect(issued.json()).toMatchObject({
      envelope: { token: { subjectId: 'account_http_user' } },
    });
  });
});

import { generateKeyPairSync } from 'node:crypto';

import { describe, expect, it, vi } from 'vitest';

import type {
  EdgeGatewayLimitsV1,
  EdgeGatewayOutcomeV2,
  EdgeModelRouteV1,
} from '../src/contracts/edge-gateway.js';
import { LocalEd25519Signer } from '../src/crypto/signed-envelope.js';
import {
  EdgeBillingAdmissionError,
  type EdgeBillingCoordinator,
} from '../src/edge-gateway/billing-coordinator.js';
import {
  type EdgeConcurrencyLimiter,
  InMemoryEdgeConcurrencyLimiter,
} from '../src/edge-gateway/concurrency-limit.js';
import {
  type EdgeRouteCircuitBreaker,
  InMemoryEdgeRouteCircuitBreaker,
} from '../src/edge-gateway/circuit-breaker.js';
import {
  createOttoEdgeGateway,
  type EdgeGatewayOutcomeSink,
  type EdgeGatewayReadinessProbe,
  type EdgeGatewaySecretResolver,
} from '../src/edge-gateway/gateway.js';
import {
  type EdgeGatewayLifecycle,
  InMemoryEdgeGatewayLifecycle,
} from '../src/edge-gateway/lifecycle.js';
import {
  createEdgeSignatureVerifier,
  encodeEdgeAccessTokenEnvelope,
} from '../src/edge-gateway/protocol.js';
import {
  normalizeEdgeUpstreamOriginPolicy,
  StaticEdgeUpstreamOriginPolicy,
  type EdgeUpstreamOriginPolicy,
} from '../src/edge-gateway/upstream-origin-policy.js';
import {
  EdgeRateLimitUnavailableError,
  type EdgeRateLimiter,
  InMemoryEdgeRateLimiter,
} from '../src/edge-gateway/rate-limit.js';
import type { EdgeRequestLimits } from '../src/edge-gateway/request-limits.js';
import { EdgeGatewayControlService } from '../src/modules/edge-gateway/service.js';

const NOW = Date.parse('2026-08-11T08:00:00.000Z');
const DEPLOYMENT_ID = 'dep_edge_fixture';
const ORGANIZATION_ID = 'org_edge_fixture';
const POLICY_VERSION = 'edge-v1';

const limits: EdgeGatewayLimitsV1 = {
  maxRequestBytes: 4_096,
  requestsPerMinute: 10,
  upstreamConnectTimeoutMs: 5_000,
  upstreamIdleTimeoutMs: 30_000,
  maxRouteAttempts: 2,
};

const primaryRoute: EdgeModelRouteV1 = {
  id: 'route_primary',
  endpoint: 'chat_completions',
  publicModel: 'otto-fast',
  upstreamModel: 'provider-model-v3',
  upstreamUrl: 'https://provider-a.test/v1/chat/completions',
  priority: 10,
  authentication: { type: 'bearer', secretBinding: 'PROVIDER_A_API_KEY' },
};

async function fixture(overrides: {
  routes?: EdgeModelRouteV1[];
  limits?: EdgeGatewayLimitsV1;
  policyVersion?: string;
  tokenPolicyVersion?: string;
  allowedModels?: string[];
  policyDurationMs?: number;
  rateLimiter?: EdgeRateLimiter;
  fetch?: typeof fetch;
  secrets?: Readonly<Record<string, string>>;
  secretResolver?: EdgeGatewaySecretResolver;
  billingCoordinator?: EdgeBillingCoordinator;
  outcomeSink?: EdgeGatewayOutcomeSink;
  concurrencyLimiter?: EdgeConcurrencyLimiter;
  circuitBreaker?: EdgeRouteCircuitBreaker;
  lifecycle?: EdgeGatewayLifecycle;
  readinessProbe?: EdgeGatewayReadinessProbe;
  requestLimits?: EdgeRequestLimits;
  responseLimits?: { maximumBytes: number; maximumDurationMs: number };
  allowedUpstreamOrigins?: readonly string[];
  upstreamOriginPolicy?: EdgeUpstreamOriginPolicy;
  now?: () => number;
  requestId?: () => string;
} = {}) {
  const { privateKey } = generateKeyPairSync('ed25519');
  const signer = new LocalEd25519Signer(
    privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
  );
  let nextId = 0;
  const control = new EdgeGatewayControlService({
    signer,
    now: () => NOW,
    id: () => `fixture_${++nextId}`,
  });
  const routes = overrides.routes ?? [primaryRoute];
  const policy = await control.issuePolicy({
    policyVersion: overrides.policyVersion ?? POLICY_VERSION,
    deploymentId: DEPLOYMENT_ID,
    organizationId: ORGANIZATION_ID,
    routes,
    limits: overrides.limits ?? limits,
    durationMs: overrides.policyDurationMs,
  });
  const access = await control.issueAccessToken({
    deploymentId: DEPLOYMENT_ID,
    organizationId: ORGANIZATION_ID,
    subjectId: 'account_edge_user',
    policyVersion: overrides.tokenPolicyVersion ?? POLICY_VERSION,
    allowedModels: overrides.allowedModels ?? ['otto-fast'],
  });
  const outcomes: EdgeGatewayOutcomeV2[] = [];
  const secrets = overrides.secrets ?? { PROVIDER_A_API_KEY: 'provider-secret-value' };
  const upstreamOriginPolicy = overrides.upstreamOriginPolicy
    ?? new StaticEdgeUpstreamOriginPolicy(
      overrides.allowedUpstreamOrigins
        ?? [...new Set(routes.map((route) => new URL(route.upstreamUrl).origin))],
    );
  let requestSequence = 0;
  const nextRequestId = () => {
    requestSequence += 1;
    return requestSequence === 1
      ? 'edge_request_fixture'
      : `edge_request_fixture_${requestSequence}`;
  };
  const metered = routes.some((route) => route.metering !== undefined);
  const gateway = createOttoEdgeGateway({
    policySource: { load: async () => policy },
    verifier: createEdgeSignatureVerifier({ [signer.keyId]: signer.publicKeyPem }),
    secretResolver: overrides.secretResolver
      ?? { get: async (binding) => secrets[binding] ?? null },
    rateLimiter: overrides.rateLimiter ?? new InMemoryEdgeRateLimiter(),
    concurrencyLimiter: overrides.concurrencyLimiter,
    circuitBreaker: overrides.circuitBreaker,
    lifecycle: overrides.lifecycle,
    outcomeSink: overrides.outcomeSink
      ?? { record: async (outcome) => { outcomes.push(outcome); } },
    billingCoordinator: overrides.billingCoordinator,
    readinessProbe: overrides.readinessProbe,
    requestLimits: overrides.requestLimits,
    responseLimits: overrides.responseLimits,
    upstreamOriginPolicy,
    fetch: overrides.fetch ?? (vi.fn(async () => new Response('{}')) as typeof fetch),
    now: overrides.now ?? (() => NOW),
    requestId: overrides.requestId ?? nextRequestId,
  });
  const authorization = `Bearer ${encodeEdgeAccessTokenEnvelope(access)}`;
  const request = (body: unknown, init: RequestInit = {}) => new Request(
    'https://edge.otto.test/v1/chat/completions',
    {
      ...init,
      method: 'POST',
      headers: {
        authorization,
        'content-type': 'application/json',
        ...(metered ? { 'idempotency-key': nextRequestId() } : {}),
        ...Object.fromEntries(new Headers(init.headers)),
      },
      body: JSON.stringify(body),
    },
  );
  return {
    access,
    authorization,
    control,
    gateway,
    outcomes,
    policy,
    request,
    signer,
    upstreamOriginPolicy,
  };
}

function billingCoordinatorFixture() {
  const reserve = vi.fn<EdgeBillingCoordinator['reserve']>(async () => ({
    reservationId: 'hold_edge_request_fixture',
  }));
  const settle = vi.fn<EdgeBillingCoordinator['settle']>(async () => undefined);
  const release = vi.fn<EdgeBillingCoordinator['release']>(async () => undefined);
  const markUncertain = vi.fn<EdgeBillingCoordinator['markUncertain']>(
    async () => undefined,
  );
  return {
    coordinator: { reserve, settle, release, markUncertain } satisfies EdgeBillingCoordinator,
    markUncertain,
    release,
    reserve,
    settle,
  };
}

describe('otto edge gateway', () => {
  it('exposes a minimal health endpoint without loading policy or secrets', async () => {
    const requestId = vi.fn(() => { throw new Error('request id unavailable'); });
    const now = vi.fn(() => { throw new Error('clock unavailable'); });
    const values = await fixture({ requestId, now });
    const response = await values.gateway.fetch(new Request('https://edge.otto.test/healthz'));
    await expect(response.json()).resolves.toEqual({ status: 'ok', service: 'otto-edge-gateway' });
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(requestId).not.toHaveBeenCalled();
    expect(now).not.toHaveBeenCalled();
  });

  it('fails closed before secrets, concurrency, billing, or upstream for an unknown adapter', async () => {
    const fetchMock = vi.fn<typeof fetch>(async () => new Response('{}'));
    const secretGet = vi.fn(async () => 'provider-secret-value');
    const billing = billingCoordinatorFixture();
    const concurrencyLimiter = new InMemoryEdgeConcurrencyLimiter(1, 1);
    await expect(fixture({
      routes: [{
        ...primaryRoute,
        providerAdapter: 'unknown-provider',
        metering: { type: 'openai_tokens', reserveUnits: 100 },
      }],
      fetch: fetchMock,
      secretResolver: { get: secretGet },
      billingCoordinator: billing.coordinator,
      concurrencyLimiter,
    })).rejects.toMatchObject({
      status: 400,
      code: 'EDGE_INVALID_ENVELOPE',
      message: 'route provider adapter and endpoint are unsupported',
    });
    expect(secretGet).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
    expect(billing.reserve).not.toHaveBeenCalled();
    expect(concurrencyLimiter.snapshot().activeRequests).toBe(0);
  });

  it.each([
    () => 'request id with spaces',
    () => '请求编号',
    () => `a${'x'.repeat(128)}`,
    () => { throw new Error('private request id backend'); },
  ])('fails business admission closed for an invalid request id %#', async (requestId) => {
    const fetchMock = vi.fn<typeof fetch>(async () => new Response('{}'));
    const secretGet = vi.fn(async () => 'provider-secret-value');
    const values = await fixture({
      fetch: fetchMock,
      requestId,
      secretResolver: { get: secretGet },
    });

    const response = await values.gateway.fetch(values.request({
      model: 'otto-fast', messages: [],
    }));

    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toEqual({
      error: {
        code: 'EDGE_REQUEST_CONTEXT_UNAVAILABLE',
        message: 'gateway request context is unavailable',
      },
    });
    expect(fetchMock).not.toHaveBeenCalled();
    expect(secretGet).not.toHaveBeenCalled();
  });

  it.each([
    () => -1,
    () => 1.5,
    () => Number.NaN,
    () => { throw new Error('private clock backend'); },
  ])('fails business admission closed for an invalid clock %#', async (now) => {
    const fetchMock = vi.fn<typeof fetch>(async () => new Response('{}'));
    const secretGet = vi.fn(async () => 'provider-secret-value');
    const values = await fixture({
      fetch: fetchMock,
      now,
      secretResolver: { get: secretGet },
    });

    const response = await values.gateway.fetch(values.request({
      model: 'otto-fast', messages: [],
    }));

    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toMatchObject({
      error: { code: 'EDGE_REQUEST_CONTEXT_UNAVAILABLE' },
    });
    expect(fetchMock).not.toHaveBeenCalled();
    expect(secretGet).not.toHaveBeenCalled();
  });

  it('accepts zero as a valid request clock boundary before lifecycle admission', async () => {
    const lifecycle = new InMemoryEdgeGatewayLifecycle({ now: () => NOW });
    lifecycle.beginDrain();
    const values = await fixture({ lifecycle, now: () => 0 });

    const response = await values.gateway.fetch(values.request({
      model: 'otto-fast', messages: [],
    }));

    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toMatchObject({
      error: { code: 'EDGE_GATEWAY_DRAINING' },
    });
  });

  it.each([
    () => NOW - 1,
    () => -1,
    () => 1.5,
    () => { throw new Error('runtime clock unavailable'); },
  ])('contains an unsafe runtime clock after request admission %#', async (runtimeNow) => {
    let admitted = false;
    const concurrencyLimiter = new InMemoryEdgeConcurrencyLimiter(1, 1);
    const values = await fixture({
      concurrencyLimiter,
      now: () => {
        if (!admitted) {
          admitted = true;
          return NOW;
        }
        return runtimeNow();
      },
    });

    const response = await values.gateway.fetch(values.request({
      model: 'otto-fast', messages: [],
    }));

    expect(response.status).toBe(200);
    await expect(response.text()).resolves.toBe('{}');
    expect(concurrencyLimiter.snapshot().activeRequests).toBe(0);
    expect(values.outcomes).toEqual([
      expect.objectContaining({
        durationMs: 0,
        occurredAtMs: NOW,
        outcome: 'succeeded',
      }),
    ]);
  });

  it('contains a failed runtime clock while closing a failed route', async () => {
    let calls = 0;
    const concurrencyLimiter = new InMemoryEdgeConcurrencyLimiter(1, 1);
    const circuitBreaker = new InMemoryEdgeRouteCircuitBreaker({
      failureThreshold: 1,
      cooldownMs: 1_000,
      now: () => NOW,
    });
    const values = await fixture({
      circuitBreaker,
      concurrencyLimiter,
      fetch: vi.fn<typeof fetch>(async () => { throw new Error('provider unavailable'); }),
      now: () => {
        calls += 1;
        if (calls === 1) return NOW;
        throw new Error('runtime clock unavailable');
      },
    });

    const response = await values.gateway.fetch(values.request({
      model: 'otto-fast', messages: [],
    }));

    expect(response.status).toBe(409);
    await expect(response.json()).resolves.toMatchObject({
      error: { code: 'EDGE_PROVIDER_SWITCH_CONFIRMATION_REQUIRED' },
    });
    expect(concurrencyLimiter.snapshot().activeRequests).toBe(0);
    expect(circuitBreaker.snapshot().openRoutes).toBe(1);
    expect(values.outcomes).toEqual([
      expect.objectContaining({
        durationMs: 0,
        occurredAtMs: NOW,
        outcome: 'upstream_failed',
      }),
    ]);
  });

  it('isolates release, route-success, and waitUntil hook failures from a response stream', async () => {
    const release = vi.fn(() => { throw new Error('release backend unavailable'); });
    const succeeded = vi.fn(() => { throw new Error('route backend unavailable'); });
    const waitUntil = vi.fn(() => { throw new Error('runtime registration unavailable'); });
    const values = await fixture({
      concurrencyLimiter: {
        acquire: () => ({ release }),
        snapshot: () => ({
          activeRequests: 1,
          globalLimit: 1,
          trackedSubjects: 1,
          subjectsAtLimit: 1,
          perSubjectLimit: 1,
        }),
      },
      circuitBreaker: {
        acquire: () => ({
          succeeded,
          failed: () => undefined,
          cancelled: () => undefined,
        }),
        snapshot: () => ({
          trackedRoutes: 1,
          failingRoutes: 0,
          openRoutes: 0,
          probeReadyRoutes: 0,
          halfOpenRoutes: 1,
          failureThreshold: 1,
          cooldownMs: 1_000,
        }),
      },
    });

    const response = await values.gateway.fetch(
      values.request({ model: 'otto-fast', messages: [] }),
      { waitUntil },
    );

    expect(response.status).toBe(200);
    await expect(response.text()).resolves.toBe('{}');
    expect(release).toHaveBeenCalledOnce();
    expect(succeeded).toHaveBeenCalledOnce();
    expect(waitUntil).toHaveBeenCalledTimes(2);
    expect(values.outcomes).toEqual([
      expect.objectContaining({ outcome: 'succeeded' }),
    ]);
  });

  it('runs an isolated route-cancel hook when the downstream discards its stream', async () => {
    const cancelled = vi.fn(() => { throw new Error('route backend unavailable'); });
    const concurrencyLimiter = new InMemoryEdgeConcurrencyLimiter(1, 1);
    const values = await fixture({
      concurrencyLimiter,
      circuitBreaker: {
        acquire: () => ({
          succeeded: () => undefined,
          failed: () => undefined,
          cancelled,
        }),
        snapshot: () => ({
          trackedRoutes: 1,
          failingRoutes: 0,
          openRoutes: 0,
          probeReadyRoutes: 0,
          halfOpenRoutes: 1,
          failureThreshold: 1,
          cooldownMs: 1_000,
        }),
      },
      fetch: vi.fn<typeof fetch>(async () => new Response(new ReadableStream<Uint8Array>({
        pull() {
          // Hold the provider stream until the downstream explicitly discards it.
        },
      }))),
    });

    const response = await values.gateway.fetch(values.request({
      model: 'otto-fast', messages: [],
    }));
    await response.body!.cancel('discard response');

    expect(cancelled).toHaveBeenCalledOnce();
    expect(concurrencyLimiter.snapshot().activeRequests).toBe(0);
    expect(values.outcomes).toEqual([
      expect.objectContaining({ outcome: 'client_cancelled' }),
    ]);
  });

  it.each(['failed', 'cancelled'] as const)(
    'isolates a route-%s hook failure while exhausting routes',
    async (completion) => {
      const failed = vi.fn(() => {
        if (completion === 'failed') throw new Error('route failure backend unavailable');
      });
      const cancelled = vi.fn(() => {
        if (completion === 'cancelled') throw new Error('route cancel backend unavailable');
      });
      const concurrencyLimiter = new InMemoryEdgeConcurrencyLimiter(1, 1);
      const values = await fixture({
        concurrencyLimiter,
        circuitBreaker: {
          acquire: () => ({ succeeded: () => undefined, failed, cancelled }),
          snapshot: () => ({
            trackedRoutes: 1,
            failingRoutes: 0,
            openRoutes: 0,
            probeReadyRoutes: 0,
            halfOpenRoutes: 1,
            failureThreshold: 1,
            cooldownMs: 1_000,
          }),
        },
        fetch: completion === 'failed'
          ? vi.fn<typeof fetch>(async () => { throw new Error('provider unavailable'); })
          : undefined,
        secretResolver: completion === 'cancelled'
          ? { get: async () => null }
          : undefined,
      });

      const response = await values.gateway.fetch(values.request({
        model: 'otto-fast', messages: [],
      }));

      expect(response.status).toBe(completion === 'failed' ? 409 : 502);
      expect(concurrencyLimiter.snapshot().activeRequests).toBe(0);
      expect(completion === 'failed' ? failed : cancelled).toHaveBeenCalledOnce();
      expect(values.outcomes).toEqual([
        expect.objectContaining({ outcome: 'upstream_failed' }),
      ]);
    },
  );

  it('isolates a synchronous outcome recorder failure from response completion', async () => {
    const concurrencyLimiter = new InMemoryEdgeConcurrencyLimiter(1, 1);
    const record = vi.fn(() => { throw new Error('outcome backend unavailable'); });
    const waitUntil = vi.fn();
    const values = await fixture({
      concurrencyLimiter,
      outcomeSink: { record },
    });

    const response = await values.gateway.fetch(
      values.request({ model: 'otto-fast', messages: [] }),
      { waitUntil },
    );

    expect(response.status).toBe(200);
    await expect(response.text()).resolves.toBe('{}');
    expect(record).toHaveBeenCalledOnce();
    expect(waitUntil).toHaveBeenCalledOnce();
    expect(concurrencyLimiter.snapshot().activeRequests).toBe(0);
  });

  it('fails closed when a concurrency adapter returns a malformed lease', async () => {
    const fetchMock = vi.fn<typeof fetch>(async () => new Response('{}'));
    const values = await fixture({
      concurrencyLimiter: {
        acquire: () => ({ release: null }) as never,
        snapshot: () => ({
          activeRequests: 0,
          globalLimit: 1,
          trackedSubjects: 0,
          subjectsAtLimit: 0,
          perSubjectLimit: 1,
        }),
      },
      fetch: fetchMock,
    });

    const response = await values.gateway.fetch(values.request({
      model: 'otto-fast', messages: [],
    }));

    expect(response.status).toBe(503);
    expect(response.headers.get('x-otto-edge-request-id')).toBe('edge_request_fixture');
    await expect(response.json()).resolves.toMatchObject({
      error: { code: 'EDGE_CONCURRENCY_UNAVAILABLE' },
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('fails closed before secret access when a circuit adapter returns a malformed attempt', async () => {
    const concurrencyLimiter = new InMemoryEdgeConcurrencyLimiter(1, 1);
    const secretGet = vi.fn(async () => 'provider-secret-value');
    const fetchMock = vi.fn<typeof fetch>(async () => new Response('{}'));
    const values = await fixture({
      concurrencyLimiter,
      circuitBreaker: {
        acquire: () => ({ succeeded: vi.fn() }) as never,
        snapshot: () => ({
          trackedRoutes: 0,
          failingRoutes: 0,
          openRoutes: 0,
          probeReadyRoutes: 0,
          halfOpenRoutes: 0,
          failureThreshold: 1,
          cooldownMs: 1_000,
        }),
      },
      fetch: fetchMock,
      secretResolver: { get: secretGet },
    });

    const response = await values.gateway.fetch(values.request({
      model: 'otto-fast', messages: [],
    }));

    expect(response.status).toBe(503);
    expect(response.headers.get('x-otto-edge-request-id')).toBe('edge_request_fixture');
    await expect(response.json()).resolves.toMatchObject({
      error: { code: 'EDGE_CIRCUIT_BREAKER_UNAVAILABLE' },
    });
    expect(secretGet).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
    expect(concurrencyLimiter.snapshot().activeRequests).toBe(0);
  });

  it('fails closed before provider access when billing returns a malformed reservation', async () => {
    const route: EdgeModelRouteV1 = {
      ...primaryRoute,
      metering: { type: 'openai_tokens', reserveUnits: 100 },
    };
    const billing = billingCoordinatorFixture();
    billing.reserve.mockResolvedValue({ reservationId: '_invalid' });
    const concurrencyLimiter = new InMemoryEdgeConcurrencyLimiter(1, 1);
    const fetchMock = vi.fn<typeof fetch>(async () => new Response('{}'));
    const values = await fixture({
      billingCoordinator: billing.coordinator,
      concurrencyLimiter,
      fetch: fetchMock,
      routes: [route],
    });

    const response = await values.gateway.fetch(values.request({
      model: 'otto-fast', messages: [],
    }));

    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toMatchObject({
      error: { code: 'EDGE_BILLING_UNAVAILABLE' },
    });
    expect(fetchMock).not.toHaveBeenCalled();
    expect(billing.reserve).toHaveBeenCalledOnce();
    expect(billing.settle).not.toHaveBeenCalled();
    expect(concurrencyLimiter.snapshot().activeRequests).toBe(0);
  });

  it('reports readiness without exposing component details or failure messages', async () => {
    for (const [state, expectedStatus] of [
      ['ready', 200],
      ['degraded', 200],
      ['unavailable', 503],
    ] as const) {
      const check = vi.fn(async () => state);
      const values = await fixture({ readinessProbe: { check } });
      const response = await values.gateway.fetch(new Request('https://edge.otto.test/readyz'));
      expect(response.status).toBe(expectedStatus);
      await expect(response.json()).resolves.toEqual({
        status: state,
        service: 'otto-edge-gateway',
      });
      expect(response.headers.get('cache-control')).toBe('no-store');
      expect(check).toHaveBeenCalledOnce();
    }

    const values = await fixture({
      readinessProbe: { check: async () => { throw new Error('private Redis endpoint'); } },
    });
    const response = await values.gateway.fetch(new Request('https://edge.otto.test/readyz'));
    expect(response.status).toBe(503);
    expect(await response.text()).not.toContain('private Redis endpoint');

    const defaults = await fixture();
    const defaultResponse = await defaults.gateway.fetch(
      new Request('https://edge.otto.test/readyz'),
    );
    expect(defaultResponse.status).toBe(200);
    await expect(defaultResponse.json()).resolves.toEqual({
      status: 'ready', service: 'otto-edge-gateway',
    });
  });

  it('keeps liveness available while rejecting readiness and new work during drain', async () => {
    const lifecycle = new InMemoryEdgeGatewayLifecycle({ now: () => NOW });
    const readinessCheck = vi.fn(async () => 'ready' as const);
    const fetchMock = vi.fn<typeof fetch>(async () => new Response('{}'));
    const values = await fixture({
      fetch: fetchMock,
      lifecycle,
      readinessProbe: { check: readinessCheck },
    });
    lifecycle.beginDrain();

    const health = await values.gateway.fetch(new Request('https://edge.otto.test/healthz'));
    expect(health.status).toBe(200);
    const readiness = await values.gateway.fetch(new Request('https://edge.otto.test/readyz'));
    expect(readiness.status).toBe(503);
    await expect(readiness.json()).resolves.toEqual({
      status: 'unavailable', service: 'otto-edge-gateway',
    });
    expect(readinessCheck).not.toHaveBeenCalled();

    const rejected = await values.gateway.fetch(values.request({
      model: 'otto-fast', messages: [],
    }));
    expect(rejected.status).toBe(503);
    expect(rejected.headers.get('retry-after')).toBe('1');
    expect(rejected.headers.get('x-otto-edge-request-id')).toBe('edge_request_fixture');
    await expect(rejected.json()).resolves.toMatchObject({
      error: { code: 'EDGE_GATEWAY_DRAINING' },
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('fails readiness and business admission closed when lifecycle state is unavailable', async () => {
    const lifecycle: EdgeGatewayLifecycle = {
      isAccepting: () => { throw new Error('private lifecycle failure'); },
      acquire: () => { throw new Error('private lifecycle failure'); },
      beginDrain: () => { throw new Error('private lifecycle failure'); },
      waitForIdle: async () => { throw new Error('private lifecycle failure'); },
      markStopped: () => { throw new Error('private lifecycle failure'); },
      snapshot: () => { throw new Error('private lifecycle failure'); },
    };
    const fetchMock = vi.fn<typeof fetch>(async () => new Response('{}'));
    const values = await fixture({ lifecycle, fetch: fetchMock });

    const readiness = await values.gateway.fetch(new Request('https://edge.otto.test/readyz'));
    expect(readiness.status).toBe(503);
    expect(await readiness.text()).not.toContain('private lifecycle failure');
    const rejected = await values.gateway.fetch(values.request({
      model: 'otto-fast', messages: [],
    }));
    expect(rejected.status).toBe(503);
    await expect(rejected.json()).resolves.toMatchObject({
      error: { code: 'EDGE_LIFECYCLE_UNAVAILABLE' },
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('verifies Control signatures, pins the upstream route, and streams without content logging', async () => {
    const encoder = new TextEncoder();
    const fetchMock = vi.fn(async (...parameters: Parameters<typeof fetch>) => {
      void parameters;
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(encoder.encode('data: {"delta":"first"}\n\n'));
          controller.enqueue(encoder.encode('data: [DONE]\n\n'));
          controller.close();
        },
      });
      return new Response(stream, {
        status: 200,
        headers: { 'content-type': 'text/event-stream', 'x-request-id': 'provider-request' },
      });
    });
    const values = await fixture({ fetch: fetchMock as typeof fetch });
    const response = await values.gateway.fetch(values.request({
      model: 'otto-fast',
      stream: true,
      messages: [{ role: 'user', content: 'private prompt must stay off Control' }],
    }, {
      headers: {
        accept: 'text/html',
        cookie: 'private-client-cookie',
        'x-api-key': 'client-controlled-key',
      },
    }));

    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toBe('text/event-stream');
    expect(response.headers.get('x-content-type-options')).toBe('nosniff');
    expect(response.headers.get('x-upstream-request-id')).toBe('provider-request');
    await expect(response.text()).resolves.toBe('data: {"delta":"first"}\n\ndata: [DONE]\n\n');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe(primaryRoute.upstreamUrl);
    const headers = new Headers(init?.headers);
    expect(headers.get('authorization')).toBe('Bearer provider-secret-value');
    expect(headers.get('accept')).toBe('text/event-stream');
    expect(headers.get('cookie')).toBeNull();
    expect(headers.get('x-api-key')).toBeNull();
    expect(headers.get('x-otto-edge-request-id')).toBe('edge_request_fixture');
    const sent = JSON.parse(String(init?.body)) as Record<string, unknown>;
    expect(sent.model).toBe('provider-model-v3');
    expect(values.outcomes).toEqual([
      expect.objectContaining({
        outcome: 'succeeded',
        publicModel: 'otto-fast',
        routeId: 'route_primary',
      }),
    ]);
    const evidence = JSON.stringify(values.outcomes);
    expect(evidence).not.toContain('private prompt');
    expect(evidence).not.toContain('provider-secret-value');
  });

  it('downgrades unsafe upstream response metadata before returning it to the client', async () => {
    const fetchMock = vi.fn<typeof fetch>(async () => new Response('<script>unsafe()</script>', {
      status: 502,
      headers: {
        'content-type': 'text/html; charset=utf-8',
        'x-request-id': 'x'.repeat(257),
      },
    }));
    const values = await fixture({ fetch: fetchMock });

    const response = await values.gateway.fetch(values.request({
      model: 'otto-fast', messages: [],
    }));

    expect(response.status).toBe(502);
    expect(response.headers.get('content-type')).toBe('application/octet-stream');
    expect(response.headers.get('x-content-type-options')).toBe('nosniff');
    expect(response.headers.get('x-upstream-request-id')).toBeNull();
    await expect(response.text()).resolves.toBe('<script>unsafe()</script>');
  });

  it('requests provider stream usage, preserves response bytes, and records only token counts', async () => {
    const meteredRoute: EdgeModelRouteV1 = {
      ...primaryRoute,
      metering: { type: 'openai_tokens', reserveUnits: 10_000 },
    };
    const providerBytes = [
      'data: {"choices":[{"delta":{"content":"private answer"}}],"usage":null}\n\n',
      'data: {"choices":[],"usage":{"prompt_tokens":7,"completion_tokens":3,"total_tokens":10}}\n\n',
      'data: [DONE]\n\n',
    ];
    const fetchMock = vi.fn<typeof fetch>(async () => new Response(
      new ReadableStream<Uint8Array>({
        start(controller) {
          for (const part of providerBytes) controller.enqueue(new TextEncoder().encode(part));
          controller.close();
        },
      }),
      { headers: { 'content-type': 'text/event-stream' } },
    ));
    const billing = billingCoordinatorFixture();
    const values = await fixture({
      routes: [meteredRoute], fetch: fetchMock, billingCoordinator: billing.coordinator,
    });
    const response = await values.gateway.fetch(values.request({
      model: 'otto-fast',
      stream: true,
      stream_options: { custom_provider_option: 'preserved' },
      messages: [{ role: 'user', content: 'private prompt' }],
    }));

    await expect(response.text()).resolves.toBe(providerBytes.join(''));
    const sent = JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body)) as {
      stream_options?: Record<string, unknown>;
    };
    expect(sent.stream_options).toEqual({
      custom_provider_option: 'preserved',
      include_usage: true,
    });
    expect(values.outcomes).toEqual([
      expect.objectContaining({
        version: 2,
        outcome: 'succeeded',
        usage: { inputTokens: 7, outputTokens: 3, totalTokens: 10 },
      }),
    ]);
    expect(billing.reserve).toHaveBeenCalledWith(expect.objectContaining({
      requestId: 'edge_request_fixture',
      reserveUnits: 10_000,
      policyVersion: POLICY_VERSION,
    }));
    expect(billing.settle).toHaveBeenCalledWith(expect.objectContaining({
      reservation: { reservationId: 'hold_edge_request_fixture' },
      routeId: 'route_primary',
      usage: { inputTokens: 7, outputTokens: 3, totalTokens: 10 },
    }));
    expect(billing.release).not.toHaveBeenCalled();
    expect(billing.markUncertain).not.toHaveBeenCalled();
    expect(JSON.stringify(values.outcomes)).not.toContain('private');
  });

  it('releases metered reservations for non-2xx provider responses even if they contain usage', async () => {
    const meteredRoute: EdgeModelRouteV1 = {
      ...primaryRoute,
      metering: { type: 'openai_tokens', reserveUnits: 10_000 },
    };
    const fetchMock = vi.fn<typeof fetch>(async () => new Response(JSON.stringify({
      error: { code: 'invalid_request' },
      usage: { prompt_tokens: 7, completion_tokens: 3, total_tokens: 10 },
    }), { status: 400, headers: { 'content-type': 'application/json' } }));
    const billing = billingCoordinatorFixture();
    const values = await fixture({
      routes: [meteredRoute], fetch: fetchMock, billingCoordinator: billing.coordinator,
    });

    const response = await values.gateway.fetch(values.request({
      model: 'otto-fast', messages: [],
    }));
    expect(response.status).toBe(400);
    await response.arrayBuffer();

    expect(billing.release).toHaveBeenCalledWith(expect.objectContaining({
      reason: 'upstream_rejected',
    }));
    expect(billing.settle).not.toHaveBeenCalled();
    expect(billing.markUncertain).not.toHaveBeenCalled();
  });

  it('records unavailable usage instead of trusting malformed provider totals', async () => {
    const meteredRoute: EdgeModelRouteV1 = {
      ...primaryRoute,
      metering: { type: 'openai_tokens', reserveUnits: 10_000 },
    };
    const fetchMock = vi.fn<typeof fetch>(async () => new Response(JSON.stringify({
      choices: [],
      usage: { prompt_tokens: 7, completion_tokens: 3, total_tokens: 11 },
    }), { headers: { 'content-type': 'application/json' } }));
    const billing = billingCoordinatorFixture();
    const values = await fixture({
      routes: [meteredRoute], fetch: fetchMock, billingCoordinator: billing.coordinator,
    });
    const response = await values.gateway.fetch(values.request({
      model: 'otto-fast', messages: [],
    }));

    expect(response.status).toBe(200);
    await response.arrayBuffer();
    expect(values.outcomes[0]).toEqual(expect.objectContaining({
      outcome: 'succeeded',
      usage: null,
    }));
    expect(billing.markUncertain).toHaveBeenCalledWith(expect.objectContaining({
      reason: 'usage_unavailable',
      routeId: 'route_primary',
    }));
    expect(billing.settle).not.toHaveBeenCalled();
  });

  it('fails closed before contacting a metered provider when billing is unavailable', async () => {
    const meteredRoute: EdgeModelRouteV1 = {
      ...primaryRoute,
      metering: { type: 'openai_tokens', reserveUnits: 2_000 },
    };
    const fetchMock = vi.fn<typeof fetch>(async () => new Response('{}'));
    const withoutCoordinator = await fixture({ routes: [meteredRoute], fetch: fetchMock });
    const unavailable = await withoutCoordinator.gateway.fetch(withoutCoordinator.request({
      model: 'otto-fast', messages: [],
    }));
    expect(unavailable.status).toBe(503);
    expect(unavailable.headers.get('x-otto-edge-request-id')).toBe('edge_request_fixture');
    await expect(unavailable.json()).resolves.toMatchObject({
      error: { code: 'EDGE_BILLING_UNAVAILABLE' },
    });
    expect(fetchMock).not.toHaveBeenCalled();

    const billing = billingCoordinatorFixture();
    billing.reserve.mockRejectedValueOnce(new EdgeBillingAdmissionError(
      402, 'EDGE_CREDIT_REQUIRED', 'internal balance details must not leak',
    ));
    const insufficient = await fixture({
      routes: [meteredRoute], fetch: fetchMock, billingCoordinator: billing.coordinator,
    });
    const denied = await insufficient.gateway.fetch(insufficient.request({
      model: 'otto-fast', messages: [],
    }));
    expect(denied.status).toBe(402);
    expect(denied.headers.get('x-otto-edge-request-id')).toBe('edge_request_fixture');
    await expect(denied.json()).resolves.toEqual({
      error: { code: 'EDGE_CREDIT_REQUIRED', message: 'insufficient credits for this request' },
    });
    expect(fetchMock).not.toHaveBeenCalled();

    const failedBilling = billingCoordinatorFixture();
    failedBilling.reserve.mockRejectedValueOnce(new Error('private billing endpoint'));
    const broken = await fixture({
      routes: [meteredRoute], fetch: fetchMock, billingCoordinator: failedBilling.coordinator,
    });
    const failed = await broken.gateway.fetch(broken.request({ model: 'otto-fast', messages: [] }));
    expect(failed.status).toBe(503);
    expect(failed.headers.get('x-otto-edge-request-id')).toBe('edge_request_fixture');
    expect(await failed.text()).not.toContain('private billing endpoint');
  });

  it('recovers a pre-provider billing failure without creating a second logical hold', async () => {
    const meteredRoute: EdgeModelRouteV1 = {
      ...primaryRoute,
      metering: { type: 'openai_tokens', reserveUnits: 2_000 },
    };
    const fetchMock = vi.fn<typeof fetch>(async () => new Response(
      JSON.stringify({
        choices: [],
        usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
      }),
      { headers: { 'content-type': 'application/json' } },
    ));
    const billing = billingCoordinatorFixture();
    billing.reserve
      .mockRejectedValueOnce(new EdgeBillingAdmissionError(
        503, 'EDGE_BILLING_UNAVAILABLE', 'Control response was interrupted',
      ))
      .mockResolvedValueOnce({ reservationId: 'hold_edge_request_fixture' });
    const values = await fixture({
      routes: [meteredRoute],
      fetch: fetchMock,
      billingCoordinator: billing.coordinator,
    });
    const body = { model: 'otto-fast', messages: [] };
    const requestInit = { headers: { 'idempotency-key': 'edge_request_recovery' } };

    const first = await values.gateway.fetch(values.request(body, requestInit));
    expect(first.status).toBe(503);
    expect(fetchMock).not.toHaveBeenCalled();

    const recovered = await values.gateway.fetch(values.request(body, requestInit));
    expect(recovered.status).toBe(200);
    await recovered.arrayBuffer();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(billing.reserve).toHaveBeenNthCalledWith(1, expect.objectContaining({
      recoveringNotSentRequest: false,
    }));
    expect(billing.reserve).toHaveBeenNthCalledWith(2, expect.objectContaining({
      recoveringNotSentRequest: true,
    }));
    expect(billing.settle).toHaveBeenCalledOnce();
  });

  it('marks a reservation uncertain when provider delivery cannot be proven', async () => {
    const meteredRoute: EdgeModelRouteV1 = {
      ...primaryRoute,
      metering: { type: 'openai_tokens', reserveUnits: 2_000 },
    };
    const failedBilling = billingCoordinatorFixture();
    const failedFetch = vi.fn<typeof fetch>(async () => { throw new Error('offline'); });
    const failed = await fixture({
      routes: [meteredRoute],
      fetch: failedFetch,
      billingCoordinator: failedBilling.coordinator,
      limits: { ...limits, maxRouteAttempts: 1 },
    });
    const failure = await failed.gateway.fetch(failed.request({ model: 'otto-fast', messages: [] }));
    expect(failure.status).toBe(409);
    await expect(failure.json()).resolves.toMatchObject({
      error: { code: 'EDGE_PROVIDER_SWITCH_CONFIRMATION_REQUIRED' },
    });
    expect(failedBilling.markUncertain).toHaveBeenCalledWith(expect.objectContaining({
      reason: 'provider_error',
      routeId: 'route_primary',
    }));
    expect(failedBilling.release).not.toHaveBeenCalled();
  });

  it('aborts an idle upstream stream and records a content-free timeout outcome', async () => {
    vi.useFakeTimers();
    try {
      const circuitBreaker = new InMemoryEdgeRouteCircuitBreaker({
        failureThreshold: 1,
        now: () => NOW,
      });
      let providerCancelled = false;
      let providerSignal: AbortSignal | null = null;
      const fetchMock = vi.fn<typeof fetch>(async (_url, init) => {
        providerSignal = init?.signal ?? null;
        return new Response(new ReadableStream<Uint8Array>({
          pull: () => new Promise<void>(() => undefined),
          cancel() {
            providerCancelled = true;
          },
        }), { headers: { 'content-type': 'text/event-stream' } });
      });
      const values = await fixture({
        circuitBreaker,
        fetch: fetchMock,
        limits: { ...limits, upstreamIdleTimeoutMs: 1_000 },
      });
      const response = await values.gateway.fetch(values.request({
        model: 'otto-fast', stream: true, messages: [],
      }));
      const content = expect(response.text()).rejects.toMatchObject({ name: 'TimeoutError' });

      await vi.advanceTimersByTimeAsync(1_000);

      await content;
      expect(providerCancelled).toBe(true);
      expect((providerSignal as AbortSignal | null)?.aborted).toBe(true);
      expect(values.outcomes).toEqual([
        expect.objectContaining({
          outcome: 'stream_timed_out',
          requestId: 'edge_request_fixture',
          routeId: 'route_primary',
        }),
      ]);
      expect(circuitBreaker.snapshot()).toEqual(expect.objectContaining({
        openRoutes: 1,
        failingRoutes: 0,
      }));
    } finally {
      vi.useRealTimers();
    }
  });

  it('aborts a response that exceeds the local byte cap and preserves billing uncertainty', async () => {
    const billing = billingCoordinatorFixture();
    const circuitBreaker = new InMemoryEdgeRouteCircuitBreaker({
      failureThreshold: 1,
      now: () => NOW,
    });
    const meteredRoute: EdgeModelRouteV1 = {
      ...primaryRoute,
      metering: { type: 'openai_tokens', reserveUnits: 2_000 },
    };
    let providerCancelled = false;
    let providerSignal: AbortSignal | null = null;
    const fetchMock = vi.fn<typeof fetch>(async (_url, init) => {
      providerSignal = init?.signal ?? null;
      return new Response(new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new Uint8Array(1_024));
          controller.enqueue(new Uint8Array([1]));
        },
        cancel() {
          providerCancelled = true;
        },
      }));
    });
    const values = await fixture({
      billingCoordinator: billing.coordinator,
      circuitBreaker,
      fetch: fetchMock,
      responseLimits: { maximumBytes: 1_024, maximumDurationMs: 60_000 },
      routes: [meteredRoute],
    });
    const response = await values.gateway.fetch(values.request({
      model: 'otto-fast', stream: true, messages: [],
    }));

    await expect(response.arrayBuffer()).rejects.toMatchObject({ name: 'QuotaExceededError' });
    await vi.waitFor(() => expect(billing.markUncertain).toHaveBeenCalledOnce());

    expect(providerCancelled).toBe(true);
    expect((providerSignal as AbortSignal | null)?.aborted).toBe(true);
    expect(values.outcomes).toEqual([
      expect.objectContaining({ outcome: 'response_limit_exceeded' }),
    ]);
    expect(billing.markUncertain).toHaveBeenCalledWith(expect.objectContaining({
      reason: 'response_limit_exceeded',
    }));
    expect(circuitBreaker.snapshot().openRoutes).toBe(1);
  });

  it('allows an upstream response exactly at the local byte cap', async () => {
    const bytes = new Uint8Array(1_024);
    const fetchMock = vi.fn<typeof fetch>(async () => new Response(bytes));
    const values = await fixture({
      fetch: fetchMock,
      responseLimits: { maximumBytes: bytes.byteLength, maximumDurationMs: 60_000 },
    });
    const response = await values.gateway.fetch(values.request({
      model: 'otto-fast', messages: [],
    }));

    expect((await response.arrayBuffer()).byteLength).toBe(bytes.byteLength);
    expect(values.outcomes).toEqual([expect.objectContaining({ outcome: 'succeeded' })]);
  });

  it('clears the total response deadline after a stream completes', async () => {
    vi.useFakeTimers();
    try {
      let providerSignal: AbortSignal | null = null;
      const fetchMock = vi.fn<typeof fetch>(async (_url, init) => {
        providerSignal = init?.signal ?? null;
        return new Response('complete');
      });
      const values = await fixture({
        fetch: fetchMock,
        responseLimits: { maximumBytes: 1_024, maximumDurationMs: 1_000 },
      });
      const response = await values.gateway.fetch(values.request({
        model: 'otto-fast', messages: [],
      }));

      await expect(response.text()).resolves.toBe('complete');
      expect(vi.getTimerCount()).toBe(0);
      await vi.advanceTimersByTimeAsync(1_000);
      expect((providerSignal as AbortSignal | null)?.aborted).toBe(false);
      expect(values.outcomes).toEqual([expect.objectContaining({ outcome: 'succeeded' })]);
    } finally {
      vi.useRealTimers();
    }
  });

  it('enforces a total response deadline even while chunks reset the idle timer', async () => {
    vi.useFakeTimers();
    try {
      const encoder = new TextEncoder();
      let providerController: ReadableStreamDefaultController<Uint8Array> | null = null;
      let providerSignal: AbortSignal | null = null;
      const fetchMock = vi.fn<typeof fetch>(async (_url, init) => {
        providerSignal = init?.signal ?? null;
        return new Response(new ReadableStream<Uint8Array>({
          start(controller) {
            providerController = controller;
          },
        }));
      });
      const values = await fixture({
        fetch: fetchMock,
        limits: { ...limits, upstreamIdleTimeoutMs: 1_000 },
        responseLimits: { maximumBytes: 1_024, maximumDurationMs: 2_000 },
      });
      const response = await values.gateway.fetch(values.request({
        model: 'otto-fast', stream: true, messages: [],
      }));
      const content = expect(response.text()).rejects.toMatchObject({ name: 'TimeoutError' });

      providerController!.enqueue(encoder.encode('first'));
      await vi.advanceTimersByTimeAsync(900);
      providerController!.enqueue(encoder.encode('second'));
      await vi.advanceTimersByTimeAsync(900);
      providerController!.enqueue(encoder.encode('third'));
      await vi.advanceTimersByTimeAsync(200);

      await content;
      expect((providerSignal as AbortSignal | null)?.aborted).toBe(true);
      expect(values.outcomes).toEqual([
        expect.objectContaining({ outcome: 'stream_timed_out' }),
      ]);
    } finally {
      vi.useRealTimers();
    }
  });

  it('cancels provider work when the downstream request disconnects', async () => {
    let providerCancelled = false;
    let providerSignal: AbortSignal | null = null;
    const fetchMock = vi.fn<typeof fetch>(async (_url, init) => {
      providerSignal = init?.signal ?? null;
      return new Response(new ReadableStream<Uint8Array>({
        pull: () => new Promise<void>(() => undefined),
        cancel() {
          providerCancelled = true;
        },
      }), { headers: { 'content-type': 'text/event-stream' } });
    });
    const circuitBreaker = new InMemoryEdgeRouteCircuitBreaker({ failureThreshold: 1 });
    const values = await fixture({ fetch: fetchMock, circuitBreaker });
    const downstream = new AbortController();
    const response = await values.gateway.fetch(values.request({
      model: 'otto-fast', stream: true, messages: [],
    }, { signal: downstream.signal }));
    const content = response.text();

    downstream.abort(new DOMException('test disconnect', 'AbortError'));

    await expect(content).rejects.toMatchObject({ name: 'AbortError' });
    expect(providerCancelled).toBe(true);
    expect((providerSignal as AbortSignal | null)?.aborted).toBe(true);
    expect(circuitBreaker.snapshot().trackedRoutes).toBe(0);
    expect(values.outcomes).toEqual([
      expect.objectContaining({
        outcome: 'client_cancelled',
        requestId: 'edge_request_fixture',
        routeId: 'route_primary',
      }),
    ]);
  });

  it('does not start response deadlines for a client that already disconnected', async () => {
    vi.useFakeTimers();
    try {
      let providerSignal: AbortSignal | null = null;
      const fetchMock = vi.fn<typeof fetch>(async (_url, init) => {
        providerSignal = init?.signal ?? null;
        return new Response('unreachable');
      });
      const values = await fixture({
        fetch: fetchMock,
        responseLimits: { maximumBytes: 1_024, maximumDurationMs: 1_000 },
      });
      const downstream = new AbortController();
      downstream.abort(new DOMException('already disconnected', 'AbortError'));

      const response = await values.gateway.fetch(values.request({
        model: 'otto-fast', messages: [],
      }, { signal: downstream.signal }));

      await expect(response.text()).rejects.toMatchObject({ name: 'AbortError' });
      expect((providerSignal as AbortSignal | null)?.aborted).toBe(true);
      expect(vi.getTimerCount()).toBe(0);
      expect(values.outcomes).toEqual([
        expect.objectContaining({ outcome: 'client_cancelled' }),
      ]);
    } finally {
      vi.useRealTimers();
    }
  });

  it('enforces the response-header connection timeout before retrying or failing', async () => {
    let providerSignal: AbortSignal | null = null;
    const fetchMock = vi.fn<typeof fetch>(async (_url, init) => new Promise<Response>(
      (_resolve, reject) => {
        providerSignal = init?.signal ?? null;
        const fail = () => reject(providerSignal?.reason ?? new DOMException('aborted', 'AbortError'));
        if (providerSignal?.aborted) fail();
        else providerSignal?.addEventListener('abort', fail, { once: true });
      },
    ));
    const values = await fixture({
      fetch: fetchMock,
      limits: { ...limits, upstreamConnectTimeoutMs: 500, maxRouteAttempts: 1 },
    });

    const response = await values.gateway.fetch(values.request({
      model: 'otto-fast', messages: [],
    }));

    expect(response.status).toBe(409);
    await expect(response.json()).resolves.toMatchObject({
      error: { code: 'EDGE_PROVIDER_SWITCH_CONFIRMATION_REQUIRED' },
    });
    expect((providerSignal as AbortSignal | null)?.aborted).toBe(true);
    expect(values.outcomes).toEqual([
      expect.objectContaining({ outcome: 'upstream_failed', upstreamStatus: null }),
    ]);
  });

  it('resets the idle deadline after every upstream chunk', async () => {
    vi.useFakeTimers();
    try {
      const encoder = new TextEncoder();
      let providerController: ReadableStreamDefaultController<Uint8Array> | null = null;
      let providerSignal: AbortSignal | null = null;
      const fetchMock = vi.fn<typeof fetch>(async (_url, init) => {
        providerSignal = init?.signal ?? null;
        return new Response(new ReadableStream<Uint8Array>({
          start(controller) {
            providerController = controller;
          },
        }));
      });
      const values = await fixture({
        fetch: fetchMock,
        limits: { ...limits, upstreamIdleTimeoutMs: 1_000 },
      });
      const response = await values.gateway.fetch(values.request({
        model: 'otto-fast', stream: true, messages: [],
      }));
      const content = response.text();

      providerController!.enqueue(encoder.encode('first'));
      await vi.advanceTimersByTimeAsync(999);
      providerController!.enqueue(encoder.encode('second'));
      await vi.advanceTimersByTimeAsync(999);
      providerController!.close();

      await expect(content).resolves.toBe('firstsecond');
      expect((providerSignal as AbortSignal | null)?.aborted).toBe(false);
      expect(values.outcomes).toEqual([
        expect.objectContaining({ outcome: 'succeeded' }),
      ]);
    } finally {
      vi.useRealTimers();
    }
  });

  it('records an upstream stream failure without exposing its error text', async () => {
    const circuitBreaker = new InMemoryEdgeRouteCircuitBreaker({
      failureThreshold: 1,
      now: () => NOW,
    });
    let providerController: ReadableStreamDefaultController<Uint8Array> | null = null;
    const fetchMock = vi.fn<typeof fetch>(async () => new Response(
      new ReadableStream<Uint8Array>({
        start(controller) {
          providerController = controller;
        },
      }),
    ));
    const values = await fixture({ circuitBreaker, fetch: fetchMock });
    const response = await values.gateway.fetch(values.request({
      model: 'otto-fast', stream: true, messages: [],
    }));
    const content = expect(response.text()).rejects.toThrow('private provider failure');

    providerController!.error(new Error('private provider failure'));

    await content;
    expect(values.outcomes).toEqual([
      expect.objectContaining({ outcome: 'upstream_failed' }),
    ]);
    expect(JSON.stringify(values.outcomes)).not.toContain('private provider failure');
    expect(circuitBreaker.snapshot()).toEqual(expect.objectContaining({
      openRoutes: 1,
      failingRoutes: 0,
    }));
  });

  it('cancels provider work when the downstream response body is discarded', async () => {
    let providerCancelled = false;
    let providerSignal: AbortSignal | null = null;
    const fetchMock = vi.fn<typeof fetch>(async (_url, init) => {
      providerSignal = init?.signal ?? null;
      return new Response(new ReadableStream<Uint8Array>({
        pull: () => new Promise<void>(() => undefined),
        cancel() {
          providerCancelled = true;
        },
      }));
    });
    const values = await fixture({ fetch: fetchMock });
    const response = await values.gateway.fetch(values.request({
      model: 'otto-fast', stream: true, messages: [],
    }));

    await response.body!.cancel('consumer discarded response');

    expect(providerCancelled).toBe(true);
    expect((providerSignal as AbortSignal | null)?.aborted).toBe(true);
    expect(values.outcomes).toEqual([
      expect.objectContaining({ outcome: 'client_cancelled' }),
    ]);
  });

  it('completes content-free responses without leaving stream lifecycle state behind', async () => {
    const fetchMock = vi.fn<typeof fetch>(async () => new Response(null, { status: 204 }));
    const values = await fixture({ fetch: fetchMock });

    const response = await values.gateway.fetch(values.request({
      model: 'otto-fast', messages: [],
    }));

    expect(response.status).toBe(204);
    expect(response.body).toBeNull();
    expect(values.outcomes).toEqual([
      expect.objectContaining({ outcome: 'succeeded', upstreamStatus: 204 }),
    ]);
  });

  it('rejects missing, forged, and policy-mismatched access tokens before provider fetch', async () => {
    const fetchMock = vi.fn(async () => new Response('{}'));
    const values = await fixture({ fetch: fetchMock as typeof fetch });
    const missing = await values.gateway.fetch(new Request(
      'https://edge.otto.test/v1/chat/completions',
      { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' },
    ));
    expect(missing.status).toBe(401);

    const forgedEnvelope = {
      ...values.access,
      token: { ...values.access.token, subjectId: 'account_attacker' },
    };
    const forged = await values.gateway.fetch(new Request(
      'https://edge.otto.test/v1/chat/completions',
      {
        method: 'POST',
        headers: {
          authorization: `Bearer ${encodeEdgeAccessTokenEnvelope(forgedEnvelope)}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({ model: 'otto-fast', messages: [] }),
      },
    ));
    expect(forged.status).toBe(401);

    const mismatch = await fixture({
      fetch: fetchMock as typeof fetch,
      tokenPolicyVersion: 'different-policy',
    });
    const mismatchResponse = await mismatch.gateway.fetch(mismatch.request({
      model: 'otto-fast', messages: [],
    }));
    expect(mismatchResponse.status).toBe(403);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('enforces model allowlists, JSON media type, body limits, and per-subject rate limits', async () => {
    const fetchMock = vi.fn(async () => new Response('{}'));
    const restricted = await fixture({
      allowedModels: ['otto-reasoning'],
      fetch: fetchMock as typeof fetch,
    });
    const forbidden = await restricted.gateway.fetch(restricted.request({
      model: 'otto-fast', messages: [],
    }));
    expect(forbidden.status).toBe(403);

    const smallLimit = await fixture({
      fetch: fetchMock as typeof fetch,
      limits: { ...limits, maxRequestBytes: 1_024 },
    });
    const tooLarge = await smallLimit.gateway.fetch(smallLimit.request({
      model: 'otto-fast', messages: [{ role: 'user', content: 'x'.repeat(2_000) }],
    }));
    expect(tooLarge.status).toBe(413);

    const rateLimited = await fixture({
      fetch: fetchMock as typeof fetch,
      limits: { ...limits, requestsPerMinute: 1 },
    });
    expect((await rateLimited.gateway.fetch(rateLimited.request({
      model: 'otto-fast', messages: [],
    }))).status).toBe(200);
    const second = await rateLimited.gateway.fetch(rateLimited.request({
      model: 'otto-fast', messages: [],
    }));
    expect(second.status).toBe(429);
    expect(second.headers.get('retry-after')).toBe('60');
  });

  it('holds concurrency for the full response stream and releases it on completion', async () => {
    const encoder = new TextEncoder();
    let closeUpstream: (() => void) | undefined;
    const fetchMock = vi.fn(async () => new Response(new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode('data: {"delta":"running"}\n\n'));
        closeUpstream = () => controller.close();
      },
    }), { headers: { 'content-type': 'text/event-stream' } }));
    const concurrencyLimiter = new InMemoryEdgeConcurrencyLimiter(1, 1);
    const values = await fixture({
      concurrencyLimiter,
      fetch: fetchMock as typeof fetch,
      limits: { ...limits, requestsPerMinute: 10 },
    });
    const first = await values.gateway.fetch(values.request({
      model: 'otto-fast', stream: true, messages: [],
    }));
    expect(first.status).toBe(200);
    expect(concurrencyLimiter.snapshot().activeRequests).toBe(1);

    const blocked = await values.gateway.fetch(values.request({
      model: 'otto-fast', stream: true, messages: [],
    }));
    expect(blocked.status).toBe(429);
    expect(blocked.headers.get('retry-after')).toBe('1');
    await expect(blocked.json()).resolves.toEqual({
      error: {
        code: 'EDGE_CONCURRENCY_LIMITED',
        message: 'too many concurrent model requests',
      },
    });

    closeUpstream!();
    await expect(first.text()).resolves.toContain('running');
    expect(concurrencyLimiter.snapshot().activeRequests).toBe(0);
    const admitted = await values.gateway.fetch(values.request({
      model: 'otto-fast', messages: [],
    }));
    expect(admitted.status).toBe(200);
    closeUpstream!();
    await admitted.text();
    expect(concurrencyLimiter.snapshot().activeRequests).toBe(0);
  });

  it('releases concurrency on cancellation, billing rejection, and admission failure', async () => {
    const concurrencyLimiter = new InMemoryEdgeConcurrencyLimiter(1, 1);
    const streaming = await fixture({
      concurrencyLimiter,
      fetch: vi.fn(async () => new Response(new ReadableStream<Uint8Array>({
        pull() {
          // Keep the stream open until the downstream cancels it.
        },
      }))) as typeof fetch,
    });
    const response = await streaming.gateway.fetch(streaming.request({
      model: 'otto-fast', stream: true, messages: [],
    }));
    expect(concurrencyLimiter.snapshot().activeRequests).toBe(1);
    await response.body!.cancel('test complete');
    expect(concurrencyLimiter.snapshot().activeRequests).toBe(0);

    const meteredRoute: EdgeModelRouteV1 = {
      ...primaryRoute,
      metering: { type: 'openai_tokens', reserveUnits: 100 },
    };
    const rejected = await fixture({
      routes: [meteredRoute],
      concurrencyLimiter,
      billingCoordinator: {
        ...billingCoordinatorFixture().coordinator,
        reserve: async () => {
          throw new EdgeBillingAdmissionError(402, 'EDGE_CREDIT_REQUIRED', 'insufficient');
        },
      },
    });
    expect((await rejected.gateway.fetch(rejected.request({
      model: 'otto-fast', messages: [],
    }))).status).toBe(402);
    expect(concurrencyLimiter.snapshot().activeRequests).toBe(0);

    const unavailable = await fixture({
      concurrencyLimiter: {
        acquire() { throw new Error('private limiter failure'); },
        snapshot: () => ({
          activeRequests: 0,
          globalLimit: 1,
          trackedSubjects: 0,
          subjectsAtLimit: 0,
          perSubjectLimit: 1,
        }),
      },
    });
    const failed = await unavailable.gateway.fetch(unavailable.request({
      model: 'otto-fast', messages: [],
    }));
    expect(failed.status).toBe(503);
    expect(await failed.text()).not.toContain('private limiter failure');
  });

  it('distinguishes temporary traffic bans and fails closed when distributed limiting is unavailable', async () => {
    const banned = await fixture({
      rateLimiter: {
        consume: async () => ({
          allowed: false, remaining: 0, retryAfterSeconds: 900, banned: true,
        }),
      },
    });
    const blocked = await banned.gateway.fetch(banned.request({
      model: 'otto-fast', messages: [],
    }));
    expect(blocked.status).toBe(429);
    expect(blocked.headers.get('retry-after')).toBe('900');
    await expect(blocked.json()).resolves.toEqual({
      error: {
        code: 'EDGE_TRAFFIC_BANNED',
        message: 'request source is temporarily blocked',
      },
    });

    const unavailable = await fixture({
      rateLimiter: {
        consume: async () => { throw new EdgeRateLimitUnavailableError(); },
      },
    });
    const failed = await unavailable.gateway.fetch(unavailable.request({
      model: 'otto-fast', messages: [],
    }));
    expect(failed.status).toBe(503);
    expect(failed.headers.get('x-otto-edge-request-id')).toBe('edge_request_fixture');
    expect(failed.headers.get('retry-after')).toBeNull();
    await expect(failed.json()).resolves.toEqual({
      error: {
        code: 'EDGE_RATE_LIMIT_UNAVAILABLE',
        message: 'gateway rate limiter is unavailable',
      },
    });
  });

  it.each([
    { allowed: 'true', remaining: 9, retryAfterSeconds: 0 },
    { allowed: true, remaining: 10, retryAfterSeconds: 0 },
    { allowed: false, remaining: 0, retryAfterSeconds: 0 },
    { allowed: false, remaining: 0, retryAfterSeconds: 604_801, banned: true },
  ])('fails closed before provider access for a malformed rate-limit result %#', async (result) => {
    const fetchMock = vi.fn<typeof fetch>(async () => new Response('{}'));
    const secretGet = vi.fn(async () => 'provider-secret-value');
    const values = await fixture({
      fetch: fetchMock,
      rateLimiter: { consume: async () => result as never },
      secretResolver: { get: secretGet },
    });

    const response = await values.gateway.fetch(values.request({
      model: 'otto-fast', messages: [],
    }));

    expect(response.status).toBe(503);
    expect(response.headers.get('x-otto-edge-request-id')).toBe('edge_request_fixture');
    await expect(response.json()).resolves.toEqual({
      error: {
        code: 'EDGE_RATE_LIMIT_UNAVAILABLE',
        message: 'gateway rate limiter is unavailable',
      },
    });
    expect(secretGet).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('handles path, method, media, JSON, model, and byte-limit boundaries fail-closed', async () => {
    const fetchMock = vi.fn(async () => new Response('{"ok":true}', { status: 200 }));
    const secretGet = vi.fn(async () => 'provider-secret-value');
    const values = await fixture({
      allowedModels: ['otto-fast', 'otto-unrouted'],
      fetch: fetchMock as typeof fetch,
      secretResolver: { get: secretGet },
      limits: { ...limits, maxRequestBytes: 1_024, requestsPerMinute: 100 },
    });
    const raw = (
      body: string | Uint8Array | undefined,
      input: { path?: string; method?: string; headers?: Record<string, string> } = {},
    ) => new Request(`https://edge.otto.test${input.path ?? '/v1/chat/completions'}`, {
      method: input.method ?? 'POST',
      headers: {
        authorization: values.authorization,
        'content-type': 'application/json',
        ...input.headers,
      },
      body,
    });
    const errorCode = async (response: Response) => {
      const body = await response.json() as { error: { code: string } };
      return body.error.code;
    };

    const missingRoute = await values.gateway.fetch(raw(undefined, {
      path: '/v1/not-a-route', method: 'GET',
    }));
    expect(missingRoute.status).toBe(404);
    await expect(errorCode(missingRoute)).resolves.toBe('EDGE_NOT_FOUND');

    for (const path of [
      '/v1/chat/completions?api-version=untrusted',
      '/v1/chat/completions#untrusted-fragment',
    ]) {
      const ambiguousTarget = await values.gateway.fetch(raw('{}', { path }));
      expect(ambiguousTarget.status).toBe(400);
      await expect(errorCode(ambiguousTarget)).resolves.toBe('EDGE_INVALID_HTTP_REQUEST');
    }
    expect(fetchMock).not.toHaveBeenCalled();
    expect(secretGet).not.toHaveBeenCalled();

    const wrongMethod = await values.gateway.fetch(raw(undefined, { method: 'GET' }));
    expect(wrongMethod.status).toBe(405);
    expect(wrongMethod.headers.get('allow')).toBe('POST');
    await expect(errorCode(wrongMethod)).resolves.toBe('EDGE_METHOD_NOT_ALLOWED');

    const wrongMedia = await values.gateway.fetch(raw('{}', {
      headers: { 'content-type': 'text/plain' },
    }));
    expect(wrongMedia.status).toBe(415);
    await expect(errorCode(wrongMedia)).resolves.toBe('EDGE_UNSUPPORTED_MEDIA_TYPE');

    for (const invalidBody of [
      '{',
      '[]',
      'null',
      '{}',
      '{"model":7}',
      '{"model":"otto-fast","stream":null}',
      '{"model":"otto-fast","stream":1}',
      '{"model":"otto-fast","stream":"true"}',
      '{"model":"otto-fast","stream":{}}',
    ]) {
      const response = await values.gateway.fetch(raw(invalidBody));
      expect(response.status).toBe(400);
      await expect(errorCode(response)).resolves.toBe('EDGE_INVALID_REQUEST');
    }
    expect(fetchMock).not.toHaveBeenCalled();
    expect(secretGet).not.toHaveBeenCalled();

    const malformedUtf8 = await values.gateway.fetch(raw(new Uint8Array([0xff, 0xfe])));
    expect(malformedUtf8.status).toBe(400);
    await expect(errorCode(malformedUtf8)).resolves.toBe('EDGE_INVALID_REQUEST');

    const invalidLength = await values.gateway.fetch(raw('{}', {
      headers: { 'content-length': 'not-an-integer' },
    }));
    expect(invalidLength.status).toBe(400);
    await expect(errorCode(invalidLength)).resolves.toBe('EDGE_INVALID_REQUEST');
    for (const contentLength of ['-1', '1.5']) {
      const response = await values.gateway.fetch(raw('{}', {
        headers: { 'content-length': contentLength },
      }));
      expect(response.status).toBe(400);
      await expect(errorCode(response)).resolves.toBe('EDGE_INVALID_REQUEST');
    }

    const declaredTooLarge = await values.gateway.fetch(raw('{}', {
      headers: { 'content-length': '1025' },
    }));
    expect(declaredTooLarge.status).toBe(413);
    await expect(errorCode(declaredTooLarge)).resolves.toBe('EDGE_REQUEST_TOO_LARGE');

    const prefix = '{"model":"otto-fast","padding":"';
    const suffix = '"}';
    const exactBody = `${prefix}${'x'.repeat(1_024 - prefix.length - suffix.length)}${suffix}`;
    expect(new TextEncoder().encode(exactBody)).toHaveLength(1_024);
    expect((await values.gateway.fetch(raw(exactBody, {
      headers: { 'content-length': '1024' },
    }))).status).toBe(200);
    const overBody = `${prefix}${'x'.repeat(1_025 - prefix.length - suffix.length)}${suffix}`;
    const overResponse = await values.gateway.fetch(raw(overBody));
    expect(overResponse.status).toBe(413);
    await expect(errorCode(overResponse)).resolves.toBe('EDGE_REQUEST_TOO_LARGE');

    const modelTooLong = await values.gateway.fetch(raw(JSON.stringify({
      model: 'x'.repeat(161), messages: [],
    })));
    expect(modelTooLong.status).toBe(400);
    await expect(errorCode(modelTooLong)).resolves.toBe('EDGE_INVALID_REQUEST');

    const unavailable = await values.gateway.fetch(raw(JSON.stringify({
      model: 'otto-unrouted', messages: [],
    })));
    expect(unavailable.status).toBe(503);
    await expect(errorCode(unavailable)).resolves.toBe('EDGE_MODEL_UNAVAILABLE');
  });

  it('enforces the local request hard cap when signed policy is more permissive', async () => {
    const secretGet = vi.fn(async () => 'provider-secret-value');
    const fetchMock = vi.fn(async () => new Response('{}'));
    const values = await fixture({
      limits: { ...limits, maxRequestBytes: 4_096 },
      requestLimits: { maximumBytes: 1_024 },
      secretResolver: { get: secretGet },
      fetch: fetchMock as typeof fetch,
    });

    const response = await values.gateway.fetch(values.request({
      model: 'otto-fast',
      messages: [{ role: 'user', content: 'x'.repeat(1_024) }],
    }));

    expect(response.status).toBe(413);
    await expect(response.json()).resolves.toMatchObject({
      error: { code: 'EDGE_REQUEST_TOO_LARGE' },
    });
    expect(secretGet).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('fails over only retryable upstream failures and never accepts a client upstream URL', async () => {
    const secondary: EdgeModelRouteV1 = {
      ...primaryRoute,
      id: 'route_secondary',
      upstreamUrl: 'https://provider-b.test/v1/chat/completions',
      priority: 20,
      authentication: { type: 'header', headerName: 'x-api-key', secretBinding: 'PROVIDER_B_API_KEY' },
    };
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response('temporarily unavailable', { status: 503 }))
      .mockResolvedValueOnce(new Response('{"ok":true}', { status: 200 }));
    const values = await fixture({
      routes: [secondary, primaryRoute],
      fetch: fetchMock as typeof fetch,
      secrets: {
        PROVIDER_A_API_KEY: 'primary-secret',
        PROVIDER_B_API_KEY: 'secondary-secret',
      },
    });
    for (const field of [
      'apiKey', 'api_key', 'authentication', 'headers', 'providerSecret',
      'secretBinding', 'upstreamUrl', 'upstream_url',
    ]) {
      const rejectedOverride = await values.gateway.fetch(values.request({
        model: 'otto-fast',
        messages: [],
        [field]: field === 'headers' ? {} : 'attacker-controlled',
      }));
      expect(rejectedOverride.status).toBe(400);
      expect(rejectedOverride.headers.get('x-otto-edge-request-id'))
        .toMatch(/^edge_request_fixture(?:_\d+)?$/);
    }
    expect(fetchMock).not.toHaveBeenCalled();

    const requestId = 'edge_failover_503';
    const firstAttempt = await values.gateway.fetch(values.request({
      model: 'otto-fast',
      messages: [],
    }, { headers: { 'idempotency-key': requestId } }));
    expect(firstAttempt.status).toBe(409);
    await expect(firstAttempt.json()).resolves.toMatchObject({
      error: { code: 'EDGE_PROVIDER_SWITCH_CONFIRMATION_REQUIRED' },
    });
    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      'https://provider-a.test/v1/chat/completions',
    ]);

    const response = await values.gateway.fetch(values.request({
      model: 'otto-fast',
      messages: [],
    }, {
      headers: {
        'idempotency-key': requestId,
        'x-otto-provider-switch-confirmation': requestId,
      },
    }));
    expect(response.status).toBe(200);
    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      'https://provider-a.test/v1/chat/completions',
      'https://provider-b.test/v1/chat/completions',
    ]);
    expect(new Headers(fetchMock.mock.calls[1]![1]?.headers).get('x-api-key'))
      .toBe('secondary-secret');

    for (const retryableStatus of [429, 502, 504]) {
      const retryableFetch = vi.fn()
        .mockResolvedValueOnce(new Response('retry', { status: retryableStatus }))
        .mockResolvedValueOnce(new Response('{}', { status: 200 }));
      const retryable = await fixture({
        routes: [primaryRoute, secondary],
        fetch: retryableFetch as typeof fetch,
        secrets: {
          PROVIDER_A_API_KEY: 'primary-secret',
          PROVIDER_B_API_KEY: 'secondary-secret',
        },
      });
      const retryableRequestId = `edge_failover_${retryableStatus}`;
      const firstRetryable = await retryable.gateway.fetch(retryable.request({
        model: 'otto-fast', messages: [],
      }, { headers: { 'idempotency-key': retryableRequestId } }));
      expect(firstRetryable.status).toBe(409);
      await expect(firstRetryable.json()).resolves.toMatchObject({
        error: { code: 'EDGE_PROVIDER_SWITCH_CONFIRMATION_REQUIRED' },
      });
      const confirmed = await retryable.gateway.fetch(retryable.request({
        model: 'otto-fast', messages: [],
      }, {
        headers: {
          'idempotency-key': retryableRequestId,
          'x-otto-provider-switch-confirmation': retryableRequestId,
        },
      }));
      expect(confirmed.status).toBe(200);
      expect(retryableFetch).toHaveBeenCalledTimes(2);
    }

    for (const terminalStatus of [400, 500]) {
      const terminalFetch = vi.fn(async () => new Response('terminal', { status: terminalStatus }));
      const noRetry = await fixture({
        routes: [primaryRoute, secondary],
        fetch: terminalFetch as typeof fetch,
        secrets: {
          PROVIDER_A_API_KEY: 'primary-secret',
          PROVIDER_B_API_KEY: 'secondary-secret',
        },
      });
      expect((await noRetry.gateway.fetch(noRetry.request({
        model: 'otto-fast', messages: [],
      }))).status).toBe(terminalStatus);
      expect(terminalFetch).toHaveBeenCalledTimes(1);
    }
  });

  it('opens failed routes, skips them during cooldown, and closes after one successful probe', async () => {
    let current = NOW;
    let primaryHealthy = false;
    let primarySecretAvailable = true;
    const fallbackRoute: EdgeModelRouteV1 = {
      ...primaryRoute,
      id: 'route_fallback',
      upstreamUrl: 'https://provider-b.test/v1/chat/completions',
      priority: 20,
      authentication: { type: 'bearer', secretBinding: 'PROVIDER_B_API_KEY' },
    };
    const breaker = new InMemoryEdgeRouteCircuitBreaker({
      failureThreshold: 1,
      cooldownMs: 1_000,
      now: () => current,
    });
    const fetchMock = vi.fn(async (url: string | URL | Request) => {
      if (String(url) === primaryRoute.upstreamUrl) {
        return new Response('{}', { status: primaryHealthy ? 200 : 503 });
      }
      return new Response('{}', { status: 200 });
    });
    const secretGet = vi.fn(async (binding: string) => {
      if (binding === 'PROVIDER_A_API_KEY') {
        return primarySecretAvailable ? 'provider-a-secret' : null;
      }
      return binding === 'PROVIDER_B_API_KEY' ? 'provider-b-secret' : null;
    });
    const values = await fixture({
      routes: [primaryRoute, fallbackRoute],
      circuitBreaker: breaker,
      fetch: fetchMock as typeof fetch,
      now: () => current,
      secretResolver: { get: secretGet },
    });
    let requestSequence = 0;
    const send = async (requestId = `edge_breaker_${++requestSequence}`, confirm = false) => {
      const response = await values.gateway.fetch(values.request({
        model: 'otto-fast', messages: [],
      }, {
        headers: {
          'idempotency-key': requestId,
          ...(confirm ? { 'x-otto-provider-switch-confirmation': requestId } : {}),
        },
      }));
      await response.text();
      return response;
    };

    const firstRequestId = 'edge_breaker_first';
    expect((await send(firstRequestId)).status).toBe(409);
    expect(fetchMock.mock.calls.map(([url]) => String(url))).toEqual([
      primaryRoute.upstreamUrl,
    ]);
    expect(secretGet.mock.calls.filter(([binding]) => binding === 'PROVIDER_A_API_KEY'))
      .toHaveLength(1);
    expect(breaker.snapshot().openRoutes).toBe(1);

    expect((await send(firstRequestId, true)).status).toBe(200);
    expect(fetchMock.mock.calls.map(([url]) => String(url))).toEqual([
      primaryRoute.upstreamUrl,
      fallbackRoute.upstreamUrl,
    ]);

    expect((await send()).status).toBe(200);
    expect(fetchMock.mock.calls.map(([url]) => String(url))).toEqual([
      primaryRoute.upstreamUrl,
      fallbackRoute.upstreamUrl,
      fallbackRoute.upstreamUrl,
    ]);
    expect(secretGet.mock.calls.filter(([binding]) => binding === 'PROVIDER_A_API_KEY'))
      .toHaveLength(1);

    current += 1_000;
    primarySecretAvailable = false;
    expect((await send()).status).toBe(200);
    expect(fetchMock.mock.calls.at(-1)?.[0]).toBe(fallbackRoute.upstreamUrl);
    expect(breaker.snapshot().halfOpenRoutes).toBe(0);
    expect(breaker.snapshot().probeReadyRoutes).toBe(1);

    primarySecretAvailable = true;
    primaryHealthy = true;
    expect((await send()).status).toBe(200);
    expect(breaker.snapshot().trackedRoutes).toBe(0);
    expect((await send()).status).toBe(200);
    expect(fetchMock.mock.calls.at(-1)?.[0]).toBe(primaryRoute.upstreamUrl);
  });

  it('opens a terminal retryable route as soon as response headers arrive', async () => {
    const breaker = new InMemoryEdgeRouteCircuitBreaker({
      failureThreshold: 1,
      cooldownMs: 1_000,
      now: () => NOW,
    });
    const fetchMock = vi.fn(async () => new Response(new ReadableStream<Uint8Array>({
      pull() {
        // A client may leave an error response body unread.
      },
    }), { status: 503 }));
    const values = await fixture({
      circuitBreaker: breaker,
      fetch: fetchMock as typeof fetch,
      now: () => NOW,
    });
    const response = await values.gateway.fetch(values.request({
      model: 'otto-fast', messages: [],
    }));
    expect(response.status).toBe(503);
    expect(breaker.snapshot().openRoutes).toBe(1);
    await response.body!.cancel('discard error body');
    expect(breaker.snapshot().openRoutes).toBe(1);
    const skipped = await values.gateway.fetch(values.request({
      model: 'otto-fast', messages: [],
    }));
    expect(skipped.status).toBe(502);
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it('fails closed without provider access when route health admission breaks', async () => {
    const concurrencyLimiter = new InMemoryEdgeConcurrencyLimiter(2, 1);
    const fetchMock = vi.fn(async () => new Response('{}'));
    const values = await fixture({
      concurrencyLimiter,
      circuitBreaker: {
        acquire() { throw new Error('private circuit state failure'); },
        snapshot: () => ({
          trackedRoutes: 0,
          failingRoutes: 0,
          openRoutes: 0,
          probeReadyRoutes: 0,
          halfOpenRoutes: 0,
          failureThreshold: 1,
          cooldownMs: 1_000,
        }),
      },
      fetch: fetchMock as typeof fetch,
    });
    const response = await values.gateway.fetch(values.request({
      model: 'otto-fast', messages: [],
    }));
    expect(response.status).toBe(503);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(concurrencyLimiter.snapshot().activeRequests).toBe(0);
    expect(await response.text()).not.toContain('private circuit state failure');
  });

  it('contains secret-provider and network exceptions without leaking internal errors', async () => {
    const secondary: EdgeModelRouteV1 = {
      ...primaryRoute,
      id: 'route_exception_fallback',
      upstreamUrl: 'https://provider-b.test/v1/chat/completions',
      priority: 20,
      authentication: { type: 'bearer', secretBinding: 'PROVIDER_B_API_KEY' },
    };
    const networkFetch = vi.fn()
      .mockRejectedValueOnce(new Error('private DNS details must not escape'))
      .mockResolvedValueOnce(new Response('{"fallback":true}', { status: 200 }));
    const values = await fixture({
      routes: [primaryRoute, secondary],
      fetch: networkFetch as typeof fetch,
      secrets: {
        PROVIDER_A_API_KEY: 'primary-secret',
        PROVIDER_B_API_KEY: 'secondary-secret',
      },
    });
    const requestId = 'edge_network_exception';
    const uncertain = await values.gateway.fetch(values.request({
      model: 'otto-fast', messages: [],
    }, { headers: { 'idempotency-key': requestId } }));
    expect(uncertain.status).toBe(409);
    await expect(uncertain.json()).resolves.toMatchObject({
      error: { code: 'EDGE_PROVIDER_SWITCH_CONFIRMATION_REQUIRED' },
    });
    expect(networkFetch).toHaveBeenCalledOnce();

    const recovered = await values.gateway.fetch(values.request({
      model: 'otto-fast', messages: [],
    }, {
      headers: {
        'idempotency-key': requestId,
        'x-otto-provider-switch-confirmation': requestId,
      },
    }));
    expect(recovered.status).toBe(200);
    expect(networkFetch).toHaveBeenCalledTimes(2);

    const unavailable = createOttoEdgeGateway({
      policySource: { load: async () => values.policy },
      verifier: createEdgeSignatureVerifier({ [values.signer.keyId]: values.signer.publicKeyPem }),
      secretResolver: { get: async () => { throw new Error('secret backend unavailable'); } },
      rateLimiter: new InMemoryEdgeRateLimiter(),
      fetch: networkFetch as typeof fetch,
      now: () => NOW,
      requestId: () => 'edge_request_secret_error',
      upstreamOriginPolicy: values.upstreamOriginPolicy,
    });
    const failed = await unavailable.fetch(values.request({ model: 'otto-fast', messages: [] }));
    expect(failed.status).toBe(502);
    expect(await failed.text()).not.toContain('secret backend');
  });

  it('fails closed when a signed policy is expired or a provider secret is absent', async () => {
    const expired = await fixture({ policyDurationMs: 60_000 });
    const gateway = createOttoEdgeGateway({
      policySource: { load: async () => expired.policy },
      verifier: createEdgeSignatureVerifier({
        [expired.signer.keyId]: expired.signer.publicKeyPem,
      }),
      secretResolver: { get: async () => null },
      rateLimiter: new InMemoryEdgeRateLimiter(),
      now: () => NOW + 60_000,
      upstreamOriginPolicy: expired.upstreamOriginPolicy,
    });
    const expiredResponse = await gateway.fetch(expired.request({
      model: 'otto-fast', messages: [],
    }));
    expect(expiredResponse.status).toBe(401);

    const missingSecret = await fixture({ secrets: {} });
    const unavailable = await missingSecret.gateway.fetch(missingSecret.request({
      model: 'otto-fast', messages: [],
    }));
    expect(unavailable.status).toBe(502);
  });

  it('normalizes a provider secret before constructing its authorization header', async () => {
    const fetchMock = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      expect(new Headers(init?.headers).get('authorization')).toBe('Bearer normalized-secret');
      return new Response('{}', { status: 200 });
    });
    const values = await fixture({
      fetch: fetchMock as typeof fetch,
      secretResolver: { get: async () => '  normalized-secret  ' },
    });

    const response = await values.gateway.fetch(values.request({
      model: 'otto-fast', messages: [],
    }));

    expect(response.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it.each([
    'unsafe\r\nheader',
    'unicode-密钥',
    'x'.repeat(8_193),
  ])('rejects an unsafe provider secret before network access %#', async (secret) => {
    const fetchMock = vi.fn(async () => new Response('{}', { status: 200 }));
    const values = await fixture({
      fetch: fetchMock as typeof fetch,
      secretResolver: { get: async () => secret },
    });

    const response = await values.gateway.fetch(values.request({
      model: 'otto-fast', messages: [],
    }));

    expect(response.status).toBe(502);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(await response.text()).not.toContain(secret.slice(0, 12));
  });

  it('rejects unsafe signed routes before they can become SSRF or secret-header policies', async () => {
    const values = await fixture();
    await expect(values.control.issuePolicy({
      policyVersion: POLICY_VERSION,
      deploymentId: DEPLOYMENT_ID,
      organizationId: ORGANIZATION_ID,
      routes: [{ ...primaryRoute, upstreamUrl: 'http://127.0.0.1/admin' }],
      limits,
    })).rejects.toMatchObject({ code: 'EDGE_INVALID_ENVELOPE' });
    await expect(values.control.issuePolicy({
      policyVersion: POLICY_VERSION,
      deploymentId: DEPLOYMENT_ID,
      organizationId: ORGANIZATION_ID,
      routes: [{
        ...primaryRoute,
        authentication: {
          type: 'header',
          headerName: 'cookie',
          secretBinding: 'PROVIDER_A_API_KEY',
        },
      }],
      limits,
    })).rejects.toMatchObject({ code: 'EDGE_INVALID_ENVELOPE' });
  });

  it('requires local origin approval before reading provider secrets or opening a connection', async () => {
    const secretGet = vi.fn(async () => 'provider-secret-value');
    const fetchMock = vi.fn(async () => new Response('{}'));
    const values = await fixture({
      allowedUpstreamOrigins: ['https://approved-provider.test'],
      fetch: fetchMock as typeof fetch,
      secretResolver: { get: secretGet },
    });

    const denied = await values.gateway.fetch(values.request({
      model: 'otto-fast', messages: [],
    }));

    expect(denied.status).toBe(503);
    await expect(denied.json()).resolves.toEqual({
      error: {
        code: 'EDGE_UPSTREAM_NOT_ALLOWED',
        message: 'model routes are not allowed by local upstream policy',
      },
    });
    expect(secretGet).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('requires local credential approval even when the signed origin is approved', async () => {
    const secretGet = vi.fn(async () => 'unrelated-secret-value');
    const fetchMock = vi.fn(async () => new Response('{}'));
    const values = await fixture({
      upstreamOriginPolicy: normalizeEdgeUpstreamOriginPolicy({
        version: 2,
        allowedUpstreams: [{
          origin: 'https://provider-a.test',
          authentications: [{
            type: 'bearer',
            secretBinding: 'DIFFERENT_PROVIDER_API_KEY',
          }],
        }],
      }),
      fetch: fetchMock as typeof fetch,
      secretResolver: { get: secretGet },
    });

    const denied = await values.gateway.fetch(values.request({
      model: 'otto-fast', messages: [],
    }));

    expect(denied.status).toBe(503);
    await expect(denied.json()).resolves.toMatchObject({
      error: { code: 'EDGE_UPSTREAM_NOT_ALLOWED' },
    });
    expect(secretGet).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('fails closed when the local origin policy cannot decide', async () => {
    const secretGet = vi.fn(async () => 'provider-secret-value');
    const fetchMock = vi.fn(async () => new Response('{}'));
    const values = await fixture({ secretResolver: { get: secretGet } });
    const gateway = createOttoEdgeGateway({
      policySource: { load: async () => values.policy },
      verifier: createEdgeSignatureVerifier({
        [values.signer.keyId]: values.signer.publicKeyPem,
      }),
      secretResolver: { get: secretGet },
      rateLimiter: new InMemoryEdgeRateLimiter(),
      fetch: fetchMock as typeof fetch,
      now: () => NOW,
      upstreamOriginPolicy: {
        allows() {
          throw new Error('private local policy failure');
        },
      },
    });

    const denied = await gateway.fetch(values.request({
      model: 'otto-fast', messages: [],
    }));

    expect(denied.status).toBe(503);
    expect(await denied.text()).not.toContain('private local policy failure');
    expect(secretGet).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('parses authorization and normalized model names without accepting token smuggling', async () => {
    const fetchMock = vi.fn<typeof fetch>(async () => new Response('{"ok":true}', {
      headers: { 'content-type': 'application/json' },
    }));
    const values = await fixture({ fetch: fetchMock as typeof fetch });
    const body = { model: 'otto-fast', messages: [] };
    for (const authorization of [
      `xBearer ${values.authorization.slice('Bearer '.length)}`,
      `Bearer ${values.authorization.slice('Bearer '.length)} trailing`,
      values.authorization.replace('Bearer ', 'Bearer'),
    ]) {
      const response = await values.gateway.fetch(values.request(body, {
        headers: { authorization },
      }));
      expect(response.status).toBe(401);
    }

    for (const authorization of [
      `  ${values.authorization}  `,
      `Bearer  ${values.authorization.slice('Bearer '.length)}`,
    ]) {
      const response = await values.gateway.fetch(values.request(body, {
        headers: { authorization },
      }));
      expect(response.status).toBe(200);
    }

    const normalized = await values.gateway.fetch(values.request({
      model: '  otto-fast  ', stream: false, messages: [],
    }, { headers: { accept: 'text/html', cookie: 'private-client-cookie' } }));
    expect(normalized.status).toBe(200);
    await expect(normalized.text()).resolves.toBe('{"ok":true}');
    const upstreamHeaders = new Headers(fetchMock.mock.calls.at(-1)?.[1]?.headers);
    expect(upstreamHeaders.get('accept')).toBe('application/json');
    expect(upstreamHeaders.get('cookie')).toBeNull();
    expect(normalized.headers.get('cache-control')).toBe('no-store');
    expect(normalized.headers.get('x-otto-edge-request-id')).toMatch(/^edge_request_fixture(?:_\d+)?$/);
    expect(normalized.headers.get('x-ratelimit-remaining')).toBe('7');
    expect(values.outcomes.at(-1)?.durationMs).toBe(0);
  });

  it('preserves request tracing, exact model boundaries, and measured duration', async () => {
    const publicModel = 'm'.repeat(160);
    const route: EdgeModelRouteV1 = { ...primaryRoute, publicModel };
    let currentTime = NOW;
    const fetchMock = vi.fn<typeof fetch>(async () => new Response('{}'));
    const values = await fixture({
      routes: [route],
      allowedModels: [publicModel],
      fetch: fetchMock,
      now: () => {
        const value = currentTime;
        currentTime += 125;
        return value;
      },
    });
    const response = await values.gateway.fetch(values.request({ model: publicModel, messages: [] }));
    expect(response.status).toBe(200);
    expect(response.headers.get('x-otto-edge-request-id')).toMatch(/^edge_request_fixture(?:_\d+)?$/);
    await expect(response.text()).resolves.toBe('{}');
    expect(values.outcomes.at(-1)?.durationMs).toBe(125);

    const rejected = await values.gateway.fetch(values.request({ model: 7, messages: [] }));
    expect(rejected.status).toBe(400);
    expect(rejected.headers.get('x-otto-edge-request-id')).toMatch(/^edge_request_fixture(?:_\d+)?$/);
  });

  it('keeps endpoint selection and equal-priority failover deterministic', async () => {
    const wrongEndpoint: EdgeModelRouteV1 = {
      ...primaryRoute,
      id: 'route_responses_only',
      endpoint: 'responses',
      upstreamUrl: 'https://wrong-endpoint.test/v1/responses',
      priority: 0,
    };
    const lexicalLast: EdgeModelRouteV1 = {
      ...primaryRoute,
      id: 'route_z_last',
      upstreamUrl: 'https://z-route.test/v1/chat/completions',
      priority: 10,
    };
    const lexicalFirst: EdgeModelRouteV1 = {
      ...primaryRoute,
      id: 'route_a_first',
      upstreamUrl: 'https://a-route.test/v1/chat/completions',
      priority: 10,
    };
    const fetchMock = vi.fn<typeof fetch>(async () => new Response('{}'));
    const values = await fixture({
      routes: [wrongEndpoint, lexicalLast, lexicalFirst],
      fetch: fetchMock as typeof fetch,
    });
    const response = await values.gateway.fetch(values.request({
      model: 'otto-fast', messages: [],
    }));
    expect(response.status).toBe(200);
    await expect(response.text()).resolves.toBe('{}');
    expect(fetchMock.mock.calls[0]?.[0]).toBe(lexicalFirst.upstreamUrl);
    expect(values.outcomes[0]?.routeId).toBe('route_a_first');
  });

  it('rejects independently signed deployment and organization token mismatches', async () => {
    const fetchMock = vi.fn(async () => new Response('{}'));
    const values = await fixture({ fetch: fetchMock as typeof fetch });
    for (const binding of [
      { deploymentId: 'dep_other', organizationId: ORGANIZATION_ID },
      { deploymentId: DEPLOYMENT_ID, organizationId: 'org_other' },
    ]) {
      const mismatched = await values.control.issueAccessToken({
        ...binding,
        subjectId: 'account_edge_user',
        policyVersion: POLICY_VERSION,
        allowedModels: ['otto-fast'],
      });
      const response = await values.gateway.fetch(new Request(
        'https://edge.otto.test/v1/chat/completions',
        {
          method: 'POST',
          headers: {
            authorization: `Bearer ${encodeEdgeAccessTokenEnvelope(mismatched)}`,
            'content-type': 'application/json',
          },
          body: JSON.stringify({ model: 'otto-fast', messages: [] }),
        },
      ));
      expect(response.status).toBe(403);
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

import { generateKeyPairSync } from 'node:crypto';

import { describe, expect, it, vi } from 'vitest';

import { LocalEd25519Signer } from '../src/crypto/signed-envelope.js';
import { createAliyunEsaGateway } from '../src/edge-gateway/aliyun-esa.js';
import { InMemoryEdgeConcurrencyLimiter } from '../src/edge-gateway/concurrency-limit.js';
import { encodeEdgeAccessTokenEnvelope } from '../src/edge-gateway/protocol.js';
import { InMemoryEdgeRateLimiter } from '../src/edge-gateway/rate-limit.js';
import { MemoryEdgeRequestLedger } from '../src/edge-gateway/request-ledger.js';
import { StaticEdgeUpstreamOriginPolicy } from '../src/edge-gateway/upstream-origin-policy.js';
import { EdgeGatewayControlService } from '../src/modules/edge-gateway/service.js';

const NOW = Date.parse('2026-08-14T08:00:00.000Z');

async function fixture(options: {
  policyValue?: string | undefined;
  providerSecret?: string | null;
  recordOutcome?: () => Promise<void>;
} = {}) {
  const { privateKey } = generateKeyPairSync('ed25519');
  const signer = new LocalEd25519Signer(
    privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
  );
  const control = new EdgeGatewayControlService({
    signer,
    now: () => NOW,
    id: () => 'esa-adapter-fixture',
  });
  const policy = await control.issuePolicy({
    policyVersion: 'esa-policy-v1',
    deploymentId: 'deployment-esa',
    organizationId: 'organization-esa',
    routes: [{
      id: 'route-esa',
      endpoint: 'chat_completions',
      publicModel: 'otto-fast',
      upstreamModel: 'provider-model',
      upstreamUrl: 'https://provider.example/v1/chat/completions',
      priority: 1,
      authentication: { type: 'bearer', secretBinding: 'PROVIDER_API_KEY' },
    }],
    limits: {
      maxRequestBytes: 4_096,
      requestsPerMinute: 10,
      upstreamConnectTimeoutMs: 5_000,
      upstreamIdleTimeoutMs: 30_000,
      maxRouteAttempts: 1,
    },
  });
  const access = await control.issueAccessToken({
    deploymentId: 'deployment-esa',
    organizationId: 'organization-esa',
    subjectId: 'account-esa',
    policyVersion: 'esa-policy-v1',
    allowedModels: ['otto-fast'],
  });
  const policyKvGet = vi.fn(async () => options.policyValue ?? JSON.stringify(policy));
  const providerSecret = vi.fn(async () => Object.hasOwn(options, 'providerSecret')
    ? options.providerSecret ?? null
    : 'provider-secret');
  const upstreamFetch = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
    expect(new Headers(init?.headers).get('authorization')).toBe('Bearer provider-secret');
    return new Response('{}', { headers: { 'content-type': 'application/json' } });
  }) as typeof fetch;
  return {
    gateway: createAliyunEsaGateway({
      policyKv: { get: policyKvGet },
      policyKey: 'edge-policy',
      controlPublicKeys: { [signer.keyId]: signer.publicKeyPem },
      providerSecret,
      rateLimiter: new InMemoryEdgeRateLimiter(),
      concurrencyLimiter: new InMemoryEdgeConcurrencyLimiter(),
      requestLedger: new MemoryEdgeRequestLedger(),
      recordOutcome: options.recordOutcome
        ? async () => options.recordOutcome!()
        : undefined,
      fetch: upstreamFetch,
      now: () => NOW,
      requestId: () => 'request-esa',
      upstreamOriginPolicy: new StaticEdgeUpstreamOriginPolicy(['https://provider.example']),
    }),
    policyKvGet,
    providerSecret,
    request: new Request('https://edge.example/v1/chat/completions', {
      method: 'POST',
      headers: {
        authorization: `Bearer ${encodeEdgeAccessTokenEnvelope(access)}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({ model: 'otto-fast', messages: [] }),
    }),
  };
}

describe('Aliyun ESA gateway adapter', () => {
  it('registers post-response outcome work with the ESA execution context', async () => {
    let complete!: () => void;
    const pending = new Promise<void>((resolve) => { complete = resolve; });
    const { gateway, request } = await fixture({ recordOutcome: async () => pending });
    const waitUntil = vi.fn<(task: Promise<unknown>) => void>();

    const response = await gateway.fetch(request, { waitUntil });
    await response.text();

    expect(response.status).toBe(200);
    expect(waitUntil).toHaveBeenCalledTimes(2);
    complete();
    await Promise.all(waitUntil.mock.calls.map(([task]) => task));
  });

  it('uses the exact EdgeKV text contract and trims provider credentials', async () => {
    const values = await fixture({ providerSecret: '  provider-secret  ' });
    const response = await values.gateway.fetch(values.request);
    await response.text();

    expect(response.status).toBe(200);
    expect(values.policyKvGet).toHaveBeenCalledWith('edge-policy', { type: 'text' });
    expect(values.providerSecret).toHaveBeenCalledWith('PROVIDER_API_KEY');
  });

  it.each([undefined, null, '', '   '])('fails closed for a missing policy or provider secret %#', async (value) => {
    const values = value === undefined
      ? await fixture({ policyValue: '' })
      : await fixture({ providerSecret: value });
    const response = await values.gateway.fetch(values.request);
    expect(response.status).toBe(503);
    expect(await response.json()).toMatchObject({ error: { code: expect.any(String) } });
  });
});

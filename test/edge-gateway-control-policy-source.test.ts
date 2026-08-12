import { generateKeyPairSync } from 'node:crypto';

import { beforeEach, describe, expect, it, vi } from 'vitest';

import type {
  EdgeGatewayPolicyV1,
  SignedEdgeGatewayPolicyV1,
} from '../src/contracts/edge-gateway.js';
import { signTelemetryRequest } from '../src/crypto/telemetry-request.js';
import { LocalEd25519Signer, signPayload } from '../src/crypto/signed-envelope.js';
import {
  ControlEdgeGatewayPolicySource,
  EdgeControlPolicySourceError,
} from '../src/edge-gateway/control-policy-source.js';
import { createEdgeSignatureVerifier } from '../src/edge-gateway/protocol.js';
import { loadEdgeGatewayServerConfiguration } from '../src/edge-gateway/server.js';

const NOW = Date.parse('2026-08-11T10:00:00.000Z');
const LEASE_TOKEN = 'edge-control-lease-token-with-sufficient-entropy';
const BINDING = {
  licenseId: 'lic_edge_sync',
  deploymentId: 'dep_edge_sync',
  organizationId: 'org_edge_sync',
  machineFingerprint: 'a'.repeat(64),
};

describe('Control edge gateway policy source', () => {
  let now: number;
  let signer: LocalEd25519Signer;
  let verifier: ReturnType<typeof createEdgeSignatureVerifier>;
  let policySequence: number;

  beforeEach(() => {
    now = NOW;
    policySequence = 0;
    const { privateKey } = generateKeyPairSync('ed25519');
    signer = new LocalEd25519Signer(
      privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    );
    verifier = createEdgeSignatureVerifier({ [signer.keyId]: signer.publicKeyPem });
  });

  async function signedPolicy(
    issuedAtMs = now,
    overrides: Partial<EdgeGatewayPolicyV1> = {},
  ): Promise<SignedEdgeGatewayPolicyV1> {
    const policy: EdgeGatewayPolicyV1 = {
      version: 1,
      policyId: `edge_policy_${++policySequence}`,
      policyVersion: 'edge-policy-v1',
      deploymentId: BINDING.deploymentId,
      organizationId: BINDING.organizationId,
      routes: [{
        id: 'route_primary',
        endpoint: 'chat_completions',
        publicModel: 'otto-fast',
        upstreamModel: 'provider-fast',
        upstreamUrl: 'https://provider.test/v1/chat/completions',
        priority: 1,
        authentication: { type: 'bearer', secretBinding: 'PROVIDER_API_KEY' },
      }],
      limits: {
        maxRequestBytes: 65_536,
        requestsPerMinute: 100,
        upstreamConnectTimeoutMs: 5_000,
        upstreamIdleTimeoutMs: 30_000,
        maxRouteAttempts: 1,
      },
      issuedAtMs,
      expiresAtMs: issuedAtMs + 15 * 60 * 1000,
      ...overrides,
    };
    return { policy, ...await signPayload(signer, policy) };
  }

  function response(policy: SignedEdgeGatewayPolicyV1): Response {
    return new Response(JSON.stringify({ policy }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }

  function source(fetchImplementation: typeof fetch, overrides: {
    nonce?: () => string;
    refreshBeforeExpiryMs?: number;
    requestTimeoutMs?: number;
  } = {}) {
    return new ControlEdgeGatewayPolicySource({
      controlBaseUrl: 'https://control.otto.test',
      binding: BINDING,
      leaseToken: LEASE_TOKEN,
      verifier,
      fetch: fetchImplementation,
      now: () => now,
      nonce: overrides.nonce ?? (() => 'edge_sync_nonce_123456789'),
      refreshBeforeExpiryMs: overrides.refreshBeforeExpiryMs,
      requestTimeoutMs: overrides.requestTimeoutMs,
    });
  }

  it('authenticates the Control request and caches a verified policy', async () => {
    const policy = await signedPolicy();
    const fetchMock = vi.fn<typeof fetch>(async (url, init) => {
      expect(url).toBe('https://control.otto.test/v1/edge-gateway/policy/resolve');
      expect(init?.method).toBe('POST');
      expect(init?.redirect).toBe('error');
      expect(init?.body).toBe(JSON.stringify(BINDING));
      const headers = new Headers(init?.headers);
      expect(headers.get('authorization')).toBe(`Bearer ${LEASE_TOKEN}`);
      expect(headers.get('x-otto-timestamp')).toBe(String(NOW));
      expect(headers.get('x-otto-nonce')).toBe('edge_sync_nonce_123456789');
      expect(headers.get('x-otto-signature')).toBe(signTelemetryRequest({
        token: LEASE_TOKEN,
        timestamp: NOW,
        nonce: 'edge_sync_nonce_123456789',
        body: BINDING,
      }));
      return response(policy);
    });
    const policySource = source(fetchMock);

    await expect(policySource.load()).resolves.toEqual(policy);
    now += 30_000;
    await expect(policySource.load()).resolves.toEqual(policy);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('coalesces concurrent refreshes into one Control request', async () => {
    const policy = await signedPolicy();
    let release: ((value: Response) => void) | undefined;
    const fetchMock = vi.fn<typeof fetch>(() => new Promise<Response>((resolve) => {
      release = resolve;
    }));
    const policySource = source(fetchMock);

    const first = policySource.load();
    const second = policySource.load();
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    release!(response(policy));

    await expect(Promise.all([first, second])).resolves.toEqual([policy, policy]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('uses a cached policy only while its signed validity window remains open', async () => {
    const policy = await signedPolicy(NOW, { expiresAtMs: NOW + 120_000 });
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(response(policy))
      .mockRejectedValue(new Error('Control unavailable'));
    const policySource = source(fetchMock);
    await expect(policySource.load()).resolves.toEqual(policy);

    now = NOW + 60_000;
    await expect(policySource.load()).resolves.toEqual(policy);
    now = NOW + 120_000;
    await expect(policySource.load()).rejects.toThrow('Control unavailable');
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it('does not return a cache entry that expires while a failed refresh is in flight', async () => {
    const policy = await signedPolicy(NOW, { expiresAtMs: NOW + 120_000 });
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(response(policy))
      .mockImplementationOnce(async () => {
        now = NOW + 120_000;
        throw new Error('Control unavailable');
      });
    const policySource = source(fetchMock);
    await expect(policySource.load()).resolves.toEqual(policy);

    now = NOW + 60_000;
    await expect(policySource.load()).rejects.toThrow('Control unavailable');
  });

  it('validates a fetched envelope at response time, not request start time', async () => {
    const policy = await signedPolicy(NOW, { expiresAtMs: NOW + 5_000 });
    const fetchMock = vi.fn<typeof fetch>(async () => {
      now = NOW + 5_000;
      return response(policy);
    });

    await expect(source(fetchMock).load()).rejects.toMatchObject({ code: 'EDGE_EXPIRED' });
  });

  it('does not poison the cache with a forged policy or wrong tenant binding', async () => {
    const initial = await signedPolicy(NOW, { expiresAtMs: NOW + 180_000 });
    const forged = await signedPolicy(NOW + 120_000);
    forged.signature = `ed25519:${'a'.repeat(86)}`;
    const wrongBinding = await signedPolicy(NOW + 121_000, {
      organizationId: 'org_other',
    });
    const replacement = await signedPolicy(NOW + 122_000);
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(response(initial))
      .mockResolvedValueOnce(response(forged))
      .mockResolvedValueOnce(response(wrongBinding))
      .mockResolvedValueOnce(response(replacement));
    const policySource = source(fetchMock);

    await expect(policySource.load()).resolves.toEqual(initial);
    now = NOW + 120_000;
    await expect(policySource.load()).resolves.toEqual(initial);
    now += 1_000;
    await expect(policySource.load()).resolves.toEqual(initial);
    now += 1_000;
    await expect(policySource.load()).resolves.toEqual(replacement);
  });

  it('rejects rollback and same-timestamp equivocation without replacing valid cache', async () => {
    const initial = await signedPolicy(NOW + 30_000, { expiresAtMs: NOW + 180_000 });
    const rollback = await signedPolicy(NOW + 20_000);
    const equivocation = await signedPolicy(NOW + 30_000);
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(response(initial))
      .mockResolvedValueOnce(response(rollback))
      .mockResolvedValueOnce(response(equivocation));
    const policySource = source(fetchMock);

    await expect(policySource.load()).resolves.toEqual(initial);
    now = NOW + 120_000;
    await expect(policySource.load()).resolves.toEqual(initial);
    now += 1;
    await expect(policySource.load()).resolves.toEqual(initial);
  });

  it('accepts an identical envelope refresh but rejects changed content under the same identity', async () => {
    const initial = await signedPolicy(NOW, {
      policyId: 'edge_policy_stable',
      expiresAtMs: NOW + 180_000,
    });
    const changedPolicy = {
      ...initial.policy,
      policyVersion: 'edge-policy-v2',
    };
    const changed = { policy: changedPolicy, ...await signPayload(signer, changedPolicy) };
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(response(initial))
      .mockResolvedValueOnce(response(initial))
      .mockResolvedValueOnce(response(changed));
    const policySource = source(fetchMock);

    await expect(policySource.load()).resolves.toEqual(initial);
    now = NOW + 120_000;
    await expect(policySource.load()).resolves.toEqual(initial);
    now += 1;
    await expect(policySource.load()).resolves.toEqual(initial);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it('normalizes surrounding configuration whitespace and generates a secure default nonce', async () => {
    const policy = await signedPolicy();
    const fetchMock = vi.fn<typeof fetch>(async (_url, init) => {
      const headers = new Headers(init?.headers);
      expect(headers.get('authorization')).toBe(`Bearer ${LEASE_TOKEN}`);
      expect(headers.get('x-otto-nonce')).toMatch(/^[a-zA-Z0-9_-]{32}$/u);
      expect(init?.body).toBe(JSON.stringify(BINDING));
      return response(policy);
    });
    const policySource = new ControlEdgeGatewayPolicySource({
      controlBaseUrl: '  https://control.otto.test  ',
      binding: {
        licenseId: ` ${BINDING.licenseId} `,
        deploymentId: ` ${BINDING.deploymentId} `,
        organizationId: ` ${BINDING.organizationId} `,
        machineFingerprint: ` ${BINDING.machineFingerprint.toUpperCase()} `,
      },
      leaseToken: ` ${LEASE_TOKEN} `,
      verifier,
      fetch: fetchMock,
      now: () => now,
    });

    await expect(policySource.load()).resolves.toEqual(policy);
  });

  it.each([
    { licenseId: '!invalid' },
    { licenseId: `a${'b'.repeat(160)}` },
    { deploymentId: 'invalid!' },
    { organizationId: 'invalid org' },
    { machineFingerprint: `g${'a'.repeat(63)}` },
    { machineFingerprint: `${'a'.repeat(64)}0` },
  ])('rejects each invalid deployment binding component %#', (override) => {
    expect(() => new ControlEdgeGatewayPolicySource({
      controlBaseUrl: 'https://control.otto.test',
      binding: { ...BINDING, ...override },
      leaseToken: LEASE_TOKEN,
      verifier,
    })).toThrow('Control policy binding is invalid');
  });

  it('enforces exact option and lease-token boundaries', () => {
    const create = (input: Partial<ConstructorParameters<
      typeof ControlEdgeGatewayPolicySource
    >[0]> = {}) => new ControlEdgeGatewayPolicySource({
      controlBaseUrl: 'https://control.otto.test',
      binding: BINDING,
      leaseToken: LEASE_TOKEN,
      verifier,
      ...input,
    });

    expect(() => create({ leaseToken: 'x'.repeat(32) })).not.toThrow();
    expect(() => create({ leaseToken: 'x'.repeat(8_192) })).not.toThrow();
    expect(() => create({ leaseToken: `x${' '.repeat(1)}y`.padEnd(32, 'x') }))
      .toThrow('Control lease token is invalid');
    for (const refreshBeforeExpiryMs of [4_999, 3_600_001, 1.5, Number.NaN]) {
      expect(() => create({ refreshBeforeExpiryMs })).toThrow('refresh window');
    }
    for (const requestTimeoutMs of [499, 60_001, 1.5, Number.NaN]) {
      expect(() => create({ requestTimeoutMs })).toThrow('request timeout');
    }
    expect(() => create({ refreshBeforeExpiryMs: 5_000, requestTimeoutMs: 500 }))
      .not.toThrow();
    expect(() => create({ refreshBeforeExpiryMs: 3_600_000, requestTimeoutMs: 60_000 }))
      .not.toThrow();
  });

  it.each([
    'short',
    `prefix_${'a'.repeat(128)}`,
    '!invalid_nonce_123456789',
  ])('rejects an invalid nonce before making a request: %s', async (nonce) => {
    const fetchMock = vi.fn<typeof fetch>();
    await expect(source(fetchMock, { nonce: () => nonce }).load()).rejects.toMatchObject({
      code: 'EDGE_CONTROL_CONFIGURATION_INVALID',
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([null, [], 'invalid', 42])(
    'rejects non-object Control response payload: %j',
    async (payload) => {
      const policySource = source(vi.fn<typeof fetch>(async () => new Response(
        JSON.stringify(payload),
      )));
      await expect(policySource.load()).rejects.toMatchObject({
        code: 'EDGE_CONTROL_RESPONSE_INVALID',
      });
    },
  );

  it('rejects a missing body, invalid JSON, and streamed response overflow', async () => {
    const missing = source(vi.fn<typeof fetch>(async () => new Response(null)));
    await expect(missing.load()).rejects.toMatchObject({
      code: 'EDGE_CONTROL_RESPONSE_INVALID',
    });

    const malformed = source(vi.fn<typeof fetch>(async () => new Response('{')));
    await expect(malformed.load()).rejects.toMatchObject({
      code: 'EDGE_CONTROL_RESPONSE_INVALID',
    });

    const overflow = source(vi.fn<typeof fetch>(async () => new Response(
      'x'.repeat(256 * 1024 + 1),
    )));
    await expect(overflow.load()).rejects.toMatchObject({
      code: 'EDGE_CONTROL_RESPONSE_INVALID',
    });
  });

  it('reassembles a multi-chunk response without corrupting byte offsets', async () => {
    const policy = await signedPolicy();
    const bytes = new TextEncoder().encode(JSON.stringify({ policy }));
    const split = Math.floor(bytes.byteLength / 2);
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(bytes.slice(0, split));
        controller.enqueue(bytes.slice(split));
        controller.close();
      },
    });
    const policySource = source(vi.fn<typeof fetch>(async () => new Response(stream)));
    await expect(policySource.load()).resolves.toEqual(policy);
  });

  it.each([
    '-1',
    '1.5',
    'not-a-number',
    String(256 * 1024 + 1),
  ])('rejects invalid declared response length %s', async (contentLength) => {
    const policySource = source(vi.fn<typeof fetch>(async () => new Response('{}', {
      headers: { 'content-length': contentLength },
    })));
    await expect(policySource.load()).rejects.toMatchObject({
      code: 'EDGE_CONTROL_RESPONSE_INVALID',
    });
  });

  it('accepts the exact maximum declared response length', async () => {
    const policy = await signedPolicy();
    const policySource = source(vi.fn<typeof fetch>(async () => response(policy)));
    const exactResponse = response(policy);
    exactResponse.headers.set('content-length', String(256 * 1024));
    const exactSource = source(vi.fn<typeof fetch>(async () => exactResponse));
    await expect(exactSource.load()).resolves.toEqual(policy);
    await expect(policySource.load()).resolves.toEqual(policy);
  });

  it('fails closed for a signed policy with the wrong deployment', async () => {
    const policy = await signedPolicy(NOW, { deploymentId: 'dep_other' });
    await expect(source(vi.fn<typeof fetch>(async () => response(policy))).load())
      .rejects.toMatchObject({ code: 'EDGE_CONTROL_BINDING_MISMATCH' });
  });

  it('preserves a network failure when no valid cached policy exists', async () => {
    const failure = new Error('network unavailable');
    await expect(source(vi.fn<typeof fetch>(async () => {
      throw failure;
    })).load()).rejects.toBe(failure);
  });

  it('fails closed for invalid response wrappers, oversized bodies, and HTTP errors', async () => {
    const invalid = source(vi.fn<typeof fetch>(async () => new Response(
      JSON.stringify({ policy: await signedPolicy(), extra: true }),
    )));
    await expect(invalid.load()).rejects.toMatchObject({
      code: 'EDGE_CONTROL_RESPONSE_INVALID',
    });

    const oversized = source(vi.fn<typeof fetch>(async () => new Response('{}', {
      headers: { 'content-length': String(256 * 1024 + 1) },
    })));
    await expect(oversized.load()).rejects.toMatchObject({
      code: 'EDGE_CONTROL_RESPONSE_INVALID',
    });

    const rejected = source(vi.fn<typeof fetch>(async () => new Response('secret details', {
      status: 503,
    })));
    await expect(rejected.load()).rejects.toMatchObject({
      code: 'EDGE_CONTROL_UNAVAILABLE',
      message: 'Control rejected the policy request',
    });
  });

  it('aborts a stalled Control request at the configured timeout', async () => {
    vi.useFakeTimers();
    try {
      const fetchMock = vi.fn<typeof fetch>((_url, init) => new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new DOMException(
          'aborted',
          'AbortError',
        )), { once: true });
      }));
      const policySource = source(fetchMock, { requestTimeoutMs: 500 });
      const pending = policySource.load();
      const rejection = expect(pending).rejects.toMatchObject({
        code: 'EDGE_CONTROL_TIMEOUT',
      });
      await vi.advanceTimersByTimeAsync(500);
      await rejection;
    } finally {
      vi.useRealTimers();
    }
  });

  it.each([
    ['not a URL', BINDING, LEASE_TOKEN],
    ['http://control.otto.test', BINDING, LEASE_TOKEN],
    ['https://user:pass@control.otto.test', BINDING, LEASE_TOKEN],
    ['https://control.otto.test?tenant=a', BINDING, LEASE_TOKEN],
    ['https://control.otto.test', { ...BINDING, machineFingerprint: 'bad' }, LEASE_TOKEN],
    ['https://control.otto.test', BINDING, 'short'],
  ])('rejects unsafe configuration %#', (controlBaseUrl, policyBinding, leaseToken) => {
    expect(() => new ControlEdgeGatewayPolicySource({
      controlBaseUrl,
      binding: policyBinding,
      leaseToken,
      verifier,
    })).toThrow(EdgeControlPolicySourceError);
  });
});

describe('edge gateway server configuration', () => {
  const common = { OTTO_EDGE_CONTROL_PUBLIC_KEYS_FILE: 'D:\\secure\\keys.json' };

  it('keeps file mode for development and offline deployments', () => {
    expect(loadEdgeGatewayServerConfiguration({
      ...common,
      OTTO_EDGE_POLICY_FILE: 'D:\\secure\\policy.json',
    })).toMatchObject({
      host: '127.0.0.1',
      port: 7790,
      policy: { type: 'file', policyFile: 'D:\\secure\\policy.json' },
      rateLimit: { type: 'memory' },
      concurrency: { globalLimit: 256, perSubjectLimit: 8 },
    });
  });

  it('loads production Redis limiting, ban and key-privacy configuration', () => {
    expect(loadEdgeGatewayServerConfiguration({
      ...common,
      OTTO_EDGE_POLICY_FILE: 'D:\\secure\\policy.json',
      OTTO_EDGE_RATE_LIMIT_BACKEND: 'redis',
      OTTO_EDGE_REDIS_URL: 'rediss://redis.internal:6379/2',
      OTTO_EDGE_RATE_LIMIT_KEY_FILE: 'D:\\secure\\edge-rate-limit.key',
      OTTO_EDGE_RATE_LIMIT_PREFIX: 'otto-production',
      OTTO_EDGE_REDIS_CONNECT_TIMEOUT_MS: '2500',
      OTTO_EDGE_RATE_LIMIT_BAN_THRESHOLD: '12',
      OTTO_EDGE_RATE_LIMIT_STRIKE_WINDOW_MS: '180000',
      OTTO_EDGE_RATE_LIMIT_BAN_MS: '900000',
      OTTO_EDGE_REDIS_ALLOW_INSECURE: 'false',
      OTTO_EDGE_MAX_CONCURRENT_REQUESTS: '512',
      OTTO_EDGE_MAX_CONCURRENT_REQUESTS_PER_SUBJECT: '12',
    })).toMatchObject({
      rateLimit: {
        type: 'redis',
        connectionString: 'rediss://redis.internal:6379/2',
        keySecretFile: 'D:\\secure\\edge-rate-limit.key',
        keyPrefix: 'otto-production',
        connectTimeoutMs: 2500,
        banThreshold: 12,
        strikeWindowMs: 180000,
        banMs: 900000,
        allowInsecure: false,
      },
      concurrency: { globalLimit: 512, perSubjectLimit: 12 },
    });
  });

  it('loads managed Control mode without putting the lease token in environment', () => {
    expect(loadEdgeGatewayServerConfiguration({
      ...common,
      OTTO_EDGE_CONTROL_URL: 'https://control.otto.test',
      OTTO_EDGE_DEPLOYMENT_IDENTITY_FILE: 'D:\\secure\\identity.json',
      OTTO_EDGE_LEASE_TOKEN_FILE: 'D:\\secure\\lease-token',
      OTTO_EDGE_CONTROL_TIMEOUT_MS: '2500',
      OTTO_EDGE_POLICY_REFRESH_BEFORE_EXPIRY_MS: '30000',
      OTTO_EDGE_KEYRING_REFRESH_INTERVAL_MS: '45000',
      OTTO_EDGE_KEYRING_REFRESH_BEFORE_EXPIRY_MS: '20000',
      OTTO_EDGE_UNKNOWN_KEY_RETRY_MS: '5000',
      OTTO_EDGE_KEYRING_FAILURE_RETRY_MS: '3000',
    })).toMatchObject({
      policy: {
        type: 'control',
        controlBaseUrl: 'https://control.otto.test',
        identityFile: 'D:\\secure\\identity.json',
        leaseTokenFile: 'D:\\secure\\lease-token',
        requestTimeoutMs: 2500,
        refreshBeforeExpiryMs: 30000,
        keyringRefreshIntervalMs: 45000,
        keyringRefreshBeforeExpiryMs: 20000,
        unknownKeyRetryMs: 5000,
        keyringFailureRetryMs: 3000,
      },
    });
  });

  it('loads explicit durable Control billing without putting keys in environment', () => {
    expect(loadEdgeGatewayServerConfiguration({
      ...common,
      OTTO_EDGE_CONTROL_URL: 'https://control.otto.test',
      OTTO_EDGE_DEPLOYMENT_IDENTITY_FILE: 'D:\\secure\\identity.json',
      OTTO_EDGE_LEASE_TOKEN_FILE: 'D:\\secure\\lease-token',
      OTTO_EDGE_BILLING_BACKEND: 'control',
      OTTO_EDGE_EXECUTION_RECEIPT_KEY_FILE: 'D:\\secure\\receipt-private.pem',
      OTTO_EDGE_BILLING_JOURNAL_FILE: 'D:\\state\\edge-billing.ndjson',
      OTTO_EDGE_BILLING_RETRY_INTERVAL_MS: '5000',
      OTTO_EDGE_OPERATIONS_TOKEN_FILE: 'D:\\secure\\edge-operations.token',
    })).toMatchObject({
      billing: {
        type: 'control',
        receiptPrivateKeyFile: 'D:\\secure\\receipt-private.pem',
        journalFile: 'D:\\state\\edge-billing.ndjson',
        retryIntervalMs: 5000,
      },
      operationsTokenFile: 'D:\\secure\\edge-operations.token',
    });
  });

  it('rejects ambiguous or out-of-range managed configuration', () => {
    expect(() => loadEdgeGatewayServerConfiguration({
      ...common,
      OTTO_EDGE_CONTROL_URL: 'https://control.otto.test',
      OTTO_EDGE_POLICY_FILE: 'D:\\secure\\policy.json',
    })).toThrow('cannot both be set');
    expect(() => loadEdgeGatewayServerConfiguration({
      ...common,
      OTTO_EDGE_CONTROL_URL: 'https://control.otto.test',
      OTTO_EDGE_DEPLOYMENT_IDENTITY_FILE: 'D:\\secure\\identity.json',
      OTTO_EDGE_LEASE_TOKEN_FILE: 'D:\\secure\\lease-token',
      OTTO_EDGE_CONTROL_TIMEOUT_MS: '499',
    })).toThrow('OTTO_EDGE_CONTROL_TIMEOUT_MS');
    expect(() => loadEdgeGatewayServerConfiguration({
      ...common,
      OTTO_EDGE_POLICY_FILE: 'D:\\secure\\policy.json',
      OTTO_EDGE_REDIS_URL: 'rediss://redis.internal:6379',
    })).toThrow('OTTO_EDGE_RATE_LIMIT_BACKEND=redis');
    expect(() => loadEdgeGatewayServerConfiguration({
      ...common,
      OTTO_EDGE_POLICY_FILE: 'D:\\secure\\policy.json',
      OTTO_EDGE_RATE_LIMIT_BACKEND: 'redis',
      OTTO_EDGE_REDIS_URL: 'rediss://redis.internal:6379',
    })).toThrow('OTTO_EDGE_RATE_LIMIT_KEY_FILE');
    expect(() => loadEdgeGatewayServerConfiguration({
      ...common,
      OTTO_EDGE_POLICY_FILE: 'D:\\secure\\policy.json',
      OTTO_EDGE_RATE_LIMIT_BACKEND: 'other',
    })).toThrow('must be memory or redis');
    expect(() => loadEdgeGatewayServerConfiguration({
      ...common,
      OTTO_EDGE_POLICY_FILE: 'D:\\secure\\policy.json',
      OTTO_EDGE_RATE_LIMIT_BACKEND: 'redis',
      OTTO_EDGE_REDIS_URL: 'rediss://redis.internal:6379',
      OTTO_EDGE_RATE_LIMIT_KEY_FILE: 'D:\\secure\\key',
      OTTO_EDGE_REDIS_ALLOW_INSECURE: 'yes',
    })).toThrow('must be true or false');
    expect(() => loadEdgeGatewayServerConfiguration({
      ...common,
      OTTO_EDGE_POLICY_FILE: 'D:\\secure\\policy.json',
      OTTO_EDGE_EXECUTION_RECEIPT_KEY_FILE: 'D:\\secure\\receipt-private.pem',
    })).toThrow('OTTO_EDGE_BILLING_BACKEND=control');
    expect(() => loadEdgeGatewayServerConfiguration({
      ...common,
      OTTO_EDGE_POLICY_FILE: 'D:\\secure\\policy.json',
      OTTO_EDGE_BILLING_BACKEND: 'control',
      OTTO_EDGE_EXECUTION_RECEIPT_KEY_FILE: 'D:\\secure\\receipt-private.pem',
      OTTO_EDGE_BILLING_JOURNAL_FILE: 'D:\\state\\edge-billing.ndjson',
    })).toThrow('requires OTTO_EDGE_CONTROL_URL');
    expect(() => loadEdgeGatewayServerConfiguration({
      ...common,
      OTTO_EDGE_CONTROL_URL: 'https://control.otto.test',
      OTTO_EDGE_DEPLOYMENT_IDENTITY_FILE: 'D:\\secure\\identity.json',
      OTTO_EDGE_LEASE_TOKEN_FILE: 'D:\\secure\\lease-token',
      OTTO_EDGE_BILLING_BACKEND: 'control',
      OTTO_EDGE_EXECUTION_RECEIPT_KEY_FILE: 'D:\\secure\\receipt-private.pem',
    })).toThrow('OTTO_EDGE_BILLING_JOURNAL_FILE');
    expect(() => loadEdgeGatewayServerConfiguration({
      ...common,
      OTTO_EDGE_POLICY_FILE: 'D:\\secure\\policy.json',
      OTTO_EDGE_MAX_CONCURRENT_REQUESTS: '0',
    })).toThrow('OTTO_EDGE_MAX_CONCURRENT_REQUESTS');
    expect(() => loadEdgeGatewayServerConfiguration({
      ...common,
      OTTO_EDGE_POLICY_FILE: 'D:\\secure\\policy.json',
      OTTO_EDGE_MAX_CONCURRENT_REQUESTS: '4',
      OTTO_EDGE_MAX_CONCURRENT_REQUESTS_PER_SUBJECT: '5',
    })).toThrow('cannot exceed');
  });
});

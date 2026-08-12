import { generateKeyPairSync } from 'node:crypto';

import { beforeEach, describe, expect, it } from 'vitest';

import type {
  EdgeModelRouteV1,
  SignedEdgeAccessTokenV1,
  SignedEdgeGatewayPolicyV1,
} from '../src/contracts/edge-gateway.js';
import { LocalEd25519Signer } from '../src/crypto/signed-envelope.js';
import {
  createEdgeSignatureVerifier,
  decodeEdgeAccessTokenEnvelope,
  edgeCanonicalJson,
  encodeEdgeAccessTokenEnvelope,
  normalizeSignedEdgeAccessToken,
  normalizeSignedEdgeGatewayPolicy,
  verifyEdgeAccessToken,
  verifyGatewayPolicy,
} from '../src/edge-gateway/protocol.js';
import { EdgeGatewayControlService } from '../src/modules/edge-gateway/service.js';

const NOW = Date.parse('2026-08-11T12:00:00.000Z');
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
const MAX_TOKEN_DURATION_MS = 15 * 60 * 1000;
const MAX_POLICY_DURATION_MS = 24 * 60 * 60 * 1000;

const route: EdgeModelRouteV1 = {
  id: 'route_protocol',
  endpoint: 'chat_completions',
  publicModel: 'otto-fast',
  upstreamModel: 'provider-model',
  upstreamUrl: 'https://provider.test/v1/chat/completions',
  priority: 10,
  authentication: { type: 'bearer', secretBinding: 'PROVIDER_API_KEY' },
};

describe('edge gateway signed protocol boundaries', () => {
  let signer: LocalEd25519Signer;
  let policy: SignedEdgeGatewayPolicyV1;
  let token: SignedEdgeAccessTokenV1;

  beforeEach(async () => {
    const { privateKey } = generateKeyPairSync('ed25519');
    signer = new LocalEd25519Signer(
      privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    );
    let id = 0;
    const control = new EdgeGatewayControlService({
      signer,
      now: () => NOW,
      id: () => `protocol_${++id}`,
    });
    policy = await control.issuePolicy({
      deploymentId: 'dep_protocol',
      organizationId: 'org_protocol',
      policyVersion: 'policy-v1',
      routes: [route],
      limits: {
        maxRequestBytes: 1_024,
        requestsPerMinute: 1,
        upstreamConnectTimeoutMs: 500,
        upstreamIdleTimeoutMs: 1_000,
        maxRouteAttempts: 1,
      },
    });
    token = await control.issueAccessToken({
      deploymentId: 'dep_protocol',
      organizationId: 'org_protocol',
      subjectId: 'account_protocol',
      policyVersion: 'policy-v1',
      allowedModels: ['otto-fast'],
    });
  });

  const invalidPolicy = (candidate: unknown, now = NOW) => {
    expect(() => normalizeSignedEdgeGatewayPolicy(candidate, now)).toThrow(expect.objectContaining({
      code: expect.stringMatching(/^EDGE_/u),
    }));
  };

  const invalidToken = (candidate: unknown, now = NOW) => {
    expect(() => normalizeSignedEdgeAccessToken(candidate, now)).toThrow(expect.objectContaining({
      code: expect.stringMatching(/^EDGE_/u),
    }));
  };

  it('canonicalizes nested objects deterministically without changing arrays', () => {
    expect(edgeCanonicalJson({ z: 1, a: { y: 2, x: 1 }, list: [{ b: 2, a: 1 }] }))
      .toBe('{"a":{"x":1,"y":2},"list":[{"a":1,"b":2}],"z":1}');
    expect(edgeCanonicalJson([3, { b: 2, a: 1 }])).toBe('[3,{"a":1,"b":2}]');
  });

  it('requires exact object shapes at every policy nesting level', () => {
    for (const candidate of [null, undefined, [], 'policy', 7]) invalidPolicy(candidate);
    invalidPolicy({ ...policy, extra: true });
    invalidPolicy({ ...policy, policy: { ...policy.policy, extra: true } });
    invalidPolicy({ ...policy, policy: { ...policy.policy, routes: [{ ...route, extra: true }] } });
    invalidPolicy({
      ...policy,
      policy: { ...policy.policy, limits: { ...policy.policy.limits, extra: true } },
    });
    invalidPolicy({
      ...policy,
      policy: {
        ...policy.policy,
        routes: [{ ...route, authentication: { ...route.authentication, extra: true } }],
      },
    });
    invalidPolicy({ ...policy, policy: [] });
    invalidPolicy({ ...policy, policy: { ...policy.policy, routes: [null] } });
    invalidPolicy({ ...policy, policy: { ...policy.policy, limits: null } });
  });

  it('enforces policy identifiers, signatures, route counts, and endpoints', () => {
    for (const policyVersion of ['', 7, '_invalid', 'bad value', `a${'x'.repeat(160)}`]) {
      invalidPolicy({ ...policy, policy: { ...policy.policy, policyVersion } });
    }
    expect(normalizeSignedEdgeGatewayPolicy({
      ...policy,
      policy: { ...policy.policy, policyVersion: `a${'x'.repeat(159)}` },
    }, NOW).policy.policyVersion).toHaveLength(160);
    for (const signature of ['', 'ed25519:short', `ed25519:${'a'.repeat(85)}`, `ed25519:${'a'.repeat(87)}`]) {
      invalidPolicy({ ...policy, signature });
    }
    for (const routes of [null, {}, [], Array.from({ length: 65 }, (_, index) => ({
      ...route,
      id: `route_${index}`,
    }))]) {
      invalidPolicy({ ...policy, policy: { ...policy.policy, routes } });
    }
    invalidPolicy({
      ...policy,
      policy: { ...policy.policy, routes: [route, { ...route }] },
    });
    invalidPolicy({
      ...policy,
      policy: { ...policy.policy, routes: [{ ...route, endpoint: 'embeddings' }] },
    });
    expect(normalizeSignedEdgeGatewayPolicy({
      ...policy,
      policy: { ...policy.policy, routes: [{ ...route, endpoint: 'responses' }] },
    }, NOW).policy.routes[0]?.endpoint).toBe('responses');
  });

  it('enforces HTTPS route, authentication binding, and custom-header boundaries', () => {
    for (const upstreamUrl of [
      'not-a-url',
      'http://provider.test/v1',
      'https://user:pass@provider.test/v1',
      'https://provider.test/v1?key=value',
      'https://provider.test/v1#fragment',
    ]) {
      invalidPolicy({
        ...policy,
        policy: { ...policy.policy, routes: [{ ...route, upstreamUrl }] },
      });
    }
    for (const authentication of [
      null,
      { type: 'unknown', secretBinding: 'PROVIDER_API_KEY' },
      { type: 'bearer' },
      { type: 'bearer', secretBinding: 'ab' },
      { type: 'bearer', secretBinding: 'lowercase_key' },
      { type: 'bearer', secretBinding: `${'A'.repeat(128)}X` },
      { type: 'header', headerName: 'cookie', secretBinding: 'PROVIDER_API_KEY' },
      { type: 'header', headerName: 'bad header', secretBinding: 'PROVIDER_API_KEY' },
      { type: 'header', headerName: 'x'.repeat(81), secretBinding: 'PROVIDER_API_KEY' },
    ]) {
      invalidPolicy({
        ...policy,
        policy: { ...policy.policy, routes: [{ ...route, authentication }] },
      });
    }
    const maximumBinding = `A${'B'.repeat(127)}`;
    const maximumHeader = `x${'a'.repeat(79)}`;
    const normalized = normalizeSignedEdgeGatewayPolicy({
      ...policy,
      policy: {
        ...policy.policy,
        routes: [{
          ...route,
          authentication: {
            type: 'header',
            headerName: maximumHeader,
            secretBinding: maximumBinding,
          },
        }],
      },
    }, NOW);
    expect(normalized.policy.routes[0]?.authentication).toEqual({
      type: 'header',
      headerName: maximumHeader,
      secretBinding: maximumBinding,
    });
  });

  it('normalizes exact usage metering policies and rejects unsafe reservation bounds', () => {
    for (const reserveUnits of [1, 10_000_000]) {
      const normalized = normalizeSignedEdgeGatewayPolicy({
        ...policy,
        policy: {
          ...policy.policy,
          routes: [{
            ...route,
            metering: { type: 'openai_tokens', reserveUnits },
          }],
        },
      }, NOW);
      expect(normalized.policy.routes[0]?.metering).toEqual({
        type: 'openai_tokens',
        reserveUnits,
      });
    }
    for (const metering of [
      null,
      {},
      { type: 'unknown', reserveUnits: 1 },
      { type: 'openai_tokens', reserveUnits: 0 },
      { type: 'openai_tokens', reserveUnits: 10_000_001 },
      { type: 'openai_tokens', reserveUnits: 1.5 },
      { type: 'openai_tokens', reserveUnits: 1, extra: true },
    ]) {
      invalidPolicy({
        ...policy,
        policy: { ...policy.policy, routes: [{ ...route, metering }] },
      });
    }
  });

  it('accepts exact limit boundaries and rejects every adjacent out-of-range value', () => {
    const cases = [
      ['maxRequestBytes', 1_024, 20 * 1_024 * 1_024, 1_023, 20 * 1_024 * 1_024 + 1],
      ['requestsPerMinute', 1, 1_000_000, 0, 1_000_001],
      ['upstreamConnectTimeoutMs', 500, 60_000, 499, 60_001],
      ['upstreamIdleTimeoutMs', 1_000, 300_000, 999, 300_001],
      ['maxRouteAttempts', 1, 8, 0, 9],
    ] as const;
    for (const [field, minimum, maximum, below, above] of cases) {
      for (const value of [minimum, maximum]) {
        const normalized = normalizeSignedEdgeGatewayPolicy({
          ...policy,
          policy: {
            ...policy.policy,
            limits: { ...policy.policy.limits, [field]: value },
          },
        }, NOW);
        expect(normalized.policy.limits[field]).toBe(value);
      }
      for (const value of [below, above, 1.5, Number.NaN]) {
        invalidPolicy({
          ...policy,
          policy: {
            ...policy.policy,
            limits: { ...policy.policy.limits, [field]: value },
          },
        });
      }
    }
  });

  it('enforces policy clock skew, expiry, ordering, and maximum duration exactly', () => {
    const atFutureBoundary = {
      ...policy,
      policy: {
        ...policy.policy,
        issuedAtMs: NOW + MAX_CLOCK_SKEW_MS,
        expiresAtMs: NOW + MAX_CLOCK_SKEW_MS + 1,
      },
    };
    expect(normalizeSignedEdgeGatewayPolicy(atFutureBoundary, NOW).policy.issuedAtMs)
      .toBe(NOW + MAX_CLOCK_SKEW_MS);
    invalidPolicy({
      ...atFutureBoundary,
      policy: {
        ...atFutureBoundary.policy,
        issuedAtMs: NOW + MAX_CLOCK_SKEW_MS + 1,
        expiresAtMs: NOW + MAX_CLOCK_SKEW_MS + 2,
      },
    });
    expect(normalizeSignedEdgeGatewayPolicy({
      ...policy,
      policy: { ...policy.policy, issuedAtMs: NOW, expiresAtMs: NOW + MAX_POLICY_DURATION_MS },
    }, NOW).policy.expiresAtMs).toBe(NOW + MAX_POLICY_DURATION_MS);
    invalidPolicy({
      ...policy,
      policy: { ...policy.policy, issuedAtMs: NOW, expiresAtMs: NOW + MAX_POLICY_DURATION_MS + 1 },
    });
    invalidPolicy({
      ...policy,
      policy: { ...policy.policy, issuedAtMs: NOW, expiresAtMs: NOW },
    });
    invalidPolicy({
      ...policy,
      policy: { ...policy.policy, issuedAtMs: NOW + 1, expiresAtMs: NOW },
    });
    invalidPolicy({
      ...policy,
      policy: { ...policy.policy, issuedAtMs: NOW - 1, expiresAtMs: NOW },
    });
    expect(normalizeSignedEdgeGatewayPolicy({
      ...policy,
      policy: { ...policy.policy, issuedAtMs: NOW - 1, expiresAtMs: NOW + 1 },
    }, NOW).policy.expiresAtMs).toBe(NOW + 1);
  });

  it('enforces token version, scope, model list, identifier, and duration boundaries', () => {
    invalidToken({ ...token, token: { ...token.token, version: 2 } });
    invalidToken({ ...token, token: { ...token.token, scope: 'admin' } });
    for (const allowedModels of [
      null,
      {},
      [],
      Array.from({ length: 65 }, (_, index) => `model-${index}`),
      [7],
      [''],
      ['x'.repeat(161)],
      ['otto-fast', 'otto-fast'],
    ]) {
      invalidToken({ ...token, token: { ...token.token, allowedModels } });
    }
    expect(normalizeSignedEdgeAccessToken({
      ...token,
      token: { ...token.token, allowedModels: ['x'.repeat(160)] },
    }, NOW).token.allowedModels[0]).toHaveLength(160);
    invalidToken({ ...token, token: { ...token.token, subjectId: '_bad' } });
    expect(normalizeSignedEdgeAccessToken({
      ...token,
      token: {
        ...token.token,
        issuedAtMs: NOW,
        expiresAtMs: NOW + MAX_TOKEN_DURATION_MS,
      },
    }, NOW).token.expiresAtMs).toBe(NOW + MAX_TOKEN_DURATION_MS);
    invalidToken({
      ...token,
      token: {
        ...token.token,
        issuedAtMs: NOW,
        expiresAtMs: NOW + MAX_TOKEN_DURATION_MS + 1,
      },
    });
  });

  it('round-trips encoded tokens and rejects malformed base64url, UTF-8, JSON, and size', () => {
    const encoded = encodeEdgeAccessTokenEnvelope(token);
    expect(decodeEdgeAccessTokenEnvelope(encoded, NOW)).toEqual(token);
    for (const malformed of [
      '',
      '!',
      'a'.repeat(16_385),
      Buffer.from('{', 'utf8').toString('base64url'),
      Buffer.from('[]', 'utf8').toString('base64url'),
      Buffer.from([0xff, 0xfe]).toString('base64url'),
    ]) {
      expect(() => decodeEdgeAccessTokenEnvelope(malformed, NOW)).toThrow(expect.objectContaining({
        code: 'EDGE_UNAUTHORIZED',
      }));
    }
    const withUnsupportedField = Buffer.from(JSON.stringify({ ...token, extra: true }), 'utf8')
      .toString('base64url');
    expect(() => decodeEdgeAccessTokenEnvelope(withUnsupportedField, NOW)).toThrow();
  });

  it('verifies valid signatures and fails closed for unknown keys and modified payloads', async () => {
    const verifier = createEdgeSignatureVerifier({ [signer.keyId]: signer.publicKeyPem });
    await expect(verifyGatewayPolicy(policy, verifier)).resolves.toEqual(policy.policy);
    await expect(verifyEdgeAccessToken(token, verifier)).resolves.toEqual(token.token);
    const modifiedPolicy = {
      ...policy,
      policy: { ...policy.policy, organizationId: 'org_attacker' },
    };
    await expect(verifyGatewayPolicy(modifiedPolicy, verifier)).rejects.toMatchObject({
      code: 'EDGE_POLICY_SIGNATURE_INVALID',
    });
    const modifiedToken = {
      ...token,
      token: { ...token.token, subjectId: 'account_attacker' },
    };
    await expect(verifyEdgeAccessToken(modifiedToken, verifier)).rejects.toMatchObject({
      code: 'EDGE_UNAUTHORIZED',
    });
    const unknown = createEdgeSignatureVerifier({});
    await expect(verifyEdgeAccessToken(token, unknown)).rejects.toMatchObject({
      code: 'EDGE_UNAUTHORIZED',
    });
  });
});

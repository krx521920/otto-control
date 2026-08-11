import { generateKeyPairSync } from 'node:crypto';

import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import type { EdgeAccessTokenV1, EdgeModelRouteV1 } from '../src/contracts/edge-gateway.js';
import { LocalEd25519Signer } from '../src/crypto/signed-envelope.js';
import {
  createEdgeSignatureVerifier,
  decodeEdgeAccessTokenEnvelope,
  EdgeGatewayProtocolError,
} from '../src/edge-gateway/protocol.js';
import { InMemoryEdgeRateLimiter } from '../src/edge-gateway/rate-limit.js';
import { EdgeGatewayControlService } from '../src/modules/edge-gateway/service.js';

const NOW = Date.parse('2026-08-11T08:00:00.000Z');

function signerFixture() {
  const { privateKey } = generateKeyPairSync('ed25519');
  return new LocalEd25519Signer(
    privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
  );
}

describe('edge gateway property and fuzz testing', () => {
  it('allows exactly the configured number of requests in every generated limit', async () => {
    await fc.assert(fc.asyncProperty(
      fc.integer({ min: 1, max: 100 }),
      async (limit) => {
        const limiter = new InMemoryEdgeRateLimiter();
        for (let count = 0; count < limit; count += 1) {
          const result = await limiter.consume({
            key: 'tenant\0subject', limit, windowMs: 60_000, now: NOW,
          });
          expect(result.allowed).toBe(true);
          expect(result.remaining).toBe(limit - count - 1);
        }
        const rejected = await limiter.consume({
          key: 'tenant\0subject', limit, windowMs: 60_000, now: NOW,
        });
        expect(rejected).toEqual({ allowed: false, remaining: 0, retryAfterSeconds: 60 });
      },
    ), { numRuns: 100 });
  });

  it('resets the limiter exactly at the generated window boundary', async () => {
    await fc.assert(fc.asyncProperty(
      fc.integer({ min: 1, max: 20 }),
      fc.integer({ min: 1_000, max: 120_000 }),
      async (limit, windowMs) => {
        const limiter = new InMemoryEdgeRateLimiter();
        for (let count = 0; count < limit; count += 1) {
          await limiter.consume({ key: 'same-key', limit, windowMs, now: NOW });
        }
        expect((await limiter.consume({
          key: 'same-key', limit, windowMs, now: NOW + windowMs - 1,
        })).allowed).toBe(false);
        expect((await limiter.consume({
          key: 'same-key', limit, windowMs, now: NOW + windowMs,
        }))).toMatchObject({ allowed: true, remaining: limit - 1 });
      },
    ), { numRuns: 100 });
  });

  it('validates limiter capacity and evicts bounded entries without denying new subjects', async () => {
    expect(() => new InMemoryEdgeRateLimiter(0)).toThrow('maximumEntries');
    expect(() => new InMemoryEdgeRateLimiter(1.5)).toThrow('maximumEntries');
    expect(() => new InMemoryEdgeRateLimiter(1)).not.toThrow();

    await fc.assert(fc.asyncProperty(
      fc.integer({ min: 1, max: 20 }),
      async (maximumEntries) => {
        const limiter = new InMemoryEdgeRateLimiter(maximumEntries);
        for (let index = 0; index < maximumEntries; index += 1) {
          expect((await limiter.consume({
            key: `subject-${index}`,
            limit: 1,
            windowMs: 60_000,
            now: NOW,
          })).allowed).toBe(true);
        }
        expect((await limiter.consume({
          key: 'new-subject',
          limit: 1,
          windowMs: 60_000,
          now: NOW,
        })).allowed).toBe(true);
        expect((await limiter.consume({
          key: 'subject-0',
          limit: 1,
          windowMs: 60_000,
          now: NOW,
        })).allowed).toBe(true);
      },
    ), { numRuns: 100 });
  });

  it('fails closed for arbitrary malformed bearer-token bytes', () => {
    fc.assert(fc.property(
      fc.uint8Array({ maxLength: 512 }),
      (bytes) => {
        let encoded = '';
        for (const byte of bytes) encoded += String.fromCharCode(byte);
        encoded = btoa(encoded).replace(/\+/gu, '-').replace(/\//gu, '_').replace(/=+$/gu, '');
        expect(() => decodeEdgeAccessTokenEnvelope(encoded, NOW))
          .toThrow(EdgeGatewayProtocolError);
      },
    ), { numRuns: 500 });
  });

  it('detects every generated signed-token subject mutation', async () => {
    const signer = signerFixture();
    const token: EdgeAccessTokenV1 = {
      version: 1,
      tokenId: 'edge_token_property',
      deploymentId: 'dep_property',
      organizationId: 'org_property',
      subjectId: 'account_original',
      scope: 'model_gateway',
      policyVersion: 'edge-v1',
      allowedModels: ['otto-fast'],
      issuedAtMs: NOW,
      expiresAtMs: NOW + 5 * 60 * 1000,
    };
    const signature = await signer.sign(token);
    const verifier = createEdgeSignatureVerifier({ [signer.keyId]: signer.publicKeyPem });
    await fc.assert(fc.asyncProperty(
      fc.stringMatching(/^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,40}$/u)
        .filter((subjectId) => subjectId !== token.subjectId),
      async (subjectId) => {
        await expect(verifier.verify(
          { ...token, subjectId },
          signer.keyId,
          signature,
        )).resolves.toBe(false);
      },
    ), { numRuns: 100 });
  });

  it('rejects every generated non-HTTPS upstream protocol', async () => {
    const signer = signerFixture();
    const control = new EdgeGatewayControlService({
      signer,
      now: () => NOW,
      id: () => 'property',
    });
    const route: EdgeModelRouteV1 = {
      id: 'route_property',
      endpoint: 'chat_completions',
      publicModel: 'otto-fast',
      upstreamModel: 'provider-model',
      upstreamUrl: 'https://provider.test/v1/chat/completions',
      priority: 1,
      authentication: { type: 'bearer', secretBinding: 'PROVIDER_API_KEY' },
    };
    await fc.assert(fc.asyncProperty(
      fc.constantFrom('http:', 'ftp:', 'file:', 'ws:', 'wss:'),
      fc.domain(),
      async (protocol, domain) => {
        await expect(control.issuePolicy({
          policyVersion: 'edge-v1',
          deploymentId: 'dep_property',
          organizationId: 'org_property',
          routes: [{ ...route, upstreamUrl: `${protocol}//${domain}/v1/chat/completions` }],
          limits: {
            maxRequestBytes: 4_096,
            requestsPerMinute: 10,
            upstreamConnectTimeoutMs: 5_000,
            upstreamIdleTimeoutMs: 30_000,
            maxRouteAttempts: 1,
          },
        })).rejects.toBeInstanceOf(EdgeGatewayProtocolError);
      },
    ), { numRuns: 100 });
  });

  it('rejects every security-sensitive provider authentication header', async () => {
    const signer = signerFixture();
    const control = new EdgeGatewayControlService({ signer, now: () => NOW, id: () => 'headers' });
    await fc.assert(fc.asyncProperty(
      fc.constantFrom(
        'authorization',
        'cookie',
        'host',
        'proxy-authorization',
        'set-cookie',
        'transfer-encoding',
      ),
      async (headerName) => {
        await expect(control.issuePolicy({
          policyVersion: 'edge-v1',
          deploymentId: 'dep_property',
          organizationId: 'org_property',
          routes: [{
            id: 'route_header_property',
            endpoint: 'chat_completions',
            publicModel: 'otto-fast',
            upstreamModel: 'provider-model',
            upstreamUrl: 'https://provider.test/v1/chat/completions',
            priority: 1,
            authentication: { type: 'header', headerName, secretBinding: 'PROVIDER_API_KEY' },
          }],
          limits: {
            maxRequestBytes: 4_096,
            requestsPerMinute: 10,
            upstreamConnectTimeoutMs: 5_000,
            upstreamIdleTimeoutMs: 30_000,
            maxRouteAttempts: 1,
          },
        })).rejects.toBeInstanceOf(EdgeGatewayProtocolError);
      },
    ), { numRuns: 100 });
  });
});

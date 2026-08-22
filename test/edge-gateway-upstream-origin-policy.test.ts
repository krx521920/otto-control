import { describe, expect, it } from 'vitest';

import type {
  EdgeModelRouteV1,
  EdgeProviderAuthentication,
} from '../src/contracts/edge-gateway.js';
import {
  normalizeEdgeUpstreamOriginPolicy,
  StaticEdgeUpstreamOriginPolicy,
} from '../src/edge-gateway/upstream-origin-policy.js';

function route(
  upstreamUrl: string,
  authentication: EdgeProviderAuthentication = {
    type: 'bearer',
    secretBinding: 'PROVIDER_API_KEY',
  },
): EdgeModelRouteV1 {
  return {
    id: 'route_test',
    endpoint: 'chat_completions',
    publicModel: 'otto-test',
    upstreamModel: 'provider-test',
    upstreamUrl,
    priority: 0,
    authentication,
  };
}

describe('edge gateway upstream origin policy', () => {
  it('allows only exact normalized HTTPS origins while permitting route paths', () => {
    const policy = new StaticEdgeUpstreamOriginPolicy([
      'https://api.example.com',
      'https://regional.example.com:8443/',
    ]);

    expect(policy.allows(route('https://api.example.com/v1/chat/completions'))).toBe(true);
    expect(policy.allows(route('https://regional.example.com:8443/v1/responses'))).toBe(true);
    expect(policy.allows(route('https://api.example.com.evil.test/v1/chat/completions'))).toBe(false);
    expect(policy.allows(route('https://api.example.com:8443/v1/chat/completions'))).toBe(false);
    expect(policy.allows(route('http://api.example.com/v1/chat/completions'))).toBe(false);
    expect(policy.allows(route('not a URL'))).toBe(false);
  });

  it('normalizes a versioned JSON policy', () => {
    const policy = normalizeEdgeUpstreamOriginPolicy({
      version: 1,
      allowedOrigins: ['https://API.EXAMPLE.COM:443'],
    });
    expect(policy.allows(route('https://api.example.com/v1/responses'))).toBe(true);
  });

  it('binds a v2 origin to explicit provider credentials and authentication headers', () => {
    const policy = normalizeEdgeUpstreamOriginPolicy({
      version: 2,
      allowedUpstreams: [{
        origin: 'https://api.example.com',
        authentications: [
          { type: 'bearer', secretBinding: 'PROVIDER_A_API_KEY' },
          { type: 'header', headerName: 'X-Api-Key', secretBinding: 'PROVIDER_A_HEADER_KEY' },
        ],
      }],
    });

    expect(policy.allows(route('https://api.example.com/v1/responses', {
      type: 'bearer', secretBinding: 'PROVIDER_A_API_KEY',
    }))).toBe(true);
    expect(policy.allows(route('https://api.example.com/v1/responses', {
      type: 'header', headerName: 'x-api-key', secretBinding: 'PROVIDER_A_HEADER_KEY',
    }))).toBe(true);
    expect(policy.allows(route('https://api.example.com/v1/responses', {
      type: 'bearer', secretBinding: 'UNRELATED_SECRET',
    }))).toBe(false);
    expect(policy.allows(route('https://api.example.com/v1/responses', {
      type: 'header', headerName: 'x-other-key', secretBinding: 'PROVIDER_A_HEADER_KEY',
    }))).toBe(false);
    expect(policy.allows(route('https://other.example.com/v1/responses', {
      type: 'bearer', secretBinding: 'PROVIDER_A_API_KEY',
    }))).toBe(false);
  });

  it('normalizes credential whitespace and accepts exact credential capacity boundaries', () => {
    const maximumSecretBinding = `A${'B'.repeat(127)}`;
    const maximumHeaderName = 'x'.repeat(80);
    const authentications: EdgeProviderAuthentication[] = Array.from(
      { length: 14 },
      (_, index) => ({ type: 'bearer', secretBinding: `PROVIDER_KEY_${index}` }),
    );
    authentications.push(
      { type: 'bearer', secretBinding: ` ${maximumSecretBinding} ` },
      { type: 'header', headerName: ` ${maximumHeaderName} `, secretBinding: ' HEADER_KEY ' },
    );
    const policy = new StaticEdgeUpstreamOriginPolicy([{
      origin: 'https://api.example.com',
      authentications,
    }]);

    expect(policy.allows(route('https://api.example.com/v1/responses', {
      type: 'bearer', secretBinding: maximumSecretBinding,
    }))).toBe(true);
    expect(policy.allows(route('https://api.example.com/v1/responses', {
      type: 'header', headerName: maximumHeaderName, secretBinding: 'HEADER_KEY',
    }))).toBe(true);
  });

  it('fails closed for a runtime route that bypasses the signed protocol validator', () => {
    const policy = normalizeEdgeUpstreamOriginPolicy({
      version: 2,
      allowedUpstreams: [{
        origin: 'https://api.example.com',
        authentications: [{ type: 'bearer', secretBinding: 'PROVIDER_API_KEY' }],
      }],
    });
    const malformed = route('https://api.example.com/v1/responses');
    malformed.authentication = {
      type: 'header',
      headerName: 'x-api-key',
    } as unknown as EdgeProviderAuthentication;

    expect(policy.allows(malformed)).toBe(false);
  });

  it('accepts the exact origin count and input length limits', () => {
    const maximumOrigins = Array.from(
      { length: 256 },
      (_, index) => `https://provider-${index}.example.com`,
    );
    const baseOrigin = 'https://length.example.com';
    const paddedOrigin = `${' '.repeat(2_048 - baseOrigin.length)}${baseOrigin}`;

    expect(new StaticEdgeUpstreamOriginPolicy(maximumOrigins)
      .allows(route('https://provider-255.example.com/v1/responses'))).toBe(true);
    expect(new StaticEdgeUpstreamOriginPolicy([paddedOrigin])
      .allows(route(`${baseOrigin}/v1/responses`))).toBe(true);
  });

  it.each([
    { origins: [] },
    {
      origins: Array.from(
        { length: 257 },
        (_, index) => `https://provider-${index}.example.com`,
      ),
    },
  ])('rejects invalid allowlist capacity %#', ({ origins }) => {
    expect(() => new StaticEdgeUpstreamOriginPolicy(origins)).toThrow('1 to 256');
  });

  it('rejects an origin above the exact input length limit', () => {
    const baseOrigin = 'https://length.example.com';
    const oversizedOrigin = `${' '.repeat(2_049 - baseOrigin.length)}${baseOrigin}`;
    expect(() => new StaticEdgeUpstreamOriginPolicy([oversizedOrigin]))
      .toThrow('edge upstream origin is invalid');
  });

  it.each([null, 42])('rejects a non-rule entry %# with the public validation error', (entry) => {
    expect(() => new StaticEdgeUpstreamOriginPolicy([
      entry as unknown as string,
    ])).toThrow('edge upstream rule is invalid');
  });

  it.each([
    { origins: ['http://api.example.com'] },
    { origins: ['https://user:password@api.example.com'] },
    { origins: ['https://api.example.com/v1'] },
    { origins: ['https://api.example.com?tenant=a'] },
    { origins: ['https://api.example.com#fragment'] },
  ])('rejects an unsafe HTTPS origin %#', ({ origins }) => {
    expect(() => new StaticEdgeUpstreamOriginPolicy(origins))
      .toThrow('edge upstream origin must be an HTTPS origin without credentials or path');
  });

  it.each([
    { origins: ['not a URL'] },
    { origins: [''] },
    { origins: ['   '] },
  ])('rejects an invalid URL origin %# with a stable validation error', ({ origins }) => {
    expect(() => new StaticEdgeUpstreamOriginPolicy(origins))
      .toThrow('edge upstream origin is invalid');
  });

  it('rejects normalized duplicates', () => {
    expect(() => new StaticEdgeUpstreamOriginPolicy([
      'https://api.example.com',
      'https://API.EXAMPLE.COM:443/',
    ])).toThrow('duplicate origins');
  });

  it('rejects duplicate origins and authentication entries in credential-bound policies', () => {
    const authentication = { type: 'bearer' as const, secretBinding: 'PROVIDER_API_KEY' };
    expect(() => new StaticEdgeUpstreamOriginPolicy([
      { origin: 'https://api.example.com', authentications: [authentication] },
      { origin: 'https://API.EXAMPLE.COM:443', authentications: [authentication] },
    ])).toThrow('duplicate origins');
    expect(() => new StaticEdgeUpstreamOriginPolicy([{
      origin: 'https://api.example.com',
      authentications: [authentication, authentication],
    }])).toThrow('authentication entries must not contain duplicates');
  });

  it.each([
    { origin: 'https://api.example.com', authentications: [] },
    {
      origin: 'https://api.example.com',
      authentications: Array.from(
        { length: 17 },
        (_, index) => ({ type: 'bearer', secretBinding: `PROVIDER_KEY_${index}` }),
      ),
    },
    {
      origin: 'https://api.example.com',
      authentications: [{ type: 'bearer', secretBinding: 'PROVIDER_API_KEY' }],
      extra: true,
    },
    {
      origin: 'https://api.example.com',
      wrong: [{ type: 'bearer', secretBinding: 'PROVIDER_API_KEY' }],
    },
  ])('rejects an invalid credential-bound upstream rule %#', (value) => {
    expect(() => new StaticEdgeUpstreamOriginPolicy([
      value as unknown as {
        origin: string;
        authentications: EdgeProviderAuthentication[];
      },
    ])).toThrow('edge upstream rule is invalid');
  });

  it.each([null, 42, { toString: () => 'https://api.example.com' }])(
    'rejects a non-string credential-bound origin %#',
    (origin) => {
      expect(() => new StaticEdgeUpstreamOriginPolicy([{
        origin: origin as unknown as string,
        authentications: [{ type: 'bearer', secretBinding: 'PROVIDER_API_KEY' }],
      }])).toThrow('edge upstream origin is invalid');
    },
  );

  it.each([
    { type: 'bearer', secretBinding: 'bad-binding' },
    { type: 'bearer', secretBinding: '-PROVIDER_API_KEY' },
    { type: 'bearer', secretBinding: 'PROVIDER_API_KEY-' },
    { type: 'bearer', secretBinding: '1PROVIDER_API_KEY' },
    { type: 'bearer', secretBinding: 'AB' },
    { type: 'bearer', secretBinding: `A${'B'.repeat(128)}` },
    { type: 'bearer', secretBinding: 42 },
  ])('rejects an unsafe secret binding %#', (authentication) => {
    expect(() => new StaticEdgeUpstreamOriginPolicy([{
      origin: 'https://api.example.com',
      authentications: [authentication as unknown as EdgeProviderAuthentication],
    }])).toThrow('edge upstream secret binding is invalid');
  });

  it.each([
    { type: 'header', headerName: 'authorization', secretBinding: 'PROVIDER_API_KEY' },
    { type: 'header', headerName: 'cookie', secretBinding: 'PROVIDER_API_KEY' },
    { type: 'header', headerName: 'host', secretBinding: 'PROVIDER_API_KEY' },
    { type: 'header', headerName: 'proxy-authorization', secretBinding: 'PROVIDER_API_KEY' },
    { type: 'header', headerName: 'set-cookie', secretBinding: 'PROVIDER_API_KEY' },
    { type: 'header', headerName: 'transfer-encoding', secretBinding: 'PROVIDER_API_KEY' },
    { type: 'header', headerName: 'connection', secretBinding: 'PROVIDER_API_KEY' },
    { type: 'header', headerName: 'content-length', secretBinding: 'PROVIDER_API_KEY' },
    { type: 'header', headerName: 'expect', secretBinding: 'PROVIDER_API_KEY' },
    { type: 'header', headerName: 'proxy-authenticate', secretBinding: 'PROVIDER_API_KEY' },
    { type: 'header', headerName: 'x-forwarded-proto', secretBinding: 'PROVIDER_API_KEY' },
    { type: 'header', headerName: 'x-forwarded-client-cert', secretBinding: 'PROVIDER_API_KEY' },
    { type: 'header', headerName: 'traceparent', secretBinding: 'PROVIDER_API_KEY' },
    { type: 'header', headerName: 'x-original-url', secretBinding: 'PROVIDER_API_KEY' },
    { type: 'header', headerName: 'x-otto-edge-request-id', secretBinding: 'PROVIDER_API_KEY' },
    { type: 'header', headerName: 'sec-fetch-site', secretBinding: 'PROVIDER_API_KEY' },
    { type: 'header', headerName: 'bad header', secretBinding: 'PROVIDER_API_KEY' },
    { type: 'header', headerName: ':x-api-key', secretBinding: 'PROVIDER_API_KEY' },
    { type: 'header', headerName: 'x-api-key:', secretBinding: 'PROVIDER_API_KEY' },
    { type: 'header', headerName: 'x'.repeat(81), secretBinding: 'PROVIDER_API_KEY' },
    { type: 'header', headerName: 42, secretBinding: 'PROVIDER_API_KEY' },
  ])('rejects an unsafe authentication header %#', (authentication) => {
    expect(() => new StaticEdgeUpstreamOriginPolicy([{
      origin: 'https://api.example.com',
      authentications: [authentication as unknown as EdgeProviderAuthentication],
    }])).toThrow('edge upstream authentication header is invalid');
  });

  it.each([
    { type: 'header', secretBinding: 'PROVIDER_API_KEY' },
    { type: 'unknown', secretBinding: 'PROVIDER_API_KEY' },
    {
      type: 'unknown',
      headerName: 'x-api-key',
      secretBinding: 'PROVIDER_API_KEY',
    },
    { type: 'bearer', secretBinding: 'PROVIDER_API_KEY', extra: true },
    { type: 'bearer', wrong: 'PROVIDER_API_KEY' },
    { type: 'header', headerName: 'x-api-key', wrong: 'PROVIDER_API_KEY' },
  ])('rejects an invalid authentication shape %#', (authentication) => {
    expect(() => new StaticEdgeUpstreamOriginPolicy([{
      origin: 'https://api.example.com',
      authentications: [authentication as unknown as EdgeProviderAuthentication],
    }])).toThrow('edge upstream authentication is invalid');
  });

  it.each([null, 1, 'policy', []])(
    'rejects a non-object policy envelope %# with a stable validation error',
    (value) => {
      expect(() => normalizeEdgeUpstreamOriginPolicy(value))
        .toThrow('edge upstream origin policy must be a JSON object');
    },
  );

  it.each([
    { version: 3, allowedOrigins: ['https://api.example.com'] },
    {
      version: 3,
      allowedUpstreams: [{
        origin: 'https://api.example.com',
        authentications: [{ type: 'bearer', secretBinding: 'PROVIDER_API_KEY' }],
      }],
    },
    { version: 2, allowedOrigins: ['https://api.example.com'] },
    { version: 2, wrong: [] },
    { version: 2, allowedUpstreams: 'https://api.example.com' },
    { version: 2, allowedUpstreams: ['https://api.example.com'] },
    {
      version: 2,
      allowedUpstreams: [
        {
          origin: 'https://api.example.com',
          authentications: [{ type: 'bearer', secretBinding: 'PROVIDER_API_KEY' }],
        },
        'https://other.example.com',
      ],
    },
    {
      version: 2,
      allowedUpstreams: [
        {
          origin: 'https://api.example.com',
          authentications: [{ type: 'bearer', secretBinding: 'PROVIDER_API_KEY' }],
        },
        null,
      ],
    },
    { version: 1, allowedOrigins: 'https://api.example.com' },
    { version: 1, wrong: [] },
    { version: 1, allowedOrigins: ['https://api.example.com', 42] },
    {
      version: 1,
      allowedOrigins: [{
        origin: 'https://api.example.com',
        authentications: [{ type: 'bearer', secretBinding: 'PROVIDER_API_KEY' }],
      }],
    },
    { version: 1, allowedOrigins: ['https://api.example.com'], extra: true },
  ])('rejects invalid policy fields %# with a stable validation error', (value) => {
    expect(() => normalizeEdgeUpstreamOriginPolicy(value))
      .toThrow('edge upstream origin policy fields are invalid');
  });
});

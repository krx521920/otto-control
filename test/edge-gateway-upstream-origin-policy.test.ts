import { describe, expect, it } from 'vitest';

import {
  normalizeEdgeUpstreamOriginPolicy,
  StaticEdgeUpstreamOriginPolicy,
} from '../src/edge-gateway/upstream-origin-policy.js';

describe('edge gateway upstream origin policy', () => {
  it('allows only exact normalized HTTPS origins while permitting route paths', () => {
    const policy = new StaticEdgeUpstreamOriginPolicy([
      'https://api.example.com',
      'https://regional.example.com:8443/',
    ]);

    expect(policy.allows('https://api.example.com/v1/chat/completions')).toBe(true);
    expect(policy.allows('https://regional.example.com:8443/v1/responses')).toBe(true);
    expect(policy.allows('https://api.example.com.evil.test/v1/chat/completions')).toBe(false);
    expect(policy.allows('https://api.example.com:8443/v1/chat/completions')).toBe(false);
    expect(policy.allows('http://api.example.com/v1/chat/completions')).toBe(false);
    expect(policy.allows('not a URL')).toBe(false);
  });

  it('normalizes a versioned JSON policy', () => {
    const policy = normalizeEdgeUpstreamOriginPolicy({
      version: 1,
      allowedOrigins: ['https://API.EXAMPLE.COM:443'],
    });
    expect(policy.allows('https://api.example.com/v1/responses')).toBe(true);
  });

  it('accepts the exact origin count and input length limits', () => {
    const maximumOrigins = Array.from(
      { length: 256 },
      (_, index) => `https://provider-${index}.example.com`,
    );
    const baseOrigin = 'https://length.example.com';
    const paddedOrigin = `${' '.repeat(2_048 - baseOrigin.length)}${baseOrigin}`;

    expect(new StaticEdgeUpstreamOriginPolicy(maximumOrigins)
      .allows('https://provider-255.example.com/v1/responses')).toBe(true);
    expect(new StaticEdgeUpstreamOriginPolicy([paddedOrigin])
      .allows(`${baseOrigin}/v1/responses`)).toBe(true);
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

  it.each([
    null,
    42,
    { length: 1, toString: () => 'https://api.example.com' },
  ])('rejects a non-string origin %# with the public validation error', (origin) => {
    expect(() => new StaticEdgeUpstreamOriginPolicy([
      origin as unknown as string,
    ])).toThrow('edge upstream origin is invalid');
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
    ])).toThrow('duplicates');
  });

  it.each([null, 1, 'policy', []])(
    'rejects a non-object policy envelope %# with a stable validation error',
    (value) => {
      expect(() => normalizeEdgeUpstreamOriginPolicy(value))
        .toThrow('edge upstream origin policy must be a JSON object');
    },
  );

  it.each([
    { version: 2, allowedOrigins: ['https://api.example.com'] },
    { version: 1, allowedOrigins: 'https://api.example.com' },
    { version: 1, allowedOrigins: ['https://api.example.com'], extra: true },
  ])('rejects invalid policy fields %# with a stable validation error', (value) => {
    expect(() => normalizeEdgeUpstreamOriginPolicy(value))
      .toThrow('edge upstream origin policy fields are invalid');
  });
});

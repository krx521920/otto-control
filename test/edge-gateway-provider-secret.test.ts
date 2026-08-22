import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { normalizeEdgeProviderSecret } from '../src/edge-gateway/provider-secret.js';
import { resolveEdgeProviderSecret } from '../src/edge-gateway/server.js';

describe('edge gateway provider secret validation', () => {
  it('normalizes surrounding whitespace without changing visible credential bytes', () => {
    expect(normalizeEdgeProviderSecret('  key_ABC-123+/=  ')).toBe('key_ABC-123+/=');
    expect(normalizeEdgeProviderSecret('x'.repeat(8_192))).toBe('x'.repeat(8_192));
  });

  it.each([
    null,
    undefined,
    42,
    {},
    '',
    '   ',
    'key\0suffix',
    'key\r\nsuffix',
    'key\tsuffix',
    '密钥',
    'x'.repeat(8_193),
  ])('rejects a non-header-safe provider secret %#', (value) => {
    expect(normalizeEdgeProviderSecret(value)).toBeNull();
  });

  it('accepts both inclusive visible ASCII boundaries', () => {
    expect(normalizeEdgeProviderSecret('!')).toBe('!');
    expect(normalizeEdgeProviderSecret('~')).toBe('~');
  });
});

describe('edge gateway provider secret files', () => {
  const fixture = fileURLToPath(new URL('./fixtures/edge-provider-api-key', import.meta.url));

  it('loads a provider credential from the corresponding _FILE variable', async () => {
    await expect(resolveEdgeProviderSecret('PROVIDER_A_API_KEY', {
      PROVIDER_A_API_KEY_FILE: fixture,
    })).resolves.toBe('provider-secret-from-file');
  });

  it('fails closed for ambiguous, missing or unsafe file values', async () => {
    await expect(resolveEdgeProviderSecret('PROVIDER_A_API_KEY', {
      PROVIDER_A_API_KEY: 'inline',
      PROVIDER_A_API_KEY_FILE: fixture,
    })).resolves.toBeNull();
    await expect(resolveEdgeProviderSecret('PROVIDER_A_API_KEY', {
      PROVIDER_A_API_KEY_FILE: `${fixture}.missing`,
    })).resolves.toBeNull();
  });
});

import { describe, expect, it } from 'vitest';

import { normalizeEdgeProviderSecret } from '../src/edge-gateway/provider-secret.js';

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

import { describe, expect, it } from 'vitest';

import { normalizeEdgeRequestId } from '../src/edge-gateway/request-id.js';

describe('edge gateway request id normalization', () => {
  it('normalizes exact valid boundaries', () => {
    expect(normalizeEdgeRequestId('  request_ABC-123:part.2  '))
      .toBe('request_ABC-123:part.2');
    expect(normalizeEdgeRequestId('a')).toBe('a');
    expect(normalizeEdgeRequestId(`a${'x'.repeat(127)}`))
      .toBe(`a${'x'.repeat(127)}`);
  });

  it.each([
    null,
    undefined,
    42,
    '',
    '   ',
    '_starts-with-punctuation',
    'request id',
    'request\tidentifier',
    'request\r\nidentifier',
    '请求编号',
    `a${'x'.repeat(128)}`,
  ])('rejects an unsafe request id %#', (value) => {
    expect(normalizeEdgeRequestId(value)).toBeNull();
  });
});

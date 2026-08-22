import { describe, expect, it } from 'vitest';

import {
  normalizeEdgeUpstreamContentType,
  normalizeEdgeUpstreamRequestId,
} from '../src/edge-gateway/upstream-response-headers.js';

describe('edge gateway upstream response header normalization', () => {
  it.each([
    ['application/json', 'application/json'],
    [' Application/Problem+JSON ; charset=utf-8 ', 'application/problem+json'],
    ['application/x-ndjson', 'application/x-ndjson'],
    ['text/event-stream; charset=utf-8', 'text/event-stream'],
  ])('canonicalizes safe content type %s', (value, expected) => {
    expect(normalizeEdgeUpstreamContentType(value)).toBe(expected);
  });

  it.each([null, '', 'text/html', 'image/svg+xml', 'application/javascript'])
    ('downgrades unsafe content type %#', (value) => {
      expect(normalizeEdgeUpstreamContentType(value)).toBe('application/octet-stream');
    });

  it('normalizes a bounded visible provider request id', () => {
    expect(normalizeEdgeUpstreamRequestId('  req_ABC-123  ')).toBe('req_ABC-123');
    expect(normalizeEdgeUpstreamRequestId('x'.repeat(256))).toBe('x'.repeat(256));
    expect(normalizeEdgeUpstreamRequestId('!')).toBe('!');
    expect(normalizeEdgeUpstreamRequestId('~')).toBe('~');
  });

  it.each([
    null,
    '',
    '   ',
    'request id',
    'request\tidentifier',
    '请求编号',
    'x'.repeat(257),
  ])('rejects unsafe provider request id %#', (value) => {
    expect(normalizeEdgeUpstreamRequestId(value)).toBeNull();
  });
});

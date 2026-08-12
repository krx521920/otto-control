import type { IncomingMessage } from 'node:http';
import { Readable } from 'node:stream';

import { describe, expect, it } from 'vitest';

import {
  convertEdgeNodeWebRequest,
  createEdgeNodeWebRequest,
  edgeNodeRequestUrl,
} from '../src/edge-gateway/node-http-adapter.js';

function incoming(overrides: {
  method?: string;
  url?: string;
  headers?: IncomingMessage['headers'];
}): IncomingMessage {
  return {
    method: overrides.method,
    url: overrides.url,
    headers: overrides.headers ?? {},
  } as IncomingMessage;
}

describe('edge gateway Node HTTP adapter', () => {
  it('uses a fixed internal origin instead of trusting the client Host header', () => {
    const controller = new AbortController();
    const request = createEdgeNodeWebRequest(incoming({
      method: 'GET',
      url: '/readyz?probe=1',
      headers: {
        host: 'attacker.example:8443',
        'x-repeated': ['first', 'second'],
        'x-absent': undefined,
      },
    }), controller.signal);

    expect(request.url).toBe('http://edge.invalid/readyz?probe=1');
    expect(request.headers.get('host')).toBeNull();
    expect(request.headers.get('x-repeated')).toBe('first, second');
    expect(request.headers.get('x-absent')).toBeNull();
    expect(request.signal.aborted).toBe(false);
    controller.abort();
    expect(request.signal.aborted).toBe(true);
  });

  it('preserves POST bytes while keeping GET and HEAD requests body-free', async () => {
    const post = Readable.from([Buffer.from('private-body')]) as IncomingMessage;
    post.method = 'POST';
    post.url = '/v1/chat/completions';
    post.headers = { 'content-type': 'application/json' };
    const postRequest = createEdgeNodeWebRequest(post, new AbortController().signal);
    expect(postRequest.method).toBe('POST');
    expect(postRequest.headers.get('content-type')).toBe('application/json');
    await expect(postRequest.text()).resolves.toBe('private-body');

    const headRequest = createEdgeNodeWebRequest(incoming({
      method: 'HEAD', url: '/healthz',
    }), new AbortController().signal);
    expect(headRequest.method).toBe('HEAD');
    expect(headRequest.body).toBeNull();

    const defaultRequest = createEdgeNodeWebRequest(incoming({
      url: '/healthz',
    }), new AbortController().signal);
    expect(defaultRequest.method).toBe('GET');
    expect(defaultRequest.body).toBeNull();
  });

  it('accepts exact origin-form and length boundaries without changing encoded paths', () => {
    expect(edgeNodeRequestUrl('/')).toBe('http://edge.invalid/');
    expect(edgeNodeRequestUrl('/%2f%2fevil.test/path?value=%23fragment'))
      .toBe('http://edge.invalid/%2f%2fevil.test/path?value=%23fragment');
    const maximum = `/${'a'.repeat(8_191)}`;
    expect(maximum).toHaveLength(8_192);
    expect(edgeNodeRequestUrl(maximum)).toBe(`http://edge.invalid${maximum}`);
  });

  it.each([
    undefined,
    '',
    'readyz',
    'prefix/readyz',
    '//attacker.example/path',
    'https://attacker.example/path',
    '/path\\segment',
    '/path#fragment',
    '/a/../admin',
    '/%2e%2e/admin',
    '/a/%2E/admin',
    '/%',
    '/%0',
    '/%GG',
    '/has space',
    '/has\ttab',
    '/非ASCII',
    `/${'a'.repeat(8_192)}`,
  ])('rejects non-origin or ambiguous request target %#', (target) => {
    expect(() => edgeNodeRequestUrl(target)).toThrow('edge request target is invalid');
  });

  it('converts malformed Fetch requests into a detail-free 400 response', async () => {
    const conversion = convertEdgeNodeWebRequest(incoming({
      method: 'CONNECT',
      url: '/v1/chat/completions',
      headers: { host: 'private-host.example' },
    }), new AbortController().signal);

    expect(conversion.ok).toBe(false);
    if (conversion.ok) throw new Error('expected request conversion to fail');
    expect(conversion.response.status).toBe(400);
    expect(conversion.response.headers.get('cache-control')).toBe('no-store');
    expect(conversion.response.headers.get('content-type')).toBe('application/json; charset=utf-8');
    const body = await conversion.response.text();
    expect(JSON.parse(body)).toEqual({
      error: { code: 'EDGE_INVALID_HTTP_REQUEST', message: 'invalid HTTP request' },
    });
    expect(body).not.toContain('private-host');
  });

  it('returns an explicit successful conversion without copying Host into the URL', () => {
    const conversion = convertEdgeNodeWebRequest(incoming({
      method: 'GET',
      url: '/healthz',
      headers: { host: 'untrusted.example' },
    }), new AbortController().signal);

    expect(conversion.ok).toBe(true);
    if (!conversion.ok) throw new Error('expected request conversion to succeed');
    expect(conversion.request.url).toBe('http://edge.invalid/healthz');
  });
});

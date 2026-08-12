import { describe, expect, it } from 'vitest';

import {
  applyEdgeNodeHttpLimits,
  edgeNodeHttpServerOptions,
  loadEdgeNodeHttpLimits,
} from '../src/edge-gateway/node-http-limits.js';

describe('edge gateway Node HTTP limits', () => {
  it('loads bounded defaults that protect idle inbound connections', () => {
    expect(loadEdgeNodeHttpLimits({})).toEqual({
      headersTimeoutMs: 15_000,
      requestTimeoutMs: 120_000,
      keepAliveTimeoutMs: 5_000,
      maximumHeaderBytes: 16_384,
      maximumHeaders: 100,
      maximumRequestsPerSocket: 1_000,
    });
  });

  it('loads explicit production limits', () => {
    expect(loadEdgeNodeHttpLimits({
      OTTO_EDGE_HTTP_HEADERS_TIMEOUT_MS: '10000',
      OTTO_EDGE_HTTP_REQUEST_TIMEOUT_MS: '180000',
      OTTO_EDGE_HTTP_KEEP_ALIVE_TIMEOUT_MS: '3000',
      OTTO_EDGE_HTTP_MAX_HEADER_BYTES: '8192',
      OTTO_EDGE_HTTP_MAX_HEADERS_COUNT: '64',
      OTTO_EDGE_HTTP_MAX_REQUESTS_PER_SOCKET: '250',
    })).toEqual({
      headersTimeoutMs: 10_000,
      requestTimeoutMs: 180_000,
      keepAliveTimeoutMs: 3_000,
      maximumHeaderBytes: 8_192,
      maximumHeaders: 64,
      maximumRequestsPerSocket: 250,
    });
  });

  it('treats whitespace-only values as unset', () => {
    expect(loadEdgeNodeHttpLimits({
      OTTO_EDGE_HTTP_HEADERS_TIMEOUT_MS: '   ',
    }).headersTimeoutMs).toBe(15_000);
  });

  it('accepts inclusive hard boundaries', () => {
    expect(loadEdgeNodeHttpLimits({
      OTTO_EDGE_HTTP_HEADERS_TIMEOUT_MS: '1000',
      OTTO_EDGE_HTTP_REQUEST_TIMEOUT_MS: '900000',
      OTTO_EDGE_HTTP_KEEP_ALIVE_TIMEOUT_MS: '500',
      OTTO_EDGE_HTTP_MAX_HEADER_BYTES: '4096',
      OTTO_EDGE_HTTP_MAX_HEADERS_COUNT: '1',
      OTTO_EDGE_HTTP_MAX_REQUESTS_PER_SOCKET: '1',
    })).toEqual({
      headersTimeoutMs: 1_000,
      requestTimeoutMs: 900_000,
      keepAliveTimeoutMs: 500,
      maximumHeaderBytes: 4_096,
      maximumHeaders: 1,
      maximumRequestsPerSocket: 1,
    });
  });

  it('allows the header and whole-request deadlines to be equal', () => {
    expect(loadEdgeNodeHttpLimits({
      OTTO_EDGE_HTTP_HEADERS_TIMEOUT_MS: '1000',
      OTTO_EDGE_HTTP_REQUEST_TIMEOUT_MS: '1000',
    })).toMatchObject({ headersTimeoutMs: 1_000, requestTimeoutMs: 1_000 });
  });

  it.each([
    ['OTTO_EDGE_HTTP_HEADERS_TIMEOUT_MS', '999'],
    ['OTTO_EDGE_HTTP_HEADERS_TIMEOUT_MS', '120001'],
    ['OTTO_EDGE_HTTP_REQUEST_TIMEOUT_MS', '999'],
    ['OTTO_EDGE_HTTP_REQUEST_TIMEOUT_MS', '900001'],
    ['OTTO_EDGE_HTTP_KEEP_ALIVE_TIMEOUT_MS', '499'],
    ['OTTO_EDGE_HTTP_KEEP_ALIVE_TIMEOUT_MS', '60001'],
    ['OTTO_EDGE_HTTP_MAX_HEADER_BYTES', '4095'],
    ['OTTO_EDGE_HTTP_MAX_HEADER_BYTES', '65537'],
    ['OTTO_EDGE_HTTP_MAX_HEADERS_COUNT', '0'],
    ['OTTO_EDGE_HTTP_MAX_HEADERS_COUNT', '2001'],
    ['OTTO_EDGE_HTTP_MAX_REQUESTS_PER_SOCKET', '0'],
    ['OTTO_EDGE_HTTP_MAX_REQUESTS_PER_SOCKET', '1000001'],
    ['OTTO_EDGE_HTTP_REQUEST_TIMEOUT_MS', '1.5'],
    ['OTTO_EDGE_HTTP_REQUEST_TIMEOUT_MS', 'NaN'],
  ])('rejects invalid %s=%s', (name, value) => {
    expect(() => loadEdgeNodeHttpLimits({ [name]: value })).toThrow(name);
  });

  it('rejects a header deadline beyond the whole-request deadline', () => {
    expect(() => loadEdgeNodeHttpLimits({
      OTTO_EDGE_HTTP_HEADERS_TIMEOUT_MS: '30000',
      OTTO_EDGE_HTTP_REQUEST_TIMEOUT_MS: '20000',
    })).toThrow(
      'OTTO_EDGE_HTTP_HEADERS_TIMEOUT_MS cannot exceed OTTO_EDGE_HTTP_REQUEST_TIMEOUT_MS',
    );
  });

  it('applies every limit to the Node server before it listens', () => {
    const server = {
      headersTimeout: 0,
      requestTimeout: 0,
      keepAliveTimeout: 0,
      maxHeadersCount: null,
      maxRequestsPerSocket: 0,
    };
    applyEdgeNodeHttpLimits(server, {
      headersTimeoutMs: 11_000,
      requestTimeoutMs: 22_000,
      keepAliveTimeoutMs: 3_000,
      maximumHeaderBytes: 8_192,
      maximumHeaders: 50,
      maximumRequestsPerSocket: 75,
    });
    expect(server).toEqual({
      headersTimeout: 11_000,
      requestTimeout: 22_000,
      keepAliveTimeout: 3_000,
      maxHeadersCount: 50,
      maxRequestsPerSocket: 75,
    });
  });

  it('applies the parser byte limit when the Node server is created', () => {
    expect(edgeNodeHttpServerOptions({
      headersTimeoutMs: 11_000,
      requestTimeoutMs: 22_000,
      keepAliveTimeoutMs: 3_000,
      maximumHeaderBytes: 12_345,
      maximumHeaders: 50,
      maximumRequestsPerSocket: 75,
    })).toEqual({ maxHeaderSize: 12_345 });
  });
});

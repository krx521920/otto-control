import { describe, expect, it } from 'vitest';

import {
  defaultEdgeUpstreamResponseLimits,
  loadEdgeUpstreamResponseLimits,
  normalizeEdgeUpstreamResponseLimits,
} from '../src/edge-gateway/upstream-response-limits.js';

describe('edge gateway upstream response limits', () => {
  it('uses bounded defaults', () => {
    expect(loadEdgeUpstreamResponseLimits({})).toEqual({
      maximumBytes: 64 * 1_024 * 1_024,
      maximumDurationMs: 15 * 60 * 1_000,
    });
    expect(normalizeEdgeUpstreamResponseLimits()).toEqual(
      defaultEdgeUpstreamResponseLimits(),
    );
  });

  it('loads explicit Node runtime limits', () => {
    expect(loadEdgeUpstreamResponseLimits({
      OTTO_EDGE_UPSTREAM_MAX_RESPONSE_BYTES: '8388608',
      OTTO_EDGE_UPSTREAM_MAX_RESPONSE_DURATION_MS: '120000',
    })).toEqual({ maximumBytes: 8_388_608, maximumDurationMs: 120_000 });
  });

  it('treats whitespace-only environment values as unset', () => {
    expect(loadEdgeUpstreamResponseLimits({
      OTTO_EDGE_UPSTREAM_MAX_RESPONSE_BYTES: '   ',
      OTTO_EDGE_UPSTREAM_MAX_RESPONSE_DURATION_MS: '\t',
    })).toEqual(defaultEdgeUpstreamResponseLimits());
  });

  it('accepts inclusive hard boundaries', () => {
    expect(loadEdgeUpstreamResponseLimits({
      OTTO_EDGE_UPSTREAM_MAX_RESPONSE_BYTES: '1024',
      OTTO_EDGE_UPSTREAM_MAX_RESPONSE_DURATION_MS: '3600000',
    })).toEqual({ maximumBytes: 1_024, maximumDurationMs: 3_600_000 });
    expect(normalizeEdgeUpstreamResponseLimits({
      maximumBytes: 256 * 1_024 * 1_024,
      maximumDurationMs: 1_000,
    })).toEqual({ maximumBytes: 268_435_456, maximumDurationMs: 1_000 });
  });

  it.each([
    ['OTTO_EDGE_UPSTREAM_MAX_RESPONSE_BYTES', '1023'],
    ['OTTO_EDGE_UPSTREAM_MAX_RESPONSE_BYTES', '268435457'],
    ['OTTO_EDGE_UPSTREAM_MAX_RESPONSE_DURATION_MS', '999'],
    ['OTTO_EDGE_UPSTREAM_MAX_RESPONSE_DURATION_MS', '3600001'],
    ['OTTO_EDGE_UPSTREAM_MAX_RESPONSE_BYTES', '1.5'],
    ['OTTO_EDGE_UPSTREAM_MAX_RESPONSE_DURATION_MS', 'NaN'],
  ])('rejects invalid %s=%s', (name, value) => {
    expect(() => loadEdgeUpstreamResponseLimits({ [name]: value })).toThrow(name);
  });

  it('rejects invalid programmatic limits', () => {
    expect(() => normalizeEdgeUpstreamResponseLimits({
      maximumBytes: 0,
      maximumDurationMs: 1_000,
    })).toThrow('edge upstream maximum response bytes');
    expect(() => normalizeEdgeUpstreamResponseLimits({
      maximumBytes: 1_024,
      maximumDurationMs: Number.NaN,
    })).toThrow('edge upstream maximum response duration');
  });
});

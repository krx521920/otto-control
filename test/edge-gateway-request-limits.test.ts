import { describe, expect, it } from 'vitest';

import {
  defaultEdgeRequestLimits,
  loadEdgeRequestLimits,
  normalizeEdgeRequestLimits,
} from '../src/edge-gateway/request-limits.js';

describe('edge gateway request limits', () => {
  it('uses a bounded four MiB default', () => {
    expect(loadEdgeRequestLimits({})).toEqual({ maximumBytes: 4 * 1_024 * 1_024 });
    expect(normalizeEdgeRequestLimits()).toEqual(defaultEdgeRequestLimits());
  });

  it('loads an explicit Node runtime limit and treats whitespace as unset', () => {
    expect(loadEdgeRequestLimits({ OTTO_EDGE_MAX_REQUEST_BYTES: '8388608' }))
      .toEqual({ maximumBytes: 8 * 1_024 * 1_024 });
    expect(loadEdgeRequestLimits({ OTTO_EDGE_MAX_REQUEST_BYTES: '   ' }))
      .toEqual(defaultEdgeRequestLimits());
  });

  it('accepts inclusive hard boundaries', () => {
    expect(normalizeEdgeRequestLimits({ maximumBytes: 1_024 }))
      .toEqual({ maximumBytes: 1_024 });
    expect(loadEdgeRequestLimits({ OTTO_EDGE_MAX_REQUEST_BYTES: '20971520' }))
      .toEqual({ maximumBytes: 20 * 1_024 * 1_024 });
  });

  it.each(['1023', '20971521', '1.5', 'NaN', 'Infinity'])(
    'rejects invalid OTTO_EDGE_MAX_REQUEST_BYTES=%s',
    (value) => {
      expect(() => loadEdgeRequestLimits({ OTTO_EDGE_MAX_REQUEST_BYTES: value }))
        .toThrow('edge maximum request bytes');
    },
  );

  it.each([0, 1_024.5, Number.NaN, Number.POSITIVE_INFINITY])(
    'rejects invalid programmatic request limit %#',
    (maximumBytes) => {
      expect(() => normalizeEdgeRequestLimits({ maximumBytes }))
        .toThrow('edge maximum request bytes');
    },
  );
});

import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  loadTracingConfiguration,
  traceLogContext,
} from '../src/observability/tracing.js';

describe('OpenTelemetry tracing configuration', () => {
  it('stays disabled unless an OTLP collector is explicitly configured', () => {
    expect(loadTracingConfiguration({ NODE_ENV: 'production' })).toBeNull();
    expect(traceLogContext()).toEqual({});
  });

  it('requires a production HTTPS OTLP traces endpoint', () => {
    expect(() => loadTracingConfiguration({
      NODE_ENV: 'production',
      CONTROL_OTLP_TRACE_ENDPOINT: 'http://collector.test/v1/traces',
    })).toThrow('must use HTTPS in production');
    expect(() => loadTracingConfiguration({
      NODE_ENV: 'production',
      CONTROL_OTLP_TRACE_ENDPOINT: 'https://collector.test/v1/metrics',
    })).toThrow('must end with /v1/traces');
    expect(() => loadTracingConfiguration({
      CONTROL_OTLP_TRACE_ENDPOINT: 'http://localhost:4318/v1/traces',
      CONTROL_TRACE_SAMPLE_RATIO: '1.1',
    })).toThrow('CONTROL_TRACE_SAMPLE_RATIO must be between 0 and 1');
  });

  it('loads exporter credentials only from a bounded JSON secret file', () => {
    const directory = mkdtempSync(join(tmpdir(), 'otto-control-otel-'));
    try {
      const headersFile = join(directory, 'headers.json');
      writeFileSync(headersFile, JSON.stringify({ Authorization: 'Bearer collector-secret' }));
      expect(loadTracingConfiguration({
        NODE_ENV: 'production',
        CONTROL_OTLP_TRACE_ENDPOINT: 'https://collector.test/v1/traces',
        CONTROL_OTLP_HEADERS_FILE: headersFile,
        CONTROL_TRACE_SAMPLE_RATIO: '0.25',
      })).toMatchObject({
        endpoint: 'https://collector.test/v1/traces',
        sampleRatio: 0.25,
        headers: { Authorization: 'Bearer collector-secret' },
      });
      writeFileSync(headersFile, JSON.stringify({ Authorization: 'bad\nheader' }));
      expect(() => loadTracingConfiguration({
        CONTROL_OTLP_TRACE_ENDPOINT: 'http://localhost:4318/v1/traces',
        CONTROL_OTLP_HEADERS_FILE: headersFile,
      })).toThrow('invalid header value');
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});

import Fastify, { type FastifyInstance } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { loadControlConfig } from '../src/config.js';
import type { DatabaseObservabilitySource } from '../src/observability/contracts.js';
import { ControlMetrics } from '../src/observability/metrics.js';

const METRICS_TOKEN = 'observability-test-token-with-at-least-32-bytes';

describe('Prometheus observability', () => {
  let app: FastifyInstance | undefined;

  afterEach(async () => {
    await app?.close();
    app = undefined;
  });

  it('exports slow requests, SLO events, PostgreSQL pool pressure, and capacity', async () => {
    const database: DatabaseObservabilitySource = {
      poolSnapshot: () => ({
        totalConnections: 7,
        idleConnections: 2,
        waitingRequests: 3,
        errorsTotal: 4,
        maximumConnections: 10,
      }),
      sampleCapacity: async () => ({
        sampledAtMs: Date.parse('2026-08-02T00:00:00.000Z'),
        databaseBytes: 12_345,
        relations: {
          control_deployments: { bytes: 2_048, estimatedRows: 17 },
        },
      }),
    };
    const config = loadControlConfig({
      NODE_ENV: 'test',
      CONTROL_METRICS_TOKEN: METRICS_TOKEN,
      CONTROL_SLOW_REQUEST_THRESHOLD_MS: '100',
      CONTROL_SLO_LATENCY_TARGET_MS: '50',
    });
    app = Fastify({ logger: false });
    await new ControlMetrics(config, database).register(app);
    app.get('/slow', async () => {
      await new Promise((resolve) => setTimeout(resolve, 120));
      return { ok: true };
    });

    expect((await app.inject({ method: 'GET', url: '/slow' })).statusCode).toBe(200);
    const response = await app.inject({
      method: 'GET',
      url: '/metrics',
      headers: { authorization: `Bearer ${METRICS_TOKEN}` },
    });

    expect(response.statusCode).toBe(200);
    expect(response.body).toMatch(/otto_control_http_slow_requests_total[^\n]*\} 1/u);
    expect(response.body).toMatch(
      /otto_control_http_slo_events_total\{[^\n]*objective="latency"[^\n]*result="bad"[^\n]*\} 1/u,
    );
    expect(response.body).toContain('otto_control_postgres_pool_waiting_requests{');
    expect(response.body).toContain('} 3');
    expect(response.body).toContain('otto_control_postgres_pool_utilization_ratio{');
    expect(response.body).toContain('} 0.5');
    expect(response.body).toContain('otto_control_database_size_bytes{');
    expect(response.body).toContain('} 12345');
    expect(response.body).toContain('relation="control_deployments"');
  });
});

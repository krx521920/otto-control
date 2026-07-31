import { afterEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';

import { buildControlApp } from '../src/app.js';
import type { ControlConfig } from '../src/config.js';

const testConfig: Readonly<ControlConfig> = {
  environment: 'test',
  host: '127.0.0.1',
  port: 7788,
  logLevel: 'silent',
  trustProxy: false,
  publicBaseUrl: null,
  version: '0.1.0-test',
  databaseUrl: null,
  databaseSsl: false,
  adminToken: null,
  tokenSecret: null,
  signerPrivateKeyFile: null,
  leaseDurationMs: 600_000,
  telemetryRetentionDays: 90,
};

let app: FastifyInstance | undefined;

afterEach(async () => {
  await app?.close();
  app = undefined;
});

describe('otto-control Fastify foundation', () => {
  it('exposes a content-free liveness endpoint with hardened headers', async () => {
    app = await buildControlApp({ config: testConfig, logger: false });
    const response = await app.inject({ method: 'GET', url: '/health/live' });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      status: 'ok',
      service: 'otto-control',
      version: '0.1.0-test',
    });
    expect(response.headers['cache-control']).toBe('no-store');
    expect(response.headers['x-content-type-options']).toBe('nosniff');
    expect(response.headers['x-request-id']).toMatch(/^[0-9a-f-]{36}$/u);
  });

  it('reports API version and only implemented capabilities', async () => {
    app = await buildControlApp({ config: testConfig, logger: false });
    const response = await app.inject({ method: 'GET', url: '/v1' });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      service: 'otto-control',
      version: '0.1.0-test',
      apiVersion: 'v1',
      capabilities: ['health'],
    });
  });

  it('returns a stable error envelope without reflecting unknown routes', async () => {
    app = await buildControlApp({ config: testConfig, logger: false });
    const response = await app.inject({
      method: 'GET',
      url: '/not-found?token=must-not-leak',
    });

    expect(response.statusCode).toBe(404);
    expect(response.json()).toMatchObject({
      error: {
        code: 'NOT_FOUND',
        message: 'Route not found',
      },
    });
    expect(response.body).not.toContain('must-not-leak');
  });
});

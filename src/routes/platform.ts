import type { FastifyInstance } from 'fastify';

import type { ControlConfig } from '../config.js';

export async function registerPlatformRoutes(
  app: FastifyInstance,
  config: Readonly<ControlConfig>,
): Promise<void> {
  app.get('/health/live', async () => ({
    status: 'ok',
    service: 'otto-control',
    version: config.version,
    timestamp: new Date().toISOString(),
    uptimeSec: Math.round(process.uptime()),
  }));

  app.get('/health/ready', async () => ({
    status: 'ready',
    service: 'otto-control',
    checks: {
      http: 'ok',
      configuration: 'ok',
    },
  }));

  app.get('/v1', async () => ({
    service: 'otto-control',
    version: config.version,
    apiVersion: 'v1',
    capabilities: [
      'health',
    ],
  }));
}

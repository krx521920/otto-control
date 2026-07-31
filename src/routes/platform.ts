import type { FastifyInstance } from 'fastify';

import type { ControlConfig } from '../config.js';

export interface PlatformRouteOptions {
  capabilities: string[];
  readiness?: () => Promise<void>;
}

export async function registerPlatformRoutes(
  app: FastifyInstance,
  config: Readonly<ControlConfig>,
  options: PlatformRouteOptions,
): Promise<void> {
  app.get('/health/live', async () => ({
    status: 'ok',
    service: 'otto-control',
    version: config.version,
    timestamp: new Date().toISOString(),
    uptimeSec: Math.round(process.uptime()),
  }));

  app.get('/health/ready', async (_request, reply) => {
    try {
      await options.readiness?.();
      return {
        status: 'ready',
        service: 'otto-control',
        checks: {
          http: 'ok',
          configuration: 'ok',
          database: options.readiness ? 'ok' : 'not_configured',
        },
      };
    } catch {
      return reply.code(503).send({
        status: 'not_ready',
        service: 'otto-control',
        checks: { http: 'ok', configuration: 'ok', database: 'unavailable' },
      });
    }
  });

  app.get('/v1', async () => ({
    service: 'otto-control',
    version: config.version,
    apiVersion: 'v1',
    capabilities: options.capabilities,
  }));
}

import { randomUUID } from 'node:crypto';

import rateLimit from '@fastify/rate-limit';
import Fastify, { type FastifyError, type FastifyInstance, type FastifyServerOptions } from 'fastify';

import { loadControlConfig, type ControlConfig } from './config.js';
import { ControlPlaneError } from './errors.js';
import type { CommercialControlRuntime } from './runtime.js';
import { registerCommercialControlRoutes } from './routes/commercial-control.js';
import { registerPlatformRoutes } from './routes/platform.js';

export interface BuildControlAppOptions {
  config?: Readonly<ControlConfig>;
  logger?: FastifyServerOptions['logger'];
  commercialControl?: CommercialControlRuntime | null;
}

function fastifyError(error: unknown): FastifyError | null {
  return error instanceof Error ? error as FastifyError : null;
}

function statusCodeFor(error: unknown): number {
  if (error instanceof ControlPlaneError) return error.statusCode;
  const candidate = fastifyError(error);
  if (candidate?.validation) return 400;
  const statusCode = candidate?.statusCode ?? 500;
  return statusCode >= 400 && statusCode <= 599 ? statusCode : 500;
}

export async function buildControlApp(
  options: BuildControlAppOptions = {},
): Promise<FastifyInstance> {
  const config = options.config ?? loadControlConfig();
  const logger = options.logger ?? {
    level: config.logLevel,
    redact: {
      paths: [
        'req.headers.authorization',
        'req.headers.cookie',
        'req.headers.x-api-key',
        'req.body.password',
        'req.body.token',
        'req.body.leaseToken',
        'req.body.telemetryToken',
      ],
      censor: '[REDACTED]',
    },
  };
  const app = Fastify({
    logger,
    bodyLimit: 1024 * 1024,
    connectionTimeout: 10_000,
    requestTimeout: 30_000,
    keepAliveTimeout: 72_000,
    routerOptions: {
      maxParamLength: 256,
    },
    trustProxy: config.trustProxy,
    genReqId: () => randomUUID(),
  });

  await app.register(rateLimit, {
    global: false,
    max: 300,
    timeWindow: '1 minute',
    hook: 'onRequest',
    skipOnError: false,
  });

  app.addHook('onRequest', async (request, reply) => {
    reply
      .header('cache-control', 'no-store')
      .header('content-security-policy', "default-src 'none'; frame-ancestors 'none'")
      .header('permissions-policy', 'camera=(), microphone=(), geolocation=()')
      .header('referrer-policy', 'no-referrer')
      .header('strict-transport-security', 'max-age=31536000; includeSubDomains')
      .header('x-content-type-options', 'nosniff')
      .header('x-frame-options', 'DENY')
      .header('x-request-id', request.id);
  });

  app.setNotFoundHandler(async (request, reply) => {
    await reply.code(404).send({
      error: {
        code: 'NOT_FOUND',
        message: 'Route not found',
        requestId: request.id,
      },
    });
  });

  app.setErrorHandler(async (error, request, reply) => {
    const statusCode = statusCodeFor(error);
    const candidate = fastifyError(error);
    if (statusCode >= 500) request.log.error({ err: error }, 'request failed');
    await reply.code(statusCode).send({
      error: {
        code: error instanceof ControlPlaneError
          ? error.code
          : statusCode === 400 ? 'INVALID_REQUEST' : 'REQUEST_FAILED',
        message: statusCode >= 500
          ? 'Internal server error'
          : candidate?.message || 'Invalid request',
        requestId: request.id,
      },
    });
  });

  const commercialControl = options.commercialControl ?? null;
  const capabilities = ['health'];
  if (commercialControl) {
    capabilities.push(
      'customer_deployment',
      'license_authority',
      'lease_revocation',
      'telemetry_health',
    );
    await registerCommercialControlRoutes(app, commercialControl);
    app.addHook('onClose', async () => commercialControl.service.close());
  }
  await registerPlatformRoutes(app, config, {
    capabilities,
    readiness: commercialControl ? () => commercialControl.service.ready() : undefined,
  });
  return app;
}

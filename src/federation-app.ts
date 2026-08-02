import { randomUUID, timingSafeEqual } from 'node:crypto';

import rateLimit from '@fastify/rate-limit';
import Fastify, { type FastifyError, type FastifyInstance, type FastifyServerOptions } from 'fastify';
import { Counter, Gauge, Histogram, Registry } from 'prom-client';

import type { FederationConfig } from './federation-config.js';
import { ControlPlaneError } from './errors.js';
import type { FederationService } from './modules/federation/service.js';
import { registerFederationRoutes } from './routes/federation.js';

function statusCodeFor(error: unknown): number {
  if (error instanceof ControlPlaneError) return error.statusCode;
  const candidate = error instanceof Error ? error as FastifyError : null;
  if (candidate?.validation) return 400;
  const code = candidate?.statusCode ?? 500;
  return code >= 400 && code <= 599 ? code : 500;
}

function bearer(request: { headers: { authorization?: string } }): string {
  return /^Bearer\s+(.+)$/iu.exec(request.headers.authorization?.trim() || '')?.[1] || '';
}

function secureEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left, 'utf8');
  const rightBytes = Buffer.from(right, 'utf8');
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}

export async function buildFederationApp(options: {
  config: Readonly<FederationConfig>;
  service: FederationService;
  logger?: FastifyServerOptions['logger'];
}): Promise<FastifyInstance> {
  const app = Fastify({
    logger: options.logger ?? {
      level: options.config.logLevel,
      redact: {
        paths: [
          'req.headers.authorization',
          'req.body.signature',
          'req.body.envelope.ciphertext',
          'req.body.request.claimToken',
        ],
        censor: '[REDACTED]',
      },
    },
    bodyLimit: options.config.maximumCiphertextBytes + 64 * 1024,
    connectionTimeout: 10_000,
    requestTimeout: 30_000,
    keepAliveTimeout: 72_000,
    trustProxy: options.config.trustProxy,
    genReqId: () => randomUUID(),
  });
  await app.register(rateLimit, { global: false, max: 300, timeWindow: '1 minute', skipOnError: false });

  const registry = new Registry();
  const requests = new Counter({
    name: 'otto_federation_http_requests_total',
    help: 'Federation HTTP requests by route, method, and status.',
    labelNames: ['route', 'method', 'status'],
    registers: [registry],
  });
  const duration = new Histogram({
    name: 'otto_federation_http_request_duration_seconds',
    help: 'Federation HTTP request duration.',
    labelNames: ['route', 'method'],
    buckets: [0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5],
    registers: [registry],
  });
  const queue = new Gauge({
    name: 'otto_federation_messages',
    help: 'Federation messages by delivery state.',
    labelNames: ['status'],
    registers: [registry],
  });
  app.addHook('onRequest', async (request, reply) => {
    reply
      .header('cache-control', 'no-store')
      .header('content-security-policy', "default-src 'none'; frame-ancestors 'none'")
      .header('permissions-policy', 'camera=(), microphone=(), geolocation=()')
      .header('strict-transport-security', 'max-age=31536000; includeSubDomains')
      .header('x-content-type-options', 'nosniff')
      .header('x-frame-options', 'DENY')
      .header('x-request-id', request.id);
    (request as typeof request & { federationStartedAt?: bigint }).federationStartedAt = process.hrtime.bigint();
  });
  app.addHook('onResponse', async (request, reply) => {
    const route = request.routeOptions.url || 'unmatched';
    requests.inc({ route, method: request.method, status: String(reply.statusCode) });
    const started = (request as typeof request & { federationStartedAt?: bigint }).federationStartedAt;
    if (started) duration.observe({ route, method: request.method }, Number(process.hrtime.bigint() - started) / 1e9);
  });
  app.setNotFoundHandler(async (request, reply) => reply.code(404).send({
    error: { code: 'NOT_FOUND', message: 'Route not found', requestId: request.id },
  }));
  app.setErrorHandler(async (error, request, reply) => {
    const statusCode = statusCodeFor(error);
    if (statusCode >= 500) request.log.error({ err: error }, 'federation request failed');
    const message = error instanceof Error ? error.message : 'Invalid request';
    return reply.code(statusCode).send({
      error: {
        code: error instanceof ControlPlaneError ? error.code : statusCode === 400 ? 'INVALID_REQUEST' : 'REQUEST_FAILED',
        message: statusCode >= 500 ? 'Internal server error' : message,
        requestId: request.id,
      },
    });
  });

  app.get('/health/live', async () => ({ status: 'ok', service: 'otto-federation' }));
  app.get('/health/ready', async (_request, reply) =>
    await options.service.ready()
      ? { status: 'ready', service: 'otto-federation' }
      : reply.code(503).send({ status: 'not_ready', service: 'otto-federation' }));
  app.get('/metrics', async (request, reply) => {
    const expected = options.config.metricsToken;
    if (!expected || !secureEqual(bearer(request), expected)) return reply.code(404).send({ error: 'not found' });
    const stats = (await options.service.status()).queue as Record<string, number>;
    for (const [status, count] of Object.entries(stats)) queue.set({ status }, count);
    return reply.type(registry.contentType).send(await registry.metrics());
  });
  await registerFederationRoutes(app, {
    service: options.service,
    adminToken: options.config.adminToken || 'development-federation-admin-token-not-for-production',
  });

  const cleanup = setInterval(() => {
    void options.service.expire().catch((error) => app.log.error({ err: error }, 'federation cleanup failed'));
  }, options.config.cleanupIntervalMs);
  cleanup.unref?.();
  app.addHook('onClose', async () => {
    clearInterval(cleanup);
    await options.service.close();
  });
  return app;
}

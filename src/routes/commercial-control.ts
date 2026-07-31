import type { FastifyInstance } from 'fastify';

import { unauthorized } from '../errors.js';
import type { CommercialControlService } from '../modules/commercial-control/service.js';
import { actorId, bearerToken, secretMatches } from './route-auth.js';

export interface CommercialControlRouteOptions {
  service: CommercialControlService;
  adminToken: string;
}

export async function registerCommercialControlRoutes(
  app: FastifyInstance,
  options: CommercialControlRouteOptions,
): Promise<void> {
  app.register(async (admin) => {
    admin.addHook('preHandler', async (request) => {
      if (!secretMatches(bearerToken(request), options.adminToken)) {
        throw unauthorized('Control administrator token is invalid');
      }
    });

    admin.post('/customers', async (request, reply) => {
      const customer = await options.service.createCustomer(request.body, actorId(request));
      return reply.code(201).send({ customer });
    });

    admin.post('/deployments', async (request, reply) => {
      const deployment = await options.service.createDeployment(request.body, actorId(request));
      return reply.code(201).send({ deployment });
    });

    admin.post('/licenses', async (request, reply) => {
      const envelope = await options.service.issueLicense(request.body, actorId(request));
      return reply.code(201).send(envelope);
    });

    admin.get('/signing-key', async () => ({ signingKey: options.service.signingKey() }));

    admin.get<{ Params: { licenseId: string } }>('/licenses/:licenseId', async (request) => (
      options.service.getLicenseEnvelope(request.params.licenseId)
    ));

    admin.post<{ Params: { licenseId: string } }>(
      '/licenses/:licenseId/revoke',
      async (request) => ({
        license: await options.service.revokeLicense(
          request.params.licenseId,
          actorId(request),
        ),
      }),
    );

    admin.get<{
      Params: { deploymentId: string };
      Querystring: { hours?: string };
    }>('/deployments/:deploymentId/health', async (request) => ({
      health: await options.service.deploymentHealth(
        request.params.deploymentId,
        request.query.hours === undefined ? 24 : Number(request.query.hours),
      ),
    }));
  }, { prefix: '/v1/admin' });

  app.post<{ Params: { licenseId: string } }>(
    '/v1/licenses/:licenseId/lease',
    async (request) => options.service.issueLease(
      request.params.licenseId,
      request.body,
      bearerToken(request),
    ),
  );

  app.post('/v1/telemetry/ingest', {
    config: {
      rateLimit: {
        max: 300,
        timeWindow: '1 minute',
        ban: 20,
      },
    },
  }, async (request, reply) => {
    const receipt = await options.service.ingestTelemetry(request.body, {
      authorization: request.headers.authorization,
      timestamp: typeof request.headers['x-otto-timestamp'] === 'string'
        ? request.headers['x-otto-timestamp']
        : undefined,
      nonce: typeof request.headers['x-otto-nonce'] === 'string'
        ? request.headers['x-otto-nonce']
        : undefined,
      signature: typeof request.headers['x-otto-signature'] === 'string'
        ? request.headers['x-otto-signature']
        : undefined,
    });
    return reply.code(202).send(receipt);
  });
}

import type { FastifyInstance } from 'fastify';

import { unauthorized } from '../errors.js';
import type { UpdatePolicyService } from '../modules/update-policy/service.js';
import { actorId, bearerToken, secretMatches } from './route-auth.js';

export interface UpdatePolicyRouteOptions {
  service: UpdatePolicyService;
  adminToken: string;
}

export async function registerUpdatePolicyRoutes(
  app: FastifyInstance,
  options: UpdatePolicyRouteOptions,
): Promise<void> {
  app.register(async (admin) => {
    admin.addHook('preHandler', async (request) => {
      if (!secretMatches(bearerToken(request), options.adminToken)) {
        throw unauthorized('Control administrator token is invalid');
      }
    });

    admin.post('/update-distributions', async (request, reply) => {
      const distribution = await options.service.createDistribution(
        request.body,
        actorId(request),
      );
      return reply.code(201).send({ distribution });
    });

    admin.put<{ Params: { deploymentId: string } }>(
      '/deployments/:deploymentId/update-distribution',
      async (request) => ({
        assignment: await options.service.assignDeployment(
          request.params.deploymentId,
          request.body,
          actorId(request),
        ),
      }),
    );

    admin.post('/update-releases', async (request, reply) => {
      const release = await options.service.createRelease(request.body, actorId(request));
      return reply.code(201).send({ release });
    });

    admin.get<{ Params: { distributionId: string } }>(
      '/update-distributions/:distributionId/releases',
      async (request) => ({
        releases: await options.service.listReleases(request.params.distributionId),
      }),
    );

    admin.post<{ Params: { releaseId: string } }>(
      '/update-releases/:releaseId/activate',
      async (request) => options.service.activateRelease(
        request.params.releaseId,
        actorId(request),
      ),
    );

    admin.post<{ Params: { releaseId: string } }>(
      '/update-releases/:releaseId/pause',
      async (request) => ({
        release: await options.service.pauseRelease(
          request.params.releaseId,
          actorId(request),
        ),
      }),
    );

    admin.post<{ Params: { releaseId: string } }>(
      '/update-releases/:releaseId/rollback',
      async (request) => options.service.rollbackRelease(
        request.params.releaseId,
        actorId(request),
      ),
    );
  }, { prefix: '/v1/admin' });

  app.post('/v1/update-policy/resolve', {
    config: {
      rateLimit: {
        max: 120,
        timeWindow: '1 minute',
        ban: 20,
      },
    },
  }, async (request) => options.service.resolve(request.body, {
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
  }));
}


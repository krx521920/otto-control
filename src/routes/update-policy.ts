import type { FastifyInstance } from 'fastify';

import type { AdminIdentityService } from '../modules/admin-identity/service.js';
import type { UpdatePolicyService } from '../modules/update-policy/service.js';
import { authenticateAdmin, consumeRouteApproval } from './route-auth.js';

export interface UpdatePolicyRouteOptions {
  service: UpdatePolicyService;
  identity: AdminIdentityService;
}

export async function registerUpdatePolicyRoutes(
  app: FastifyInstance,
  options: UpdatePolicyRouteOptions,
): Promise<void> {
  app.register(async (admin) => {
    admin.post('/update-distributions', async (request, reply) => {
      const auth = await authenticateAdmin(request, options, 'update_distribution.manage');
      const distribution = await options.service.createDistribution(
        request.body,
        auth.actorId,
      );
      return reply.code(201).send({ distribution });
    });

    admin.put<{ Params: { deploymentId: string } }>(
      '/deployments/:deploymentId/update-distribution',
      async (request) => {
        const auth = await authenticateAdmin(request, options, 'update_distribution.manage');
        return { assignment: await options.service.assignDeployment(
          request.params.deploymentId,
          request.body,
          auth.actorId,
        ) };
      },
    );

    admin.post('/update-releases', async (request, reply) => {
      const auth = await authenticateAdmin(request, options, 'update_release.create');
      const release = await options.service.createRelease(request.body, auth.actorId);
      return reply.code(201).send({ release });
    });

    admin.get<{ Params: { distributionId: string } }>(
      '/update-distributions/:distributionId/releases',
      async (request) => {
        await authenticateAdmin(request, options, 'update_release.read');
        return { releases: await options.service.listReleases(request.params.distributionId) };
      },
    );

    admin.post<{ Params: { releaseId: string } }>(
      '/update-releases/:releaseId/activate',
      async (request) => {
        const auth = await authenticateAdmin(request, options, 'update_release.publish');
        await consumeRouteApproval(request, options.identity, auth.principal, {
          operation: 'update_release.activate',
          targetType: 'update_release',
          targetId: request.params.releaseId,
          request: {},
        });
        return options.service.activateRelease(request.params.releaseId, auth.actorId);
      },
    );

    admin.post<{ Params: { releaseId: string } }>(
      '/update-releases/:releaseId/pause',
      async (request) => {
        const auth = await authenticateAdmin(request, options, 'update_release.publish');
        return { release: await options.service.pauseRelease(
          request.params.releaseId,
          auth.actorId,
        ) };
      },
    );

    admin.post<{ Params: { releaseId: string } }>(
      '/update-releases/:releaseId/rollback',
      async (request) => {
        const auth = await authenticateAdmin(request, options, 'update_release.publish');
        await consumeRouteApproval(request, options.identity, auth.principal, {
          operation: 'update_release.rollback',
          targetType: 'update_release',
          targetId: request.params.releaseId,
          request: {},
        });
        return options.service.rollbackRelease(request.params.releaseId, auth.actorId);
      },
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

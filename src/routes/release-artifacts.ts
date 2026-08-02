import type { FastifyInstance } from 'fastify';

import type { AdminIdentityService } from '../modules/admin-identity/service.js';
import type { ReleaseArtifactService } from '../modules/release-artifacts/service.js';
import { authenticateAdmin, consumeRouteApproval } from './route-auth.js';

export interface ReleaseArtifactRouteOptions {
  service: ReleaseArtifactService;
  identity: AdminIdentityService;
}

export async function registerReleaseArtifactRoutes(
  app: FastifyInstance,
  options: ReleaseArtifactRouteOptions,
): Promise<void> {
  app.register(async (admin) => {
    admin.post<{ Params: { releaseId: string } }>(
      '/update-releases/:releaseId/artifact-uploads',
      async (request, reply) => {
        const auth = await authenticateAdmin(request, options, 'update_release.create');
        const result = await options.service.createUpload(
          request.params.releaseId,
          request.body,
          auth.actorId,
        );
        return reply.code(201).send(result);
      },
    );

    admin.post<{ Params: { releaseId: string } }>(
      '/update-releases/:releaseId/artifact-uploads/complete',
      async (request, reply) => {
        const auth = await authenticateAdmin(request, options, 'update_release.create');
        const artifact = await options.service.completeUpload(
          request.params.releaseId,
          request.body,
          auth.actorId,
        );
        return reply.code(201).send({ artifact });
      },
    );

    admin.post<{ Params: { releaseId: string } }>(
      '/update-releases/:releaseId/artifacts',
      async (request, reply) => {
        const auth = await authenticateAdmin(request, options, 'update_release.create');
        const artifact = await options.service.register(
          request.params.releaseId,
          request.body,
          auth.actorId,
        );
        return reply.code(201).send({ artifact });
      },
    );

    admin.get<{ Params: { releaseId: string } }>(
      '/update-releases/:releaseId/artifacts',
      async (request) => {
        await authenticateAdmin(request, options, 'update_release.read');
        return { artifacts: await options.service.list(request.params.releaseId) };
      },
    );

    admin.post<{ Params: { artifactId: string } }>(
      '/release-artifacts/:artifactId/revoke',
      async (request) => {
        const auth = await authenticateAdmin(request, options, 'update_release.publish');
        await consumeRouteApproval(request, options.identity, auth.principal, {
          operation: 'release_artifact.revoke',
          targetType: 'release_artifact',
          targetId: request.params.artifactId,
          request: request.body ?? {},
        });
        return options.service.revoke(request.params.artifactId, request.body, auth.actorId);
      },
    );
  }, { prefix: '/v1/admin' });

  app.get<{ Params: { artifactId: string } }>(
    '/v1/release-artifacts/:artifactId/download',
    {
      config: {
        rateLimit: { max: 300, timeWindow: '1 minute', ban: 30 },
      },
    },
    async (request, reply) => {
      const resolved = await options.service.resolveDownload(request.params.artifactId);
      return reply
        .header('cache-control', 'no-store')
        .header('x-otto-download-expires-at', resolved.expiresAt)
        .redirect(resolved.url, 307);
    },
  );
}

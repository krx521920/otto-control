import { timingSafeEqual } from 'node:crypto';

import type { FastifyInstance, FastifyRequest } from 'fastify';

import type { FederationSignedRequest, SignedFederationEnvelope } from '../contracts/federation.js';
import { unauthorized } from '../errors.js';
import type { FederationService } from '../modules/federation/service.js';

function tokenMatches(candidate: string, expected: string): boolean {
  const left = Buffer.from(candidate, 'utf8');
  const right = Buffer.from(expected, 'utf8');
  return left.length === right.length && timingSafeEqual(left, right);
}

function requireAdmin(request: FastifyRequest, token: string): void {
  const authorization = request.headers.authorization?.trim() || '';
  const candidate = /^Bearer\s+(.+)$/iu.exec(authorization)?.[1] || '';
  if (!tokenMatches(candidate, token)) throw unauthorized('federation administrator token is invalid');
}

export async function registerFederationRoutes(
  app: FastifyInstance,
  options: { service: FederationService; adminToken: string },
): Promise<void> {
  app.get('/v1/federation/status', async () => options.service.status());
  app.get<{ Params: { deploymentId: string } }>(
    '/v1/federation/directory/:deploymentId',
    { config: { rateLimit: { max: 120, timeWindow: '1 minute' } } },
    async (request) => options.service.directoryEntry(request.params.deploymentId),
  );
  app.get<{ Params: { deploymentId: string; keyId: string } }>(
    '/v1/federation/directory/:deploymentId/keys/:keyId',
    { config: { rateLimit: { max: 240, timeWindow: '1 minute' } } },
    async (request) => options.service.directoryKey(request.params.deploymentId, request.params.keyId),
  );

  app.post<{ Body: SignedFederationEnvelope }>(
    '/v1/federation/envelopes',
    { config: { rateLimit: { max: 600, timeWindow: '1 minute', ban: 20 } } },
    async (request, reply) => reply.code(202).send(await options.service.enqueue(request.body)),
  );
  app.post<{ Body: FederationSignedRequest<Record<string, unknown>> }>(
    '/v1/federation/inbox/claim',
    { config: { rateLimit: { max: 300, timeWindow: '1 minute', ban: 20 } } },
    async (request) => options.service.claim(request.body),
  );
  app.post<{ Body: FederationSignedRequest<Record<string, unknown>> }>(
    '/v1/federation/inbox/ack',
    { config: { rateLimit: { max: 600, timeWindow: '1 minute', ban: 20 } } },
    async (request) => options.service.acknowledge(request.body),
  );
  app.post<{ Body: FederationSignedRequest<Record<string, unknown>> }>(
    '/v1/federation/a2a/grants',
    { config: { rateLimit: { max: 120, timeWindow: '1 minute', ban: 20 } } },
    async (request, reply) => reply.code(201).send(await options.service.createA2aGrant(request.body)),
  );
  app.post<{ Body: FederationSignedRequest<Record<string, unknown>> }>(
    '/v1/federation/a2a/grants/revoke',
    { config: { rateLimit: { max: 120, timeWindow: '1 minute', ban: 20 } } },
    async (request) => options.service.revokeA2aGrant(request.body),
  );

  app.register(async (admin) => {
    admin.addHook('onRequest', async (request) => requireAdmin(request, options.adminToken));
    admin.get<{ Querystring: { limit?: string } }>('/deployments', async (request) =>
      options.service.listDeployments(request.query.limit));
    admin.post<{ Body: Record<string, unknown> }>('/deployments', async (request, reply) =>
      reply.code(201).send(await options.service.registerDeployment(request.body || {})));
    admin.patch<{ Params: { deploymentId: string }; Body: Record<string, unknown> }>(
      '/deployments/:deploymentId/status',
      async (request) => options.service.setDeploymentStatus(request.params.deploymentId, request.body?.status),
    );
    admin.post<{ Params: { deploymentId: string }; Body: Record<string, unknown> }>(
      '/deployments/:deploymentId/keys',
      async (request, reply) => reply.code(201).send(
        await options.service.registerKey(request.params.deploymentId, request.body || {}),
      ),
    );
    admin.post<{ Params: { deploymentId: string; keyId: string } }>(
      '/deployments/:deploymentId/keys/:keyId/revoke',
      async (request) => options.service.revokeKey(request.params.deploymentId, request.params.keyId),
    );
    admin.post<{ Params: { deploymentId: string }; Body: Record<string, unknown> }>(
      '/deployments/:deploymentId/blocks',
      async (request, reply) => reply.code(201).send(
        await options.service.setBlock(request.params.deploymentId, request.body || {}),
      ),
    );
    admin.delete<{ Params: { deploymentId: string; blockedDeploymentId: string } }>(
      '/deployments/:deploymentId/blocks/:blockedDeploymentId',
      async (request) => options.service.removeBlock(
        request.params.deploymentId,
        request.params.blockedDeploymentId,
      ),
    );
  }, { prefix: '/v1/admin/federation' });
}

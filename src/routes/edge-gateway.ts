import type { FastifyInstance, FastifyRequest } from 'fastify';

import type { AdminIdentityService } from '../modules/admin-identity/service.js';
import type {
  EdgeGatewayControlService,
  EdgeGatewayRequestAuthentication,
} from '../modules/edge-gateway/service.js';
import { authenticateAdmin } from './route-auth.js';

export interface EdgeGatewayRouteOptions {
  service: EdgeGatewayControlService;
  identity: AdminIdentityService;
}

function requestAuthentication(request: FastifyRequest): EdgeGatewayRequestAuthentication {
  return {
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
  };
}

export async function registerEdgeGatewayRoutes(
  app: FastifyInstance,
  options: EdgeGatewayRouteOptions,
): Promise<void> {
  app.register(async (admin) => {
    admin.get<{ Params: { deploymentId: string } }>(
      '/deployments/:deploymentId/edge-gateway-policy',
      async (request) => {
        await authenticateAdmin(request, options, 'edge_gateway.read');
        return { policy: await options.service.policy(request.params.deploymentId) };
      },
    );

    admin.put<{ Params: { deploymentId: string } }>(
      '/deployments/:deploymentId/edge-gateway-policy',
      async (request) => {
        const auth = await authenticateAdmin(request, options, 'edge_gateway.manage');
        return {
          policy: await options.service.configurePolicy(
            request.params.deploymentId,
            request.body,
            auth.actorId,
          ),
        };
      },
    );
  }, { prefix: '/v1/admin' });

  app.post('/v1/edge-gateway/policy/resolve', {
    config: { rateLimit: { max: 120, timeWindow: '1 minute', ban: 20 } },
  }, async (request) => ({
    policy: await options.service.resolvePolicy(
      request.body,
      requestAuthentication(request),
    ),
  }));

  app.post('/v1/edge-gateway/access-tokens', {
    config: { rateLimit: { max: 300, timeWindow: '1 minute', ban: 20 } },
  }, async (request, reply) => reply.code(201).send(
    await options.service.issueDeploymentAccessToken(
      request.body,
      requestAuthentication(request),
    ),
  ));
}

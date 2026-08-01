import type { FastifyInstance } from 'fastify';

import type { AdminIdentityService } from '../modules/admin-identity/service.js';
import type { AuditAnchorService } from '../modules/audit-anchor/service.js';
import { authenticateAdmin } from './route-auth.js';

export interface AuditAnchorRouteOptions {
  service: AuditAnchorService;
  identity: AdminIdentityService;
}

export async function registerAuditAnchorRoutes(
  app: FastifyInstance,
  options: AuditAnchorRouteOptions,
): Promise<void> {
  app.get<{ Querystring: { limit?: string } }>(
    '/v1/admin/audit/anchors',
    async (request) => {
      await authenticateAdmin(request, options, 'audit.read');
      return options.service.list(request.query.limit === undefined ? 50 : Number(request.query.limit));
    },
  );

  app.post('/v1/admin/audit/anchors/poll', async (request) => {
    const auth = await authenticateAdmin(request, options, 'audit.anchor.manage');
    return options.service.pollOnce(auth.actorId, true);
  });

  app.post<{ Params: { anchorId: string } }>(
    '/v1/admin/audit/anchors/:anchorId/retry',
    async (request) => {
      const auth = await authenticateAdmin(request, options, 'audit.anchor.manage');
      return { anchor: await options.service.retry(request.params.anchorId, auth.actorId) };
    },
  );
}

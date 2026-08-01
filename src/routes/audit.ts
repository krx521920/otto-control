import type { FastifyInstance } from 'fastify';

import type { AdminIdentityService } from '../modules/admin-identity/service.js';
import type { AuditService } from '../modules/audit/service.js';
import { authenticateAdmin } from './route-auth.js';

export interface AuditRouteOptions {
  service: AuditService;
  identity: AdminIdentityService;
}

export async function registerAuditRoutes(
  app: FastifyInstance,
  options: AuditRouteOptions,
): Promise<void> {
  app.get<{ Querystring: Record<string, string | undefined> }>(
    '/v1/admin/audit/events',
    async (request) => {
      await authenticateAdmin(request, options, 'audit.read');
      return options.service.events(request.query);
    },
  );

  app.get<{ Querystring: Record<string, string | undefined> }>(
    '/v1/admin/audit/export.csv',
    async (request, reply) => {
      await authenticateAdmin(request, options, 'audit.export');
      const csv = await options.service.exportCsv(request.query);
      const date = new Date().toISOString().slice(0, 10);
      return reply
        .type('text/csv; charset=utf-8')
        .header('content-disposition', `attachment; filename="otto-control-audit-${date}.csv"`)
        .send(csv);
    },
  );

  app.post('/v1/admin/audit/verify', async (request) => {
    await authenticateAdmin(request, options, 'audit.verify');
    return options.service.verify();
  });
}

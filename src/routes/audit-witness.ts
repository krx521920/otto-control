import type { FastifyInstance } from 'fastify';

import type { AdminIdentityService } from '../modules/admin-identity/service.js';
import type { AuditWitnessService } from '../modules/audit-witness/service.js';
import { authenticateAdmin, bearerToken } from './route-auth.js';

export interface AuditWitnessRouteOptions {
  service: AuditWitnessService;
  identity: AdminIdentityService;
}

export async function registerAuditWitnessRoutes(
  app: FastifyInstance,
  options: AuditWitnessRouteOptions,
): Promise<void> {
  app.post('/v1/audit-witness/anchors', {
    config: { rateLimit: { max: 120, timeWindow: '1 minute' } },
  }, async (request, reply) => {
    const result = await options.service.ingest(request.body, bearerToken(request));
    return reply
      .code(result.replayed ? 200 : 201)
      .header('x-otto-audit-anchor-reference', result.receipt.id)
      .send(result);
  });

  app.get<{ Querystring: { sourceId?: string; limit?: string } }>(
    '/v1/admin/audit-witness/receipts',
    async (request) => {
      await authenticateAdmin(request, options, 'audit.read');
      return options.service.list(request.query);
    },
  );
}

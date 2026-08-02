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

  app.get<{ Querystring: { limit?: string } }>(
    '/v1/admin/audit-witness/worm/status',
    async (request) => {
      await authenticateAdmin(request, options, 'audit.read');
      return options.service.evidenceStatus(request.query.limit ? Number(request.query.limit) : 50);
    },
  );

  app.post('/v1/admin/audit-witness/worm/poll', async (request) => {
    await authenticateAdmin(request, options, 'audit.anchor.manage');
    return options.service.pollEvidenceOnce();
  });

  app.post<{ Params: { receiptId: string } }>(
    '/v1/admin/audit-witness/worm/:receiptId/retry',
    async (request) => {
      const principal = await authenticateAdmin(request, options, 'audit.anchor.manage');
      return options.service.retryEvidence(request.params.receiptId, principal.actorId);
    },
  );

  app.post<{ Params: { receiptId: string } }>(
    '/v1/admin/audit-witness/worm/:receiptId/verify',
    async (request) => {
      await authenticateAdmin(request, options, 'audit.verify');
      return options.service.verifyEvidence(request.params.receiptId);
    },
  );

  app.post<{ Body: { continuationToken?: unknown; limit?: unknown } }>(
    '/v1/admin/audit-witness/worm/recover',
    async (request) => {
      const principal = await authenticateAdmin(request, options, 'audit.anchor.manage');
      return options.service.recoverEvidence(request.body ?? {}, principal.actorId);
    },
  );
}

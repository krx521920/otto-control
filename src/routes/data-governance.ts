import type { FastifyInstance } from 'fastify';

import type { AdminIdentityService } from '../modules/admin-identity/service.js';
import type { DataGovernanceService } from '../modules/data-governance/service.js';
import { authenticateAdmin, consumeRouteApproval } from './route-auth.js';

export interface DataGovernanceRouteOptions {
  service: DataGovernanceService;
  identity: AdminIdentityService;
  telemetryRetentionDays: number;
}

export async function registerDataGovernanceRoutes(
  app: FastifyInstance,
  options: DataGovernanceRouteOptions,
): Promise<void> {
  app.get('/v1/privacy/notice', async () => options.service.privacyNotice());
  app.get('/v1/privacy/data-map', async () => options.service.dataMap());

  app.get('/v1/admin/data-governance/status', async (request) => {
    await authenticateAdmin(request, options, 'data_governance.read');
    return options.service.status();
  });

  app.get<{ Params: { id: string } }>(
    '/v1/admin/data-governance/requests/:id',
    async (request) => {
      await authenticateAdmin(request, options, 'data_governance.read');
      return options.service.request(request.params.id);
    },
  );

  app.post<{ Body: Record<string, unknown> }>(
    '/v1/admin/data-governance/privacy-acceptances',
    async (request, reply) => {
      const { actorId } = await authenticateAdmin(request, options, 'data_governance.manage');
      const record = await options.service.acceptPrivacyPolicy(actorId, request.body || {});
      return reply.code(201).send(record);
    },
  );

  app.post<{ Params: { customerId: string }; Body: Record<string, unknown> }>(
    '/v1/admin/customers/:customerId/data-exports',
    async (request, reply) => {
      const { actorId } = await authenticateAdmin(request, options, 'data_export.create');
      const result = await options.service.exportCustomer(
        actorId,
        request.params.customerId,
        request.body?.reason,
      );
      return reply.code(201).send(result);
    },
  );

  app.post<{ Params: { customerId: string }; Body: Record<string, unknown> }>(
    '/v1/admin/customers/:customerId/erasure-requests',
    async (request, reply) => {
      const { actorId } = await authenticateAdmin(request, options, 'customer_erasure.manage');
      const result = await options.service.requestCustomerErasure(
        actorId,
        request.params.customerId,
        request.body?.reason,
      );
      return reply.code(202).send(result);
    },
  );

  app.post<{ Params: { id: string }; Body: Record<string, unknown> }>(
    '/v1/admin/data-governance/erasure-requests/:id/execute',
    async (request) => {
      const { actorId, principal } = await authenticateAdmin(
        request,
        options,
        'customer_erasure.manage',
      );
      await consumeRouteApproval(request, options.identity, principal, {
        operation: 'customer_erasure.execute',
        targetType: 'data_governance_request',
        targetId: request.params.id,
        request: request.body || {},
      });
      return options.service.executeCustomerErasure(actorId, request.params.id);
    },
  );

  app.post<{ Body: Record<string, unknown> }>(
    '/v1/admin/data-governance/legal-holds',
    async (request, reply) => {
      const { actorId, principal } = await authenticateAdmin(request, options, 'legal_hold.manage');
      const body = request.body || {};
      const targetId = typeof body.customerId === 'string' ? body.customerId : '';
      await consumeRouteApproval(request, options.identity, principal, {
        operation: 'legal_hold.create',
        targetType: 'customer',
        targetId,
        request: body,
      });
      return reply.code(201).send(await options.service.createLegalHold(actorId, body));
    },
  );

  app.post<{ Params: { id: string }; Body: Record<string, unknown> }>(
    '/v1/admin/data-governance/legal-holds/:id/release',
    async (request) => {
      const { actorId, principal } = await authenticateAdmin(request, options, 'legal_hold.manage');
      const body = request.body || {};
      await consumeRouteApproval(request, options.identity, principal, {
        operation: 'legal_hold.release',
        targetType: 'legal_hold',
        targetId: request.params.id,
        request: body,
      });
      return options.service.releaseLegalHold(actorId, request.params.id, body.reason);
    },
  );

  app.post<{ Body: Record<string, unknown> }>(
    '/v1/admin/data-governance/forensic-exports',
    async (request, reply) => {
      const { actorId, principal } = await authenticateAdmin(
        request,
        options,
        'forensic_export.create',
      );
      const body = request.body || {};
      const targetId = typeof body.customerId === 'string' ? body.customerId : '';
      await consumeRouteApproval(request, options.identity, principal, {
        operation: 'forensic_export.create',
        targetType: 'customer',
        targetId,
        request: body,
      });
      return reply.code(201).send(await options.service.forensicExport(actorId, body));
    },
  );

  app.post('/v1/admin/data-governance/retention/run', async (request) => {
    const { actorId } = await authenticateAdmin(request, options, 'data_governance.manage');
    return options.service.runRetention(actorId, options.telemetryRetentionDays);
  });
}

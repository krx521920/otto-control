import type { FastifyInstance } from 'fastify';

import type { AdminIdentityService } from '../modules/admin-identity/service.js';
import type { BillingService } from '../modules/billing/service.js';
import { authenticateAdmin, bearerToken, consumeRouteApproval } from './route-auth.js';

export interface BillingRouteOptions {
  service: BillingService;
  identity: AdminIdentityService;
}

export async function registerBillingRoutes(
  app: FastifyInstance,
  options: BillingRouteOptions,
): Promise<void> {
  app.register(async (admin) => {
    admin.get<{ Params: { customerId: string } }>(
      '/billing/customers/:customerId/account',
      async (request) => {
        await authenticateAdmin(request, options, 'billing.read');
        return { account: await options.service.account(request.params.customerId) };
      },
    );

    admin.get<{ Params: { customerId: string } }>(
      '/billing/customers/:customerId/rates',
      async (request) => {
        await authenticateAdmin(request, options, 'billing.read');
        return { rates: await options.service.rates(request.params.customerId) };
      },
    );

    admin.put<{ Params: { customerId: string; module: string } }>(
      '/billing/customers/:customerId/rates/:module',
      async (request) => {
        const auth = await authenticateAdmin(request, options, 'billing.manage');
        const body = { ...(request.body as Record<string, unknown> ?? {}), module: request.params.module };
        await consumeRouteApproval(request, options.identity, auth.principal, {
          operation: 'billing.rate.set',
          targetType: 'customer',
          targetId: request.params.customerId,
          request: body,
        });
        return { rate: await options.service.setRate(
          request.params.customerId,
          body,
          auth.actorId,
        ) };
      },
    );

    admin.post<{ Params: { customerId: string } }>(
      '/billing/customers/:customerId/topups',
      async (request, reply) => {
        const auth = await authenticateAdmin(request, options, 'billing.topup');
        await consumeRouteApproval(request, options.identity, auth.principal, {
          operation: 'billing.topup',
          targetType: 'customer',
          targetId: request.params.customerId,
          request: request.body ?? {},
        });
        const result = await options.service.topUp(
          request.params.customerId,
          request.body,
          auth.actorId,
        );
        return reply.code(result.replayed ? 200 : 201).send(result);
      },
    );

    admin.post<{ Params: { customerId: string } }>(
      '/billing/customers/:customerId/refunds',
      async (request, reply) => {
        const auth = await authenticateAdmin(request, options, 'billing.refund');
        await consumeRouteApproval(request, options.identity, auth.principal, {
          operation: 'billing.refund',
          targetType: 'customer',
          targetId: request.params.customerId,
          request: request.body ?? {},
        });
        const result = await options.service.refund(
          request.params.customerId,
          request.body,
          auth.actorId,
        );
        return reply.code(result.replayed ? 200 : 201).send(result);
      },
    );

    admin.get<{
      Params: { customerId: string };
      Querystring: Record<string, string | undefined>;
    }>('/billing/customers/:customerId/transactions', async (request) => {
      await authenticateAdmin(request, options, 'billing.read');
      return { transactions: await options.service.transactions(
        request.params.customerId,
        request.query,
      ) };
    });

    admin.get<{
      Params: { customerId: string };
      Querystring: Record<string, string | undefined>;
    }>('/billing/customers/:customerId/statement', async (request) => {
      await authenticateAdmin(request, options, 'billing.read');
      return { statement: await options.service.statement(request.params.customerId, request.query) };
    });

    admin.get<{
      Params: { customerId: string };
      Querystring: Record<string, string | undefined>;
    }>('/billing/customers/:customerId/export.csv', async (request, reply) => {
      await authenticateAdmin(request, options, 'billing.read');
      const csv = await options.service.exportCsv(request.params.customerId, request.query);
      return reply
        .type('text/csv; charset=utf-8')
        .header('content-disposition', `attachment; filename="otto-billing-${request.params.customerId}.csv"`)
        .send(csv);
    });
  }, { prefix: '/v1/admin' });

  app.post('/v1/billing/usage/consume', {
    config: { rateLimit: { max: 600, timeWindow: '1 minute', ban: 20 } },
  }, async (request, reply) => {
    const result = await options.service.consumeUsage(request.body, bearerToken(request));
    return reply.code(result.replayed ? 200 : 201).send(result);
  });

  app.post('/v1/billing/holds', async (request, reply) => {
    const result = await options.service.createHold(request.body, bearerToken(request));
    return reply.code(result.replayed ? 200 : 201).send(result);
  });

  app.post<{ Params: { holdId: string } }>(
    '/v1/billing/holds/:holdId/capture',
    async (request, reply) => {
      const result = await options.service.captureHold(
        request.params.holdId,
        request.body,
        bearerToken(request),
      );
      return reply.code(result.replayed ? 200 : 201).send(result);
    },
  );

  app.post<{ Params: { holdId: string } }>(
    '/v1/billing/holds/:holdId/release',
    async (request) => options.service.releaseHold(
      request.params.holdId,
      request.body,
      bearerToken(request),
    ),
  );
}

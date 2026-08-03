import type { FastifyInstance } from 'fastify';

import type { AdminIdentityService } from '../modules/admin-identity/service.js';
import type { CommercialDeliveryService } from '../modules/commercial-delivery/service.js';
import { authenticateAdmin } from './route-auth.js';

export async function registerCommercialDeliveryRoutes(
  app: FastifyInstance,
  options: { service: CommercialDeliveryService; identity: AdminIdentityService },
): Promise<void> {
  app.get<{
    Params: { customerId: string };
    Querystring: Record<string, string | undefined>;
  }>('/v1/admin/customers/:customerId/delivery-package.json', async (request, reply) => {
    const auth = await authenticateAdmin(request, options, 'customer_delivery.read');
    const result = await options.service.package(
      auth.actorId,
      request.params.customerId,
      request.query,
    );
    return reply
      .type('application/json; charset=utf-8')
      .header('cache-control', 'no-store')
      .header(
        'content-disposition',
        `attachment; filename="otto-delivery-${request.params.customerId}.json"`,
      )
      .send(result);
  });

  app.get<{
    Params: { customerId: string };
    Querystring: Record<string, string | undefined>;
  }>('/v1/admin/customers/:customerId/roi-report.csv', async (request, reply) => {
    const auth = await authenticateAdmin(request, options, 'customer_delivery.read');
    const csv = await options.service.roiCsv(
      auth.actorId,
      request.params.customerId,
      request.query,
    );
    return reply
      .type('text/csv; charset=utf-8')
      .header('cache-control', 'no-store')
      .header(
        'content-disposition',
        `attachment; filename="otto-roi-${request.params.customerId}.csv"`,
      )
      .send(csv);
  });
}

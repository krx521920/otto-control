import type { FastifyInstance } from 'fastify';

import type { AdminIdentityService } from '../modules/admin-identity/service.js';
import type { AlertDeliveryService } from '../modules/alert-delivery/service.js';
import { authenticateAdmin } from './route-auth.js';

export interface AlertDeliveryRouteOptions {
  service: AlertDeliveryService;
  identity: AdminIdentityService;
}

export async function registerAlertDeliveryRoutes(
  app: FastifyInstance,
  options: AlertDeliveryRouteOptions,
): Promise<void> {
  app.get<{ Querystring: { limit?: string } }>(
    '/v1/admin/alerts/deliveries',
    async (request) => {
      await authenticateAdmin(request, options, 'alert.read');
      return options.service.list(request.query.limit === undefined ? 50 : Number(request.query.limit));
    },
  );

  app.post('/v1/admin/alerts/poll', async (request) => {
    const auth = await authenticateAdmin(request, options, 'alert.manage');
    return options.service.pollOnce(auth.actorId);
  });

  app.post<{ Params: { deliveryId: string } }>(
    '/v1/admin/alerts/deliveries/:deliveryId/retry',
    async (request) => {
      const auth = await authenticateAdmin(request, options, 'alert.manage');
      return { delivery: await options.service.retry(request.params.deliveryId, auth.actorId) };
    },
  );
}

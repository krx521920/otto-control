import type { FastifyInstance } from 'fastify';

import type { AdminIdentityService } from '../modules/admin-identity/service.js';
import type { BackupStatusService } from '../modules/backup-status/service.js';
import { authenticateAdmin } from './route-auth.js';

export interface BackupStatusRouteOptions {
  service: BackupStatusService;
  identity: AdminIdentityService;
}

export async function registerBackupStatusRoutes(
  app: FastifyInstance,
  options: BackupStatusRouteOptions,
): Promise<void> {
  app.get<{ Querystring: { limit?: string } }>(
    '/v1/admin/backups/status',
    async (request) => {
      await authenticateAdmin(request, options, 'backup.read');
      return options.service.status(request.query.limit === undefined ? 20 : Number(request.query.limit));
    },
  );
}

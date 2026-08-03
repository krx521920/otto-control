import Fastify from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import type { AdminIdentityService } from '../src/modules/admin-identity/service.js';
import type { CommercialDeliveryService } from '../src/modules/commercial-delivery/service.js';
import { registerCommercialDeliveryRoutes } from '../src/routes/commercial-delivery.js';

describe('commercial delivery routes', () => {
  it('requires the dedicated read permission and returns downloadable evidence', async () => {
    const app = Fastify();
    const identity = {
      authenticate: vi.fn(async () => ({
        accountId: 'admin_001',
        sessionId: 'session_001',
        username: 'admin',
        displayName: 'Admin',
        roles: ['auditor'],
        permissions: ['customer_delivery.read'],
        mfaVerifiedAt: new Date(),
      })),
    } as unknown as AdminIdentityService;
    const service = {
      package: vi.fn(async () => ({ bundle: { version: 1 }, signature: 'ed25519:test' })),
      roiCsv: vi.fn(async () => '\uFEFFmodule,verifiedTasks\r\nmeeting_agent,2\r\n'),
    } as unknown as CommercialDeliveryService;
    await registerCommercialDeliveryRoutes(app, { service, identity });

    const delivery = await app.inject({
      method: 'GET',
      url: '/v1/admin/customers/customer_001/delivery-package.json',
      headers: { authorization: 'Bearer admin-session' },
    });
    expect(delivery.statusCode).toBe(200);
    expect(delivery.headers['cache-control']).toBe('no-store');
    expect(delivery.headers['content-disposition']).toContain('otto-delivery-customer_001.json');

    const roi = await app.inject({
      method: 'GET',
      url: '/v1/admin/customers/customer_001/roi-report.csv',
      headers: { authorization: 'Bearer admin-session' },
    });
    expect(roi.statusCode).toBe(200);
    expect(roi.headers['content-disposition']).toContain('otto-roi-customer_001.csv');
    await app.close();
  });
});

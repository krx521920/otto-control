import Fastify from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { AdminPrincipal } from '../src/contracts/admin-identity.js';
import type { AdminIdentityService } from '../src/modules/admin-identity/service.js';
import type { DataGovernanceService } from '../src/modules/data-governance/service.js';
import { registerDataGovernanceRoutes } from '../src/routes/data-governance.js';

describe('data governance HTTP routes', () => {
  const apps: Array<ReturnType<typeof Fastify>> = [];
  afterEach(async () => Promise.all(apps.splice(0).map((app) => app.close())));

  it('keeps notices public and requires a consumed dual-control approval for erasure', async () => {
    const principal: AdminPrincipal = {
      accountId: 'admin_001',
      sessionId: 'session_001',
      username: 'security.admin',
      displayName: 'Security admin',
      roles: ['security_admin'],
      permissions: ['data_governance.read', 'customer_erasure.manage'],
      mfaVerifiedAt: new Date(),
    };
    const consumeApproval = vi.fn(async () => undefined);
    const identity = {
      authenticate: vi.fn(async () => principal),
      consumeApproval,
    } as unknown as AdminIdentityService;
    const executeCustomerErasure = vi.fn(async () => ({ completed: true }));
    const service = {
      privacyNotice: () => ({ version: '2026-08-01' }),
      dataMap: () => ({ primaryRegion: 'CN-BJ' }),
      executeCustomerErasure,
    } as unknown as DataGovernanceService;
    const app = Fastify();
    apps.push(app);
    await registerDataGovernanceRoutes(app, {
      identity,
      service,
      telemetryRetentionDays: 90,
    });

    expect((await app.inject({ method: 'GET', url: '/v1/privacy/notice' })).json())
      .toEqual({ version: '2026-08-01' });
    const response = await app.inject({
      method: 'POST',
      url: '/v1/admin/data-governance/erasure-requests/dgr_001/execute',
      headers: {
        authorization: 'Bearer session-token',
        'x-otto-approval-id': 'approval_001',
      },
      payload: {},
    });
    expect(response.statusCode).toBe(200);
    expect(consumeApproval).toHaveBeenCalledWith(principal, 'approval_001', {
      operation: 'customer_erasure.execute',
      targetType: 'data_governance_request',
      targetId: 'dgr_001',
      request: {},
    });
    expect(executeCustomerErasure).toHaveBeenCalledWith('admin_001', 'dgr_001');
  });
});

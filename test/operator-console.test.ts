import vm from 'node:vm';

import Fastify from 'fastify';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { registerOperatorConsoleRoutes } from '../src/routes/operator-console.js';

describe('operator console assets', () => {
  let app: ReturnType<typeof Fastify>;

  beforeEach(async () => {
    app = Fastify();
    await registerOperatorConsoleRoutes(app);
  });

  afterEach(async () => {
    await app.close();
  });

  it('serves a no-store console with a restrictive same-origin policy', async () => {
    const response = await app.inject({ method: 'GET', url: '/admin' });
    expect(response.statusCode).toBe(200);
    expect(response.headers['cache-control']).toBe('no-store');
    expect(response.headers['content-security-policy']).toContain("script-src 'self'");
    expect(response.headers['content-security-policy']).toContain("connect-src 'self'");
    expect(response.headers['content-security-policy']).not.toContain("'unsafe-inline'");
    expect(response.body).toContain('商业运营控制台');
    expect(response.body).toContain('/admin/assets/app.js');
    expect(response.body).not.toContain('CONTROL_ADMIN_TOKEN');
  });

  it('keeps administrator sessions tab-scoped and renders data without innerHTML', async () => {
    const response = await app.inject({ method: 'GET', url: '/admin/assets/app.js' });
    expect(response.statusCode).toBe(200);
    expect(response.headers['content-type']).toContain('text/javascript');
    expect(() => new vm.Script(response.body)).not.toThrow();
    expect(response.body).toContain('sessionStorage');
    expect(response.body).not.toContain('localStorage');
    expect(response.body).not.toContain('innerHTML');
    expect(response.body).toContain('/v1/admin-auth/login');
    expect(response.body).toContain('/v1/admin/overview?limit=50');
    expect(response.body).toContain("byId('alert-channels')");
    expect(response.body).toContain('delivery.channelId');
    expect(response.body).toContain("'customer.create'");
    expect(response.body).toContain("'deployment.create'");
    expect(response.body).toContain("'license.issue'");
    expect(response.body).toContain('hasPermission(permission)');
    expect(response.body).toContain('syncOfflineLicenseControls()');
    expect(response.body).toContain("request('/v1/admin/customers', { method: 'POST'");
    expect(response.body).toContain("request('/v1/admin/deployments', { method: 'POST'");
    expect(response.body).toContain("request('/v1/admin/licenses', { method: 'POST'");
    expect(response.body).toContain("'/summary'");
    expect(response.body).toContain("'/lifecycle?limit=50'");
    expect(response.body).toContain("'/seats'");
    expect(response.body).toContain("'/renew'");
    expect(response.body).toContain("'/resize'");
    expect(response.body).toContain("hasPermission('license.manage')");
    expect(response.body).toContain("hasPermission('license.usage.read')");
    expect(response.body).toContain('/v1/admin/approvals?limit=50');
    expect(response.body).toContain('/v1/admin/audit/events?');
    expect(response.body).toContain('/v1/admin/audit/verify');
    expect(response.body).toContain('/v1/admin/audit/export.csv?');
    expect(response.body).toContain('/v1/admin/audit/anchors?');
    expect(response.body).toContain('/v1/admin/audit/anchors/poll');
    expect(response.body).toContain('/v1/admin/audit-witness/receipts?');
    expect(response.body).toContain("'x-otto-approval-id': approval.id");
    expect(response.body).toContain("operation: 'license.revoke'");
    expect(response.body).toContain("hasPermission('approval.decide')");
    expect(response.body).toContain('approval.request || {}');
    expect(response.body).toContain('URL.createObjectURL(blob)');
    expect(response.body).toContain('otto-license-');
  });
});

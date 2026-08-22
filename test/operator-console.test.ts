import vm from 'node:vm';

import Fastify from 'fastify';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { ADMIN_APPROVAL_OPERATIONS } from '../src/contracts/admin-identity.js';
import { OPERATOR_CONSOLE_APPROVAL_ACTIONS } from '../src/modules/operator-console/approval-assets.js';
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
    expect(response.body).toContain('查看边缘网关');
    expect(response.body).toContain('管理边缘网关');
    expect(response.body).toContain('syncOfflineLicenseControls()');
    expect(response.body).toContain("request('/v1/admin/customers', { method: 'POST'");
    expect(response.body).toContain("request('/v1/admin/deployments', { method: 'POST'");
    expect(response.body).toContain("request('/v1/admin/deployment-enrollments', {");
    expect(response.body).toContain("request('/v1/admin/licenses', { method: 'POST'");
    expect(response.body).toContain("/delivery-package.json");
    expect(response.body).toContain("renderCommercialPlanCatalog");
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
    expect(response.body).toContain('/v1/admin/roles');
    expect(response.body).toContain('/v1/admin/accounts');
    expect(response.body).toContain('/v1/admin-auth/enroll/confirm');
    expect(response.body).toContain('/v1/admin-auth/bootstrap');
    expect(response.body).toContain('/v1/admin-auth/bootstrap/status');
    expect(response.body).toContain("sessionStorage.setItem(sessionKey, result.token)");
    expect(response.body).toContain('currentRecoveryCodes');
    expect(response.body).toContain('navigator.clipboard.writeText');
    expect(response.body).toContain("'x-otto-approval-id': approval.id");
    expect(response.body).toContain("operation: 'license.revoke'");
    expect(response.body).toContain("hasPermission('approval.decide')");
    expect(response.body).toContain('approval.request || {}');
    expect(response.body).toContain('URL.createObjectURL(blob)');
    expect(response.body).toContain('otto-license-');
    expect(response.body).toContain('otto-deployment-bootstrap-');
    expect(response.body).toContain('clearDeploymentEnrollmentResult');
  });

  it('offers a one-time private deployment enrollment without persisting its secret', async () => {
    const [page, script] = await Promise.all([
      app.inject({ method: 'GET', url: '/admin' }),
      app.inject({ method: 'GET', url: '/admin/assets/app.js' }),
    ]);
    expect(page.body).toContain('id="create-deployment-enrollment-button"');
    expect(page.body).toContain('id="deployment-enrollment-dialog"');
    expect(page.body).toContain('id="deployment-enrollment-result-secret"');
    expect(page.body).toContain('id="enroll-organization-name"');
    expect(page.body).toContain('id="enroll-ceo-username"');
    expect(page.body).toContain('id="enroll-ceo-phone"');
    expect(page.body).toContain('口令关闭后立即从页面内存清除');
    expect(script.body).toContain("hasPermission('enterprise.provision')");
    expect(script.body).toContain("hasPermission('deployment.create')");
    expect(script.body).toContain("hasPermission('license.issue')");
    expect(script.body).toContain("'/v1/admin/deployment-enrollments'");
    expect(script.body).toContain("organizationName: byId('enroll-organization-name')");
    expect(script.body).toContain("ceoUsername: byId('enroll-ceo-username')");
    expect(script.body).toContain("ceoPhone: byId('enroll-ceo-phone')");
    expect(script.body).toContain('activeDeploymentEnrollment = null');
    expect(script.body).toContain("addEventListener('close', clearDeploymentEnrollmentResult)");
    expect(script.body).not.toContain('localStorage');
  });

  it('renders RBAC account management and one-time MFA enrollment without exposing tokens', async () => {
    const [page, script] = await Promise.all([
      app.inject({ method: 'GET', url: '/admin' }),
      app.inject({ method: 'GET', url: '/admin/assets/app.js' }),
    ]);
    expect(page.body).toContain('id="admin-identity-center"');
    expect(page.body).toContain('id="admin-accounts-body"');
    expect(page.body).toContain('id="create-admin-dialog"');
    expect(page.body).toContain('id="activation-dialog"');
    expect(page.body).toContain('id="recovery-codes-dialog"');
    expect(page.body).not.toContain('CONTROL_ADMIN_TOKEN');
    expect(script.body).toContain("hasPermission('identity.manage')");
    expect(script.body).toContain("method: 'PUT', body: JSON.stringify({ roleIds })");
    expect(script.body).toContain("account.id === state.principal.accountId");
    expect(script.body).toContain("downloadText('otto-control-admin-enrollment-");
    expect(script.body).not.toContain('innerHTML');
  });

  it('maps every approved high-risk operation to RBAC metadata and a real executor', async () => {
    expect(Object.keys(OPERATOR_CONSOLE_APPROVAL_ACTIONS).sort()).toEqual(
      [...ADMIN_APPROVAL_OPERATIONS].sort(),
    );
    const response = await app.inject({ method: 'GET', url: '/admin/assets/app.js' });
    const executorStart = response.body.indexOf('const definitions = {');
    const executorEnd = response.body.indexOf('return definitions[approval.operation]', executorStart);
    expect(executorStart).toBeGreaterThan(-1);
    expect(executorEnd).toBeGreaterThan(executorStart);
    const executorSource = response.body.slice(executorStart, executorEnd);
    for (const operation of ADMIN_APPROVAL_OPERATIONS) {
      expect(executorSource, `${operation} executor`).toContain(`'${operation}'`);
    }
    expect(response.body).not.toContain('尚未接入控制台执行器');
    expect(response.body).toContain('/execution-receipt-keys/');
    expect(response.body).toContain('/data-governance/forensic-exports');
  });

  it('does not ship an unbound command button', async () => {
    const [page, script] = await Promise.all([
      app.inject({ method: 'GET', url: '/admin' }),
      app.inject({ method: 'GET', url: '/admin/assets/app.js' }),
    ]);
    const buttons = [...page.body.matchAll(/<button\b([^>]*)>/gu)].map((match) => match[1]!);
    const namedButtons = buttons
      .map((attributes) => /\bid="([^"]+)"/u.exec(attributes)?.[1] ?? null)
      .filter((id): id is string => id !== null);
    expect(new Set(namedButtons).size).toBe(namedButtons.length);
    for (const id of namedButtons) {
      expect(script.body, `${id} binding`).toContain(`byId('${id}')`);
    }
    const anonymousCommands = buttons.filter((attributes) => !/\bid="/u.test(attributes));
    for (const attributes of anonymousCommands) {
      expect(
        /\btype="submit"|\bdata-close=|\bdata-mode=|\bdata-tab=/u.test(attributes),
        `anonymous button must use a declarative handler: ${attributes}`,
      ).toBe(true);
    }
  });
});

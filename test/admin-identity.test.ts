import { describe, expect, it } from 'vitest';

import { ControlPlaneError } from '../src/errors.js';
import { generateTotpCode } from '../src/modules/admin-identity/crypto.js';
import { AdminIdentityService } from '../src/modules/admin-identity/service.js';
import { MemoryControlStore } from './helpers/memory-store.js';

const CONTROL_SECRET = 'test-control-secret-with-at-least-thirty-two-bytes';
const PASSWORD = 'SecureControl2026';

async function enrolledSuperAdmin() {
  let now = Date.UTC(2026, 6, 31, 4, 0, 0);
  const store = new MemoryControlStore();
  const identity = new AdminIdentityService({ store, controlSecret: CONTROL_SECRET, now: () => now });
  const enrollment = await identity.bootstrap({
    username: 'root.admin',
    displayName: 'Root Admin',
    password: PASSWORD,
  });
  const session = await identity.confirmEnrollment({
    accountId: enrollment.account.id,
    enrollmentToken: enrollment.enrollmentToken,
    totpCode: generateTotpCode(enrollment.mfaSecret, now),
  });
  return {
    store,
    identity,
    enrollment,
    session,
    setNow(value: number) { now = value; },
    now: () => now,
  };
}

describe('administrator identity service', () => {
  it('bootstraps once, confirms TOTP enrollment and issues hashed sessions', async () => {
    const fixture = await enrolledSuperAdmin();

    expect(fixture.session.recoveryCodes).toHaveLength(10);
    expect(fixture.session.principal.roles).toContain('super_admin');
    expect(fixture.session.principal.permissions).toContain('identity.manage');
    expect([...fixture.store.adminSessions.values()][0]?.tokenHash).not.toBe(fixture.session.token);
    await expect(fixture.identity.authenticate(fixture.session.token)).resolves.toMatchObject({
      accountId: fixture.enrollment.account.id,
    });
    await expect(fixture.identity.bootstrap({
      username: 'other.admin',
      displayName: 'Other',
      password: PASSWORD,
    })).rejects.toMatchObject({ code: 'CONFLICT' });
  });

  it('requires password plus MFA and locks repeated failed logins', async () => {
    const fixture = await enrolledSuperAdmin();
    const validCode = generateTotpCode(fixture.enrollment.mfaSecret, fixture.now());
    const login = await fixture.identity.login({
      username: 'ROOT.ADMIN',
      password: PASSWORD,
      totpCode: validCode,
    });
    expect(login.principal.username).toBe('root.admin');

    for (let attempt = 0; attempt < 5; attempt += 1) {
      await expect(fixture.identity.login({
        username: 'root.admin',
        password: 'WrongPassword2026',
        totpCode: validCode,
      })).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    }
    await expect(fixture.identity.login({
      username: 'root.admin',
      password: PASSWORD,
      totpCode: validCode,
    })).rejects.toThrow('temporarily locked');
  });

  it('enforces RBAC, last-super-admin protection and dual-control approvals', async () => {
    const fixture = await enrolledSuperAdmin();
    const securityEnrollment = await fixture.identity.createAccount(fixture.session.principal, {
      username: 'security.admin',
      displayName: 'Security Admin',
      password: PASSWORD,
      roleIds: ['security_admin'],
    });
    const securitySession = await fixture.identity.confirmEnrollment({
      accountId: securityEnrollment.account.id,
      enrollmentToken: securityEnrollment.enrollmentToken,
      totpCode: generateTotpCode(securityEnrollment.mfaSecret, fixture.now()),
    });

    expect(() => fixture.identity.requirePermission(
      securitySession.principal,
      'license.issue',
    )).toThrowError(ControlPlaneError);
    await expect(fixture.identity.replaceRoles(
      fixture.session.principal,
      fixture.session.principal.accountId,
      ['auditor'],
    )).rejects.toMatchObject({ code: 'CONFLICT' });

    const request = { replacementKeyId: '0123456789abcdef', reason: 'compromised' };
    const approval = await fixture.identity.requestApproval(fixture.session.principal, {
      operation: 'signing_key.revoke',
      targetType: 'signing_key',
      targetId: 'fedcba9876543210',
      request: { ...request, prompt: 'must never enter approval storage' },
    });
    expect(approval.request).toEqual(request);
    expect(approval.request).not.toHaveProperty('prompt');
    await expect(fixture.identity.requestApproval(fixture.session.principal, {
      operation: 'signing_key.revoke',
      targetType: 'signing_key',
      targetId: 'fedcba9876543210',
      request,
    })).rejects.toMatchObject({ code: 'CONFLICT' });
    await expect(fixture.identity.requestApproval(fixture.session.principal, {
      operation: 'unknown.operation',
      targetType: 'unknown',
      targetId: 'unknown_target',
      request: {},
    })).rejects.toMatchObject({ code: 'INVALID_REQUEST' });
    await expect(fixture.identity.requestApproval(fixture.session.principal, {
      operation: 'signing_key.revoke',
      targetType: 'signing_key',
      targetId: 'fedcba9876543210',
      request: { reason: 'x'.repeat(17 * 1024) },
    })).rejects.toMatchObject({ code: 'INVALID_REQUEST' });
    await expect(fixture.identity.decideApproval(
      fixture.session.principal,
      approval.id,
      'approve',
      null,
    )).rejects.toThrow('self approval');
    const approved = await fixture.identity.decideApproval(
      securitySession.principal,
      approval.id,
      'approve',
      'Reviewed key incident',
    );
    expect(approved.status).toBe('approved');
    await expect(fixture.identity.consumeApproval(fixture.session.principal, approval.id, {
      operation: 'signing_key.revoke',
      targetType: 'signing_key',
      targetId: 'fedcba9876543210',
      request: { ...request, reason: 'different request' },
    })).rejects.toMatchObject({ code: 'APPROVAL_REQUIRED' });
    await expect(fixture.identity.consumeApproval(fixture.session.principal, approval.id, {
      operation: 'signing_key.revoke',
      targetType: 'signing_key',
      targetId: 'fedcba9876543210',
      request,
    })).resolves.toBeUndefined();
    await expect(fixture.identity.consumeApproval(fixture.session.principal, approval.id, {
      operation: 'signing_key.revoke',
      targetType: 'signing_key',
      targetId: 'fedcba9876543210',
      request,
    })).rejects.toMatchObject({ code: 'APPROVAL_REQUIRED' });
  });
});

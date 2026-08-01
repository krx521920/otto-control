import { generateKeyPairSync } from 'node:crypto';

import { afterEach, describe, expect, it } from 'vitest';

import { buildControlApp } from '../src/app.js';
import type { ControlConfig } from '../src/config.js';
import { LocalEd25519Signer } from '../src/crypto/signed-envelope.js';
import { ManagedSigningKeyring } from '../src/crypto/signing-keyring.js';
import { generateTotpCode } from '../src/modules/admin-identity/crypto.js';
import { AdminIdentityService } from '../src/modules/admin-identity/service.js';
import { CommercialControlService } from '../src/modules/commercial-control/service.js';
import { ControlTokenIssuer } from '../src/modules/commercial-control/token-issuer.js';
import { UpdatePolicyService } from '../src/modules/update-policy/service.js';
import { ReleaseArtifactService } from '../src/modules/release-artifacts/service.js';
import { BackupStatusService } from '../src/modules/backup-status/service.js';
import { AlertDeliveryService } from '../src/modules/alert-delivery/service.js';
import { MemoryControlStore } from './helpers/memory-store.js';

const ADMIN_TOKEN = 'bootstrap-admin-token-that-is-at-least-32-bytes';
const TOKEN_SECRET = 'route-control-token-secret-that-is-long-enough';
const PASSWORD = 'SecureControl2026';
const config: Readonly<ControlConfig> = {
  environment: 'test',
  host: '127.0.0.1',
  port: 7788,
  logLevel: 'silent',
  trustProxy: false,
  publicBaseUrl: 'https://control.otto.test',
  version: '0.6.0-test',
  databaseUrl: null,
  databaseSsl: false,
  adminToken: ADMIN_TOKEN,
  tokenSecret: TOKEN_SECRET,
  signerPrivateKeyFile: null,
  signerKeyringFile: null,
  leaseDurationMs: 600_000,
  telemetryRetentionDays: 90,
  updatePolicyDurationMs: 300_000,
  backupReportDirectory: null,
  backupStatusMaximumAgeHours: 48,
  alertChannelsFile: null,
  alertWebhookUrl: null,
  alertWebhookSecretFile: null,
  alertPollIntervalMs: 60_000,
  alertWebhookTimeoutMs: 10_000,
  alertWebhookMaxAttempts: 8,
  alertRetentionDays: 365,
  auditAnchorUrl: null,
  auditAnchorTokenFile: null,
  auditAnchorIntervalMs: 900_000,
  auditAnchorPollIntervalMs: 60_000,
  auditAnchorTimeoutMs: 10_000,
  auditAnchorMaxAttempts: 8,
};

describe('administrator identity HTTP routes', () => {
  const apps: Awaited<ReturnType<typeof buildControlApp>>[] = [];

  afterEach(async () => {
    await Promise.all(apps.splice(0).map((app) => app.close()));
  });

  it('uses the global token only for bootstrap and requires MFA sessions for business APIs', async () => {
    const store = new MemoryControlStore();
    const keys = generateKeyPairSync('ed25519');
    const localSigner = new LocalEd25519Signer(
      keys.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    );
    const signer = await ManagedSigningKeyring.create({
      store,
      providers: [{ signer: localSigner, provider: 'local' }],
    });
    const tokenIssuer = new ControlTokenIssuer(TOKEN_SECRET);
    const identity = new AdminIdentityService({ store, controlSecret: TOKEN_SECRET });
    const releaseArtifacts = new ReleaseArtifactService({ store, signer });
    const backupStatus = new BackupStatusService({ reportDirectory: null });
    const alerts = new AlertDeliveryService({
      store,
      backupStatus,
      webhookUrl: null,
      webhookSecretFile: null,
    });
    const app = await buildControlApp({
      config,
      logger: false,
      commercialControl: {
        adminToken: ADMIN_TOKEN,
        identity,
        releaseArtifacts,
        backupStatus,
        alerts,
        service: new CommercialControlService({
          store,
          signer,
          keyring: signer,
          tokenIssuer,
          publicBaseUrl: config.publicBaseUrl!,
        }),
        updatePolicy: new UpdatePolicyService({
          store,
          signer,
          tokenIssuer,
          releaseArtifacts,
        }),
      },
    });
    apps.push(app);

    const bootstrap = await app.inject({
      method: 'POST',
      url: '/v1/admin-auth/bootstrap',
      headers: { authorization: `Bearer ${ADMIN_TOKEN}` },
      payload: { username: 'root.admin', displayName: 'Root Admin', password: PASSWORD },
    });
    expect(bootstrap.statusCode).toBe(201);
    const enrollment = bootstrap.json().enrollment as {
      account: { id: string };
      enrollmentToken: string;
      mfaSecret: string;
    };
    const confirmation = await app.inject({
      method: 'POST',
      url: '/v1/admin-auth/enroll/confirm',
      payload: {
        accountId: enrollment.account.id,
        enrollmentToken: enrollment.enrollmentToken,
        totpCode: generateTotpCode(enrollment.mfaSecret),
      },
    });
    expect(confirmation.statusCode).toBe(200);
    expect(confirmation.json().recoveryCodes).toHaveLength(10);
    const sessionToken = confirmation.json().token as string;

    const legacyAttempt = await app.inject({
      method: 'POST',
      url: '/v1/admin/customers',
      headers: { authorization: `Bearer ${ADMIN_TOKEN}` },
      payload: { name: 'Legacy token must fail' },
    });
    expect(legacyAttempt.statusCode).toBe(401);

    const created = await app.inject({
      method: 'POST',
      url: '/v1/admin/customers',
      headers: { authorization: `Bearer ${sessionToken}` },
      payload: { name: 'Authenticated customer' },
    });
    expect(created.statusCode).toBe(201);

    const securityAccountResponse = await app.inject({
      method: 'POST',
      url: '/v1/admin/accounts',
      headers: { authorization: `Bearer ${sessionToken}` },
      payload: {
        username: 'security.admin',
        displayName: 'Security Admin',
        password: PASSWORD,
        roleIds: ['security_admin'],
      },
    });
    expect(securityAccountResponse.statusCode).toBe(201);
    const securityEnrollment = securityAccountResponse.json().enrollment as {
      account: { id: string };
      enrollmentToken: string;
      mfaSecret: string;
    };
    const securityConfirmation = await app.inject({
      method: 'POST',
      url: '/v1/admin-auth/enroll/confirm',
      payload: {
        accountId: securityEnrollment.account.id,
        enrollmentToken: securityEnrollment.enrollmentToken,
        totpCode: generateTotpCode(securityEnrollment.mfaSecret),
      },
    });
    expect(securityConfirmation.statusCode).toBe(200);
    const securityToken = securityConfirmation.json().token as string;
    const forbiddenCustomer = await app.inject({
      method: 'POST',
      url: '/v1/admin/customers',
      headers: { authorization: `Bearer ${securityToken}` },
      payload: { name: 'RBAC must reject this' },
    });
    expect(forbiddenCustomer.statusCode).toBe(403);
    expect(forbiddenCustomer.json()).toMatchObject({ error: { code: 'FORBIDDEN' } });

    const unapprovedRevocation = await app.inject({
      method: 'POST',
      url: '/v1/admin/licenses/lic_missing/revoke',
      headers: { authorization: `Bearer ${sessionToken}` },
    });
    expect(unapprovedRevocation.statusCode).toBe(428);
    expect(unapprovedRevocation.json()).toMatchObject({
      error: { code: 'APPROVAL_REQUIRED' },
    });

    const platform = await app.inject({ method: 'GET', url: '/v1' });
    expect(platform.json().capabilities).toEqual(expect.arrayContaining([
      'admin_identity',
      'admin_rbac',
      'admin_mfa',
      'dual_control_approval',
    ]));
  });
});

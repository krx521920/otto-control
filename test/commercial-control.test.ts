import { createHmac, generateKeyPairSync, verify, type KeyObject } from 'node:crypto';

import { beforeEach, describe, expect, it } from 'vitest';

import { canonicalJson, LocalEd25519Signer } from '../src/crypto/signed-envelope.js';
import { signTelemetryRequest } from '../src/crypto/telemetry-request.js';
import { CommercialControlService } from '../src/modules/commercial-control/service.js';
import { ControlTokenIssuer } from '../src/modules/commercial-control/token-issuer.js';
import { MemoryControlStore } from './helpers/memory-store.js';

const ADMIN = 'admin@example.test';
const DEPLOYMENT_ID = 'dep_1234567890abcdef';
const ORGANIZATION_ID = 'org_acme';
const FINGERPRINT = 'a'.repeat(64);
const TOKEN_SECRET = 'test-control-token-secret-that-is-long-enough';

function verifyEnvelope(
  publicKey: KeyObject,
  payload: unknown,
  signature: string,
): boolean {
  return verify(
    null,
    Buffer.from(canonicalJson(payload)),
    publicKey,
    Buffer.from(signature.slice('ed25519:'.length), 'base64url'),
  );
}

describe('commercial control service', () => {
  let store: MemoryControlStore;
  let service: CommercialControlService;
  let publicKey: KeyObject;
  let now: number;

  beforeEach(async () => {
    store = new MemoryControlStore();
    const keys = generateKeyPairSync('ed25519');
    publicKey = keys.publicKey;
    const privateKey = keys.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
    now = Date.parse('2026-07-31T02:00:00.000Z');
    service = new CommercialControlService({
      store,
      signer: new LocalEd25519Signer(privateKey),
      tokenIssuer: new ControlTokenIssuer(TOKEN_SECRET),
      publicBaseUrl: 'https://control.otto.test',
      now: () => now,
    });
    const customer = await service.createCustomer({ name: 'Acme Park' }, ADMIN);
    await service.createDeployment({
      deploymentId: DEPLOYMENT_ID,
      customerId: customer.id,
      organizationId: ORGANIZATION_ID,
      machineFingerprint: FINGERPRINT,
      name: 'Acme primary server',
    }, ADMIN);
  });

  it('issues an Otto-compatible online License without storing plaintext tokens', async () => {
    const envelope = await service.issueLicense({
      deploymentId: DEPLOYMENT_ID,
      plan: 'enterprise',
      expiresAt: '2027-07-31T02:00:00.000Z',
      seatLimit: 200,
      billingEnforcement: 'enforce',
      modules: ['enterprise_tree', 'direct_messages', 'park_service'],
    }, ADMIN);

    expect(envelope.license).toMatchObject({
      deploymentId: DEPLOYMENT_ID,
      organizationId: ORGANIZATION_ID,
      machineFingerprint: FINGERPRINT,
      offline: false,
      telemetryAllowed: true,
      billingEnforcement: 'enforce',
      issuedAtMs: now,
    });
    expect(envelope.license.leaseEndpoint).toBe(
      `https://control.otto.test/v1/licenses/${envelope.license.id}/lease`,
    );
    expect(envelope.license.billingEndpoint).toBe(
      'https://control.otto.test/v1/billing/usage/consume',
    );
    expect(envelope.license.billingHoldEndpoint).toBe(
      'https://control.otto.test/v1/billing/holds',
    );
    expect(envelope.license.leaseToken).toHaveLength(43);
    expect(envelope.license.telemetryToken).toHaveLength(43);
    expect(envelope.signature).toMatch(/^ed25519:/u);
    expect(verifyEnvelope(publicKey, envelope.license, envelope.signature)).toBe(true);

    const stored = store.licenses.get(envelope.license.id)!;
    expect(JSON.stringify(stored)).not.toContain(envelope.license.leaseToken!);
    expect(JSON.stringify(stored)).not.toContain(envelope.license.telemetryToken!);
  });

  it('refuses real-time billing enforcement in an offline License', async () => {
    await expect(service.issueLicense({
      deploymentId: DEPLOYMENT_ID,
      plan: 'government-offline',
      expiresAt: '2027-07-31T02:00:00.000Z',
      seatLimit: 200,
      billingEnforcement: 'enforce',
      modules: ['enterprise_tree'],
      offline: true,
    }, ADMIN)).rejects.toMatchObject({ code: 'INVALID_REQUEST' });
  });

  it('builds a safe operator overview and classifies License lifecycle risk', async () => {
    const day = 24 * 60 * 60 * 1000;
    const issue = (expiresInDays: number, gracePeriodDays = 7) => service.issueLicense({
      deploymentId: DEPLOYMENT_ID,
      plan: 'enterprise',
      expiresAt: new Date(now + expiresInDays * day).toISOString(),
      seatLimit: 20,
      gracePeriodDays,
      modules: ['enterprise_tree', 'direct_messages'],
    }, ADMIN);
    await issue(90);
    await issue(10);
    await issue(1);
    await issue(1, 0);
    const revoked = await issue(90);
    await service.revokeLicense(revoked.license.id, ADMIN);
    now += 2 * day;

    const overview = await service.operatorOverview(10);
    expect(overview.counts).toEqual({
      customers: { total: 1, active: 1, suspended: 0 },
      deployments: { total: 1, active: 1, suspended: 0 },
      licenses: {
        total: 5,
        active: 2,
        expiringSoon: 1,
        grace: 1,
        expired: 1,
        revoked: 1,
      },
    });
    expect(new Set(overview.recent.licenses.map((license) => license.state))).toEqual(
      new Set(['active', 'expiring', 'grace', 'expired', 'revoked']),
    );
    const serialized = JSON.stringify(overview);
    expect(serialized).not.toContain(FINGERPRINT);
    expect(serialized).not.toContain('signature');
    expect(serialized).not.toContain('leaseToken');
    await expect(service.operatorOverview(51)).rejects.toMatchObject({
      code: 'INVALID_REQUEST',
    });
  });

  it('issues a ten-minute signed lease and rejects replayed nonces', async () => {
    const license = await service.issueLicense({
      deploymentId: DEPLOYMENT_ID,
      plan: 'enterprise',
      expiresAt: '2027-07-31T02:00:00.000Z',
      seatLimit: 20,
      modules: ['enterprise_tree'],
    }, ADMIN);
    const request = {
      version: 1,
      licenseId: license.license.id,
      deploymentId: DEPLOYMENT_ID,
      organizationId: ORGANIZATION_ID,
      machineFingerprint: FINGERPRINT,
      nonce: 'nonce_1234567890abcdef',
    } as const;
    const lease = await service.issueLease(
      license.license.id,
      request,
      license.license.leaseToken!,
    );

    expect(lease.lease.expiresAtMs - lease.lease.issuedAtMs).toBe(10 * 60 * 1000);
    expect(verifyEnvelope(publicKey, lease.lease, lease.signature)).toBe(true);
    await expect(service.issueLease(
      license.license.id,
      request,
      license.license.leaseToken!,
    )).rejects.toMatchObject({ code: 'CONFLICT' });
  });

  it('fails closed after revocation and on deployment binding mismatches', async () => {
    const license = await service.issueLicense({
      deploymentId: DEPLOYMENT_ID,
      plan: 'enterprise',
      expiresAt: '2027-07-31T02:00:00.000Z',
      seatLimit: 20,
      modules: ['enterprise_tree'],
    }, ADMIN);
    await expect(service.issueLease(license.license.id, {
      version: 1,
      licenseId: license.license.id,
      deploymentId: DEPLOYMENT_ID,
      organizationId: 'org_other',
      machineFingerprint: FINGERPRINT,
      nonce: 'nonce_1234567890abcdef',
    }, license.license.leaseToken!)).rejects.toMatchObject({ code: 'INVALID_REQUEST' });

    await service.revokeLicense(license.license.id, ADMIN);
    await expect(service.issueLease(license.license.id, {
      version: 1,
      licenseId: license.license.id,
      deploymentId: DEPLOYMENT_ID,
      organizationId: ORGANIZATION_ID,
      machineFingerprint: FINGERPRINT,
      nonce: 'nonce_abcdef1234567890',
    }, license.license.leaseToken!)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
  });

  it('renews and resizes without invalidating the current deployment token', async () => {
    const issued = await service.issueLicense({
      deploymentId: DEPLOYMENT_ID,
      plan: 'enterprise',
      expiresAt: '2027-07-31T02:00:00.000Z',
      seatLimit: 20,
      modules: ['enterprise_tree'],
    }, ADMIN);
    const leaseToken = issued.license.leaseToken!;
    const renewed = await service.renewLicense(issued.license.id, {
      expiresAt: '2028-07-31T02:00:00.000Z',
      gracePeriodDays: 10,
    }, ADMIN);
    const resized = await service.resizeLicense(issued.license.id, {
      seatLimit: 12,
      seatEnforcement: 'enforce',
      gracePeriodDays: 2,
    }, ADMIN);

    expect(renewed.license).toMatchObject({ revision: 2, gracePeriodMs: 10 * 86_400_000 });
    expect(resized.license).toMatchObject({
      revision: 3,
      seatLimit: 12,
      seatEnforcement: 'enforce',
      gracePeriodMs: 2 * 86_400_000,
    });
    expect(renewed.license.leaseToken).toBe(leaseToken);
    expect(resized.license.leaseToken).toBe(leaseToken);
    expect(await service.licenseLifecycle(issued.license.id, 20)).toMatchObject([
      { revision: 3, changeType: 'downgraded' },
      { revision: 2, changeType: 'renewed' },
    ]);
  });

  it('enforces seat overage only after the configured grace period', async () => {
    const issued = await service.issueLicense({
      deploymentId: DEPLOYMENT_ID,
      plan: 'enterprise',
      expiresAt: '2027-07-31T02:00:00.000Z',
      seatLimit: 2,
      gracePeriodDays: 1,
      seatEnforcement: 'enforce',
      modules: ['enterprise_tree'],
    }, ADMIN);
    const request = (nonce: string) => ({
      version: 1 as const,
      licenseId: issued.license.id,
      deploymentId: DEPLOYMENT_ID,
      organizationId: ORGANIZATION_ID,
      machineFingerprint: FINGERPRINT,
      nonce,
      activeSeatCount: 3,
    });
    const duringGrace = await service.issueLease(
      issued.license.id,
      request('seat_overage_nonce_0001'),
      issued.license.leaseToken!,
    );
    expect(duringGrace.lease).toMatchObject({
      activeSeatCount: 3,
      seatLimit: 2,
      seatStatus: 'overage_grace',
      graceReasons: ['seat_overage'],
    });

    now += 86_400_000;
    await expect(service.issueLease(
      issued.license.id,
      request('seat_overage_nonce_0002'),
      issued.license.leaseToken!,
    )).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    expect(await service.licenseSeatUsage(issued.license.id)).toMatchObject({
      activeSeats: 3,
      status: 'blocked',
    });
  });

  it('keeps online deployments running during expiry grace and stops afterward', async () => {
    const expiresAtMs = now + 24 * 60 * 60 * 1000;
    const issued = await service.issueLicense({
      deploymentId: DEPLOYMENT_ID,
      plan: 'enterprise',
      expiresAt: new Date(expiresAtMs).toISOString(),
      seatLimit: 20,
      gracePeriodDays: 2,
      modules: ['enterprise_tree'],
    }, ADMIN);
    now = expiresAtMs + 60 * 60 * 1000;
    const duringGrace = await service.issueLease(issued.license.id, {
      version: 1,
      licenseId: issued.license.id,
      deploymentId: DEPLOYMENT_ID,
      organizationId: ORGANIZATION_ID,
      machineFingerprint: FINGERPRINT,
      nonce: 'expiration_grace_nonce_01',
    }, issued.license.leaseToken!);
    expect(duringGrace.lease).toMatchObject({
      graceReasons: ['expiration'],
      graceExpiresAtMs: expiresAtMs + 2 * 24 * 60 * 60 * 1000,
    });

    now = expiresAtMs + 2 * 24 * 60 * 60 * 1000;
    await expect(service.issueLease(issued.license.id, {
      version: 1,
      licenseId: issued.license.id,
      deploymentId: DEPLOYMENT_ID,
      organizationId: ORGANIZATION_ID,
      machineFingerprint: FINGERPRINT,
      nonce: 'expiration_grace_nonce_02',
    }, issued.license.leaseToken!)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
  });

  it('rotates tokens and atomically moves the deployment machine binding', async () => {
    const issued = await service.issueLicense({
      deploymentId: DEPLOYMENT_ID,
      plan: 'enterprise',
      expiresAt: '2027-07-31T02:00:00.000Z',
      seatLimit: 20,
      modules: ['enterprise_tree'],
    }, ADMIN);
    const previousToken = issued.license.leaseToken!;
    const nextFingerprint = 'b'.repeat(64);
    const transferred = await service.transferLicenseMachine(issued.license.id, {
      machineFingerprint: nextFingerprint,
    }, ADMIN);

    expect(transferred.license).toMatchObject({
      revision: 2,
      machineFingerprint: nextFingerprint,
    });
    expect(transferred.license.leaseToken).not.toBe(previousToken);
    expect(store.deployments.get(DEPLOYMENT_ID)?.machineFingerprint).toBe(nextFingerprint);
    await expect(service.issueLease(issued.license.id, {
      version: 1,
      licenseId: issued.license.id,
      deploymentId: DEPLOYMENT_ID,
      organizationId: ORGANIZATION_ID,
      machineFingerprint: nextFingerprint,
      nonce: 'machine_transfer_nonce_01',
    }, previousToken)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
  });

  it('rebinds only to another active deployment owned by the same customer', async () => {
    const customerId = store.deployments.get(DEPLOYMENT_ID)!.customerId;
    const targetDeploymentId = 'dep_abcdef1234567890';
    await service.createDeployment({
      deploymentId: targetDeploymentId,
      customerId,
      organizationId: 'org_acme_replacement',
      machineFingerprint: 'c'.repeat(64),
      name: 'Acme replacement server',
    }, ADMIN);
    const otherCustomer = await service.createCustomer({ name: 'Other customer' }, ADMIN);
    const foreignDeploymentId = 'dep_feedface12345678';
    await service.createDeployment({
      deploymentId: foreignDeploymentId,
      customerId: otherCustomer.id,
      organizationId: 'org_other_customer',
      machineFingerprint: 'd'.repeat(64),
      name: 'Foreign server',
    }, ADMIN);
    const issued = await service.issueLicense({
      deploymentId: DEPLOYMENT_ID,
      plan: 'enterprise',
      expiresAt: '2027-07-31T02:00:00.000Z',
      seatLimit: 20,
      modules: ['enterprise_tree'],
    }, ADMIN);

    await expect(service.rebindLicenseDeployment(issued.license.id, {
      deploymentId: foreignDeploymentId,
    }, ADMIN)).rejects.toMatchObject({ code: 'CONFLICT' });
    const rebound = await service.rebindLicenseDeployment(issued.license.id, {
      deploymentId: targetDeploymentId,
    }, ADMIN);
    expect(rebound.license).toMatchObject({
      revision: 2,
      deploymentId: targetDeploymentId,
      organizationId: 'org_acme_replacement',
      machineFingerprint: 'c'.repeat(64),
    });
    expect(rebound.license.leaseToken).not.toBe(issued.license.leaseToken);
  });

  it('matches Otto telemetry HMAC bytes independently', () => {
    const token = 'telemetry-token-that-is-at-least-32-characters';
    const timestamp = 1_785_463_200_000;
    const nonce = 'telemetry_nonce_contract_01';
    const body = {
      version: 1,
      deploymentId: DEPLOYMENT_ID,
      events: [{ eventType: 'runtime_health', payload: { uptimeSec: 30 } }],
    };
    const expected = 'hmac-sha256:' + createHmac('sha256', token)
      .update(`${timestamp}\n${nonce}\n${canonicalJson(body)}`, 'utf8')
      .digest('base64url');
    expect(signTelemetryRequest({ token, timestamp, nonce, body })).toBe(expected);
  });
});

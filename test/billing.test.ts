import { describe, expect, it } from 'vitest';

import { BillingService } from '../src/modules/billing/service.js';
import { ControlTokenIssuer } from '../src/modules/commercial-control/token-issuer.js';
import { MemoryControlStore } from './helpers/memory-store.js';

const CUSTOMER_ID = 'cus_billing';
const DEPLOYMENT_ID = 'dep_billing';
const ORGANIZATION_ID = 'org_billing';
const FINGERPRINT = 'b'.repeat(64);
const LICENSE_ID = 'lic_billing';
const TOKEN_SECRET = 'test-control-token-secret-that-is-long-enough';

async function fixture() {
  const store = new MemoryControlStore();
  await store.createCustomer({ id: CUSTOMER_ID, name: 'Billing Customer' });
  await store.createDeployment({
    id: DEPLOYMENT_ID,
    customerId: CUSTOMER_ID,
    organizationId: ORGANIZATION_ID,
    machineFingerprint: FINGERPRINT,
    name: 'Billing deployment',
  });
  const now = Date.parse('2026-07-31T04:00:00.000Z');
  await store.createLicense({
    id: LICENSE_ID,
    revision: 1,
    deploymentId: DEPLOYMENT_ID,
    customerName: 'Billing Customer',
    organizationId: ORGANIZATION_ID,
    machineFingerprint: FINGERPRINT,
    plan: 'enterprise',
    issuedAtMs: now - 60_000,
    expiresAtMs: now + 365 * 24 * 60 * 60 * 1000,
    seatLimit: 20,
    gracePeriodMs: 7 * 24 * 60 * 60 * 1000,
    seatEnforcement: 'monitor',
    modules: ['enterprise_tree'],
    offline: false,
    telemetryAllowed: true,
    leaseEndpoint: 'https://control.test/v1/licenses/lic_billing/lease',
    tokenVersion: 1,
    signature: 'ed25519:test',
    signingKeyId: 'key_test',
    revokedAtMs: null,
  });
  const tokens = new ControlTokenIssuer(TOKEN_SECRET);
  const service = new BillingService({ store, tokenIssuer: tokens, now: () => now });
  const token = tokens.issue({
    purpose: 'lease',
    licenseId: LICENSE_ID,
    deploymentId: DEPLOYMENT_ID,
    version: 1,
  });
  const binding = {
    licenseId: LICENSE_ID,
    deploymentId: DEPLOYMENT_ID,
    organizationId: ORGANIZATION_ID,
    machineFingerprint: FINGERPRINT,
  };
  return { store, service, token, binding, now };
}

describe('commercial credit billing', () => {
  it('fails closed for unsigned usage when legacy migration mode is disabled', async () => {
    const { store, token, binding, now } = await fixture();
    const service = new BillingService({
      store,
      tokenIssuer: new ControlTokenIssuer(TOKEN_SECRET),
      now: () => now,
      allowLegacyUsageReports: false,
    });
    await expect(service.consumeUsage({
      ...binding,
      module: 'model_gateway',
      units: 1,
      idempotencyKey: 'legacy:disabled',
      referenceId: 'legacy:disabled',
    }, token)).rejects.toMatchObject({ code: 'CONFLICT' });
  });

  it('prices usage centrally and prevents duplicate charges', async () => {
    const { service, token, binding } = await fixture();
    await service.setRate(CUSTOMER_ID, {
      module: 'model_gateway',
      unitSize: 1_000,
      creditsPerUnit: 3,
    }, 'admin');
    await service.topUp(CUSTOMER_ID, {
      organizationId: ORGANIZATION_ID,
      amount: 100,
      idempotencyKey: 'topup:invoice-1',
      referenceId: 'invoice-1',
    }, 'admin');

    const request = {
      ...binding,
      module: 'model_gateway',
      units: 1_001,
      idempotencyKey: 'usage:message-1',
      referenceId: 'usage-1',
    };
    const first = await service.consumeUsage(request, token);
    const replay = await service.consumeUsage(request, token);

    expect(first.transaction.billedAmount).toBe(6);
    expect(first.account.availableBalance).toBe(94);
    expect(replay.replayed).toBe(true);
    expect(replay.transaction.id).toBe(first.transaction.id);
    expect((await service.account(CUSTOMER_ID, ORGANIZATION_ID)).availableBalance).toBe(94);
    await expect(service.consumeUsage({ ...request, units: 2_001 }, token))
      .rejects.toMatchObject({ code: 'CONFLICT' });
  });

  it('freezes estimated credits, captures actual usage, and releases the remainder', async () => {
    const { service, token, binding } = await fixture();
    await service.setRate(CUSTOMER_ID, {
      module: 'meeting_agent', unitSize: 30, creditsPerUnit: 4,
    }, 'admin');
    await service.topUp(CUSTOMER_ID, {
      organizationId: ORGANIZATION_ID,
      amount: 50, idempotencyKey: 'topup:meeting', referenceId: 'invoice-meeting',
    }, 'admin');

    const held = await service.createHold({
      ...binding,
      module: 'meeting_agent',
      units: 90,
      expiresInSeconds: 600,
      idempotencyKey: 'hold:meeting-1',
    }, token);
    expect(held.hold.amount).toBe(12);
    expect(held.account).toMatchObject({ availableBalance: 38, frozenBalance: 12 });

    const captured = await service.captureHold(held.hold.id, {
      ...binding,
      units: 45,
      idempotencyKey: 'capture:meeting-1',
      referenceId: 'meeting-1',
    }, token);
    expect(captured.transaction.billedAmount).toBe(8);
    expect(captured.account).toMatchObject({ availableBalance: 42, frozenBalance: 0 });
    expect(captured.hold.status).toBe('captured');
  });

  it('limits cumulative refunds to the original charge', async () => {
    const { service, token, binding } = await fixture();
    await service.setRate(CUSTOMER_ID, {
      module: 'park_service', unitSize: 1, creditsPerUnit: 10,
    }, 'admin');
    await service.topUp(CUSTOMER_ID, {
      organizationId: ORGANIZATION_ID,
      amount: 100, idempotencyKey: 'topup:park', referenceId: 'invoice-park',
    }, 'admin');
    const consumed = await service.consumeUsage({
      ...binding,
      module: 'park_service',
      units: 2,
      idempotencyKey: 'usage:park-1',
      referenceId: 'work-order-1',
    }, token);

    await service.refund(CUSTOMER_ID, {
      transactionId: consumed.transaction.id,
      amount: 8,
      idempotencyKey: 'refund:park-1a',
      referenceId: 'refund-order-1a',
    }, 'finance-admin');
    await service.refund(CUSTOMER_ID, {
      transactionId: consumed.transaction.id,
      amount: 12,
      idempotencyKey: 'refund:park-1b',
      referenceId: 'refund-order-1b',
    }, 'finance-admin');
    await expect(service.refund(CUSTOMER_ID, {
      transactionId: consumed.transaction.id,
      amount: 1,
      idempotencyKey: 'refund:park-over',
      referenceId: 'refund-order-over',
    }, 'finance-admin')).rejects.toMatchObject({ code: 'CONFLICT' });
    expect((await service.account(CUSTOMER_ID, ORGANIZATION_ID)).availableBalance).toBe(100);
  });

  it('automatically releases expired holds and exports auditable statements', async () => {
    const { store, token, binding, now } = await fixture();
    let clock = now;
    const service = new BillingService({
      store,
      tokenIssuer: new ControlTokenIssuer(TOKEN_SECRET),
      now: () => clock,
    });
    await service.setRate(CUSTOMER_ID, {
      module: 'model_gateway', unitSize: 100, creditsPerUnit: 2,
    }, 'admin');
    await service.topUp(CUSTOMER_ID, {
      organizationId: ORGANIZATION_ID,
      amount: 20, idempotencyKey: 'topup:expiry', referenceId: 'invoice-expiry',
    }, 'admin');
    await service.createHold({
      ...binding,
      module: 'model_gateway', units: 500, expiresInSeconds: 60,
      idempotencyKey: 'hold:expiry',
    }, token);
    clock += 61_000;
    expect(await service.account(CUSTOMER_ID, ORGANIZATION_ID)).toMatchObject({
      availableBalance: 20,
      frozenBalance: 0,
    });
    const statement = await service.statement(CUSTOMER_ID, {
      from: '2026-07-31T00:00:00.000Z',
      to: '2026-08-01T00:00:00.000Z',
    });
    expect(statement).toMatchObject({ totalToppedUp: 20, closingBalance: 20 });
    const csv = await service.exportCsv(CUSTOMER_ID, {
      from: '2026-07-31T00:00:00.000Z',
      to: '2026-08-01T00:00:00.000Z',
    });
    expect(csv).toContain('transactionId');
    expect(csv).toContain('expiry:');
  });
});

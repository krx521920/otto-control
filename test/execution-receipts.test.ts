import { generateKeyPairSync } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import type { ExecutionReceiptV2Payload } from '../src/contracts/billing.js';
import { LocalEd25519Signer } from '../src/crypto/signed-envelope.js';
import { BillingService } from '../src/modules/billing/service.js';
import { ControlTokenIssuer } from '../src/modules/commercial-control/token-issuer.js';
import { MemoryControlStore } from './helpers/memory-store.js';

const CUSTOMER_ID = 'cus_receipts';
const DEPLOYMENT_ID = 'dep_receipts';
const ORGANIZATION_ID = 'org_receipts';
const LICENSE_ID = 'lic_receipts';
const FINGERPRINT = 'c'.repeat(64);
const TOKEN_SECRET = 'receipt-control-token-secret-that-is-long-enough';

async function fixture() {
  const store = new MemoryControlStore();
  let clock = Date.parse('2026-08-03T04:00:00.000Z');
  await store.createCustomer({ id: CUSTOMER_ID, name: 'Receipt customer' });
  await store.createDeployment({
    id: DEPLOYMENT_ID,
    customerId: CUSTOMER_ID,
    organizationId: ORGANIZATION_ID,
    machineFingerprint: FINGERPRINT,
    name: 'Receipt deployment',
  });
  await store.createLicense({
    id: LICENSE_ID,
    revision: 1,
    deploymentId: DEPLOYMENT_ID,
    customerName: 'Receipt customer',
    organizationId: ORGANIZATION_ID,
    machineFingerprint: FINGERPRINT,
    plan: 'enterprise',
    issuedAtMs: clock - 60_000,
    expiresAtMs: clock + 365 * 24 * 60 * 60 * 1000,
    seatLimit: 100,
    gracePeriodMs: 7 * 24 * 60 * 60 * 1000,
    seatEnforcement: 'enforce',
    modules: ['enterprise_tree'],
    offline: false,
    telemetryAllowed: true,
    leaseEndpoint: 'https://control.test/v1/licenses/lic_receipts/lease',
    tokenVersion: 1,
    signature: 'ed25519:test',
    signingKeyId: 'key_control',
    revokedAtMs: null,
  });
  const tokens = new ControlTokenIssuer(TOKEN_SECRET);
  const service = new BillingService({ store, tokenIssuer: tokens, now: () => clock });
  const token = tokens.issue({
    purpose: 'lease',
    licenseId: LICENSE_ID,
    deploymentId: DEPLOYMENT_ID,
    version: 1,
  });
  const { privateKey } = generateKeyPairSync('ed25519');
  const signer = new LocalEd25519Signer(
    privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
  );
  await service.registerExecutionReceiptKey(DEPLOYMENT_ID, {
    publicKeyPem: signer.publicKeyPem,
    expiresAt: new Date(clock + 30 * 24 * 60 * 60 * 1000).toISOString(),
  }, 'security-admin');
  await service.setRate(CUSTOMER_ID, {
    module: 'model_gateway',
    unitSize: 1_000,
    creditsPerUnit: 3,
  }, 'billing-admin');
  await service.topUp(CUSTOMER_ID, {
    amount: 100,
    idempotencyKey: 'topup:receipts',
    referenceId: 'invoice:receipts',
  }, 'billing-admin');

  const signReceipt = async (overrides: Partial<ExecutionReceiptV2Payload> = {}) => {
    const receipt: ExecutionReceiptV2Payload = {
      version: 2,
      receiptId: 'exec_11111111111111111111111111111111',
      deploymentId: DEPLOYMENT_ID,
      organizationId: ORGANIZATION_ID,
      taskId: 'task_receipt_1',
      moduleId: 'model_gateway',
      units: 1_001,
      model: 'deepseek-v3',
      issuedAtMs: clock,
      expiresAtMs: clock + 60 * 60 * 1000,
      sequence: 1,
      policyVersion: 'commercial-v2',
      ...overrides,
    };
    return {
      receipt,
      signingKeyId: signer.keyId,
      signature: await signer.sign(receipt),
    };
  };
  const request = (envelope: Awaited<ReturnType<typeof signReceipt>>) => ({
    licenseId: LICENSE_ID,
    machineFingerprint: FINGERPRINT,
    envelope,
  });
  return {
    store,
    service,
    signer,
    token,
    signReceipt,
    request,
    setClock: (value: number) => { clock = value; },
    now: clock,
  };
}

describe('signed execution receipt v2', () => {
  it('verifies, charges once, and preserves auditable evidence', async () => {
    const { service, token, signReceipt, request } = await fixture();
    const envelope = await signReceipt();

    const first = await service.consumeExecutionReceipt(request(envelope), token);
    const replay = await service.consumeExecutionReceipt(request(envelope), token);

    expect(first.replayed).toBe(false);
    expect(first.transaction.billedAmount).toBe(6);
    expect(first.receipt).toMatchObject({
      receiptId: envelope.receipt.receiptId,
      verificationStatus: 'verified',
      transactionId: first.transaction.id,
    });
    expect(replay.replayed).toBe(true);
    expect(replay.transaction.id).toBe(first.transaction.id);
    expect((await service.account(CUSTOMER_ID)).availableBalance).toBe(94);
    expect(await service.executionReceipt(CUSTOMER_ID, envelope.receipt.receiptId))
      .toMatchObject({ taskId: 'task_receipt_1', sequence: 1 });
    expect(await service.executionReceipts(CUSTOMER_ID, {})).toHaveLength(1);
    const refund = await service.refund(CUSTOMER_ID, {
      transactionId: first.transaction.id,
      amount: 2,
      idempotencyKey: 'refund:receipt-1',
      referenceId: 'dispute:receipt-1',
    }, 'finance-admin');
    expect(refund.transaction.metadata).toMatchObject({
      executionReceiptId: envelope.receipt.receiptId,
      receiptVerificationStatus: 'verified',
    });
    const csv = await service.exportCsv(CUSTOMER_ID, {});
    expect(csv).toContain(envelope.receipt.receiptId);
    expect(csv).toContain('receiptVerificationStatus');
  });

  it('rejects forged, out-of-order, duplicate-task, expired, and revoked evidence', async () => {
    const {
      service, token, signReceipt, request, signer, setClock, now,
    } = await fixture();
    const first = await signReceipt();
    const forged = {
      ...first,
      receipt: { ...first.receipt, units: 9_999 },
    };
    await expect(service.consumeExecutionReceipt(request(forged), token))
      .rejects.toMatchObject({ code: 'UNAUTHORIZED' });

    await service.consumeExecutionReceipt(request(first), token);
    const outOfOrder = await signReceipt({
      receiptId: 'exec_33333333333333333333333333333333',
      taskId: 'task_receipt_3',
      sequence: 3,
    });
    await expect(service.consumeExecutionReceipt(request(outOfOrder), token))
      .rejects.toMatchObject({ code: 'CONFLICT' });

    const duplicateTask = await signReceipt({
      receiptId: 'exec_22222222222222222222222222222222',
      sequence: 2,
    });
    await expect(service.consumeExecutionReceipt(request(duplicateTask), token))
      .rejects.toMatchObject({ code: 'CONFLICT' });

    const second = await signReceipt({
      receiptId: 'exec_44444444444444444444444444444444',
      taskId: 'task_receipt_2',
      sequence: 2,
    });
    await service.consumeExecutionReceipt(request(second), token);

    const expired = await signReceipt({
      receiptId: 'exec_55555555555555555555555555555555',
      taskId: 'task_receipt_expired',
      issuedAtMs: now,
      expiresAtMs: now + 1_000,
      sequence: 3,
    });
    setClock(now + 2_000);
    await expect(service.consumeExecutionReceipt(request(expired), token))
      .rejects.toMatchObject({ code: 'UNAUTHORIZED' });

    await service.revokeExecutionReceiptKey(DEPLOYMENT_ID, signer.keyId, 'security-admin');
    const revoked = await signReceipt({
      receiptId: 'exec_66666666666666666666666666666666',
      taskId: 'task_receipt_revoked',
      sequence: 3,
    });
    await expect(service.consumeExecutionReceipt(request(revoked), token))
      .rejects.toMatchObject({ code: 'UNAUTHORIZED' });
  });

  it('refuses content fields so billing evidence cannot exfiltrate user data', async () => {
    const { service, token, signReceipt, request } = await fixture();
    const envelope = await signReceipt();
    await expect(service.consumeExecutionReceipt(request({
      ...envelope,
      receipt: { ...envelope.receipt, prompt: 'must never leave the deployment' },
    } as typeof envelope), token)).rejects.toMatchObject({ code: 'INVALID_REQUEST' });
  });
});

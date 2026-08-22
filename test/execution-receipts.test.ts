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

async function fixture(options: { registerReceiptKey?: boolean } = {}) {
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
  if (options.registerReceiptKey !== false) {
    await service.registerExecutionReceiptKey(DEPLOYMENT_ID, {
      publicKeyPem: signer.publicKeyPem,
      expiresAt: new Date(clock + 30 * 24 * 60 * 60 * 1000).toISOString(),
    }, 'security-admin');
  }
  await service.setRate(CUSTOMER_ID, {
    module: 'model_gateway',
    unitSize: 1_000,
    creditsPerUnit: 3,
  }, 'billing-admin');
  await service.topUp(CUSTOMER_ID, {
    organizationId: ORGANIZATION_ID,
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
    binding: {
      licenseId: LICENSE_ID,
      deploymentId: DEPLOYMENT_ID,
      organizationId: ORGANIZATION_ID,
      machineFingerprint: FINGERPRINT,
    },
    setClock: (value: number) => { clock = value; },
    now: clock,
  };
}

describe('signed execution receipt v2', () => {
  it('aggregates independent monotonic edge-node sequences and closes gaps in order', async () => {
    const {
      service, store, signer, token, signReceipt, binding,
    } = await fixture();
    const nodeA = 'edge_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    await service.registerEdgeBillingNode(DEPLOYMENT_ID, {
      nodeId: nodeA,
      signingKeyId: signer.keyId,
    }, 'billing-admin');

    const sequenceTwo = await signReceipt({
      receiptId: 'exec_22222222222222222222222222222222',
      taskId: 'edge_task_2',
      sequence: 2,
      units: 1,
    });
    await service.submitEdgeBillingEvent({
      ...binding,
      eventId: 'edgeevt_22222222222222222222222222222222',
      nodeId: nodeA,
      nodeSequence: 2,
      envelope: sequenceTwo,
    }, token);
    expect(await service.edgeBillingAggregationStatus(DEPLOYMENT_ID)).toMatchObject({
      pending: 1,
      reconciled: 0,
      sequenceGaps: 1,
    });

    const sequenceOne = await signReceipt({
      receiptId: 'exec_11111111111111111111111111111112',
      taskId: 'edge_task_1',
      sequence: 1,
      units: 1,
    });
    const request = {
      ...binding,
      eventId: 'edgeevt_11111111111111111111111111111111',
      nodeId: nodeA,
      nodeSequence: 1,
      envelope: sequenceOne,
    };
    await service.submitEdgeBillingEvent(request, token);
    await service.submitEdgeBillingEvent(request, token);

    const { privateKey } = generateKeyPairSync('ed25519');
    const secondSigner = new LocalEd25519Signer(
      privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    );
    await service.registerExecutionReceiptKey(DEPLOYMENT_ID, {
      publicKeyPem: secondSigner.publicKeyPem,
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
    }, 'security-admin');
    const nodeB = 'edge_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
    await service.registerEdgeBillingNode(DEPLOYMENT_ID, {
      nodeId: nodeB,
      signingKeyId: secondSigner.keyId,
    }, 'billing-admin');
    const receiptB: ExecutionReceiptV2Payload = {
      ...sequenceOne.receipt,
      receiptId: 'exec_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      taskId: 'edge_task_b1',
      sequence: 1,
    };
    await service.submitEdgeBillingEvent({
      ...binding,
      eventId: 'edgeevt_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      nodeId: nodeB,
      nodeSequence: 1,
      envelope: {
        receipt: receiptB,
        signingKeyId: secondSigner.keyId,
        signature: await secondSigner.sign(receiptB),
      },
    }, token);

    expect(await service.edgeBillingAggregationStatus(DEPLOYMENT_ID)).toMatchObject({
      nodes: 2,
      activeNodes: 2,
      pending: 0,
      reconciled: 3,
      sequenceGaps: 0,
    });
    expect((await service.account(CUSTOMER_ID, ORGANIZATION_ID)).availableBalance).toBe(91);
    expect(store.executionReceipts.get(sequenceOne.receipt.receiptId)?.edgeNodeId).toBe(nodeA);
    expect(store.executionReceipts.get(receiptB.receiptId)?.edgeNodeId).toBe(nodeB);
  });

  it('moves persistently failing edge aggregation events to the dead letter state', async () => {
    const {
      service, signer, token, signReceipt, binding, setClock, now,
    } = await fixture();
    const nodeId = 'edge_cccccccccccccccccccccccccccccccc';
    await service.registerEdgeBillingNode(DEPLOYMENT_ID, {
      nodeId,
      signingKeyId: signer.keyId,
    }, 'billing-admin');
    const envelope = await signReceipt({
      receiptId: 'exec_cccccccccccccccccccccccccccccccc',
      taskId: 'edge_task_missing_rate',
      moduleId: 'meeting_agent',
      units: 1,
    });
    await service.submitEdgeBillingEvent({
      ...binding,
      eventId: 'edgeevt_cccccccccccccccccccccccccccccccc',
      nodeId,
      nodeSequence: 1,
      envelope,
    }, token);
    for (let attempt = 1; attempt < 8; attempt += 1) {
      setClock(now + attempt * 10 * 60 * 1000);
      await service.reconcileEdgeBillingEvents(1, nodeId);
    }
    expect(await service.edgeBillingAggregationStatus(DEPLOYMENT_ID)).toMatchObject({
      retrying: 0,
      deadLetter: 1,
      reconciled: 0,
    });
    await service.setRate(CUSTOMER_ID, {
      module: 'meeting_agent', unitSize: 1_000, creditsPerUnit: 2,
    }, 'billing-admin');
    await expect(service.retryEdgeBillingDeadLetters(10)).resolves.toEqual({
      requeued: 1,
      reconciled: 1,
    });
    expect(await service.edgeBillingAggregationStatus(DEPLOYMENT_ID)).toMatchObject({
      deadLetter: 0,
      reconciled: 1,
    });
  });

  it('repairs queue state after settlement succeeded before the queue checkpoint', async () => {
    const { service, store, signer, token, signReceipt, binding } = await fixture();
    const nodeId = 'edge_dddddddddddddddddddddddddddddddd';
    await service.registerEdgeBillingNode(DEPLOYMENT_ID, {
      nodeId, signingKeyId: signer.keyId,
    }, 'billing-admin');
    const envelope = await signReceipt({
      receiptId: 'exec_dddddddddddddddddddddddddddddddd',
      taskId: 'edge_crash_window', sequence: 1, units: 1,
    });
    const request = {
      ...binding,
      eventId: 'edgeevt_dddddddddddddddddddddddddddddddd',
      nodeId,
      nodeSequence: 1,
      envelope,
    };
    await service.submitEdgeBillingEvent(request, token);
    const settled = store.edgeBillingEvents.get(request.eventId)!;
    store.edgeBillingEvents.set(request.eventId, {
      ...settled,
      state: 'retrying',
      reconciledAt: null,
      nextAttemptAt: new Date(0),
    });
    const balance = (await service.account(CUSTOMER_ID, ORGANIZATION_ID)).availableBalance;
    await expect(service.reconcileEdgeBillingEvents(1, nodeId)).resolves.toBe(1);
    expect((await service.account(CUSTOMER_ID, ORGANIZATION_ID)).availableBalance).toBe(balance);
    expect(store.edgeBillingEvents.get(request.eventId)?.state).toBe('reconciled');
  });

  it('bootstraps only the first deployment key with proof of possession', async () => {
    const { service, signer, token, now } = await fixture({ registerReceiptKey: false });
    const claim = {
      version: 1 as const,
      licenseId: LICENSE_ID,
      deploymentId: DEPLOYMENT_ID,
      organizationId: ORGANIZATION_ID,
      machineFingerprint: FINGERPRINT,
      keyId: signer.keyId,
      publicKeyPem: signer.publicKeyPem,
      issuedAtMs: now,
      expiresAtMs: now + 365 * 24 * 60 * 60 * 1000,
      nonce: 'bootstrap-proof-0001',
    };
    const signed = { ...claim, signature: await signer.sign(claim) };

    await expect(service.bootstrapExecutionReceiptKey(signed, token)).resolves
      .toMatchObject({ replayed: false, key: { keyId: signer.keyId, status: 'active' } });
    await expect(service.bootstrapExecutionReceiptKey(signed, token)).resolves
      .toMatchObject({ replayed: true, key: { keyId: signer.keyId, status: 'active' } });
    expect(await service.executionReceiptKeys(DEPLOYMENT_ID)).toHaveLength(1);

    await expect(service.bootstrapExecutionReceiptKey({
      ...signed,
      prompt: 'must never reach Control',
    }, token)).rejects.toMatchObject({ code: 'INVALID_REQUEST' });

    const { privateKey } = generateKeyPairSync('ed25519');
    const replacement = new LocalEd25519Signer(
      privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    );
    const replacementClaim = {
      ...claim,
      keyId: replacement.keyId,
      publicKeyPem: replacement.publicKeyPem,
      nonce: 'bootstrap-proof-0002',
    };
    await expect(service.bootstrapExecutionReceiptKey({
      ...replacementClaim,
      signature: await replacement.sign(replacementClaim),
    }, token)).rejects.toMatchObject({ code: 'CONFLICT' });
  });

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
    expect((await service.account(CUSTOMER_ID, ORGANIZATION_ID)).availableBalance).toBe(94);
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

  it('atomically settles a credit hold with signed usage and releases the unused amount', async () => {
    const {
      service, token, signReceipt, request, binding,
    } = await fixture();
    const held = await service.createHold({
      ...binding,
      module: 'model_gateway',
      units: 3_000,
      expiresInSeconds: 600,
      idempotencyKey: 'hold:edge-request-1',
    }, token);
    expect(held.hold.amount).toBe(9);
    expect(held.account).toMatchObject({ availableBalance: 91, frozenBalance: 9 });

    const envelope = await signReceipt();
    const settled = await service.settleHoldWithExecutionReceipt(
      held.hold.id,
      request(envelope),
      token,
    );
    expect(settled.replayed).toBe(false);
    expect(settled.hold.status).toBe('captured');
    expect(settled.transaction).toMatchObject({
      type: 'capture',
      billedAmount: 6,
      metadata: {
        holdId: held.hold.id,
        executionReceiptId: envelope.receipt.receiptId,
        receiptVerificationStatus: 'verified',
      },
    });
    expect(settled.account).toMatchObject({
      availableBalance: 94,
      frozenBalance: 0,
      totalConsumed: 6,
    });
    expect(settled.receipt.transactionId).toBe(settled.transaction.id);

    const replay = await service.settleHoldWithExecutionReceipt(
      held.hold.id,
      request(envelope),
      token,
    );
    expect(replay.replayed).toBe(true);
    expect(replay.transaction.id).toBe(settled.transaction.id);
    expect((await service.account(CUSTOMER_ID, ORGANIZATION_ID))).toMatchObject({
      availableBalance: 94,
      frozenBalance: 0,
      totalConsumed: 6,
    });
  });

  it('rejects forged, mismatched, expired, and content-bearing hold settlements', async () => {
    const {
      service, token, signReceipt, request, binding, setClock, now,
    } = await fixture();
    const held = await service.createHold({
      ...binding,
      module: 'model_gateway',
      units: 2_000,
      expiresInSeconds: 60,
      idempotencyKey: 'hold:edge-security',
    }, token);
    const envelope = await signReceipt();

    await expect(service.settleHoldWithExecutionReceipt(held.hold.id, request({
      ...envelope,
      receipt: { ...envelope.receipt, units: 1_002 },
    }), token)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    await expect(service.settleHoldWithExecutionReceipt(held.hold.id, {
      ...request(envelope),
      prompt: 'must never reach Control',
    }, token)).rejects.toMatchObject({ code: 'INVALID_REQUEST' });

    const wrongModule = await signReceipt({ moduleId: 'meeting_agent' });
    await expect(service.settleHoldWithExecutionReceipt(
      held.hold.id,
      request(wrongModule),
      token,
    )).rejects.toMatchObject({ code: 'CONFLICT' });

    setClock(now + 61_000);
    await expect(service.settleHoldWithExecutionReceipt(
      held.hold.id,
      request(envelope),
      token,
    )).rejects.toMatchObject({ code: 'CREDIT_HOLD_UNAVAILABLE' });
    expect((await service.account(CUSTOMER_ID, ORGANIZATION_ID))).toMatchObject({
      availableBalance: 100,
      frozenBalance: 0,
    });
  });

  it('isolates enterprise wallets inside a shared licensed deployment', async () => {
    const { service, token, signReceipt, request } = await fixture();
    const secondOrganizationId = 'org_shared_tenant_beta';
    const envelope = await signReceipt({
      organizationId: secondOrganizationId,
      receiptId: 'exec_99999999999999999999999999999999',
      taskId: 'task_shared_tenant_beta',
    });

    await expect(service.consumeExecutionReceipt(request(envelope), token))
      .rejects.toMatchObject({ code: 'CONFLICT' });
    expect((await service.account(CUSTOMER_ID, ORGANIZATION_ID)).availableBalance).toBe(100);

    await service.topUp(CUSTOMER_ID, {
      organizationId: secondOrganizationId,
      amount: 25,
      idempotencyKey: 'topup:shared-tenant-beta',
      referenceId: 'invoice:shared-tenant-beta',
    }, 'billing-admin');
    const result = await service.consumeExecutionReceipt(request(envelope), token);

    expect(result.replayed).toBe(false);
    expect(result.receipt).toMatchObject({
      organizationId: secondOrganizationId,
      deploymentId: DEPLOYMENT_ID,
      verificationStatus: 'verified',
    });
    expect(result.account).toMatchObject({
      organizationId: secondOrganizationId,
      availableBalance: 19,
    });
    expect((await service.account(CUSTOMER_ID, ORGANIZATION_ID)).availableBalance).toBe(100);
    expect(await service.executionReceipts(CUSTOMER_ID, {})).toEqual([
      expect.objectContaining({ organizationId: secondOrganizationId }),
    ]);
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

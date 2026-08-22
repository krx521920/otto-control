import { createHmac } from 'node:crypto';

import { describe, expect, it, vi } from 'vitest';

import type {
  AcceptPaymentWebhookResult,
  PaymentCreditLedger,
  PaymentLedgerActionRecord,
  PaymentOrderRecord,
  PaymentProvider,
  PaymentStore,
  PaymentWebhookEvent,
  ReservePaymentOrderInput,
} from '../src/contracts/payments.js';
import { HmacSha256PaymentProvider } from '../src/modules/payments/hmac-sha256-provider.js';
import { PaymentService } from '../src/modules/payments/service.js';

const NOW = Date.parse('2026-08-21T06:00:00.000Z');

function copyOrder(order: PaymentOrderRecord): PaymentOrderRecord {
  return { ...order };
}

class MemoryPaymentStore implements PaymentStore {
  readonly orders = new Map<string, PaymentOrderRecord>();
  readonly idempotency = new Map<string, string>();
  readonly eventResults = new Map<string, AcceptPaymentWebhookResult>();
  readonly actions = new Map<string, PaymentLedgerActionRecord>();
  acceptCalls = 0;

  async reserveOrder(input: ReservePaymentOrderInput) {
    const replayId = this.idempotency.get(input.idempotencyKey);
    if (replayId) return { order: copyOrder(this.orders.get(replayId)!), replayed: true };
    const order: PaymentOrderRecord = {
      id: input.id,
      merchantOrderId: input.merchantOrderId,
      providerId: input.providerId,
      providerOrderId: null,
      customerId: input.customerId,
      organizationId: input.organizationId,
      amountMinor: input.amountMinor,
      currency: input.currency,
      credits: input.credits,
      status: 'creating',
      idempotencyKey: input.idempotencyKey,
      requestSha256: input.requestSha256,
      checkoutUrl: null,
      providerPaymentId: null,
      creditedCredits: 0,
      reversedCredits: 0,
      refundedAmountMinor: 0,
      failureCode: null,
      expiresAt: input.expiresAt,
      paidAt: null,
      createdAt: input.createdAt,
      updatedAt: input.createdAt,
    };
    this.orders.set(order.id, order);
    this.idempotency.set(input.idempotencyKey, order.id);
    return { order: copyOrder(order), replayed: false };
  }

  async activateOrder(input: {
    orderId: string; providerOrderId: string; checkoutUrl: string; expiresAt: Date; updatedAt: Date;
  }) {
    const order = this.orders.get(input.orderId)!;
    Object.assign(order, {
      providerOrderId: input.providerOrderId,
      checkoutUrl: input.checkoutUrl,
      expiresAt: input.expiresAt,
      updatedAt: input.updatedAt,
      status: 'pending' as const,
      failureCode: null,
    });
    return copyOrder(order);
  }

  async failOrder(input: { orderId: string; failureCode: string; updatedAt: Date }) {
    const order = this.orders.get(input.orderId)!;
    Object.assign(order, { status: 'failed' as const, failureCode: input.failureCode, updatedAt: input.updatedAt });
    return copyOrder(order);
  }

  async getOrder(orderId: string) {
    const order = this.orders.get(orderId);
    return order ? copyOrder(order) : null;
  }

  async getOrderByMerchantOrderId(merchantOrderId: string) {
    const order = [...this.orders.values()].find((candidate) => candidate.merchantOrderId === merchantOrderId);
    return order ? copyOrder(order) : null;
  }

  async acceptVerifiedWebhook(input: {
    event: PaymentWebhookEvent; payloadSha256: string; receivedAt: Date;
  }) {
    this.acceptCalls += 1;
    const replay = this.eventResults.get(input.event.eventId);
    if (replay) return {
      ...replay,
      order: copyOrder(replay.order),
      ledgerActions: replay.ledgerActions.map((action) => ({ ...action })),
      replayed: true,
    };
    const order = [...this.orders.values()]
      .find((candidate) => candidate.merchantOrderId === input.event.merchantOrderId)!;
    order.status = input.event.type === 'payment.succeeded' ? 'paid' : 'closed';
    order.providerPaymentId = input.event.providerPaymentId;
    order.paidAt = input.event.type === 'payment.succeeded' ? input.event.occurredAt : null;
    order.updatedAt = input.receivedAt;
    const actions: PaymentLedgerActionRecord[] = [];
    if (input.event.type === 'payment.succeeded') {
      order.creditedCredits = order.credits;
      const action: PaymentLedgerActionRecord = {
        id: `action_${input.event.eventId}`,
        orderId: order.id,
        webhookEventId: input.event.eventId,
        type: 'credit',
        credits: order.credits,
        idempotencyKey: `payment-credit:${input.event.eventId}`,
        state: 'pending',
        attempts: 0,
        nextAttemptAt: input.receivedAt,
        lastErrorCode: null,
        ledgerTransactionId: null,
        createdAt: input.receivedAt,
        updatedAt: input.receivedAt,
      };
      actions.push(action);
      this.actions.set(action.id, action);
    }
    const result: AcceptPaymentWebhookResult = {
      order: copyOrder(order),
      event: { ...input.event, payloadSha256: input.payloadSha256, receivedAt: input.receivedAt },
      ledgerActions: actions.map((action) => ({ ...action })),
      replayed: false,
    };
    this.eventResults.set(input.event.eventId, result);
    return result;
  }

  async listReadyLedgerActions(input: { now: Date; limit: number }) {
    return [...this.actions.values()]
      .filter((action) => ['pending', 'retrying'].includes(action.state)
        && action.nextAttemptAt.getTime() <= input.now.getTime())
      .slice(0, input.limit)
      .map((action) => ({ ...action }));
  }

  async markLedgerActionApplied(input: {
    actionId: string; ledgerTransactionId: string; appliedAt: Date;
  }) {
    const action = this.actions.get(input.actionId)!;
    Object.assign(action, {
      state: 'applied' as const,
      ledgerTransactionId: input.ledgerTransactionId,
      updatedAt: input.appliedAt,
    });
  }

  async markLedgerActionFailed(input: {
    actionId: string; errorCode: string; deadLetter: boolean; nextAttemptAt: Date; updatedAt: Date;
  }) {
    const action = this.actions.get(input.actionId)!;
    Object.assign(action, {
      attempts: action.attempts + 1,
      state: input.deadLetter ? 'dead_letter' as const : 'retrying' as const,
      lastErrorCode: input.errorCode,
      nextAttemptAt: input.nextAttemptAt,
      updatedAt: input.updatedAt,
    });
  }
}

function provider(event?: Partial<PaymentWebhookEvent>): PaymentProvider {
  return {
    id: 'generic-payment',
    createPayment: vi.fn(async (input) => ({
      providerOrderId: 'provider-order-1',
      checkoutUrl: 'https://pay.example.test/checkout/order-1',
      expiresAt: new Date(input.expiresAt.getTime() - 1_000),
    })),
    verifyWebhook: vi.fn(async (): Promise<PaymentWebhookEvent> => ({
      providerId: 'generic-payment',
      eventId: 'payment-event-1',
      type: 'payment.succeeded',
      merchantOrderId: 'merchant-order-1',
      providerPaymentId: 'provider-payment-1',
      amountMinor: 10_000,
      currency: 'CNY',
      occurredAt: new Date(NOW),
      ...event,
    })),
  };
}

function orderInput() {
  return {
    providerId: 'generic-payment',
    customerId: 'customer-1',
    organizationId: 'organization-1',
    amountMinor: 10_000,
    currency: 'cny',
    credits: 1_000,
    idempotencyKey: 'payment-idempotency-1',
    description: 'Otto credits',
  };
}

function serviceFixture(providerOverride = provider()) {
  const store = new MemoryPaymentStore();
  const applied: Array<Parameters<PaymentCreditLedger['apply']>[0]> = [];
  const ledger: PaymentCreditLedger = {
    apply: vi.fn(async (input) => {
      applied.push(input);
      return { transactionId: 'credit-transaction-1', replayed: false };
    }),
  };
  const service = new PaymentService({
    store,
    ledger,
    providers: [providerOverride],
    now: () => NOW,
    generateOrderId: () => 'payment-order-1',
    generateMerchantOrderId: () => 'merchant-order-1',
    retryBaseMs: 1_000,
  });
  return { service, store, ledger, provider: providerOverride, applied };
}

describe('payment service', () => {
  it('creates one provider checkout for an idempotent organization-scoped order', async () => {
    const fixture = serviceFixture();

    const first = await fixture.service.createOrder(orderInput());
    const replay = await fixture.service.createOrder(orderInput());

    expect(first).toMatchObject({
      status: 'pending',
      customerId: 'customer-1',
      organizationId: 'organization-1',
      currency: 'CNY',
    });
    expect(replay.id).toBe(first.id);
    expect(fixture.provider.createPayment).toHaveBeenCalledTimes(1);
  });

  it('rejects reuse of an idempotency key for a different amount', async () => {
    const fixture = serviceFixture();
    await fixture.service.createOrder(orderInput());

    await expect(fixture.service.createOrder({ ...orderInput(), amountMinor: 20_000 }))
      .rejects.toMatchObject({ code: 'CONFLICT' });
    expect(fixture.provider.createPayment).toHaveBeenCalledTimes(1);
  });

  it('validates webhook order bindings before persistence and credits only its organization', async () => {
    const fixture = serviceFixture();
    await fixture.service.createOrder(orderInput());

    const result = await fixture.service.acceptWebhook({
      providerId: 'generic-payment',
      rawBody: Buffer.from('{"event":"opaque"}'),
      headers: {},
    });

    expect(result.acceptance.replayed).toBe(false);
    expect(result.ledger).toMatchObject({ applied: 1, retrying: 0, deadLetter: 0 });
    expect(fixture.applied).toEqual([expect.objectContaining({
      customerId: 'customer-1',
      organizationId: 'organization-1',
      credits: 1_000,
      type: 'credit',
    })]);
    expect(fixture.store.acceptCalls).toBe(1);
  });

  it('rejects an amount mismatch before the event or ledger action is stored', async () => {
    const fixture = serviceFixture(provider({ amountMinor: 9_999 }));
    await fixture.service.createOrder(orderInput());

    await expect(fixture.service.acceptWebhook({
      providerId: 'generic-payment',
      rawBody: Buffer.from('{"event":"opaque"}'),
      headers: {},
    })).rejects.toMatchObject({ code: 'CONFLICT' });

    expect(fixture.store.acceptCalls).toBe(0);
    expect(fixture.store.actions.size).toBe(0);
    expect(fixture.ledger.apply).not.toHaveBeenCalled();
  });

  it('does not credit a duplicate verified webhook twice', async () => {
    const fixture = serviceFixture();
    await fixture.service.createOrder(orderInput());
    const webhook = {
      providerId: 'generic-payment',
      rawBody: Buffer.from('{"event":"opaque"}'),
      headers: {},
    };

    await fixture.service.acceptWebhook(webhook);
    const replay = await fixture.service.acceptWebhook(webhook);

    expect(replay.acceptance.replayed).toBe(true);
    expect(fixture.ledger.apply).toHaveBeenCalledTimes(1);
  });

  it('rejects a missing or replaced provider transaction binding', async () => {
    const missing = serviceFixture(provider({ providerPaymentId: null }));
    await missing.service.createOrder(orderInput());
    await expect(missing.service.acceptWebhook({
      providerId: 'generic-payment',
      rawBody: Buffer.from('{"event":"opaque"}'),
      headers: {},
    })).rejects.toMatchObject({ code: 'CONFLICT' });
    expect(missing.store.acceptCalls).toBe(0);

    const replaced = serviceFixture();
    const order = await replaced.service.createOrder(orderInput());
    replaced.store.orders.get(order.id)!.providerPaymentId = 'provider-payment-original';
    await expect(replaced.service.acceptWebhook({
      providerId: 'generic-payment',
      rawBody: Buffer.from('{"event":"opaque"}'),
      headers: {},
    })).rejects.toMatchObject({ code: 'CONFLICT' });
    expect(replaced.store.acceptCalls).toBe(0);
  });
});

describe('generic HMAC SHA-256 payment provider', () => {
  const secret = Buffer.from('0123456789abcdef0123456789abcdef');
  const body = Buffer.from(JSON.stringify({
    eventId: 'payment-event-1',
    type: 'payment.succeeded',
    merchantOrderId: 'merchant-order-1',
    providerPaymentId: 'provider-payment-1',
    amountMinor: 10_000,
    currency: 'CNY',
    occurredAt: new Date(NOW).toISOString(),
  }));
  const timestamp = String(NOW);

  function hmacProvider() {
    return new HmacSha256PaymentProvider({
      id: 'generic-self-hosted',
      resolveWebhookSecret: async () => secret,
      createPayment: async () => ({
        providerOrderId: 'provider-order-1',
        checkoutUrl: 'https://pay.example.test/order-1',
        expiresAt: new Date(NOW + 60_000),
      }),
    });
  }

  function signature(rawBody = body) {
    return createHmac('sha256', secret).update(timestamp).update('.').update(rawBody).digest('hex');
  }

  it('verifies the raw body and timestamp before parsing a generic event', async () => {
    const event = await hmacProvider().verifyWebhook({
      rawBody: body,
      headers: {
        'x-otto-payment-timestamp': timestamp,
        'x-otto-payment-signature': `v1=${signature()}`,
      },
      receivedAt: new Date(NOW),
    });
    expect(event).toMatchObject({
      providerId: 'generic-self-hosted',
      eventId: 'payment-event-1',
      amountMinor: 10_000,
    });
  });

  it('rejects tampering and stale callbacks', async () => {
    await expect(hmacProvider().verifyWebhook({
      rawBody: Buffer.from(body.toString('utf8').replace('10000', '10001')),
      headers: {
        'x-otto-payment-timestamp': timestamp,
        'x-otto-payment-signature': signature(),
      },
      receivedAt: new Date(NOW),
    })).rejects.toMatchObject({ code: 'UNAUTHORIZED' });

    await expect(hmacProvider().verifyWebhook({
      rawBody: body,
      headers: {
        'x-otto-payment-timestamp': timestamp,
        'x-otto-payment-signature': signature(),
      },
      receivedAt: new Date(NOW + 5 * 60_000 + 1),
    })).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
  });

  it('requires a provider transaction id for successful payments and refunds', async () => {
    const missingIdBody = Buffer.from(body.toString('utf8')
      .replace('"providerPaymentId":"provider-payment-1",', ''));
    const missingIdSignature = createHmac('sha256', secret)
      .update(timestamp).update('.').update(missingIdBody).digest('hex');

    await expect(hmacProvider().verifyWebhook({
      rawBody: missingIdBody,
      headers: {
        'x-otto-payment-timestamp': timestamp,
        'x-otto-payment-signature': missingIdSignature,
      },
      receivedAt: new Date(NOW),
    })).rejects.toMatchObject({ code: 'INVALID_REQUEST' });
  });
});

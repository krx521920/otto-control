import { createHash, randomUUID } from 'node:crypto';

import type {
  AcceptPaymentWebhookResult,
  PaymentCreditLedger,
  PaymentLedgerActionRecord,
  PaymentOrderRecord,
  PaymentProvider,
  PaymentStore,
  PaymentWebhookEvent,
} from '../../contracts/payments.js';
import { canonicalJson } from '../../crypto/signed-envelope.js';
import { conflict, invalidRequest } from '../../errors.js';

const ID_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,159}$/u;
const IDEMPOTENCY_KEY_PATTERN = /^[\u0021-\u007e]{8,160}$/u;
const METADATA_KEY_PATTERN = /^[a-zA-Z][a-zA-Z0-9_.:-]{0,63}$/u;
const DEFAULT_ORDER_TTL_MS = 30 * 60_000;
const MIN_ORDER_TTL_MS = 60_000;
const MAX_ORDER_TTL_MS = 24 * 60 * 60_000;
const DEFAULT_BATCH_SIZE = 50;
const DEFAULT_MAX_ATTEMPTS = 8;
const DEFAULT_RETRY_BASE_MS = 30_000;
const MAX_RETRY_DELAY_MS = 60 * 60_000;

export interface CreatePaymentOrderInput {
  providerId: string;
  customerId: string;
  organizationId: string;
  amountMinor: number;
  currency: string;
  credits: number;
  idempotencyKey: string;
  description: string;
  metadata?: Readonly<Record<string, string>>;
  expiresInMs?: number;
}

export interface AcceptPaymentWebhookInput {
  providerId: string;
  rawBody: Buffer;
  headers: Readonly<Record<string, string | string[] | undefined>>;
  receivedAt?: Date;
}

export interface PaymentLedgerProcessingResult {
  processed: number;
  applied: number;
  replayed: number;
  retrying: number;
  deadLetter: number;
}

export interface PaymentWebhookProcessingResult {
  acceptance: AcceptPaymentWebhookResult;
  ledger: PaymentLedgerProcessingResult;
}

export interface PaymentServiceOptions {
  store: PaymentStore;
  ledger: PaymentCreditLedger;
  providers: readonly PaymentProvider[];
  now?: () => number;
  generateOrderId?: () => string;
  generateMerchantOrderId?: () => string;
  ledgerBatchSize?: number;
  maxLedgerAttempts?: number;
  retryBaseMs?: number;
}

function requiredId(value: string, field: string): string {
  const normalized = value.trim();
  if (!ID_PATTERN.test(normalized)) throw invalidRequest(`${field} is invalid`);
  return normalized;
}

function normalizeCurrency(value: string): string {
  const normalized = value.trim().toUpperCase();
  if (!/^[A-Z]{3}$/u.test(normalized)) throw invalidRequest('currency is invalid');
  return normalized;
}

function normalizeDescription(value: string): string {
  const normalized = value.trim();
  if (!normalized || normalized.length > 200 || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    throw invalidRequest('description is invalid');
  }
  return normalized;
}

function normalizeMetadata(
  value: Readonly<Record<string, string>> | undefined,
): Readonly<Record<string, string>> {
  const entries = Object.entries(value ?? {});
  if (entries.length > 20) throw invalidRequest('payment metadata has too many entries');
  const normalized: Record<string, string> = {};
  for (const [key, item] of entries) {
    if (!METADATA_KEY_PATTERN.test(key) || item.length > 200
      || /[\u0000-\u001f\u007f]/u.test(item)) {
      throw invalidRequest('payment metadata is invalid');
    }
    normalized[key] = item;
  }
  return normalized;
}

function positiveSafeInteger(value: number, field: string): number {
  if (!Number.isSafeInteger(value) || value < 1) throw invalidRequest(`${field} is invalid`);
  return value;
}

function normalizeTtl(value: number | undefined): number {
  const ttl = value ?? DEFAULT_ORDER_TTL_MS;
  if (!Number.isSafeInteger(ttl) || ttl < MIN_ORDER_TTL_MS || ttl > MAX_ORDER_TTL_MS) {
    throw invalidRequest('expiresInMs must be between 1 minute and 24 hours');
  }
  return ttl;
}

function validateCheckout(
  checkout: Awaited<ReturnType<PaymentProvider['createPayment']>>,
  now: Date,
): void {
  requiredId(checkout.providerOrderId, 'providerOrderId');
  let url: URL;
  try {
    url = new URL(checkout.checkoutUrl);
  } catch {
    throw new Error('payment provider returned an invalid checkout URL');
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) {
    throw new Error('payment provider checkout URL must use HTTPS without credentials or fragments');
  }
  if (!Number.isFinite(checkout.expiresAt.getTime())
    || checkout.expiresAt.getTime() <= now.getTime()
    || checkout.expiresAt.getTime() > now.getTime() + MAX_ORDER_TTL_MS) {
    throw new Error('payment provider returned an invalid checkout expiry');
  }
}

function sha256(value: unknown): string {
  return createHash('sha256').update(canonicalJson(value)).digest('hex');
}

function safeFailureCode(prefix: 'PROVIDER' | 'LEDGER', error: unknown): string {
  if (error && typeof error === 'object' && 'code' in error
    && typeof error.code === 'string' && /^[A-Z][A-Z0-9_]{1,63}$/u.test(error.code)) {
    return `${prefix}_${error.code}`.slice(0, 80);
  }
  return `${prefix}_${prefix === 'PROVIDER' ? 'CREATE' : 'APPLY'}_FAILED`;
}

function retryDelayMs(attempt: number, baseMs: number): number {
  return Math.min(MAX_RETRY_DELAY_MS, baseMs * (2 ** Math.max(0, attempt - 1)));
}

function generatedId(prefix: string): string {
  return `${prefix}_${randomUUID().replaceAll('-', '')}`;
}

export class PaymentService {
  readonly #store: PaymentStore;
  readonly #ledger: PaymentCreditLedger;
  readonly #providers: ReadonlyMap<string, PaymentProvider>;
  readonly #now: () => number;
  readonly #generateOrderId: () => string;
  readonly #generateMerchantOrderId: () => string;
  readonly #ledgerBatchSize: number;
  readonly #maxLedgerAttempts: number;
  readonly #retryBaseMs: number;

  constructor(options: PaymentServiceOptions) {
    this.#store = options.store;
    this.#ledger = options.ledger;
    const providers = new Map<string, PaymentProvider>();
    for (const provider of options.providers) {
      requiredId(provider.id, 'payment provider id');
      if (providers.has(provider.id)) throw new Error(`duplicate payment provider id: ${provider.id}`);
      providers.set(provider.id, provider);
    }
    this.#providers = providers;
    this.#now = options.now ?? Date.now;
    this.#generateOrderId = options.generateOrderId ?? (() => generatedId('payment'));
    this.#generateMerchantOrderId = options.generateMerchantOrderId
      ?? (() => generatedId('merchant'));
    this.#ledgerBatchSize = options.ledgerBatchSize ?? DEFAULT_BATCH_SIZE;
    this.#maxLedgerAttempts = options.maxLedgerAttempts ?? DEFAULT_MAX_ATTEMPTS;
    this.#retryBaseMs = options.retryBaseMs ?? DEFAULT_RETRY_BASE_MS;
    if (!Number.isSafeInteger(this.#ledgerBatchSize)
      || this.#ledgerBatchSize < 1 || this.#ledgerBatchSize > 500) {
      throw new Error('payment ledgerBatchSize must be between 1 and 500');
    }
    if (!Number.isSafeInteger(this.#maxLedgerAttempts)
      || this.#maxLedgerAttempts < 1 || this.#maxLedgerAttempts > 20) {
      throw new Error('payment maxLedgerAttempts must be between 1 and 20');
    }
    if (!Number.isSafeInteger(this.#retryBaseMs)
      || this.#retryBaseMs < 1_000 || this.#retryBaseMs > MAX_RETRY_DELAY_MS) {
      throw new Error('payment retryBaseMs must be between 1 second and 1 hour');
    }
  }

  async createOrder(input: CreatePaymentOrderInput): Promise<PaymentOrderRecord> {
    const providerId = requiredId(input.providerId, 'providerId');
    const provider = this.#providers.get(providerId);
    if (!provider) throw invalidRequest('payment provider is unsupported');
    const customerId = requiredId(input.customerId, 'customerId');
    const organizationId = requiredId(input.organizationId, 'organizationId');
    const amountMinor = positiveSafeInteger(input.amountMinor, 'amountMinor');
    const credits = positiveSafeInteger(input.credits, 'credits');
    const currency = normalizeCurrency(input.currency);
    const idempotencyKey = input.idempotencyKey.trim();
    if (!IDEMPOTENCY_KEY_PATTERN.test(idempotencyKey)) {
      throw invalidRequest('idempotencyKey is invalid');
    }
    const description = normalizeDescription(input.description);
    const metadata = normalizeMetadata(input.metadata);
    const ttlMs = normalizeTtl(input.expiresInMs);
    const now = new Date(this.#now());
    const expiresAt = new Date(now.getTime() + ttlMs);
    const requestSha256 = sha256({
      providerId, customerId, organizationId, amountMinor, currency, credits,
      description, metadata, ttlMs,
    });
    const reserved = await this.#store.reserveOrder({
      id: requiredId(this.#generateOrderId(), 'generated payment order id'),
      merchantOrderId: requiredId(
        this.#generateMerchantOrderId(),
        'generated merchant order id',
      ),
      providerId,
      customerId,
      organizationId,
      amountMinor,
      currency,
      credits,
      idempotencyKey,
      requestSha256,
      expiresAt,
      createdAt: now,
    });
    if (reserved.order.requestSha256 !== requestSha256) {
      throw conflict('payment idempotency key was already used for a different request');
    }
    if (reserved.replayed && !['creating', 'failed'].includes(reserved.order.status)) {
      return reserved.order;
    }

    try {
      const checkout = await provider.createPayment({
        merchantOrderId: reserved.order.merchantOrderId,
        amountMinor,
        currency,
        description,
        expiresAt,
        metadata: { ...metadata, ottoPaymentOrderId: reserved.order.id },
      });
      validateCheckout(checkout, now);
      return await this.#store.activateOrder({
        orderId: reserved.order.id,
        providerOrderId: checkout.providerOrderId,
        checkoutUrl: checkout.checkoutUrl,
        expiresAt: checkout.expiresAt,
        updatedAt: new Date(this.#now()),
      });
    } catch (error) {
      try {
        await this.#store.failOrder({
          orderId: reserved.order.id,
          failureCode: safeFailureCode('PROVIDER', error),
          updatedAt: new Date(this.#now()),
        });
      } catch {
        // Keep the original provider error. Replaying the same key can recover the order.
      }
      throw error;
    }
  }

  async acceptWebhook(input: AcceptPaymentWebhookInput): Promise<PaymentWebhookProcessingResult> {
    const providerId = requiredId(input.providerId, 'providerId');
    const provider = this.#providers.get(providerId);
    if (!provider) throw invalidRequest('payment provider is unsupported');
    if (!Buffer.isBuffer(input.rawBody) || input.rawBody.byteLength < 2
      || input.rawBody.byteLength > 1024 * 1024) {
      throw invalidRequest('payment webhook body size is invalid');
    }
    const receivedAt = input.receivedAt ?? new Date(this.#now());
    if (!Number.isFinite(receivedAt.getTime())) throw invalidRequest('receivedAt is invalid');
    const event = await provider.verifyWebhook({
      rawBody: input.rawBody,
      headers: input.headers,
      receivedAt,
    });
    if (event.providerId !== provider.id) {
      throw conflict('verified payment webhook provider binding is invalid');
    }
    const order = await this.#store.getOrderByMerchantOrderId(event.merchantOrderId);
    if (!order) throw conflict('payment webhook order binding is invalid');
    this.#assertWebhookBindings(order, event, providerId);
    const acceptance = await this.#store.acceptVerifiedWebhook({
      event,
      payloadSha256: createHash('sha256').update(input.rawBody).digest('hex'),
      receivedAt,
    });
    this.#assertAcceptedWebhookBindings(acceptance, providerId);
    return { acceptance, ledger: await this.processReadyLedgerActions() };
  }

  async processReadyLedgerActions(
    limit = this.#ledgerBatchSize,
  ): Promise<PaymentLedgerProcessingResult> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 500) {
      throw invalidRequest('payment ledger action limit must be between 1 and 500');
    }
    const result: PaymentLedgerProcessingResult = {
      processed: 0, applied: 0, replayed: 0, retrying: 0, deadLetter: 0,
    };
    const actions = await this.#store.listReadyLedgerActions({
      now: new Date(this.#now()),
      limit,
    });
    for (const action of actions) {
      result.processed += 1;
      await this.#processLedgerAction(action, result);
    }
    return result;
  }

  async #processLedgerAction(
    action: PaymentLedgerActionRecord,
    result: PaymentLedgerProcessingResult,
  ): Promise<void> {
    try {
      if (!Number.isSafeInteger(action.credits) || action.credits < 1) {
        throw new Error('payment ledger action credits are invalid');
      }
      const order = await this.#store.getOrder(action.orderId);
      if (!order) throw new Error('payment ledger action order is missing');
      const applied = await this.#ledger.apply({
        type: action.type,
        customerId: order.customerId,
        organizationId: order.organizationId,
        credits: action.credits,
        idempotencyKey: action.idempotencyKey,
        referenceId: action.webhookEventId,
        metadata: {
          paymentOrderId: order.id,
          merchantOrderId: order.merchantOrderId,
          paymentProviderId: order.providerId,
          webhookEventId: action.webhookEventId,
        },
      });
      await this.#store.markLedgerActionApplied({
        actionId: action.id,
        ledgerTransactionId: applied.transactionId,
        appliedAt: new Date(this.#now()),
      });
      if (applied.replayed) result.replayed += 1;
      else result.applied += 1;
    } catch (error) {
      const failedAt = new Date(this.#now());
      const attempt = action.attempts + 1;
      const deadLetter = attempt >= this.#maxLedgerAttempts;
      await this.#store.markLedgerActionFailed({
        actionId: action.id,
        errorCode: safeFailureCode('LEDGER', error),
        deadLetter,
        nextAttemptAt: deadLetter
          ? failedAt
          : new Date(failedAt.getTime() + retryDelayMs(attempt, this.#retryBaseMs)),
        updatedAt: failedAt,
      });
      if (deadLetter) result.deadLetter += 1;
      else result.retrying += 1;
    }
  }

  #assertAcceptedWebhookBindings(
    acceptance: AcceptPaymentWebhookResult,
    providerId: string,
  ): void {
    this.#assertWebhookBindings(acceptance.order, acceptance.event, providerId);
  }

  #assertWebhookBindings(
    order: PaymentOrderRecord,
    event: PaymentWebhookEvent,
    providerId: string,
  ): void {
    if (order.providerId !== providerId || event.providerId !== providerId
      || event.merchantOrderId !== order.merchantOrderId
      || event.currency !== order.currency) {
      throw conflict('payment webhook does not match its order binding');
    }
    if (event.type === 'payment.succeeded' && event.amountMinor !== order.amountMinor) {
      throw conflict('payment amount does not match the order');
    }
    if (event.type !== 'payment.closed' && !event.providerPaymentId) {
      throw conflict('payment provider transaction binding is missing');
    }
    if (order.providerPaymentId && event.providerPaymentId !== order.providerPaymentId) {
      throw conflict('payment provider transaction binding changed');
    }
    if (event.type === 'refund.succeeded'
      && (event.amountMinor < 1 || event.amountMinor > order.amountMinor)) {
      throw conflict('payment refund amount is outside the order amount');
    }
    if (event.type === 'payment.closed' && event.amountMinor !== 0) {
      throw conflict('closed payment event amount must be zero');
    }
  }
}

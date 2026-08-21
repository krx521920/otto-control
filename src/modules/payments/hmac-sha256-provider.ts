import { createHmac, timingSafeEqual } from 'node:crypto';

import type {
  CreateProviderPaymentInput,
  PaymentCheckout,
  PaymentProvider,
  PaymentWebhookEvent,
  PaymentWebhookEventType,
  PaymentWebhookVerificationInput,
} from '../../contracts/payments.js';
import { PAYMENT_WEBHOOK_EVENT_TYPES } from '../../contracts/payments.js';
import { invalidRequest, unauthorized } from '../../errors.js';

const ID_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,159}$/u;
const SIGNATURE_PATTERN = /^(?:v1=)?([a-f0-9]{64})$/iu;

export interface HmacSha256PaymentProviderOptions {
  id: string;
  resolveWebhookSecret: () => Promise<Buffer>;
  createPayment: (input: CreateProviderPaymentInput) => Promise<PaymentCheckout>;
  timestampHeader?: string;
  signatureHeader?: string;
  toleranceMs?: number;
}

function headerValue(
  headers: Readonly<Record<string, string | string[] | undefined>>,
  name: string,
): string {
  const entry = Object.entries(headers)
    .find(([key]) => key.toLowerCase() === name.toLowerCase())?.[1];
  if (Array.isArray(entry)) {
    if (entry.length !== 1) throw unauthorized(`ambiguous ${name} header`);
    return entry[0]?.trim() ?? '';
  }
  return entry?.trim() ?? '';
}

function requiredId(body: Record<string, unknown>, field: string): string {
  const value = typeof body[field] === 'string' ? body[field].trim() : '';
  if (!ID_PATTERN.test(value)) throw invalidRequest(`payment webhook ${field} is invalid`);
  return value;
}

function webhookType(value: unknown): PaymentWebhookEventType {
  if (typeof value !== 'string'
    || !(PAYMENT_WEBHOOK_EVENT_TYPES as readonly string[]).includes(value)) {
    throw invalidRequest('payment webhook type is unsupported');
  }
  return value as PaymentWebhookEventType;
}

function parseWebhook(providerId: string, rawBody: Buffer): PaymentWebhookEvent {
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawBody.toString('utf8')) as unknown;
  } catch {
    throw invalidRequest('payment webhook body must be valid JSON');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw invalidRequest('payment webhook body must be an object');
  }
  const body = parsed as Record<string, unknown>;
  const type = webhookType(body.type);
  const amountMinor = Number(body.amountMinor);
  const minimum = type === 'payment.closed' ? 0 : 1;
  if (!Number.isSafeInteger(amountMinor) || amountMinor < minimum) {
    throw invalidRequest('payment webhook amountMinor is invalid');
  }
  const currency = typeof body.currency === 'string' ? body.currency.trim().toUpperCase() : '';
  if (!/^[A-Z]{3}$/u.test(currency)) throw invalidRequest('payment webhook currency is invalid');
  const occurredAt = new Date(String(body.occurredAt ?? ''));
  if (!Number.isFinite(occurredAt.getTime())) {
    throw invalidRequest('payment webhook occurredAt is invalid');
  }
  const providerPaymentId = body.providerPaymentId === null || body.providerPaymentId === undefined
    ? null
    : requiredId(body, 'providerPaymentId');
  if (type !== 'payment.closed' && !providerPaymentId) {
    throw invalidRequest('payment webhook providerPaymentId is required');
  }
  return {
    providerId,
    eventId: requiredId(body, 'eventId'),
    type,
    merchantOrderId: requiredId(body, 'merchantOrderId'),
    providerPaymentId,
    amountMinor,
    currency,
    occurredAt,
  };
}

export class HmacSha256PaymentProvider implements PaymentProvider {
  /** Generic/self-hosted integration only; this is not WeChat Pay or Alipay protocol support. */
  readonly kind = 'generic-self-hosted' as const;
  readonly id: string;
  readonly #resolveWebhookSecret: () => Promise<Buffer>;
  readonly #createPayment: (input: CreateProviderPaymentInput) => Promise<PaymentCheckout>;
  readonly #timestampHeader: string;
  readonly #signatureHeader: string;
  readonly #toleranceMs: number;

  constructor(options: HmacSha256PaymentProviderOptions) {
    if (!ID_PATTERN.test(options.id)) throw new Error('payment provider id is invalid');
    this.id = options.id;
    this.#resolveWebhookSecret = options.resolveWebhookSecret;
    this.#createPayment = options.createPayment;
    this.#timestampHeader = options.timestampHeader ?? 'x-otto-payment-timestamp';
    this.#signatureHeader = options.signatureHeader ?? 'x-otto-payment-signature';
    this.#toleranceMs = options.toleranceMs ?? 5 * 60 * 1000;
    if (!Number.isSafeInteger(this.#toleranceMs) || this.#toleranceMs < 1_000) {
      throw new Error('payment webhook toleranceMs is invalid');
    }
  }

  createPayment(input: CreateProviderPaymentInput): Promise<PaymentCheckout> {
    return this.#createPayment(input);
  }

  async verifyWebhook(input: PaymentWebhookVerificationInput): Promise<PaymentWebhookEvent> {
    const timestampText = headerValue(input.headers, this.#timestampHeader);
    if (!/^\d{10,13}$/u.test(timestampText)) {
      throw unauthorized('payment webhook timestamp is missing or invalid');
    }
    const timestampNumber = Number(timestampText);
    const timestampMs = timestampText.length === 10 ? timestampNumber * 1_000 : timestampNumber;
    if (!Number.isSafeInteger(timestampMs)
      || Math.abs(input.receivedAt.getTime() - timestampMs) > this.#toleranceMs) {
      throw unauthorized('payment webhook timestamp is outside the accepted window');
    }
    const signatureText = headerValue(input.headers, this.#signatureHeader);
    const signatureMatch = SIGNATURE_PATTERN.exec(signatureText);
    if (!signatureMatch?.[1]) throw unauthorized('payment webhook signature is missing or invalid');
    const supplied = Buffer.from(signatureMatch[1], 'hex');
    const secret = await this.#resolveWebhookSecret();
    if (secret.byteLength < 32) throw new Error('payment webhook secret must contain at least 32 bytes');
    const expected = createHmac('sha256', secret)
      .update(timestampText)
      .update('.')
      .update(input.rawBody)
      .digest();
    if (supplied.byteLength !== expected.byteLength || !timingSafeEqual(supplied, expected)) {
      throw unauthorized('payment webhook signature verification failed');
    }
    return parseWebhook(this.id, input.rawBody);
  }
}

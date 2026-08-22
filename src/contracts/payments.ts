export const PAYMENT_ORDER_STATUSES = [
  'creating', 'pending', 'paid', 'partially_refunded', 'refunded', 'closed', 'failed',
] as const;

export type PaymentOrderStatus = (typeof PAYMENT_ORDER_STATUSES)[number];

export const PAYMENT_WEBHOOK_EVENT_TYPES = [
  'payment.succeeded', 'payment.closed', 'refund.succeeded',
] as const;

export type PaymentWebhookEventType = (typeof PAYMENT_WEBHOOK_EVENT_TYPES)[number];
export type PaymentLedgerActionType = 'credit' | 'debit';
export type PaymentLedgerActionState = 'pending' | 'retrying' | 'applied' | 'dead_letter';

export interface PaymentOrderRecord {
  id: string;
  merchantOrderId: string;
  providerId: string;
  providerOrderId: string | null;
  customerId: string;
  organizationId: string;
  amountMinor: number;
  currency: string;
  credits: number;
  status: PaymentOrderStatus;
  idempotencyKey: string;
  requestSha256: string;
  checkoutUrl: string | null;
  providerPaymentId: string | null;
  creditedCredits: number;
  reversedCredits: number;
  refundedAmountMinor: number;
  failureCode: string | null;
  expiresAt: Date;
  paidAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface PaymentWebhookEvent {
  providerId: string;
  eventId: string;
  type: PaymentWebhookEventType;
  merchantOrderId: string;
  providerPaymentId: string | null;
  amountMinor: number;
  currency: string;
  occurredAt: Date;
}

export interface PaymentWebhookEventRecord extends PaymentWebhookEvent {
  payloadSha256: string;
  receivedAt: Date;
}

export interface PaymentLedgerActionRecord {
  id: string;
  orderId: string;
  webhookEventId: string;
  type: PaymentLedgerActionType;
  credits: number;
  idempotencyKey: string;
  state: PaymentLedgerActionState;
  attempts: number;
  nextAttemptAt: Date;
  lastErrorCode: string | null;
  ledgerTransactionId: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface PaymentCheckout {
  providerOrderId: string;
  checkoutUrl: string;
  expiresAt: Date;
}

export interface CreateProviderPaymentInput {
  merchantOrderId: string;
  amountMinor: number;
  currency: string;
  description: string;
  expiresAt: Date;
  metadata: Readonly<Record<string, string>>;
}

export interface PaymentWebhookVerificationInput {
  rawBody: Buffer;
  headers: Readonly<Record<string, string | string[] | undefined>>;
  receivedAt: Date;
}

export interface PaymentProvider {
  readonly id: string;
  createPayment(input: CreateProviderPaymentInput): Promise<PaymentCheckout>;
  verifyWebhook(input: PaymentWebhookVerificationInput): Promise<PaymentWebhookEvent>;
}

export interface ReservePaymentOrderInput {
  id: string;
  merchantOrderId: string;
  providerId: string;
  customerId: string;
  organizationId: string;
  amountMinor: number;
  currency: string;
  credits: number;
  idempotencyKey: string;
  requestSha256: string;
  expiresAt: Date;
  createdAt: Date;
}

export interface PaymentOrderMutationResult {
  order: PaymentOrderRecord;
  replayed: boolean;
}

export interface AcceptPaymentWebhookResult {
  order: PaymentOrderRecord;
  event: PaymentWebhookEventRecord;
  ledgerActions: PaymentLedgerActionRecord[];
  replayed: boolean;
}

export interface PaymentStore {
  reserveOrder(input: ReservePaymentOrderInput): Promise<PaymentOrderMutationResult>;
  activateOrder(input: {
    orderId: string; providerOrderId: string; checkoutUrl: string; expiresAt: Date; updatedAt: Date;
  }): Promise<PaymentOrderRecord>;
  failOrder(input: {
    orderId: string; failureCode: string; updatedAt: Date;
  }): Promise<PaymentOrderRecord>;
  getOrder(orderId: string): Promise<PaymentOrderRecord | null>;
  getOrderByMerchantOrderId(merchantOrderId: string): Promise<PaymentOrderRecord | null>;
  acceptVerifiedWebhook(input: {
    event: PaymentWebhookEvent; payloadSha256: string; receivedAt: Date;
  }): Promise<AcceptPaymentWebhookResult>;
  listReadyLedgerActions(input: {
    now: Date; limit: number;
  }): Promise<PaymentLedgerActionRecord[]>;
  markLedgerActionApplied(input: {
    actionId: string; ledgerTransactionId: string; appliedAt: Date;
  }): Promise<void>;
  markLedgerActionFailed(input: {
    actionId: string; errorCode: string; deadLetter: boolean; nextAttemptAt: Date; updatedAt: Date;
  }): Promise<void>;
}

export interface PaymentCreditLedger {
  apply(input: {
    type: PaymentLedgerActionType;
    customerId: string;
    organizationId: string;
    credits: number;
    idempotencyKey: string;
    referenceId: string;
    metadata: Readonly<Record<string, string>>;
  }): Promise<{ transactionId: string; replayed: boolean }>;
}

export type InvoiceStatus = 'requested' | 'issuing' | 'issued' | 'failed' | 'voided';

export interface InvoiceProvider {
  readonly id: string;
  createInvoice(input: {
    invoiceId: string;
    amountMinor: number;
    currency: string;
    title: string;
    taxNumber: string;
    merchantOrderIds: readonly string[];
  }): Promise<{ providerInvoiceId: string }>;
  getInvoice(providerInvoiceId: string): Promise<{
    status: InvoiceStatus; downloadUrl: string | null; failureCode: string | null;
  }>;
}

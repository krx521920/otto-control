export const OTTO_BILLING_MODULES = [
  'model_gateway',
  'meeting_agent',
  'park_service',
  'atoa',
  'feishu',
  'enterprise_knowledge',
  'skill_market',
  'data_visualization',
  'document_generation',
] as const;

export type OttoBillingModule = (typeof OTTO_BILLING_MODULES)[number];

export const CREDIT_TRANSACTION_TYPES = [
  'topup',
  'freeze',
  'capture',
  'release',
  'consume',
  'refund',
] as const;

export type CreditTransactionType = (typeof CREDIT_TRANSACTION_TYPES)[number];
export type CreditHoldStatus = 'active' | 'captured' | 'released' | 'expired';

export interface CreditAccountRecord {
  customerId: string;
  organizationId: string;
  availableBalance: number;
  frozenBalance: number;
  totalToppedUp: number;
  totalConsumed: number;
  totalRefunded: number;
  version: number;
  createdAt: Date;
  updatedAt: Date;
}

export interface BillingRateRecord {
  customerId: string;
  module: OttoBillingModule;
  unitSize: number;
  creditsPerUnit: number;
  updatedBy: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface CreditHoldRecord {
  id: string;
  customerId: string;
  organizationId: string;
  deploymentId: string;
  module: OttoBillingModule;
  amount: number;
  status: CreditHoldStatus;
  idempotencyKey: string;
  expiresAt: Date;
  createdAt: Date;
  updatedAt: Date;
}

export interface CreditTransactionRecord {
  id: string;
  customerId: string;
  organizationId: string | null;
  deploymentId: string | null;
  module: OttoBillingModule | null;
  type: CreditTransactionType;
  availableDelta: number;
  frozenDelta: number;
  billedAmount: number;
  availableAfter: number;
  frozenAfter: number;
  idempotencyKey: string;
  referenceId: string | null;
  relatedTransactionId: string | null;
  description: string;
  metadata: Record<string, unknown>;
  occurredAt: Date;
  createdAt: Date;
}

export interface CreditMutationResult {
  account: CreditAccountRecord;
  transaction: CreditTransactionRecord;
  replayed: boolean;
}

export interface CreditHoldMutationResult extends CreditMutationResult {
  hold: CreditHoldRecord;
}

export interface CreditStatementLine {
  organizationId: string;
  module: OttoBillingModule;
  consumedCredits: number;
  refundedCredits: number;
  netCredits: number;
  transactionCount: number;
}

export interface CreditStatement {
  customerId: string;
  from: Date;
  to: Date;
  openingBalance: number;
  closingBalance: number;
  totalToppedUp: number;
  totalConsumed: number;
  totalRefunded: number;
  lines: CreditStatementLine[];
}

export type ExecutionReceiptKeyStatus = 'active' | 'revoked';

export interface ExecutionReceiptKeyRecord {
  deploymentId: string;
  keyId: string;
  publicKeyPem: string;
  status: ExecutionReceiptKeyStatus;
  notBefore: Date;
  expiresAt: Date | null;
  revokedAt: Date | null;
  createdAt: Date;
}

export interface ExecutionReceiptV2Payload {
  version: 2;
  receiptId: string;
  deploymentId: string;
  organizationId: string;
  taskId: string;
  moduleId: OttoBillingModule;
  units: number;
  model: string | null;
  issuedAtMs: number;
  expiresAtMs: number;
  sequence: number;
  policyVersion: string;
}

export interface SignedExecutionReceiptV2 {
  receipt: ExecutionReceiptV2Payload;
  signingKeyId: string;
  signature: string;
}

export interface ExecutionReceiptRecord extends ExecutionReceiptV2Payload {
  customerId: string;
  signingKeyId: string;
  signature: string;
  transactionId: string;
  verificationStatus: 'verified';
  receivedAt: Date;
}

export interface ExecutionReceiptMutationResult extends CreditMutationResult {
  receipt: ExecutionReceiptRecord;
}

export interface ExecutionReceiptHoldMutationResult extends ExecutionReceiptMutationResult {
  hold: CreditHoldRecord;
}

export function isOttoBillingModule(value: string): value is OttoBillingModule {
  return (OTTO_BILLING_MODULES as readonly string[]).includes(value);
}

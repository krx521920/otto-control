import { randomUUID } from 'node:crypto';

import type {
  CreditHoldMutationResult,
  CreditMutationResult,
  CreditStatement,
  CreditTransactionRecord,
  ExecutionReceiptMutationResult,
  ExecutionReceiptRecord,
  OttoBillingModule,
} from '../../contracts/billing.js';
import { isOttoBillingModule } from '../../contracts/billing.js';
import { conflict, invalidRequest, notFound, unauthorized } from '../../errors.js';
import type { ControlStore, LicenseRecord } from '../../storage/control-store.js';
import type { ControlTokenIssuer } from '../commercial-control/token-issuer.js';
import {
  normalizeExecutionReceiptEnvelope,
  normalizeExecutionReceiptKeyBootstrap,
  normalizeExecutionReceiptPublicKey,
  verifyExecutionReceipt,
} from './execution-receipt.js';

const ID_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,159}$/u;
const FINGERPRINT_PATTERN = /^[a-f0-9]{64}$/u;
const MAX_CREDITS = 9_000_000_000_000_000;
const MAX_UNITS = 9_000_000_000_000;
const MAX_RECEIPT_KEY_LIFETIME_MS = 400 * 24 * 60 * 60 * 1000;
const RECEIPT_REQUEST_FIELDS = new Set(['licenseId', 'machineFingerprint', 'envelope']);

interface AuthenticatedDeployment {
  customerId: string;
  license: LicenseRecord;
  organizationId: string;
  deploymentId: string;
}

function objectValue(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw invalidRequest('request body must be an object');
  }
  return value as Record<string, unknown>;
}

function requiredString(
  body: Record<string, unknown>,
  field: string,
  maxLength = 160,
): string {
  const value = typeof body[field] === 'string' ? body[field].trim() : '';
  if (!value || value.length > maxLength) throw invalidRequest(`${field} is invalid`);
  return value;
}

function exactFields(body: Record<string, unknown>, expected: Set<string>, name: string): void {
  const unknown = Object.keys(body).filter((field) => !expected.has(field));
  if (unknown.length > 0) throw invalidRequest(`${name} contains unsupported fields`);
}

function optionalDate(value: unknown, field: string): Date | null {
  if (value === undefined || value === null || value === '') return null;
  const parsed = new Date(String(value));
  if (!Number.isFinite(parsed.getTime())) throw invalidRequest(`${field} is invalid`);
  return parsed;
}

function positiveInteger(value: unknown, field: string, maximum = MAX_CREDITS): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > maximum) {
    throw invalidRequest(`${field} must be a positive safe integer`);
  }
  return parsed;
}

function optionalDescription(body: Record<string, unknown>, fallback: string): string {
  if (body.description === undefined) return fallback;
  if (typeof body.description !== 'string' || body.description.length > 500) {
    throw invalidRequest('description is invalid');
  }
  return body.description.trim();
}

function idempotencyKey(body: Record<string, unknown>): string {
  const key = requiredString(body, 'idempotencyKey');
  if (!ID_PATTERN.test(key)) throw invalidRequest('idempotencyKey is invalid');
  return key;
}

function moduleValue(body: Record<string, unknown>): OttoBillingModule {
  const module = requiredString(body, 'module', 80);
  if (!isOttoBillingModule(module)) throw invalidRequest(`unknown billing module: ${module}`);
  return module;
}

function transactionId(): string {
  return `ctx_${randomUUID().replaceAll('-', '')}`;
}

function holdId(): string {
  return `hold_${randomUUID().replaceAll('-', '')}`;
}

function parseRange(rawFrom: unknown, rawTo: unknown): { from: Date; to: Date } {
  const to = rawTo === undefined ? new Date(Date.now() + 1) : new Date(String(rawTo));
  const from = rawFrom === undefined
    ? new Date(to.getTime() - 30 * 24 * 60 * 60 * 1000)
    : new Date(String(rawFrom));
  if (!Number.isFinite(from.getTime()) || !Number.isFinite(to.getTime()) || from >= to) {
    throw invalidRequest('from and to must define a valid increasing date range');
  }
  if (to.getTime() - from.getTime() > 366 * 24 * 60 * 60 * 1000) {
    throw invalidRequest('billing range cannot exceed 366 days');
  }
  return { from, to };
}

function csvCell(value: unknown): string {
  const text = value === null || value === undefined ? '' : String(value);
  return `"${text.replaceAll('"', '""')}"`;
}

export interface BillingServiceOptions {
  store: ControlStore;
  tokenIssuer: ControlTokenIssuer;
  now?: () => number;
  allowLegacyUsageReports?: boolean;
}

export class BillingService {
  readonly #store: ControlStore;
  readonly #tokens: ControlTokenIssuer;
  readonly #now: () => number;
  readonly #allowLegacyUsageReports: boolean;

  constructor(options: BillingServiceOptions) {
    this.#store = options.store;
    this.#tokens = options.tokenIssuer;
    this.#now = options.now ?? Date.now;
    this.#allowLegacyUsageReports = options.allowLegacyUsageReports ?? true;
  }

  async account(customerId: string, organizationId: string) {
    if (!ID_PATTERN.test(organizationId)) throw invalidRequest('organizationId is invalid');
    await this.#releaseExpiredHolds(customerId);
    const account = await this.#store.getCreditAccount(customerId, organizationId);
    if (!account) throw notFound('credit account not found');
    return account;
  }

  async setRate(customerId: string, raw: unknown, actorId: string) {
    const body = objectValue(raw);
    const module = moduleValue(body);
    const unitSize = positiveInteger(body.unitSize, 'unitSize', MAX_UNITS);
    const creditsPerUnit = positiveInteger(body.creditsPerUnit, 'creditsPerUnit');
    const rate = await this.#store.setBillingRate({
      customerId,
      module,
      unitSize,
      creditsPerUnit,
      actorId,
      changedAt: new Date(this.#now()),
    });
    await this.#store.appendAuditEvent({
      actorId,
      action: 'billing.rate.set',
      targetType: 'customer',
      targetId: customerId,
      detail: { module, unitSize, creditsPerUnit },
    });
    return rate;
  }

  async rates(customerId: string) {
    return this.#store.listBillingRates(customerId);
  }

  async registerExecutionReceiptKey(
    deploymentId: string,
    raw: unknown,
    actorId: string,
  ) {
    const body = objectValue(raw);
    const normalized = normalizeExecutionReceiptPublicKey(body.publicKeyPem);
    if (body.keyId !== undefined && String(body.keyId).trim().toLowerCase() !== normalized.keyId) {
      throw invalidRequest('keyId does not match the Ed25519 public key');
    }
    const now = this.#now();
    const existing = await this.#store.getExecutionReceiptKey(deploymentId, normalized.keyId);
    const notBefore = optionalDate(body.notBefore, 'notBefore')
      ?? existing?.notBefore
      ?? new Date(now - 5 * 60 * 1000);
    const expiresAt = optionalDate(body.expiresAt, 'expiresAt') ?? existing?.expiresAt ?? null;
    if (!expiresAt || expiresAt.getTime() <= Math.max(now, notBefore.getTime())) {
      throw invalidRequest('expiresAt must be later than the current time and notBefore');
    }
    if (expiresAt.getTime() - notBefore.getTime() > MAX_RECEIPT_KEY_LIFETIME_MS) {
      throw invalidRequest('execution receipt key lifetime cannot exceed 400 days');
    }
    const deployment = await this.#store.getDeployment(deploymentId);
    if (!deployment) throw notFound('deployment not found');
    const key = await this.#store.registerExecutionReceiptKey({
      deploymentId,
      keyId: normalized.keyId,
      publicKeyPem: normalized.publicKeyPem,
      notBefore,
      expiresAt,
      createdAt: existing?.createdAt ?? new Date(now),
    });
    if (!existing) {
      await this.#store.appendAuditEvent({
        actorId,
        action: 'billing.execution_receipt_key.registered',
        targetType: 'deployment',
        targetId: deploymentId,
        detail: {
          keyId: key.keyId,
          notBefore: key.notBefore.toISOString(),
          expiresAt: key.expiresAt?.toISOString() ?? null,
        },
      });
    }
    return key;
  }

  async bootstrapExecutionReceiptKey(raw: unknown, bearerToken: string) {
    const now = this.#now();
    const { claim } = normalizeExecutionReceiptKeyBootstrap(raw, now);
    const authenticated = await this.#authenticateDeployment({
      licenseId: claim.licenseId,
      deploymentId: claim.deploymentId,
      organizationId: claim.organizationId,
      machineFingerprint: claim.machineFingerprint,
    }, bearerToken);
    const notBefore = new Date(claim.issuedAtMs - 5 * 60 * 1000);
    const expiresAt = new Date(claim.expiresAtMs);
    if (expiresAt.getTime() - notBefore.getTime() > MAX_RECEIPT_KEY_LIFETIME_MS) {
      throw invalidRequest('execution receipt key lifetime cannot exceed 400 days');
    }
    const result = await this.#store.bootstrapExecutionReceiptKey({
      deploymentId: authenticated.deploymentId,
      keyId: claim.keyId,
      publicKeyPem: claim.publicKeyPem,
      notBefore,
      expiresAt,
      createdAt: new Date(now),
    });
    if (!result.replayed) {
      await this.#store.appendAuditEvent({
        actorId: `deployment:${authenticated.deploymentId}`,
        action: 'billing.execution_receipt_key.bootstrapped',
        targetType: 'deployment',
        targetId: authenticated.deploymentId,
        detail: {
          keyId: result.key.keyId,
          notBefore: result.key.notBefore.toISOString(),
          expiresAt: result.key.expiresAt?.toISOString() ?? null,
        },
      });
    }
    return result;
  }

  async revokeExecutionReceiptKey(deploymentId: string, keyId: string, actorId: string) {
    const normalizedKeyId = keyId.trim().toLowerCase();
    const existing = await this.#store.getExecutionReceiptKey(deploymentId, normalizedKeyId);
    if (!existing) throw notFound('execution receipt key not found');
    const key = await this.#store.revokeExecutionReceiptKey({
      deploymentId,
      keyId: normalizedKeyId,
      revokedAt: new Date(this.#now()),
    });
    if (!key) throw notFound('execution receipt key not found');
    if (existing.status === 'active') {
      await this.#store.appendAuditEvent({
        actorId,
        action: 'billing.execution_receipt_key.revoked',
        targetType: 'deployment',
        targetId: deploymentId,
        detail: { keyId: key.keyId },
      });
    }
    return key;
  }

  async executionReceiptKeys(deploymentId: string) {
    return this.#store.listExecutionReceiptKeys(deploymentId);
  }

  async topUp(customerId: string, raw: unknown, actorId: string): Promise<CreditMutationResult> {
    const body = objectValue(raw);
    const organizationId = requiredString(body, 'organizationId');
    if (!ID_PATTERN.test(organizationId)) throw invalidRequest('organizationId is invalid');
    const amount = positiveInteger(body.amount, 'amount');
    const key = idempotencyKey(body);
    const referenceId = requiredString(body, 'referenceId');
    const result = await this.#store.topUpCredits({
      transactionId: transactionId(),
      customerId,
      organizationId,
      amount,
      idempotencyKey: key,
      referenceId,
      description: optionalDescription(body, 'Credit top-up'),
      metadata: { channel: 'admin', organizationId },
      occurredAt: new Date(this.#now()),
    });
    if (!result.replayed) {
      await this.#store.appendAuditEvent({
        actorId,
        action: 'billing.topup',
        targetType: 'organization',
        targetId: organizationId,
        detail: { customerId, amount, transactionId: result.transaction.id, referenceId },
      });
    }
    return result;
  }

  async refund(customerId: string, raw: unknown, actorId: string): Promise<CreditMutationResult> {
    const body = objectValue(raw);
    const amount = positiveInteger(body.amount, 'amount');
    const key = idempotencyKey(body);
    const relatedTransactionId = requiredString(body, 'transactionId');
    const referenceId = requiredString(body, 'referenceId');
    const result = await this.#store.refundCredits({
      transactionId: transactionId(),
      customerId,
      relatedTransactionId,
      amount,
      idempotencyKey: key,
      referenceId,
      description: optionalDescription(body, 'Credit refund'),
      metadata: { channel: 'admin' },
      occurredAt: new Date(this.#now()),
    });
    if (!result) throw notFound('refundable credit transaction not found');
    if (!result.replayed) {
      await this.#store.appendAuditEvent({
        actorId,
        action: 'billing.refund',
        targetType: 'credit_transaction',
        targetId: relatedTransactionId,
        detail: { amount, refundTransactionId: result.transaction.id, referenceId },
      });
    }
    return result;
  }

  async createHold(raw: unknown, bearerToken: string): Promise<CreditHoldMutationResult> {
    const body = objectValue(raw);
    const authenticated = await this.#authenticateDeployment(body, bearerToken, true);
    await this.#releaseExpiredHolds(authenticated.customerId);
    const module = moduleValue(body);
    const units = positiveInteger(body.units, 'units', MAX_UNITS);
    const amount = await this.#price(authenticated.customerId, module, units);
    const expiresInSeconds = body.expiresInSeconds === undefined
      ? 900
      : positiveInteger(body.expiresInSeconds, 'expiresInSeconds', 3600);
    if (expiresInSeconds < 60) throw invalidRequest('expiresInSeconds must be at least 60');
    return this.#store.createCreditHold({
      holdId: holdId(),
      transactionId: transactionId(),
      customerId: authenticated.customerId,
      organizationId: authenticated.organizationId,
      deploymentId: authenticated.deploymentId,
      module,
      amount,
      idempotencyKey: idempotencyKey(body),
      expiresAt: new Date(this.#now() + expiresInSeconds * 1000),
      occurredAt: new Date(this.#now()),
    });
  }

  async captureHold(
    id: string,
    raw: unknown,
    bearerToken: string,
  ): Promise<CreditHoldMutationResult> {
    const body = objectValue(raw);
    const authenticated = await this.#authenticateDeployment(body, bearerToken, true);
    const hold = await this.#store.getCreditHold(id);
    if (!hold || hold.customerId !== authenticated.customerId) throw notFound('credit hold not found');
    if (
      hold.deploymentId !== authenticated.deploymentId ||
      hold.organizationId !== authenticated.organizationId
    ) throw unauthorized('credit hold does not belong to this deployment');
    const units = positiveInteger(body.units, 'units', MAX_UNITS);
    const amount = await this.#price(authenticated.customerId, hold.module, units);
    const result = await this.#store.captureCreditHold({
      transactionId: transactionId(),
      holdId: id,
      customerId: authenticated.customerId,
      amount,
      idempotencyKey: idempotencyKey(body),
      referenceId: requiredString(body, 'referenceId'),
      description: 'Captured metered usage',
      occurredAt: new Date(this.#now()),
    });
    if (!result) throw notFound('credit hold not found');
    return result;
  }

  async releaseHold(
    id: string,
    raw: unknown,
    bearerToken: string,
  ): Promise<CreditHoldMutationResult> {
    const body = objectValue(raw);
    const authenticated = await this.#authenticateDeployment(body, bearerToken, true);
    const hold = await this.#store.getCreditHold(id);
    if (!hold || hold.customerId !== authenticated.customerId) throw notFound('credit hold not found');
    if (
      hold.deploymentId !== authenticated.deploymentId ||
      hold.organizationId !== authenticated.organizationId
    ) {
      throw unauthorized('credit hold does not belong to this deployment');
    }
    const result = await this.#store.releaseCreditHold({
      transactionId: transactionId(),
      holdId: id,
      customerId: authenticated.customerId,
      idempotencyKey: idempotencyKey(body),
      reason: 'released',
      description: 'Released unused credit hold',
      occurredAt: new Date(this.#now()),
    });
    if (!result) throw notFound('credit hold not found');
    return result;
  }

  async consumeUsage(raw: unknown, bearerToken: string): Promise<CreditMutationResult> {
    if (!this.#allowLegacyUsageReports) {
      throw conflict('legacy usage reports are disabled; submit a signed execution receipt');
    }
    const body = objectValue(raw);
    const authenticated = await this.#authenticateDeployment(body, bearerToken, true);
    await this.#releaseExpiredHolds(authenticated.customerId);
    const module = moduleValue(body);
    const units = positiveInteger(body.units, 'units', MAX_UNITS);
    const rate = await this.#store.getBillingRate(authenticated.customerId, module);
    if (!rate) throw conflict(`billing rate is not configured for ${module}`);
    const amount = Math.ceil(units / rate.unitSize) * rate.creditsPerUnit;
    if (!Number.isSafeInteger(amount) || amount > MAX_CREDITS) {
      throw conflict('calculated charge exceeds the supported range');
    }
    return this.#store.consumeCredits({
      transactionId: transactionId(),
      customerId: authenticated.customerId,
      organizationId: authenticated.organizationId,
      deploymentId: authenticated.deploymentId,
      module,
      amount,
      idempotencyKey: idempotencyKey(body),
      referenceId: requiredString(body, 'referenceId'),
      description: 'Metered module usage',
      metadata: { units, unitSize: rate.unitSize, creditsPerUnit: rate.creditsPerUnit },
      occurredAt: new Date(this.#now()),
    });
  }

  async consumeExecutionReceipt(
    raw: unknown,
    bearerToken: string,
  ): Promise<ExecutionReceiptMutationResult> {
    const body = objectValue(raw);
    exactFields(body, RECEIPT_REQUEST_FIELDS, 'execution receipt request');
    const now = this.#now();
    const envelope = normalizeExecutionReceiptEnvelope(body.envelope, now);
    const authenticated = await this.#authenticateDeployment({
      licenseId: body.licenseId,
      machineFingerprint: body.machineFingerprint,
      deploymentId: envelope.receipt.deploymentId,
      organizationId: envelope.receipt.organizationId,
    }, bearerToken, true);
    await this.#releaseExpiredHolds(authenticated.customerId);
    const key = await this.#store.getExecutionReceiptKey(
      authenticated.deploymentId,
      envelope.signingKeyId,
    );
    if (!key) throw unauthorized('execution receipt signing key is unknown');
    verifyExecutionReceipt(envelope, key);
    const amount = await this.#price(
      authenticated.customerId,
      envelope.receipt.moduleId,
      envelope.receipt.units,
    );
    const result = await this.#store.ingestExecutionReceipt({
      transactionId: transactionId(),
      customerId: authenticated.customerId,
      amount,
      envelope,
      metadata: {
        evidenceTrust: 'deployment_signed_receipt_v2',
        executionReceiptId: envelope.receipt.receiptId,
        receiptVerificationStatus: 'verified',
        signingKeyId: envelope.signingKeyId,
        sequence: envelope.receipt.sequence,
        policyVersion: envelope.receipt.policyVersion,
        units: envelope.receipt.units,
        model: envelope.receipt.model,
      },
      receivedAt: new Date(now),
    });
    if (!result.replayed) {
      await this.#store.appendAuditEvent({
        actorId: `deployment:${authenticated.deploymentId}`,
        action: 'billing.execution_receipt.consumed',
        targetType: 'execution_receipt',
        targetId: result.receipt.receiptId,
        detail: {
          customerId: authenticated.customerId,
          organizationId: authenticated.organizationId,
          deploymentId: authenticated.deploymentId,
          taskId: result.receipt.taskId,
          module: result.receipt.moduleId,
          units: result.receipt.units,
          sequence: result.receipt.sequence,
          transactionId: result.transaction.id,
        },
      });
    }
    return result;
  }

  async transactions(customerId: string, raw: Record<string, unknown>) {
    const { from, to } = parseRange(raw.from, raw.to);
    const organizationId = raw.organizationId === undefined
      ? undefined
      : requiredString(raw, 'organizationId');
    const module = raw.module === undefined ? undefined : moduleValue(raw);
    const limit = raw.limit === undefined ? 500 : positiveInteger(raw.limit, 'limit', 10_000);
    return this.#store.listCreditTransactions({
      customerId, from, to, organizationId, module, limit,
    });
  }

  async executionReceipts(customerId: string, raw: Record<string, unknown>) {
    const { from, to } = parseRange(raw.from, raw.to);
    const organizationId = raw.organizationId === undefined
      ? undefined
      : requiredString(raw, 'organizationId');
    const deploymentId = raw.deploymentId === undefined
      ? undefined
      : requiredString(raw, 'deploymentId');
    const module = raw.module === undefined ? undefined : moduleValue(raw);
    const limit = raw.limit === undefined ? 500 : positiveInteger(raw.limit, 'limit', 10_000);
    return this.#store.listExecutionReceipts({
      customerId, from, to, organizationId, deploymentId, module, limit,
    });
  }

  async executionReceipt(customerId: string, receiptId: string): Promise<ExecutionReceiptRecord> {
    const receipt = await this.#store.getExecutionReceipt(receiptId);
    if (!receipt || receipt.customerId !== customerId) throw notFound('execution receipt not found');
    return receipt;
  }

  async statement(customerId: string, raw: Record<string, unknown>): Promise<CreditStatement> {
    await this.#releaseExpiredHolds(customerId);
    const { from, to } = parseRange(raw.from, raw.to);
    const statement = await this.#store.getCreditStatement({ customerId, from, to });
    if (!statement) throw notFound('credit account not found');
    return statement;
  }

  async exportCsv(customerId: string, raw: Record<string, unknown>): Promise<string> {
    const transactions = await this.transactions(customerId, { ...raw, limit: 10_000 });
    const header = [
      'transactionId', 'occurredAt', 'customerId', 'organizationId', 'deploymentId',
      'module', 'type', 'billedAmount', 'availableDelta', 'frozenDelta',
      'availableAfter', 'frozenAfter', 'idempotencyKey', 'referenceId',
      'relatedTransactionId', 'description', 'executionReceiptId',
      'receiptVerificationStatus',
    ];
    const rows = transactions.map((item: CreditTransactionRecord) => [
      item.id, item.occurredAt.toISOString(), item.customerId, item.organizationId,
      item.deploymentId, item.module, item.type, item.billedAmount, item.availableDelta,
      item.frozenDelta, item.availableAfter, item.frozenAfter, item.idempotencyKey,
      item.referenceId, item.relatedTransactionId, item.description,
      item.metadata.executionReceiptId, item.metadata.receiptVerificationStatus,
    ]);
    return `\uFEFF${[header, ...rows].map((row) => row.map(csvCell).join(',')).join('\r\n')}\r\n`;
  }

  async #price(customerId: string, module: OttoBillingModule, units: number): Promise<number> {
    const rate = await this.#store.getBillingRate(customerId, module);
    if (!rate) throw conflict(`billing rate is not configured for ${module}`);
    const amount = Math.ceil(units / rate.unitSize) * rate.creditsPerUnit;
    if (!Number.isSafeInteger(amount) || amount > MAX_CREDITS) {
      throw conflict('calculated charge exceeds the supported range');
    }
    return amount;
  }

  async #releaseExpiredHolds(customerId: string): Promise<void> {
    const now = new Date(this.#now());
    const holds = await this.#store.listExpiredCreditHolds({
      customerId,
      expiredBefore: now,
      limit: 100,
    });
    for (const hold of holds) {
      try {
        await this.#store.releaseCreditHold({
          transactionId: transactionId(),
          holdId: hold.id,
          customerId,
          idempotencyKey: `expiry:${hold.id}`,
          reason: 'expired',
          description: 'Expired credit hold released automatically',
          occurredAt: now,
        });
      } catch (error) {
        if (!(error instanceof Error) || !error.message.includes('no longer active')) throw error;
      }
    }
  }

  async #authenticateDeployment(
    body: Record<string, unknown>,
    bearerToken: string,
    allowDeploymentOrganization = false,
  ): Promise<AuthenticatedDeployment> {
    const licenseId = requiredString(body, 'licenseId');
    const deploymentId = requiredString(body, 'deploymentId');
    const organizationId = requiredString(body, 'organizationId');
    if (!ID_PATTERN.test(organizationId)) throw invalidRequest('organizationId is invalid');
    const machineFingerprint = requiredString(body, 'machineFingerprint', 64).toLowerCase();
    if (!FINGERPRINT_PATTERN.test(machineFingerprint)) {
      throw invalidRequest('machineFingerprint is invalid');
    }
    const license = await this.#store.getLicense(licenseId);
    if (!license) throw unauthorized('License is invalid');
    if (license.offline) throw unauthorized('offline License cannot use online billing');
    if (license.revokedAtMs !== null || this.#now() >= license.expiresAtMs + license.gracePeriodMs) {
      throw unauthorized('License is revoked or expired');
    }
    if (
      license.deploymentId !== deploymentId ||
      (!allowDeploymentOrganization && license.organizationId !== organizationId) ||
      license.machineFingerprint !== machineFingerprint
    ) throw unauthorized('billing request binding is invalid');
    const expected = this.#tokens.issue({
      purpose: 'lease',
      licenseId,
      deploymentId,
      version: license.tokenVersion,
    });
    if (!this.#tokens.matches(bearerToken, expected)) throw unauthorized('billing token is invalid');
    const deployment = await this.#store.getDeployment(deploymentId);
    if (!deployment || deployment.status !== 'active') throw unauthorized('deployment is inactive');
    return { customerId: deployment.customerId, license, organizationId, deploymentId };
  }
}

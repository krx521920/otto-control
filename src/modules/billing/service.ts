import { randomUUID } from 'node:crypto';

import type {
  CreditHoldMutationResult,
  CreditMutationResult,
  CreditStatement,
  CreditTransactionRecord,
  OttoBillingModule,
} from '../../contracts/billing.js';
import { isOttoBillingModule } from '../../contracts/billing.js';
import { conflict, invalidRequest, notFound, unauthorized } from '../../errors.js';
import type { ControlStore, LicenseRecord } from '../../storage/control-store.js';
import type { ControlTokenIssuer } from '../commercial-control/token-issuer.js';

const ID_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,159}$/u;
const FINGERPRINT_PATTERN = /^[a-f0-9]{64}$/u;
const MAX_CREDITS = 9_000_000_000_000_000;
const MAX_UNITS = 9_000_000_000_000;

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
}

export class BillingService {
  readonly #store: ControlStore;
  readonly #tokens: ControlTokenIssuer;
  readonly #now: () => number;

  constructor(options: BillingServiceOptions) {
    this.#store = options.store;
    this.#tokens = options.tokenIssuer;
    this.#now = options.now ?? Date.now;
  }

  async account(customerId: string) {
    await this.#releaseExpiredHolds(customerId);
    const account = await this.#store.getCreditAccount(customerId);
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

  async topUp(customerId: string, raw: unknown, actorId: string): Promise<CreditMutationResult> {
    const body = objectValue(raw);
    const amount = positiveInteger(body.amount, 'amount');
    const key = idempotencyKey(body);
    const referenceId = requiredString(body, 'referenceId');
    const result = await this.#store.topUpCredits({
      transactionId: transactionId(),
      customerId,
      amount,
      idempotencyKey: key,
      referenceId,
      description: optionalDescription(body, 'Credit top-up'),
      metadata: { channel: 'admin' },
      occurredAt: new Date(this.#now()),
    });
    if (!result.replayed) {
      await this.#store.appendAuditEvent({
        actorId,
        action: 'billing.topup',
        targetType: 'customer',
        targetId: customerId,
        detail: { amount, transactionId: result.transaction.id, referenceId },
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
    const authenticated = await this.#authenticateDeployment(body, bearerToken);
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
    const authenticated = await this.#authenticateDeployment(body, bearerToken);
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
    const authenticated = await this.#authenticateDeployment(body, bearerToken);
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
    const body = objectValue(raw);
    const authenticated = await this.#authenticateDeployment(body, bearerToken);
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
      'relatedTransactionId', 'description',
    ];
    const rows = transactions.map((item: CreditTransactionRecord) => [
      item.id, item.occurredAt.toISOString(), item.customerId, item.organizationId,
      item.deploymentId, item.module, item.type, item.billedAmount, item.availableDelta,
      item.frozenDelta, item.availableAfter, item.frozenAfter, item.idempotencyKey,
      item.referenceId, item.relatedTransactionId, item.description,
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
  ): Promise<AuthenticatedDeployment> {
    const licenseId = requiredString(body, 'licenseId');
    const deploymentId = requiredString(body, 'deploymentId');
    const organizationId = requiredString(body, 'organizationId');
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
      license.deploymentId !== deploymentId || license.organizationId !== organizationId ||
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

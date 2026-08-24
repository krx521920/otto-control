import { createHash, randomUUID } from 'node:crypto';

import type {
  CreditHoldMutationResult,
  CreditMutationResult,
  CreditStatement,
  CreditTransactionRecord,
  ExecutionReceiptHoldMutationResult,
  ExecutionReceiptMutationResult,
  ExecutionReceiptRecord,
  EdgeBillingAggregationEventRecord,
  OttoBillingModule,
} from '../../contracts/billing.js';
import { isOttoBillingModule } from '../../contracts/billing.js';
import {
  ControlPlaneError,
  conflict,
  creditHoldUnavailable,
  invalidRequest,
  notFound,
  unauthorized,
} from '../../errors.js';
import { canonicalJson } from '../../crypto/signed-envelope.js';
import type { ControlStore } from '../../storage/control-store.js';
import type { ControlTokenIssuer } from '../commercial-control/token-issuer.js';
import {
  authenticateOnlineDeployment,
  type AuthenticatedOnlineDeployment,
} from '../commercial-control/deployment-authentication.js';
import {
  normalizeExecutionReceiptEnvelope,
  normalizeExecutionReceiptKeyBootstrap,
  normalizeExecutionReceiptPublicKey,
  verifyExecutionReceipt,
} from './execution-receipt.js';

const ID_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,159}$/u;
const MAX_CREDITS = 9_000_000_000_000_000;
const MAX_UNITS = 9_000_000_000_000;
const MAX_RECEIPT_KEY_LIFETIME_MS = 400 * 24 * 60 * 60 * 1000;
const MAX_HOLD_LIFETIME_SECONDS = 4 * 60 * 60;
const RECEIPT_REQUEST_FIELDS = new Set(['licenseId', 'machineFingerprint', 'envelope']);
const RECEIPT_STATUS_REQUEST_FIELDS = new Set([
  'licenseId', 'machineFingerprint', 'deploymentId', 'organizationId', 'receiptId',
]);
const EXECUTION_RECEIPT_ID = /^exec_[a-f0-9]{32}$/u;
const EDGE_NODE_ID = /^edge_[a-f0-9]{32}$/u;
const EDGE_EVENT_ID = /^edgeevt_[a-f0-9]{32}$/u;
const HOLD_ID = /^hold_[a-f0-9]{32}$/u;
const EDGE_EVENT_FIELDS = new Set([
  'eventId', 'nodeId', 'nodeSequence', 'holdId', 'licenseId', 'deploymentId',
  'organizationId', 'machineFingerprint', 'envelope',
]);
const MAX_EDGE_AGGREGATION_ATTEMPTS = 8;
const EDGE_RETRY_INTERVAL_MS = 10_000;

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
  #edgeRetryTimer?: ReturnType<typeof setInterval>;

  constructor(options: BillingServiceOptions) {
    this.#store = options.store;
    this.#tokens = options.tokenIssuer;
    this.#now = options.now ?? Date.now;
    this.#allowLegacyUsageReports = options.allowLegacyUsageReports ?? true;
  }

  start(onError: (error: unknown) => void = () => undefined): void {
    if (this.#edgeRetryTimer) return;
    this.#edgeRetryTimer = setInterval(() => {
      void this.reconcileEdgeBillingEvents(100).catch(onError);
    }, EDGE_RETRY_INTERVAL_MS);
    this.#edgeRetryTimer.unref?.();
  }

  close(): void {
    if (this.#edgeRetryTimer) clearInterval(this.#edgeRetryTimer);
    this.#edgeRetryTimer = undefined;
  }

  async registerEdgeBillingNode(deploymentId: string, raw: unknown, actorId: string) {
    const body = objectValue(raw);
    exactFields(body, new Set(['nodeId', 'signingKeyId']), 'edge billing node');
    const nodeId = requiredString(body, 'nodeId');
    const signingKeyId = requiredString(body, 'signingKeyId').toLowerCase();
    if (!EDGE_NODE_ID.test(nodeId) || !/^[a-f0-9]{16}$/u.test(signingKeyId)) {
      throw invalidRequest('edge billing node identity is invalid');
    }
    const deployment = await this.#store.getDeployment(deploymentId);
    if (!deployment) throw notFound('deployment not found');
    const key = await this.#store.getExecutionReceiptKey(deploymentId, signingKeyId);
    if (!key || key.status !== 'active') {
      throw conflict('edge billing node requires an active dedicated receipt key');
    }
    const existing = await this.#store.getEdgeBillingNode(nodeId);
    const node = await this.#store.registerEdgeBillingNode({
      nodeId,
      deploymentId,
      organizationId: deployment.organizationId,
      signingKeyId,
      createdAt: new Date(this.#now()),
    });
    if (!existing) {
      await this.#store.appendAuditEvent({
        actorId,
        action: 'billing.edge_node.registered',
        targetType: 'edge_billing_node',
        targetId: nodeId,
        detail: { deploymentId, organizationId: node.organizationId, signingKeyId },
      });
    }
    return node;
  }

  async revokeEdgeBillingNode(deploymentId: string, nodeId: string, actorId: string) {
    if (!EDGE_NODE_ID.test(nodeId)) throw invalidRequest('edge billing node id is invalid');
    const existing = await this.#store.getEdgeBillingNode(nodeId);
    if (!existing || existing.deploymentId !== deploymentId) {
      throw notFound('edge billing node not found');
    }
    const node = await this.#store.revokeEdgeBillingNode({
      nodeId, deploymentId, revokedAt: new Date(this.#now()),
    });
    if (!node) throw notFound('edge billing node not found');
    if (existing.status === 'active') {
      await this.#store.appendAuditEvent({
        actorId,
        action: 'billing.edge_node.revoked',
        targetType: 'edge_billing_node',
        targetId: nodeId,
        detail: { deploymentId, signingKeyId: node.signingKeyId },
      });
    }
    return node;
  }

  async edgeBillingNodes(deploymentId: string) {
    return this.#store.listEdgeBillingNodes(deploymentId);
  }

  async submitEdgeBillingEvent(raw: unknown, bearerToken: string) {
    const body = objectValue(raw);
    exactFields(body, EDGE_EVENT_FIELDS, 'edge billing event');
    const eventId = requiredString(body, 'eventId');
    const nodeId = requiredString(body, 'nodeId');
    const nodeSequence = positiveInteger(body.nodeSequence, 'nodeSequence', Number.MAX_SAFE_INTEGER);
    const holdIdValue = body.holdId === undefined || body.holdId === null
      ? null
      : requiredString(body, 'holdId');
    if (!EDGE_EVENT_ID.test(eventId) || !EDGE_NODE_ID.test(nodeId)
      || (holdIdValue && !HOLD_ID.test(holdIdValue))) {
      throw invalidRequest('edge billing event identity is invalid');
    }
    const now = this.#now();
    const envelope = normalizeExecutionReceiptEnvelope(body.envelope, now);
    if (envelope.receipt.sequence !== nodeSequence) {
      throw invalidRequest('nodeSequence must equal the signed receipt sequence');
    }
    const authenticated = await this.#authenticateDeployment({
      licenseId: body.licenseId,
      deploymentId: body.deploymentId,
      organizationId: body.organizationId,
      machineFingerprint: body.machineFingerprint,
    }, bearerToken, true);
    if (envelope.receipt.deploymentId !== authenticated.deploymentId
      || envelope.receipt.organizationId !== authenticated.organizationId) {
      throw unauthorized('edge billing receipt does not belong to this tenant');
    }
    const node = await this.#store.getEdgeBillingNode(nodeId);
    if (!node || node.status !== 'active'
      || node.deploymentId !== authenticated.deploymentId
      || node.organizationId !== authenticated.organizationId
      || node.signingKeyId !== envelope.signingKeyId) {
      throw unauthorized('edge billing node is not active for this tenant');
    }
    const key = await this.#store.getExecutionReceiptKey(node.deploymentId, node.signingKeyId);
    if (!key) throw unauthorized('edge billing node signing key is unknown');
    verifyExecutionReceipt(envelope, key);
    const evidence = { eventId, nodeId, nodeSequence, holdId: holdIdValue, envelope };
    const result = await this.#store.enqueueEdgeBillingEvent({
      ...evidence,
      customerId: authenticated.customerId,
      deploymentId: authenticated.deploymentId,
      organizationId: authenticated.organizationId,
      payloadSha256: createHash('sha256').update(canonicalJson(evidence)).digest('hex'),
      receivedAt: new Date(now),
    });
    await this.reconcileEdgeBillingEvents(100, nodeId);
    return {
      event: this.#eventWithoutEnvelope(result.event),
      replayed: result.replayed,
      aggregation: await this.#store.getEdgeBillingAggregationStatus(node.deploymentId),
    };
  }

  async reconcileEdgeBillingEvents(limit = 100, nodeId?: string): Promise<number> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1_000) {
      throw invalidRequest('edge billing retry limit is invalid');
    }
    let reconciled = 0;
    for (let index = 0; index < limit; index += 1) {
      const ready = await this.#store.listReadyEdgeBillingEvents({
        now: new Date(this.#now()), limit: 1, nodeId,
      });
      const event = ready[0];
      if (!event) break;
      try {
        await this.#reconcileEdgeBillingEvent(event);
        await this.#store.markEdgeBillingEventReconciled({
          eventId: event.eventId, reconciledAt: new Date(this.#now()),
        });
        reconciled += 1;
      } catch (error) {
        const attempts = event.attempts + 1;
        const now = this.#now();
        const errorCode = error instanceof ControlPlaneError ? error.code : 'AGGREGATION_FAILED';
        await this.#store.markEdgeBillingEventFailed({
          eventId: event.eventId,
          errorCode,
          deadLetter: attempts >= MAX_EDGE_AGGREGATION_ATTEMPTS,
          nextAttemptAt: new Date(now + Math.min(300_000, 1000 * (2 ** attempts))),
          updatedAt: new Date(now),
        });
        break;
      }
    }
    return reconciled;
  }

  async retryEdgeBillingDeadLetters(limit = 100) {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1_000) {
      throw invalidRequest('edge billing retry limit is invalid');
    }
    const requeued = await this.#store.retryEdgeBillingDeadLetters({
      now: new Date(this.#now()), limit,
    });
    const reconciled = await this.reconcileEdgeBillingEvents(limit);
    return { requeued, reconciled };
  }

  async edgeBillingAggregationStatus(deploymentId?: string) {
    return this.#store.getEdgeBillingAggregationStatus(deploymentId);
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
      const boundNodes = (await this.#store.listEdgeBillingNodes(deploymentId))
        .filter((node) => node.signingKeyId === normalizedKeyId && node.status === 'active');
      for (const node of boundNodes) {
        await this.#store.revokeEdgeBillingNode({
          nodeId: node.nodeId,
          deploymentId,
          revokedAt: new Date(this.#now()),
        });
      }
      await this.#store.appendAuditEvent({
        actorId,
        action: 'billing.execution_receipt_key.revoked',
        targetType: 'deployment',
        targetId: deploymentId,
        detail: { keyId: key.keyId, revokedEdgeNodeIds: boundNodes.map((node) => node.nodeId) },
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
      : positiveInteger(
          body.expiresInSeconds,
          'expiresInSeconds',
          MAX_HOLD_LIFETIME_SECONDS,
        );
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
  async executionReceiptStatus(raw: unknown, bearerToken: string) {
    const body = objectValue(raw);
    exactFields(body, RECEIPT_STATUS_REQUEST_FIELDS, 'execution receipt status request');
    const receiptId = requiredString(body, 'receiptId');
    if (!EXECUTION_RECEIPT_ID.test(receiptId)) {
      throw invalidRequest('receiptId is invalid');
    }
    const authenticated = await this.#authenticateDeployment(
      body,
      bearerToken,
      true,
    );
    const receipt = await this.#store.getExecutionReceipt(receiptId);
    if (
      !receipt ||
      receipt.deploymentId !== authenticated.deploymentId ||
      receipt.organizationId !== authenticated.organizationId
    ) {
      return { status: 'missing' as const, receiptId };
    }
    return { status: 'consumed' as const, receipt };
  }

  async settleHoldWithExecutionReceipt(
    id: string,
    raw: unknown,
    bearerToken: string,
  ): Promise<ExecutionReceiptHoldMutationResult> {
    const body = objectValue(raw);
    exactFields(body, RECEIPT_REQUEST_FIELDS, 'execution receipt settlement request');
    const now = this.#now();
    const envelope = normalizeExecutionReceiptEnvelope(body.envelope, now);
    const authenticated = await this.#authenticateDeployment({
      licenseId: body.licenseId,
      machineFingerprint: body.machineFingerprint,
      deploymentId: envelope.receipt.deploymentId,
      organizationId: envelope.receipt.organizationId,
    }, bearerToken, true);
    await this.#releaseExpiredHolds(authenticated.customerId);
    const hold = await this.#store.getCreditHold(id);
    if (!hold || hold.customerId !== authenticated.customerId) {
      throw notFound('credit hold not found');
    }
    if (hold.status === 'released' || hold.status === 'expired') {
      throw creditHoldUnavailable('credit hold is no longer active');
    }
    if (hold.deploymentId !== authenticated.deploymentId
      || hold.organizationId !== authenticated.organizationId) {
      throw unauthorized('credit hold does not belong to this deployment');
    }
    if (hold.module !== envelope.receipt.moduleId) {
      throw conflict('execution receipt module does not match credit hold');
    }
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
    const result = await this.#store.settleCreditHoldWithExecutionReceipt({
      transactionId: transactionId(),
      holdId: id,
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
    if (!result) throw notFound('credit hold not found');
    if (!result.replayed) {
      await this.#store.appendAuditEvent({
        actorId: `deployment:${authenticated.deploymentId}`,
        action: 'billing.execution_receipt.hold_settled',
        targetType: 'execution_receipt',
        targetId: result.receipt.receiptId,
        detail: {
          customerId: authenticated.customerId,
          organizationId: authenticated.organizationId,
          deploymentId: authenticated.deploymentId,
          holdId: result.hold.id,
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

  async #reconcileEdgeBillingEvent(event: EdgeBillingAggregationEventRecord): Promise<void> {
    const node = await this.#store.getEdgeBillingNode(event.nodeId);
    if (!node || node.status !== 'active' || node.deploymentId !== event.deploymentId
      || node.organizationId !== event.organizationId
      || node.signingKeyId !== event.envelope.signingKeyId) {
      throw conflict('edge billing node binding is inactive');
    }
    const key = await this.#store.getExecutionReceiptKey(node.deploymentId, node.signingKeyId);
    if (!key) throw conflict('edge billing node signing key is unknown');
    verifyExecutionReceipt(event.envelope, key);
    const amount = await this.#price(
      event.customerId,
      event.envelope.receipt.moduleId,
      event.envelope.receipt.units,
    );
    const common = {
      transactionId: transactionId(),
      customerId: event.customerId,
      amount,
      envelope: event.envelope,
      metadata: {
        evidenceTrust: 'edge_node_signed_receipt_v2',
        edgeNodeId: event.nodeId,
        edgeEventId: event.eventId,
        nodeSequence: event.nodeSequence,
        executionReceiptId: event.envelope.receipt.receiptId,
        receiptVerificationStatus: 'verified',
        signingKeyId: event.envelope.signingKeyId,
        policyVersion: event.envelope.receipt.policyVersion,
        units: event.envelope.receipt.units,
        model: event.envelope.receipt.model,
      },
      receivedAt: event.receivedAt,
      edgeNodeId: event.nodeId,
    };
    let result;
    if (event.holdId) {
      await this.#releaseExpiredHolds(event.customerId);
      const hold = await this.#store.getCreditHold(event.holdId);
      if (hold && hold.status === 'active' && (
        hold.customerId !== event.customerId
        || hold.deploymentId !== event.deploymentId
        || hold.organizationId !== event.organizationId
        || hold.module !== event.envelope.receipt.moduleId
      )) throw conflict('edge billing event does not match its credit hold');
      try {
        result = hold?.status === 'active'
          ? await this.#store.settleCreditHoldWithExecutionReceipt({
              ...common,
              holdId: event.holdId,
            })
          : await this.#store.ingestExecutionReceipt(common);
      } catch (error) {
        const current = await this.#store.getCreditHold(event.holdId);
        if (!(error instanceof ControlPlaneError) || current?.status === 'active') throw error;
        result = await this.#store.ingestExecutionReceipt(common);
      }
      if (!result) result = await this.#store.ingestExecutionReceipt(common);
    } else {
      result = await this.#store.ingestExecutionReceipt(common);
    }
    if (!result.replayed) {
      await this.#store.appendAuditEvent({
        actorId: `edge-node:${event.nodeId}`,
        action: 'billing.edge_event.reconciled',
        targetType: 'edge_billing_event',
        targetId: event.eventId,
        detail: {
          deploymentId: event.deploymentId,
          organizationId: event.organizationId,
          nodeSequence: event.nodeSequence,
          receiptId: result.receipt.receiptId,
          transactionId: result.transaction.id,
        },
      });
    }
  }

  #eventWithoutEnvelope(event: EdgeBillingAggregationEventRecord) {
    const { envelope: _envelope, ...safe } = event;
    void _envelope;
    return safe;
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
  ): Promise<AuthenticatedOnlineDeployment> {
    const licenseId = requiredString(body, 'licenseId');
    const deploymentId = requiredString(body, 'deploymentId');
    const organizationId = requiredString(body, 'organizationId');
    const machineFingerprint = requiredString(body, 'machineFingerprint', 64).toLowerCase();
    return authenticateOnlineDeployment({
      store: this.#store,
      tokens: this.#tokens,
      binding: { licenseId, deploymentId, organizationId, machineFingerprint },
      bearerToken,
      nowMs: this.#now(),
      purpose: 'billing',
      allowDeploymentOrganization,
    });
  }
}

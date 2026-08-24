import { describe, expect, it, vi } from 'vitest';

import type {
  EdgeBillingCoordinator,
  EdgeBillingOutboxAction,
  PreparedEdgeBillingDelivery,
} from '../src/edge-gateway/billing-coordinator.js';
import { PostgresEdgeBillingOutboxWorker } from '../src/edge-gateway/postgres-billing-outbox-worker.js';
import type { PostgresEdgeRequestLedger } from '../src/edge-gateway/postgres-request-ledger.js';

const identity = {
  requestId: 'request_shared_outbox',
  tokenId: 'token_one',
  deploymentId: 'deployment_one',
  organizationId: 'organization_one',
  subjectId: 'subject_one',
  endpoint: 'responses' as const,
  publicModel: 'model-one',
  policyVersion: 'policy-one',
};

const settlement: EdgeBillingOutboxAction = {
  type: 'settle',
  request: {
    ...identity,
    reservation: { reservationId: `hold_${'a'.repeat(32)}` },
    routeId: 'route_one',
    usage: { inputTokens: 2, outputTokens: 3, totalTokens: 5 },
    occurredAtMs: 1_800_000_000_000,
  },
};

const prepared: PreparedEdgeBillingDelivery = {
  version: 1,
  action: 'uncertain',
  requestId: identity.requestId,
  reservationId: `hold_${'a'.repeat(32)}`,
  routeId: 'route_one',
  reason: 'usage_unavailable',
  occurredAtMs: 1_800_000_000_000,
};

function fixture(input: { deliveryError?: Error; retryError?: Error } = {}) {
  const prepareSettlementDelivery = vi.fn(async () => prepared);
  const prepareReleaseDelivery = vi.fn(() => prepared);
  const prepareUncertainDelivery = vi.fn(() => prepared);
  const deliverPrepared = vi.fn(async () => {
    if (input.deliveryError) throw input.deliveryError;
  });
  const claimBillingActions = vi.fn(async (options: {
    prepare(action: unknown): Promise<unknown>;
  }) => {
    const generated = await options.prepare({ action: settlement, sequence: 7 });
    return [{
      requestId: identity.requestId,
      action: settlement,
      actionHash: 'a'.repeat(64),
      preparedDelivery: generated,
      preparedHash: 'b'.repeat(64),
      sequenceScope: 'edge_scope',
      sequence: 7,
      claimOwner: 'worker_one',
      claimUntilMs: 1_800_000_030_000,
      claimEpoch: 3,
      attempts: 1,
    }];
  });
  const ackBillingAction = vi.fn(async () => undefined);
  const retryBillingAction = vi.fn(async () => {
    if (input.retryError) throw input.retryError;
    return { requestId: identity.requestId, attempts: 1, nextAttemptAtMs: 1_800_000_001_000 };
  });
  const coordinator = {
    reserve: vi.fn(),
    settle: vi.fn(),
    release: vi.fn(),
    markUncertain: vi.fn(),
    prepareSettlementDelivery,
    prepareReleaseDelivery,
    prepareUncertainDelivery,
    deliverPrepared,
  } as unknown as EdgeBillingCoordinator;
  const ledger = {
    claimBillingActions,
    ackBillingAction,
    retryBillingAction,
  } as unknown as PostgresEdgeRequestLedger;
  const onError = vi.fn();
  const worker = new PostgresEdgeBillingOutboxWorker({
    ledger,
    coordinator,
    sequenceScope: 'edge_scope',
    onError,
  });
  return {
    ackBillingAction,
    claimBillingActions,
    deliverPrepared,
    onError,
    prepareSettlementDelivery,
    retryBillingAction,
    worker,
  };
}

describe('PostgreSQL edge billing outbox worker', () => {
  it('prepares once, delivers the stored payload, and acknowledges with its fence', async () => {
    const values = fixture();

    await expect(values.worker.flush()).resolves.toBe(1);

    expect(values.prepareSettlementDelivery).toHaveBeenCalledWith(
      settlement.request,
      7,
    );
    expect(values.deliverPrepared).toHaveBeenCalledWith(prepared);
    expect(values.ackBillingAction).toHaveBeenCalledWith({
      requestId: identity.requestId,
      claimEpoch: 3,
    });
    expect(values.retryBillingAction).not.toHaveBeenCalled();
    expect(values.worker.snapshot()).toMatchObject({
      state: 'ready',
      delivered: 1,
      retried: 0,
    });
  });

  it('requeues a failed delivery without exposing the upstream error text', async () => {
    const values = fixture({ deliveryError: new Error('secret provider detail') });

    await expect(values.worker.flush()).resolves.toBe(0);

    expect(values.ackBillingAction).not.toHaveBeenCalled();
    expect(values.retryBillingAction).toHaveBeenCalledWith({
      requestId: identity.requestId,
      claimEpoch: 3,
      errorCode: 'EDGE_BILLING_DELIVERY_FAILED',
    });
    expect(values.worker.snapshot()).toMatchObject({
      state: 'degraded',
      delivered: 0,
      retried: 1,
      lastErrorCode: 'EDGE_BILLING_DELIVERY_FAILED',
    });
  });

  it('does not hide a fencing failure while trying to requeue', async () => {
    const retryError = new Error('claim fence changed');
    const values = fixture({
      deliveryError: new Error('network unavailable'),
      retryError,
    });

    await expect(values.worker.flush()).resolves.toBe(0);
    expect(values.onError).toHaveBeenCalledWith(retryError);
    expect(values.onError).toHaveBeenCalledTimes(2);
  });

  it('coalesces concurrent flush requests so a batch is not claimed twice', async () => {
    const values = fixture();

    await Promise.all([values.worker.flush(), values.worker.flush(), values.worker.flush()]);

    expect(values.claimBillingActions).toHaveBeenCalledOnce();
    expect(values.deliverPrepared).toHaveBeenCalledOnce();
  });

  it('refuses a coordinator that cannot produce stable shared deliveries', () => {
    const ledger = {} as PostgresEdgeRequestLedger;
    const coordinator = {
      reserve: vi.fn(),
      settle: vi.fn(),
      release: vi.fn(),
      markUncertain: vi.fn(),
    } as unknown as EdgeBillingCoordinator;

    expect(() => new PostgresEdgeBillingOutboxWorker({
      ledger,
      coordinator,
      sequenceScope: 'edge_scope',
    })).toThrow('does not support the shared outbox');
  });
});

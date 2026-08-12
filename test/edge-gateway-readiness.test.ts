import { describe, expect, it, vi } from 'vitest';

import type { EdgeBillingCoordinator } from '../src/edge-gateway/billing-coordinator.js';
import { InMemoryEdgeGatewayLifecycle } from '../src/edge-gateway/lifecycle.js';
import { createEdgeGatewayReadinessProbe } from '../src/edge-gateway/server.js';

function billing(state: 'ready' | 'degraded' | 'unavailable'): EdgeBillingCoordinator {
  return {
    reserve: vi.fn(),
    settle: vi.fn(),
    release: vi.fn(),
    markUncertain: vi.fn(),
    operationalStatus: vi.fn(() => ({
      state,
      activeReservations: 0,
      recoveredReservations: 0,
      pendingSettlements: state === 'unavailable' ? 1 : 0,
      pendingReleases: 0,
      uncertainReservations: state === 'degraded' ? 1 : 0,
      journalEntries: 1,
      lastReceiptSequence: 0,
    })),
  };
}

describe('Edge Gateway readiness composition', () => {
  it('requires both policy and shared limiter health before reporting billing state', async () => {
    const policySource = { load: vi.fn(async () => ({})) };
    const healthCheck = vi.fn(async () => undefined);
    for (const state of ['ready', 'degraded', 'unavailable'] as const) {
      const probe = createEdgeGatewayReadinessProbe({
        policySource,
        rateLimiter: { consume: vi.fn(), healthCheck },
        billingCoordinator: billing(state),
      });
      await expect(probe.check()).resolves.toBe(state);
    }
    expect(policySource.load).toHaveBeenCalledTimes(3);
    expect(healthCheck).toHaveBeenCalledTimes(3);
  });

  it('fails closed when policy or Redis health cannot be established', async () => {
    const billingCoordinator = billing('ready');
    const policyFailure = createEdgeGatewayReadinessProbe({
      policySource: { load: async () => { throw new Error('expired policy'); } },
      rateLimiter: { consume: vi.fn(), healthCheck: vi.fn() },
      billingCoordinator,
    });
    await expect(policyFailure.check()).resolves.toBe('unavailable');
    expect(billingCoordinator.operationalStatus).not.toHaveBeenCalled();

    const redisFailure = createEdgeGatewayReadinessProbe({
      policySource: { load: async () => ({}) },
      rateLimiter: {
        consume: vi.fn(),
        healthCheck: async () => { throw new Error('private Redis endpoint'); },
      },
      billingCoordinator,
    });
    await expect(redisFailure.check()).resolves.toBe('unavailable');
    expect(billingCoordinator.operationalStatus).not.toHaveBeenCalled();
  });

  it('supports development mode without Redis or Control billing probes', async () => {
    const probe = createEdgeGatewayReadinessProbe({
      policySource: { load: async () => ({}) },
      rateLimiter: { consume: vi.fn() },
    });
    await expect(probe.check()).resolves.toBe('ready');
  });

  it('fails readiness immediately during drain without contacting dependencies', async () => {
    const lifecycle = new InMemoryEdgeGatewayLifecycle({ now: () => 100 });
    lifecycle.beginDrain();
    const policySource = { load: vi.fn(async () => ({})) };
    const healthCheck = vi.fn(async () => undefined);
    const billingCoordinator = billing('ready');
    const probe = createEdgeGatewayReadinessProbe({
      policySource,
      rateLimiter: { consume: vi.fn(), healthCheck },
      billingCoordinator,
      lifecycle,
    });

    await expect(probe.check()).resolves.toBe('unavailable');
    expect(policySource.load).not.toHaveBeenCalled();
    expect(healthCheck).not.toHaveBeenCalled();
    expect(billingCoordinator.operationalStatus).not.toHaveBeenCalled();
  });
});

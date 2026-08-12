import { describe, expect, it, vi } from 'vitest';

import {
  InMemoryEdgeGatewayLifecycle,
} from '../src/edge-gateway/lifecycle.js';
import {
  drainEdgeGatewayServer,
  isEdgeDrainExemptRequest,
} from '../src/edge-gateway/server.js';

describe('edge gateway lifecycle', () => {
  it('exempts only exact read-only probes while draining', () => {
    for (const path of ['/healthz', '/readyz?probe=1', '/v1/operations/status']) {
      expect(isEdgeDrainExemptRequest('GET', path)).toBe(true);
    }
    for (const [method, path] of [
      ['POST', '/healthz'],
      ['HEAD', '/readyz'],
      ['POST', '/v1/operations/status'],
      ['GET', '/v1/operations/billing/retry'],
      ['GET', '/v1/operations/status/extra'],
      ['GET', ''],
    ]) {
      expect(isEdgeDrainExemptRequest(method, path)).toBe(false);
    }
    expect(isEdgeDrainExemptRequest(undefined, undefined)).toBe(false);
  });

  it('stops admission and waits for every active request lease exactly once', async () => {
    const lifecycle = new InMemoryEdgeGatewayLifecycle({ now: () => 123 });
    const first = lifecycle.acquire();
    const second = lifecycle.acquire();

    expect(first).not.toBeNull();
    expect(second).not.toBeNull();
    expect(lifecycle.snapshot()).toEqual({
      state: 'accepting',
      activeRequests: 2,
      drainStartedAtMs: null,
    });
    expect(lifecycle.beginDrain()).toBe(true);
    expect(lifecycle.beginDrain()).toBe(false);
    expect(lifecycle.acquire()).toBeNull();

    const idle = lifecycle.waitForIdle(1_000);
    first!.release();
    first!.release();
    await expect(Promise.race([
      idle.then(() => 'idle'),
      new Promise<string>((resolve) => setTimeout(() => resolve('pending'), 0)),
    ])).resolves.toBe('pending');
    second!.release();

    await expect(idle).resolves.toBe(true);
    expect(lifecycle.snapshot()).toEqual({
      state: 'draining',
      activeRequests: 0,
      drainStartedAtMs: 123,
    });
    lifecycle.markStopped();
    expect(lifecycle.snapshot().state).toBe('stopped');
    expect(lifecycle.isAccepting()).toBe(false);
    expect(lifecycle.acquire()).toBeNull();
  });

  it('returns a bounded timeout without discarding the active request count', async () => {
    vi.useFakeTimers();
    try {
      const lifecycle = new InMemoryEdgeGatewayLifecycle({ now: () => 0 });
      const lease = lifecycle.acquire()!;
      lifecycle.beginDrain();
      const idle = lifecycle.waitForIdle(1_000);

      await vi.advanceTimersByTimeAsync(999);
      expect(lifecycle.snapshot().activeRequests).toBe(1);
      await vi.advanceTimersByTimeAsync(1);
      await expect(idle).resolves.toBe(false);

      lease.release();
      await expect(lifecycle.waitForIdle(0)).resolves.toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it('rejects invalid clocks and timeout boundaries without changing state', async () => {
    for (const now of [-1, 1.5, Number.MAX_SAFE_INTEGER + 1, Number.NaN]) {
      const lifecycle = new InMemoryEdgeGatewayLifecycle({ now: () => now });
      expect(() => lifecycle.beginDrain()).toThrow('lifecycle drain time');
      expect(lifecycle.isAccepting()).toBe(true);
    }
    const lifecycle = new InMemoryEdgeGatewayLifecycle();
    for (const timeout of [-1, 1.5, 300_001, Number.MAX_SAFE_INTEGER + 1, Number.NaN]) {
      await expect(lifecycle.waitForIdle(timeout)).rejects.toThrow('lifecycle drain timeout');
    }
    await expect(lifecycle.waitForIdle(300_000)).resolves.toBe(true);
  });

  it('closes the listener after a clean drain without forcing connections', async () => {
    const lifecycle = new InMemoryEdgeGatewayLifecycle({ now: () => 10 });
    const lease = lifecycle.acquire()!;
    let closeCallback: ((error?: Error) => void) | undefined;
    const server = {
      close: vi.fn((callback: (error?: Error) => void) => {
        closeCallback = callback;
        return server;
      }),
      closeAllConnections: vi.fn(),
    };

    const result = drainEdgeGatewayServer({ server: server as never, lifecycle, timeoutMs: 1_000 });
    expect(lifecycle.snapshot().state).toBe('draining');
    lease.release();
    closeCallback!();

    await expect(result).resolves.toBe(true);
    expect(server.closeAllConnections).not.toHaveBeenCalled();
    expect(lifecycle.snapshot().state).toBe('stopped');
  });

  it('forcibly closes connections after the grace period expires', async () => {
    vi.useFakeTimers();
    try {
      const lifecycle = new InMemoryEdgeGatewayLifecycle({ now: () => 20 });
      const lease = lifecycle.acquire()!;
      let closeCallback: ((error?: Error) => void) | undefined;
      const server = {
        close: vi.fn((callback: (error?: Error) => void) => {
          closeCallback = callback;
          return server;
        }),
        closeAllConnections: vi.fn(() => {
          lease.release();
          closeCallback!();
        }),
      };
      const result = drainEdgeGatewayServer({
        server: server as never,
        lifecycle,
        timeoutMs: 1_000,
      });

      await vi.advanceTimersByTimeAsync(1_000);

      await expect(result).resolves.toBe(false);
      expect(server.closeAllConnections).toHaveBeenCalledOnce();
      expect(lifecycle.snapshot()).toEqual({
        state: 'stopped',
        activeRequests: 0,
        drainStartedAtMs: 20,
      });
    } finally {
      vi.useRealTimers();
    }
  });
});

import { describe, expect, it, vi } from 'vitest';

import { InMemoryEdgeGatewayBackgroundTasks } from '../src/edge-gateway/background-tasks.js';
import {
  InMemoryEdgeGatewayLifecycle,
} from '../src/edge-gateway/lifecycle.js';
import {
  drainEdgeGatewayServer,
  isEdgeDrainExemptRequest,
} from '../src/edge-gateway/server-lifecycle.js';

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
    const closeBilling = vi.fn();
    const closeRedis = vi.fn(async () => undefined);
    let closeCallback: ((error?: Error) => void) | undefined;
    const server = {
      close: vi.fn((callback: (error?: Error) => void) => {
        closeCallback = callback;
        return server;
      }),
      closeAllConnections: vi.fn(),
    };

    const result = drainEdgeGatewayServer({
      server: server as never,
      lifecycle,
      resources: [{ close: closeBilling }, { close: closeRedis }],
      timeoutMs: 1_000,
    });
    expect(lifecycle.snapshot().state).toBe('draining');
    lease.release();
    closeCallback!();

    await expect(result).resolves.toBe(true);
    expect(closeBilling).toHaveBeenCalledOnce();
    expect(closeRedis).toHaveBeenCalledOnce();
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

  it('keeps shutdown draining until response-detached billing work completes', async () => {
    const lifecycle = new InMemoryEdgeGatewayLifecycle({ now: () => 30 });
    const backgroundTasks = new InMemoryEdgeGatewayBackgroundTasks();
    let complete!: () => void;
    backgroundTasks.waitUntil(new Promise<void>((resolve) => { complete = resolve; }));
    const server = {
      close: vi.fn((callback: (error?: Error) => void) => {
        callback();
        return server;
      }),
      closeAllConnections: vi.fn(),
    };

    const result = drainEdgeGatewayServer({
      server: server as never,
      lifecycle,
      backgroundTasks,
      timeoutMs: 1_000,
    });
    await expect(Promise.race([
      result.then(() => 'drained'),
      new Promise<string>((resolve) => setTimeout(() => resolve('pending'), 0)),
    ])).resolves.toBe('pending');
    expect(backgroundTasks.snapshot()).toMatchObject({
      state: 'ready',
      activeTasks: 1,
      maximumTasks: 1_024,
      peakActiveTasks: 1,
      failedTasks: 0,
      overflowedTasks: 0,
    });

    complete();
    await expect(result).resolves.toBe(true);
    expect(backgroundTasks.snapshot()).toMatchObject({
      state: 'ready',
      activeTasks: 0,
      peakActiveTasks: 1,
    });
    expect(server.closeAllConnections).not.toHaveBeenCalled();
  });

  it('forces shutdown when detached work exceeds the shared grace period', async () => {
    vi.useFakeTimers();
    try {
      const lifecycle = new InMemoryEdgeGatewayLifecycle({ now: () => 40 });
      const backgroundTasks = new InMemoryEdgeGatewayBackgroundTasks();
      backgroundTasks.waitUntil(new Promise<void>(() => undefined));
      const server = {
        close: vi.fn((callback: (error?: Error) => void) => {
          callback();
          return server;
        }),
        closeAllConnections: vi.fn(),
      };
      const result = drainEdgeGatewayServer({
        server: server as never,
        lifecycle,
        backgroundTasks,
        timeoutMs: 1_000,
      });

      await vi.advanceTimersByTimeAsync(1_000);
      await expect(result).resolves.toBe(false);
      expect(server.closeAllConnections).toHaveBeenCalledOnce();
    } finally {
      vi.useRealTimers();
    }
  });

  it('contains rejected detached work and validates drain timeouts', async () => {
    const backgroundTasks = new InMemoryEdgeGatewayBackgroundTasks();
    backgroundTasks.waitUntil(Promise.reject(new Error('billing unavailable')));
    await expect(backgroundTasks.waitForIdle(1_000)).resolves.toBe(true);
    expect(backgroundTasks.snapshot()).toMatchObject({
      state: 'degraded',
      activeTasks: 0,
      failedTasks: 1,
      overflowedTasks: 0,
      lastFailureAtMs: expect.any(Number),
    });
    for (const timeout of [-1, 1.5, 300_001, Number.NaN]) {
      await expect(backgroundTasks.waitForIdle(timeout)).rejects.toThrow('background task drain');
    }
  });

  it('bounds tracked work and exposes overflow as unavailable', async () => {
    const backgroundTasks = new InMemoryEdgeGatewayBackgroundTasks(1);
    let completeTracked!: () => void;
    let completeOverflow!: () => void;
    backgroundTasks.waitUntil(new Promise<void>((resolve) => { completeTracked = resolve; }));
    backgroundTasks.waitUntil(new Promise<void>((resolve) => { completeOverflow = resolve; }));

    expect(backgroundTasks.isAccepting()).toBe(false);
    expect(backgroundTasks.snapshot()).toMatchObject({
      state: 'unavailable',
      activeTasks: 1,
      maximumTasks: 1,
      peakActiveTasks: 1,
      failedTasks: 0,
      overflowedTasks: 1,
      lastOverflowAtMs: expect.any(Number),
    });

    completeOverflow();
    completeTracked();
    await expect(backgroundTasks.waitForIdle(1_000)).resolves.toBe(true);
    expect(backgroundTasks.snapshot().activeTasks).toBe(0);
    expect(backgroundTasks.snapshot().state).toBe('unavailable');
  });

  it('does not report a graceful drain when detached work rejects', async () => {
    const lifecycle = new InMemoryEdgeGatewayLifecycle();
    const backgroundTasks = new InMemoryEdgeGatewayBackgroundTasks();
    let rejectTask!: (error: Error) => void;
    backgroundTasks.waitUntil(new Promise<void>((_resolve, reject) => { rejectTask = reject; }));
    const server = {
      close: vi.fn((callback: (error?: Error) => void) => {
        callback();
        return server;
      }),
      closeAllConnections: vi.fn(),
    };

    const result = drainEdgeGatewayServer({
      server: server as never,
      lifecycle,
      backgroundTasks,
      timeoutMs: 1_000,
    });
    rejectTask(new Error('durable write failed'));

    await expect(result).resolves.toBe(false);
    expect(server.closeAllConnections).toHaveBeenCalledOnce();
    expect(backgroundTasks.snapshot().failedTasks).toBe(1);
  });

  it('does not hide a detached-work failure that happened before shutdown began', async () => {
    const lifecycle = new InMemoryEdgeGatewayLifecycle();
    const backgroundTasks = new InMemoryEdgeGatewayBackgroundTasks();
    backgroundTasks.waitUntil(Promise.reject(new Error('earlier durable write failed')));
    await expect(backgroundTasks.waitForIdle(1_000)).resolves.toBe(true);
    const server = {
      close: vi.fn((callback: (error?: Error) => void) => {
        callback();
        return server;
      }),
      closeAllConnections: vi.fn(),
    };

    await expect(drainEdgeGatewayServer({
      server: server as never,
      lifecycle,
      backgroundTasks,
      timeoutMs: 1_000,
    })).resolves.toBe(false);
    expect(server.closeAllConnections).toHaveBeenCalledOnce();
    expect(backgroundTasks.snapshot().state).toBe('degraded');
  });

  it('uses one absolute deadline for listener close and never reports a hanging close as graceful', async () => {
    vi.useFakeTimers();
    try {
      const lifecycle = new InMemoryEdgeGatewayLifecycle();
      const server = {
        close: vi.fn(() => server),
        closeAllConnections: vi.fn(),
      };
      const result = drainEdgeGatewayServer({
        server: server as never,
        lifecycle,
        timeoutMs: 1_000,
      });

      await vi.advanceTimersByTimeAsync(1_000);
      await expect(result).resolves.toBe(false);
      expect(server.closeAllConnections).toHaveBeenCalledOnce();
      expect(lifecycle.snapshot().state).toBe('draining');
    } finally {
      vi.useRealTimers();
    }
  });

  it('closes owned resources and treats any close failure as forced shutdown', async () => {
    const lifecycle = new InMemoryEdgeGatewayLifecycle();
    const closeBilling = vi.fn();
    const closeRedis = vi.fn(async () => { throw new Error('Redis quit failed'); });
    const server = {
      close: vi.fn((callback: (error?: Error) => void) => {
        callback();
        return server;
      }),
      closeAllConnections: vi.fn(),
    };

    await expect(drainEdgeGatewayServer({
      server: server as never,
      lifecycle,
      resources: [{ close: closeBilling }, { close: closeRedis }],
      timeoutMs: 1_000,
    })).resolves.toBe(false);

    expect(closeBilling).toHaveBeenCalledOnce();
    expect(closeRedis).toHaveBeenCalledOnce();
    expect(server.closeAllConnections).toHaveBeenCalledOnce();
    expect(lifecycle.snapshot().state).toBe('stopped');
  });

  it('force-closes a resource that exceeds the absolute shutdown deadline', async () => {
    vi.useFakeTimers();
    try {
      const lifecycle = new InMemoryEdgeGatewayLifecycle();
      const forceClose = vi.fn();
      const server = {
        close: vi.fn((callback: (error?: Error) => void) => {
          callback();
          return server;
        }),
        closeAllConnections: vi.fn(),
      };
      const result = drainEdgeGatewayServer({
        server: server as never,
        lifecycle,
        resources: [{ close: () => new Promise<void>(() => undefined), forceClose }],
        timeoutMs: 1_000,
      });

      await vi.advanceTimersByTimeAsync(1_000);
      await expect(result).resolves.toBe(false);
      expect(forceClose).toHaveBeenCalledOnce();
      expect(server.closeAllConnections).toHaveBeenCalledOnce();
      expect(lifecycle.snapshot().state).toBe('stopped');
    } finally {
      vi.useRealTimers();
    }
  });

  it('does not reset the absolute deadline between request drain and resource close', async () => {
    vi.useFakeTimers();
    try {
      const lifecycle = new InMemoryEdgeGatewayLifecycle();
      const lease = lifecycle.acquire()!;
      const forceClose = vi.fn();
      const server = {
        close: vi.fn((callback: (error?: Error) => void) => {
          callback();
          return server;
        }),
        closeAllConnections: vi.fn(),
      };
      setTimeout(() => lease.release(), 600);
      const result = drainEdgeGatewayServer({
        server: server as never,
        lifecycle,
        resources: [{
          close: () => new Promise<void>((resolve) => setTimeout(resolve, 500)),
          forceClose,
        }],
        timeoutMs: 1_000,
      });

      await vi.advanceTimersByTimeAsync(999);
      await expect(Promise.race([
        result.then(() => 'settled'),
        Promise.resolve('pending'),
      ])).resolves.toBe('pending');
      await vi.advanceTimersByTimeAsync(1);
      await expect(result).resolves.toBe(false);
      expect(forceClose).toHaveBeenCalledOnce();
      expect(server.closeAllConnections).toHaveBeenCalledOnce();
    } finally {
      vi.useRealTimers();
    }
  });

  it('rejects invalid shutdown and queue bounds', async () => {
    for (const maximum of [0, 1.5, 100_001, Number.NaN]) {
      expect(() => new InMemoryEdgeGatewayBackgroundTasks(maximum)).toThrow(
        'maximum background tasks',
      );
    }
    const lifecycle = new InMemoryEdgeGatewayLifecycle();
    const server = { close: vi.fn(), closeAllConnections: vi.fn() };
    for (const timeoutMs of [-1, 1.5, 300_001, Number.NaN]) {
      await expect(drainEdgeGatewayServer({
        server: server as never,
        lifecycle,
        timeoutMs,
      })).rejects.toThrow('edge gateway shutdown timeout');
    }
    expect(server.close).not.toHaveBeenCalled();
  });
});

import type { Server } from 'node:http';

import type { EdgeGatewayBackgroundTaskWaiter } from './background-tasks.js';
import type { EdgeGatewayLifecycle } from './lifecycle.js';

export interface EdgeGatewayShutdownResource {
  close(): void | Promise<void>;
  forceClose?(): void;
}

interface BoundedResult<T> {
  completed: boolean;
  rejected: boolean;
  value?: T;
}

async function settleBefore<T>(
  task: Promise<T>,
  deadlineAtMs: number,
): Promise<BoundedResult<T>> {
  const remainingMs = Math.max(0, deadlineAtMs - Date.now());
  if (remainingMs === 0) {
    void task.catch(() => undefined);
    return { completed: false, rejected: false };
  }
  return new Promise<BoundedResult<T>>((resolve) => {
    let settled = false;
    const finish = (result: BoundedResult<T>) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };
    const timer = setTimeout(() => finish({ completed: false, rejected: false }), remainingMs);
    void task.then(
      (value) => finish({ completed: true, rejected: false, value }),
      () => finish({ completed: true, rejected: true }),
    );
  });
}

export function isEdgeDrainExemptRequest(
  method: string | undefined,
  requestUrl: string | undefined,
): boolean {
  if (method !== 'GET') return false;
  const path = (requestUrl ?? '').split('?', 1)[0];
  return path === '/healthz'
    || path === '/readyz'
    || path === '/v1/operations/status';
}

export async function drainEdgeGatewayServer(input: {
  server: Pick<Server, 'close' | 'closeAllConnections'>;
  lifecycle: EdgeGatewayLifecycle;
  backgroundTasks?: EdgeGatewayBackgroundTaskWaiter;
  resources?: readonly EdgeGatewayShutdownResource[];
  timeoutMs: number;
}): Promise<boolean> {
  if (!Number.isSafeInteger(input.timeoutMs) || input.timeoutMs < 0 || input.timeoutMs > 300_000) {
    throw new Error('edge gateway shutdown timeout must be an integer between 0 and 300000');
  }
  const deadlineAtMs = Date.now() + input.timeoutMs;
  input.lifecycle.beginDrain();
  const serverClose: { state: 'pending' | 'closed' | 'failed' } = { state: 'pending' };
  const serverClosed = new Promise<void>((resolve, reject) => {
    try {
      input.server.close((error) => {
        if (error) {
          serverClose.state = 'failed';
          reject(error);
        } else {
          serverClose.state = 'closed';
          resolve();
        }
      });
    } catch (error) {
      serverClose.state = 'failed';
      reject(error);
    }
  });
  const backgroundBefore = input.backgroundTasks?.snapshot();
  const requestsDrained = await input.lifecycle.waitForIdle(
    Math.max(0, deadlineAtMs - Date.now()),
  );
  const backgroundDrained = requestsDrained && input.backgroundTasks
    ? await input.backgroundTasks.waitForIdle(Math.max(0, deadlineAtMs - Date.now()))
    : requestsDrained;
  const backgroundAfter = input.backgroundTasks?.snapshot();
  const backgroundClean = !backgroundBefore || !backgroundAfter
    || (backgroundAfter.failedTasks === backgroundBefore.failedTasks
      && backgroundAfter.failedTasks === 0
      && backgroundAfter.overflowedTasks === backgroundBefore.overflowedTasks
      && backgroundAfter.overflowedTasks === 0);

  const resourceResults = await Promise.all((input.resources ?? []).map(async (resource) => (
    settleBefore(Promise.resolve().then(() => resource.close()), deadlineAtMs)
  )));
  resourceResults.forEach((result, index) => {
    if (result.completed && !result.rejected) return;
    try {
      input.resources?.[index]?.forceClose?.();
    } catch {
      // The failed or timed-out graceful close is already reflected below.
    }
  });
  let graceful = requestsDrained
    && backgroundDrained
    && backgroundClean
    && resourceResults.every((result) => result.completed && !result.rejected);

  let closeResult = await settleBefore(serverClosed, deadlineAtMs);
  if (!graceful || !closeResult.completed || closeResult.rejected) {
    graceful = false;
    try {
      input.server.closeAllConnections();
    } catch {
      serverClose.state = 'failed';
    }
    closeResult = await settleBefore(serverClosed, deadlineAtMs);
  }
  if (serverClose.state === 'closed') input.lifecycle.markStopped();
  return graceful && closeResult.completed && !closeResult.rejected && serverClose.state === 'closed';
}

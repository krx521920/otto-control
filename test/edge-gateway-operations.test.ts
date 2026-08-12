import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type {
  EdgeBillingCoordinator,
  EdgeBillingOperationalState,
} from '../src/edge-gateway/billing-coordinator.js';
import { InMemoryEdgeConcurrencyLimiter } from '../src/edge-gateway/concurrency-limit.js';
import {
  handleEdgeOperationsRequest,
  loadEdgeOperationsToken,
} from '../src/edge-gateway/server.js';

const TOKEN = 'edge-operations-token'.padEnd(48, 'x');

function request(path: string, method = 'GET', token = TOKEN): Request {
  return new Request(`https://edge.otto.test${path}`, {
    method,
    headers: token ? { authorization: `Bearer ${token}` } : {},
  });
}

function billing(initialState: EdgeBillingOperationalState = 'ready') {
  let state = initialState;
  const flushPending = vi.fn(async () => { state = 'ready'; });
  const coordinator: EdgeBillingCoordinator = {
    reserve: vi.fn(),
    settle: vi.fn(),
    release: vi.fn(),
    markUncertain: vi.fn(),
    flushPending,
    operationalStatus: () => ({
      state,
      activeReservations: 0,
      recoveredReservations: state === 'degraded' ? 1 : 0,
      pendingSettlements: state === 'unavailable' ? 1 : 0,
      pendingReleases: 0,
      uncertainReservations: 0,
      journalEntries: 7,
      lastReceiptSequence: 3,
    }),
  };
  return { coordinator, flushPending };
}

describe('Edge Gateway protected operations API', () => {
  let directory: string;

  beforeEach(async () => {
    directory = await mkdtemp(join(tmpdir(), 'otto-edge-operations-'));
  });

  afterEach(async () => {
    await rm(directory, { recursive: true, force: true });
  });

  it('loads only a bounded opaque token from the configured secret file', async () => {
    const file = join(directory, 'operations.token');
    await writeFile(file, `${TOKEN}\n`, 'utf8');
    await expect(loadEdgeOperationsToken(file)).resolves.toBe(TOKEN);
    await writeFile(file, 'short', 'utf8');
    await expect(loadEdgeOperationsToken(file)).rejects.toThrow('is invalid');
    await writeFile(file, `${'x'.repeat(32)}\nsecond-line`, 'utf8');
    await expect(loadEdgeOperationsToken(file)).rejects.toThrow('is invalid');
    await expect(loadEdgeOperationsToken(join(directory, 'missing')))
      .rejects.toThrow('could not be read');
  });

  it('returns authenticated aggregate status without identifiers, money, or secrets', async () => {
    const values = billing('degraded');
    const concurrencyLimiter = new InMemoryEdgeConcurrencyLimiter(10, 2);
    const lease = concurrencyLimiter.acquire('private-subject');
    const response = await handleEdgeOperationsRequest(
      request('/v1/operations/status'),
      { token: TOKEN, billingCoordinator: values.coordinator, concurrencyLimiter },
    );
    expect(response?.status).toBe(200);
    const body = await response!.text();
    expect(JSON.parse(body)).toEqual({
      service: 'otto-edge-gateway',
      billing: {
        state: 'degraded',
        activeReservations: 0,
        recoveredReservations: 1,
        pendingSettlements: 0,
        pendingReleases: 0,
        uncertainReservations: 0,
        journalEntries: 7,
        lastReceiptSequence: 3,
      },
      concurrency: {
        activeRequests: 1,
        globalLimit: 10,
        trackedSubjects: 1,
        subjectsAtLimit: 0,
        perSubjectLimit: 2,
      },
    });
    expect(body).not.toContain(TOKEN);
    expect(body).not.toContain('organization');
    expect(body).not.toContain('amount');
    expect(body).not.toContain('private-subject');
    lease!.release();
  });

  it('rejects missing and incorrect credentials before reading billing state', async () => {
    const operationalStatus = vi.fn();
    const coordinator = { ...billing().coordinator, operationalStatus };
    for (const supplied of ['', `${TOKEN}wrong`]) {
      const response = await handleEdgeOperationsRequest(
        request('/v1/operations/status', 'GET', supplied),
        { token: TOKEN, billingCoordinator: coordinator },
      );
      expect(response?.status).toBe(401);
      expect(response?.headers.get('www-authenticate')).toBe('Bearer');
    }
    expect(operationalStatus).not.toHaveBeenCalled();
  });

  it('retries only the existing durable queue and returns its resulting state', async () => {
    const values = billing('unavailable');
    const response = await handleEdgeOperationsRequest(
      request('/v1/operations/billing/retry', 'POST'),
      { token: TOKEN, billingCoordinator: values.coordinator },
    );
    expect(response?.status).toBe(200);
    expect(values.flushPending).toHaveBeenCalledOnce();
    await expect(response!.json()).resolves.toMatchObject({ billing: { state: 'ready' } });

    const missing = await handleEdgeOperationsRequest(
      request('/v1/operations/billing/retry', 'POST'),
      { token: TOKEN },
    );
    expect(missing?.status).toBe(409);

    const stillPending = billing('unavailable');
    stillPending.flushPending.mockImplementationOnce(async () => undefined);
    const unavailable = await handleEdgeOperationsRequest(
      request('/v1/operations/billing/retry', 'POST'),
      { token: TOKEN, billingCoordinator: stillPending.coordinator },
    );
    expect(unavailable?.status).toBe(503);
    await expect(unavailable!.json()).resolves.toMatchObject({
      billing: { state: 'unavailable', pendingSettlements: 1 },
    });
  });

  it('fails closed on retry errors and never forwards unknown operations', async () => {
    const values = billing('unavailable');
    values.flushPending.mockRejectedValueOnce(new Error('private Control endpoint'));
    const failed = await handleEdgeOperationsRequest(
      request('/v1/operations/billing/retry', 'POST'),
      { token: TOKEN, billingCoordinator: values.coordinator },
    );
    expect(failed?.status).toBe(503);
    expect(await failed!.text()).not.toContain('private Control endpoint');

    const brokenStatus = billing();
    brokenStatus.coordinator.operationalStatus = () => { throw new Error('private journal path'); };
    const statusFailure = await handleEdgeOperationsRequest(
      request('/v1/operations/status'),
      { token: TOKEN, billingCoordinator: brokenStatus.coordinator },
    );
    expect(statusFailure?.status).toBe(503);
    expect(await statusFailure!.text()).not.toContain('private journal path');

    const unknown = await handleEdgeOperationsRequest(
      request('/v1/operations/delete-journal', 'DELETE'),
      { token: TOKEN, billingCoordinator: values.coordinator },
    );
    expect(unknown?.status).toBe(404);
    await expect(handleEdgeOperationsRequest(
      request('/v1/chat/completions', 'POST'),
      { token: TOKEN, billingCoordinator: values.coordinator },
    )).resolves.toBeNull();
  });
});

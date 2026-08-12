import { createHash, createPublicKey, generateKeyPairSync, verify } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { canonicalJson, LocalEd25519Signer } from '../src/crypto/signed-envelope.js';
import type { ControlEdgeBillingCoordinatorOptions } from '../src/edge-gateway/control-billing-coordinator.js';
import { ControlEdgeBillingCoordinator } from '../src/edge-gateway/control-billing-coordinator.js';

const NOW = Date.parse('2026-08-12T02:00:00.000Z');
const BINDING = {
  licenseId: 'lic_edge_billing',
  deploymentId: 'dep_edge_billing',
  organizationId: 'org_edge_billing',
  machineFingerprint: 'a'.repeat(64),
};
const LEASE_TOKEN = 'lease-token-edge-billing'.padEnd(64, 'x');
const HOLD_ONE = `hold_${'1'.repeat(32)}`;
const HOLD_TWO = `hold_${'2'.repeat(32)}`;

function response(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function signer() {
  const { privateKey } = generateKeyPairSync('ed25519');
  return new LocalEd25519Signer(
    privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
  );
}

function identity(requestId: string) {
  return {
    requestId,
    tokenId: `token_${requestId}`,
    deploymentId: BINDING.deploymentId,
    organizationId: BINDING.organizationId,
    subjectId: 'account_edge_billing',
    endpoint: 'chat_completions' as const,
    publicModel: 'otto-fast',
    policyVersion: 'edge-policy-v3',
  };
}

function journalContent(events: Record<string, unknown>[]): string {
  let previousHash: string | null = null;
  return `${events.map((event, index) => {
    const payload = {
      version: 1,
      index: index + 1,
      previousHash,
      ...event,
    };
    const hash = createHash('sha256').update(canonicalJson(payload)).digest('hex');
    previousHash = hash;
    return JSON.stringify({ ...payload, hash });
  }).join('\n')}\n`;
}

describe('Control-backed Edge billing coordinator', () => {
  let directory: string;
  const coordinators: ControlEdgeBillingCoordinator[] = [];

  beforeEach(async () => {
    directory = await mkdtemp(join(tmpdir(), 'otto-edge-billing-'));
  });

  afterEach(async () => {
    for (const coordinator of coordinators) coordinator.close();
    await rm(directory, { recursive: true, force: true });
  });

  const create = async (
    fetchImplementation: typeof fetch,
    receiptSigner = signer(),
    journalFile = join(directory, 'billing.ndjson'),
    overrides: Partial<ControlEdgeBillingCoordinatorOptions> = {},
  ) => {
    const coordinator = await ControlEdgeBillingCoordinator.create({
      controlBaseUrl: 'https://control.otto.test',
      binding: BINDING,
      leaseToken: LEASE_TOKEN,
      signer: receiptSigner,
      journalFile,
      fetch: fetchImplementation,
      now: () => NOW,
      randomHex: () => 'f'.repeat(32),
      retryIntervalMs: 60 * 60 * 1000,
      ...overrides,
    });
    coordinators.push(coordinator);
    return coordinator;
  };

  it('bootstraps its key, reserves before execution, and settles signed usage without content', async () => {
    const calls: Array<{ url: string; body: Record<string, unknown> }> = [];
    const fetchMock = vi.fn<typeof fetch>(async (input, init) => {
      const url = String(input);
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      calls.push({ url, body });
      if (url.endsWith('/execution-receipt-keys/bootstrap')) return response({ replayed: false }, 201);
      if (url.endsWith('/v1/billing/holds')) return response({ hold: { id: HOLD_ONE } }, 201);
      if (url.includes('/execution-receipts')) return response({ replayed: false }, 201);
      throw new Error(`unexpected URL: ${url}`);
    });
    const coordinator = await create(fetchMock);
    const request = identity('request_edge_billing_1');
    const reservation = await coordinator.reserve({ ...request, reserveUnits: 4_000 });
    await coordinator.settle({
      ...request,
      reservation,
      routeId: 'route_primary',
      usage: { inputTokens: 125, outputTokens: 25, totalTokens: 150 },
      occurredAtMs: NOW + 500,
    });

    expect(reservation).toEqual({ reservationId: HOLD_ONE });
    const hold = calls.find((item) => item.url.endsWith('/v1/billing/holds'))!;
    expect(hold.body).toEqual(expect.objectContaining({
      ...BINDING,
      module: 'model_gateway',
      units: 4_000,
    }));
    const settlement = calls.find((item) => item.url.includes(`${HOLD_ONE}/execution-receipts`))!;
    expect(settlement.body).toEqual(expect.objectContaining({
      licenseId: BINDING.licenseId,
      machineFingerprint: BINDING.machineFingerprint,
      envelope: expect.objectContaining({
        signingKeyId: expect.stringMatching(/^[a-f0-9]{16}$/u),
        receipt: expect.objectContaining({
          version: 2,
          deploymentId: BINDING.deploymentId,
          organizationId: BINDING.organizationId,
          moduleId: 'model_gateway',
          units: 150,
          sequence: 1,
          policyVersion: 'edge-policy-v3',
        }),
      }),
    }));
    const bootstrap = calls.find((item) => item.url.endsWith('/execution-receipt-keys/bootstrap'))!;
    expect(bootstrap.body).toEqual(expect.objectContaining({
      version: 1,
      ...BINDING,
      keyId: expect.stringMatching(/^[a-f0-9]{16}$/u),
      issuedAtMs: NOW,
      expiresAtMs: NOW + 31_536_000_000,
      nonce: expect.stringMatching(/^[a-zA-Z0-9_-]{32}$/u),
      signature: expect.stringMatching(/^ed25519:[a-zA-Z0-9_-]{86}$/u),
    }));
    const settlementEnvelope = settlement.body.envelope as {
      receipt: Record<string, unknown>;
      signature: string;
    };
    expect(settlementEnvelope.receipt).toEqual(expect.objectContaining({
      receiptId: `exec_${'f'.repeat(32)}`,
      taskId: expect.stringMatching(/^edge_[a-f0-9]{32}$/u),
      model: 'otto-fast',
      issuedAtMs: NOW,
      expiresAtMs: NOW + 518_400_000,
    }));
    expect(verify(
      null,
      Buffer.from(canonicalJson(settlementEnvelope.receipt)),
      createPublicKey((bootstrap.body.publicKeyPem as string)),
      Buffer.from(settlementEnvelope.signature.slice('ed25519:'.length), 'base64url'),
    )).toBe(true);
    for (const call of calls) {
      const invocation = fetchMock.mock.calls.find(([input]) => String(input) === call.url)!;
      const headers = new Headers(invocation[1]?.headers);
      expect(invocation[1]).toEqual(expect.objectContaining({ method: 'POST', redirect: 'error' }));
      expect(headers.get('authorization')).toBe(`Bearer ${LEASE_TOKEN}`);
      expect(headers.get('content-type')).toBe('application/json');
      expect(headers.get('accept')).toBe('application/json');
    }
    const journal = await readFile(join(directory, 'billing.ndjson'), 'utf8');
    expect(journal).not.toContain('prompt');
    expect(journal).not.toContain('reply');
    const records = journal.split('\n').filter(Boolean).map((line) => JSON.parse(line) as {
      hash: string;
      [field: string]: unknown;
    });
    expect(records).toHaveLength(3);
    for (const { hash, ...payload } of records) {
      expect(hash).toMatch(/^[a-f0-9]{64}$/u);
      expect(hash).toBe(createHash('sha256').update(canonicalJson(payload)).digest('hex'));
    }
  });

  it('replays a durable pending settlement after restart and preserves sequence order', async () => {
    const receiptSigner = signer();
    let firstSettlement = true;
    const firstFetch = vi.fn<typeof fetch>(async (input) => {
      const url = String(input);
      if (url.endsWith('/execution-receipt-keys/bootstrap')) return response({ replayed: false }, 201);
      if (url.endsWith('/v1/billing/holds')) return response({ hold: { id: HOLD_ONE } }, 201);
      if (url.includes('/execution-receipts') && firstSettlement) {
        firstSettlement = false;
        throw new Error('network interrupted after journal commit');
      }
      return response({ replayed: false }, 201);
    });
    const first = await create(firstFetch, receiptSigner);
    const firstRequest = identity('request_edge_billing_1');
    const firstReservation = await first.reserve({ ...firstRequest, reserveUnits: 1_000 });
    await first.settle({
      ...firstRequest,
      reservation: firstReservation,
      routeId: 'route_primary',
      usage: { inputTokens: 6, outputTokens: 4, totalTokens: 10 },
      occurredAtMs: NOW,
    });
    first.close();

    const settlementSequences: number[] = [];
    let nextHold = HOLD_TWO;
    const secondFetch = vi.fn<typeof fetch>(async (input, init) => {
      const url = String(input);
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      if (url.endsWith('/execution-receipt-keys/bootstrap')) return response({ replayed: true });
      if (url.endsWith('/v1/billing/holds')) {
        const id = nextHold;
        nextHold = HOLD_ONE;
        return response({ hold: { id } }, 201);
      }
      if (url.includes('/execution-receipts')) {
        const envelope = body.envelope as { receipt: { sequence: number } };
        settlementSequences.push(envelope.receipt.sequence);
        return response({ replayed: false }, 201);
      }
      throw new Error(`unexpected URL: ${url}`);
    });
    const second = await create(secondFetch, receiptSigner);
    expect(settlementSequences).toEqual([1]);

    const secondRequest = identity('request_edge_billing_2');
    const secondReservation = await second.reserve({ ...secondRequest, reserveUnits: 1_000 });
    await second.settle({
      ...secondRequest,
      reservation: secondReservation,
      routeId: 'route_primary',
      usage: { inputTokens: 10, outputTokens: 5, totalTokens: 15 },
      occurredAtMs: NOW,
    });
    expect(settlementSequences).toEqual([1, 2]);
    second.close();
    const third = await create(secondFetch, receiptSigner);
    expect(settlementSequences).toEqual([1, 2]);
    await expect(third.reserve({ ...firstRequest, reserveUnits: 1_000 }))
      .rejects.toThrow('already finalized');
    await expect(third.reserve({ ...secondRequest, reserveUnits: 1_000 }))
      .rejects.toThrow('already finalized');
  });

  it('falls back to direct signed receipt consumption only after an expired hold conflict', async () => {
    const paths: string[] = [];
    let directBody: Record<string, unknown> | undefined;
    const fetchMock = vi.fn<typeof fetch>(async (input, init) => {
      const path = new URL(String(input)).pathname;
      paths.push(path);
      if (path.endsWith('/execution-receipt-keys/bootstrap')) return response({ replayed: false }, 201);
      if (path === '/v1/billing/holds') return response({ hold: { id: HOLD_ONE } }, 201);
      if (path.includes(HOLD_ONE)) {
        return response({
          error: { code: 'CREDIT_HOLD_UNAVAILABLE', message: 'credit hold has expired' },
        }, 409);
      }
      if (path === '/v1/billing/execution-receipts') {
        directBody = JSON.parse(String(init?.body)) as Record<string, unknown>;
        return response({ replayed: false }, 201);
      }
      throw new Error(`unexpected path: ${path}`);
    });
    const coordinator = await create(fetchMock);
    const request = identity('request_edge_direct_fallback');
    const reservation = await coordinator.reserve({ ...request, reserveUnits: 100 });
    await coordinator.settle({
      ...request,
      reservation,
      routeId: 'route_primary',
      usage: { inputTokens: 7, outputTokens: 3, totalTokens: 10 },
      occurredAtMs: NOW,
    });
    expect(paths).toContain(`/v1/billing/holds/${HOLD_ONE}/execution-receipts`);
    expect(paths).toContain('/v1/billing/execution-receipts');
    expect(directBody).toEqual({
      licenseId: BINDING.licenseId,
      machineFingerprint: BINDING.machineFingerprint,
      envelope: expect.objectContaining({ receipt: expect.objectContaining({ units: 10 }) }),
    });
  });

  it('keeps a receipt pending when direct fallback is temporarily unavailable', async () => {
    let directAttempts = 0;
    const fetchMock = vi.fn<typeof fetch>(async (input) => {
      const path = new URL(String(input)).pathname;
      if (path === '/v1/billing/holds') return response({ hold: { id: HOLD_ONE } }, 201);
      if (path.includes(HOLD_ONE)) {
        return response({ error: { code: 'CREDIT_HOLD_UNAVAILABLE' } }, 409);
      }
      if (path === '/v1/billing/execution-receipts') {
        directAttempts += 1;
        if (directAttempts === 1) throw new Error('direct settlement unavailable');
        return response({ replayed: false }, 201);
      }
      throw new Error(`unexpected path: ${path}`);
    });
    const coordinator = await create(
      fetchMock, signer(), join(directory, 'direct-retry.ndjson'),
      { bootstrapReceiptKey: false },
    );
    const request = identity('request_edge_direct_retry');
    const reservation = await coordinator.reserve({ ...request, reserveUnits: 100 });
    await coordinator.settle({
      ...request,
      reservation,
      routeId: 'route_primary',
      usage: { inputTokens: 3, outputTokens: 2, totalTokens: 5 },
      occurredAtMs: NOW,
    });
    expect(directAttempts).toBe(1);
    await coordinator.flushPending();
    expect(directAttempts).toBe(2);
    await expect(coordinator.reserve({ ...request, reserveUnits: 100 }))
      .rejects.toThrow('already finalized');
  });

  it('does not bypass a hold for unrelated Control conflicts', async () => {
    let directAttempts = 0;
    let holdAttempts = 0;
    const fetchMock = vi.fn<typeof fetch>(async (input) => {
      const path = new URL(String(input)).pathname;
      if (path === '/v1/billing/holds') return response({ hold: { id: HOLD_ONE } }, 201);
      if (path.includes(HOLD_ONE)) {
        holdAttempts += 1;
        if (holdAttempts === 1) {
          return response({ error: { code: 'CONFLICT', message: 'sequence conflict' } }, 409);
        }
        return response({ replayed: false }, 201);
      }
      if (path === '/v1/billing/execution-receipts') {
        directAttempts += 1;
        return response({ replayed: false }, 201);
      }
      throw new Error(`unexpected path: ${path}`);
    });
    const coordinator = await create(
      fetchMock, signer(), join(directory, 'hold-conflict.ndjson'),
      { bootstrapReceiptKey: false },
    );
    const request = identity('request_edge_hold_conflict');
    const reservation = await coordinator.reserve({ ...request, reserveUnits: 100 });
    await coordinator.settle({
      ...request,
      reservation,
      routeId: 'route_primary',
      usage: { inputTokens: 4, outputTokens: 1, totalTokens: 5 },
      occurredAtMs: NOW,
    });
    expect(directAttempts).toBe(0);
    await coordinator.flushPending();
    expect(holdAttempts).toBe(2);
    expect(directAttempts).toBe(0);
  });

  it('does not bypass a hold for transport failures or a non-conflict hold status', async () => {
    for (const failure of ['transport', 'server-status'] as const) {
      let holdAttempts = 0;
      let directAttempts = 0;
      const fetchMock = vi.fn<typeof fetch>(async (input) => {
        const path = new URL(String(input)).pathname;
        if (path === '/v1/billing/holds') return response({ hold: { id: HOLD_ONE } }, 201);
        if (path.includes(HOLD_ONE)) {
          holdAttempts += 1;
          if (holdAttempts > 1) return response({ replayed: false }, 201);
          if (failure === 'transport') throw new Error('connection reset');
          return response({ error: { code: 'CREDIT_HOLD_UNAVAILABLE' } }, 500);
        }
        if (path === '/v1/billing/execution-receipts') {
          directAttempts += 1;
          return response({ replayed: false }, 201);
        }
        throw new Error(`unexpected path: ${path}`);
      });
      const coordinator = await create(
        fetchMock,
        signer(),
        join(directory, `${failure}-settlement.ndjson`),
        { bootstrapReceiptKey: false },
      );
      const request = identity(`request_edge_${failure.replace('-', '_')}`);
      const reservation = await coordinator.reserve({ ...request, reserveUnits: 100 });
      await coordinator.settle({
        ...request,
        reservation,
        routeId: 'route_primary',
        usage: { inputTokens: 4, outputTokens: 1, totalTokens: 5 },
        occurredAtMs: NOW,
      });
      expect(holdAttempts).toBe(1);
      expect(directAttempts).toBe(0);
      await coordinator.flushPending();
      expect(holdAttempts).toBe(2);
      expect(directAttempts).toBe(0);
    }
  });

  it('fails closed for malformed Control conflict bodies instead of bypassing the hold', async () => {
    const malformedBodies: unknown[] = [
      null,
      [],
      'CREDIT_HOLD_UNAVAILABLE',
      {},
      { error: null },
      { error: [] },
      { error: 'CREDIT_HOLD_UNAVAILABLE' },
      { error: {} },
      { error: { code: null } },
      { error: { code: [] } },
    ];
    for (const [index, malformedBody] of malformedBodies.entries()) {
      let holdAttempts = 0;
      let directAttempts = 0;
      const fetchMock = vi.fn<typeof fetch>(async (input) => {
        const path = new URL(String(input)).pathname;
        if (path === '/v1/billing/holds') return response({ hold: { id: HOLD_ONE } }, 201);
        if (path.includes(HOLD_ONE)) {
          holdAttempts += 1;
          return holdAttempts === 1
            ? response(malformedBody, 409)
            : response({ replayed: false }, 201);
        }
        if (path === '/v1/billing/execution-receipts') {
          directAttempts += 1;
          return response({ replayed: false }, 201);
        }
        throw new Error(`unexpected path: ${path}`);
      });
      const coordinator = await create(
        fetchMock,
        signer(),
        join(directory, `malformed-conflict-${index}.ndjson`),
        { bootstrapReceiptKey: false },
      );
      const request = identity(`request_edge_malformed_conflict_${index}`);
      const reservation = await coordinator.reserve({ ...request, reserveUnits: 100 });
      await coordinator.settle({
        ...request,
        reservation,
        routeId: 'route_primary',
        usage: { inputTokens: 4, outputTokens: 1, totalTokens: 5 },
        occurredAtMs: NOW,
      });
      expect(holdAttempts).toBe(1);
      expect(directAttempts).toBe(0);
      await coordinator.flushPending();
      expect(holdAttempts).toBe(2);
      expect(directAttempts).toBe(0);
    }
  });

  it('replays a durable pending release after restart', async () => {
    const receiptSigner = signer();
    const firstFetch = vi.fn<typeof fetch>(async (input) => {
      const path = new URL(String(input)).pathname;
      if (path.endsWith('/execution-receipt-keys/bootstrap')) return response({ replayed: false }, 201);
      if (path === '/v1/billing/holds') return response({ hold: { id: HOLD_ONE } }, 201);
      if (path.endsWith('/release')) throw new Error('release network unavailable');
      throw new Error(`unexpected path: ${path}`);
    });
    const first = await create(firstFetch, receiptSigner);
    const request = identity('request_edge_release_restart');
    const reservation = await first.reserve({ ...request, reserveUnits: 100 });
    await first.release({
      ...request, reservation, reason: 'no_usable_route', occurredAtMs: NOW,
    });
    expect(first.operationalStatus()).toMatchObject({
      state: 'unavailable', pendingReleases: 1, pendingSettlements: 0,
    });
    first.close();

    let releases = 0;
    const secondFetch = vi.fn<typeof fetch>(async (input) => {
      const path = new URL(String(input)).pathname;
      if (path.endsWith('/execution-receipt-keys/bootstrap')) return response({ replayed: true });
      if (path.endsWith('/release')) {
        releases += 1;
        return response({ replayed: false });
      }
      throw new Error(`unexpected path: ${path}`);
    });
    const second = await create(secondFetch, receiptSigner);
    expect(releases).toBe(1);
    expect(second.operationalStatus()).toMatchObject({
      state: 'ready', pendingReleases: 0, recoveredReservations: 0,
    });
    await expect(second.reserve({ ...request, reserveUnits: 100 }))
      .rejects.toThrow('already finalized');
    await second.flushPending();
    expect(releases).toBe(1);
    second.close();
    const third = await create(secondFetch, receiptSigner);
    expect(releases).toBe(1);
    await expect(third.reserve({ ...request, reserveUnits: 100 }))
      .rejects.toThrow('already finalized');
    const journal = await readFile(join(directory, 'billing.ndjson'), 'utf8');
    expect(journal).toContain('release_pending');
    expect(journal).toContain('released');
  });

  it('coalesces concurrent reservations and never reuses a finalized request ID', async () => {
    let holds = 0;
    let releaseBody: Record<string, unknown> | undefined;
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const fetchMock = vi.fn<typeof fetch>(async (input, init) => {
      const path = new URL(String(input)).pathname;
      if (path === '/v1/billing/holds') {
        holds += 1;
        await gate;
        return response({ hold: { id: HOLD_ONE } }, 201);
      }
      if (path.endsWith('/release')) {
        releaseBody = JSON.parse(String(init?.body)) as Record<string, unknown>;
        return response({ replayed: false });
      }
      throw new Error(`unexpected path: ${path}`);
    });
    const coordinator = await create(
      fetchMock, signer(), join(directory, 'coalesced.ndjson'),
      { bootstrapReceiptKey: false },
    );
    const request = identity('request_edge_coalesced');
    const first = coordinator.reserve({ ...request, reserveUnits: 100 });
    const second = coordinator.reserve({ ...request, reserveUnits: 100 });
    release!();
    await expect(Promise.all([first, second])).resolves.toEqual([
      { reservationId: HOLD_ONE },
      { reservationId: HOLD_ONE },
    ]);
    expect(holds).toBe(1);
    const reservation = await coordinator.reserve({ ...request, reserveUnits: 100 });
    expect(reservation).toEqual({ reservationId: HOLD_ONE });
    expect(holds).toBe(1);
    await coordinator.release({
      ...request, reservation, reason: 'zero_usage', occurredAtMs: NOW,
    });
    expect(releaseBody).toEqual({
      ...BINDING,
      idempotencyKey: expect.stringMatching(/^edge-release:[a-f0-9]{32}$/u),
    });
    await expect(coordinator.reserve({ ...request, reserveUnits: 100 }))
      .rejects.toThrow('already finalized');
  });

  it('restores an active reservation after restart without creating a second hold', async () => {
    const receiptSigner = signer();
    const journal = join(directory, 'active-reservation.ndjson');
    const firstFetch = vi.fn<typeof fetch>(async () => response({ hold: { id: HOLD_ONE } }, 201));
    const first = await create(firstFetch, receiptSigner, journal, { bootstrapReceiptKey: false });
    const request = identity('request_edge_active_restart');
    await first.reserve({ ...request, reserveUnits: 100 });
    first.close();

    const secondFetch = vi.fn<typeof fetch>();
    const second = await create(secondFetch, receiptSigner, journal, { bootstrapReceiptKey: false });
    expect(second.operationalStatus()).toMatchObject({
      state: 'degraded',
      activeReservations: 1,
      recoveredReservations: 1,
      journalEntries: 1,
      lastReceiptSequence: 0,
    });
    await expect(second.reserve({ ...request, reserveUnits: 100 }))
      .resolves.toEqual({ reservationId: HOLD_ONE });
    expect(secondFetch).not.toHaveBeenCalled();
  });

  it('uses the bounded retry timer to recover a durable release', async () => {
    vi.useFakeTimers();
    try {
      let releaseAttempts = 0;
      const fetchMock = vi.fn<typeof fetch>(async (input) => {
        const path = new URL(String(input)).pathname;
        if (path === '/v1/billing/holds') return response({ hold: { id: HOLD_ONE } }, 201);
        if (path.endsWith('/release')) {
          releaseAttempts += 1;
          if (releaseAttempts === 1) throw new Error('temporary outage');
          return response({ replayed: false });
        }
        throw new Error(`unexpected path: ${path}`);
      });
      const coordinator = await create(
        fetchMock, signer(), join(directory, 'timer.ndjson'),
        { bootstrapReceiptKey: false, retryIntervalMs: 1_000 },
      );
      const request = identity('request_edge_timer');
      const reservation = await coordinator.reserve({ ...request, reserveUnits: 100 });
      await coordinator.release({
        ...request, reservation, reason: 'no_usable_route', occurredAtMs: NOW,
      });
      expect(releaseAttempts).toBe(1);
      await vi.advanceTimersByTimeAsync(1_000);
      expect(releaseAttempts).toBe(2);
      await vi.waitFor(async () => {
        await expect(coordinator.reserve({ ...request, reserveUnits: 100 }))
          .rejects.toThrow('already finalized');
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it('replays multiple pending receipts strictly in sequence order', async () => {
    const receiptSigner = signer();
    let holdIndex = 0;
    let randomIndex = 0;
    const firstFetch = vi.fn<typeof fetch>(async (input) => {
      const path = new URL(String(input)).pathname;
      if (path === '/v1/billing/holds') {
        holdIndex += 1;
        return response({ hold: { id: holdIndex === 1 ? HOLD_ONE : HOLD_TWO } }, 201);
      }
      if (path.includes('/execution-receipts')) throw new Error('Control offline');
      throw new Error(`unexpected path: ${path}`);
    });
    const journal = join(directory, 'ordered.ndjson');
    const first = await create(firstFetch, receiptSigner, journal, {
      bootstrapReceiptKey: false,
      randomHex: () => `${++randomIndex}`.padStart(32, '0'),
    });
    for (const [index, holdId] of [[1, HOLD_ONE], [2, HOLD_TWO]] as const) {
      const request = identity(`request_edge_ordered_${index}`);
      const reservation = await first.reserve({ ...request, reserveUnits: 100 });
      expect(reservation.reservationId).toBe(holdId);
      await first.settle({
        ...request,
        reservation,
        routeId: 'route_primary',
        usage: { inputTokens: index, outputTokens: 1, totalTokens: index + 1 },
        occurredAtMs: NOW,
      });
    }
    first.close();

    const sequences: number[] = [];
    const secondFetch = vi.fn<typeof fetch>(async (_input, init) => {
      const body = JSON.parse(String(init?.body)) as {
        envelope: { receipt: { sequence: number } };
      };
      sequences.push(body.envelope.receipt.sequence);
      return response({ replayed: false }, 201);
    });
    const second = await create(secondFetch, receiptSigner, journal, {
      bootstrapReceiptKey: false,
    });
    expect(sequences).toEqual([1, 2]);
    await second.flushPending();
    expect(sequences).toEqual([1, 2]);
    await expect(second.reserve({
      ...identity('request_edge_ordered_1'), reserveUnits: 100,
    })).rejects.toThrow('already finalized');
  });

  it('sorts out-of-order journal entries before sending contiguous receipt sequences', async () => {
    const journal = join(directory, 'out-of-order.ndjson');
    const envelope = (sequence: number) => ({
      receipt: { sequence },
      signingKeyId: 'a'.repeat(16),
      signature: `ed25519:${'x'.repeat(86)}`,
    });
    await writeFile(journal, journalContent([
      { type: 'reserved', requestId: 'request_order_1', reservationId: HOLD_ONE },
      { type: 'reserved', requestId: 'request_order_2', reservationId: HOLD_TWO },
      {
        type: 'settlement_pending',
        requestId: 'request_order_2',
        reservationId: HOLD_TWO,
        envelope: envelope(2),
      },
      {
        type: 'settlement_pending',
        requestId: 'request_order_1',
        reservationId: HOLD_ONE,
        envelope: envelope(1),
      },
    ]), 'utf8');
    const sequences: number[] = [];
    const fetchMock = vi.fn<typeof fetch>(async (_input, init) => {
      const body = JSON.parse(String(init?.body)) as {
        envelope: { receipt: { sequence: number } };
      };
      sequences.push(body.envelope.receipt.sequence);
      return response({ replayed: false }, 201);
    });
    await create(fetchMock, signer(), journal, { bootstrapReceiptKey: false });
    expect(sequences).toEqual([1, 2]);
  });

  it('persists releases and uncertain executions without submitting message content', async () => {
    let hold = HOLD_ONE;
    const paths: string[] = [];
    const fetchMock = vi.fn<typeof fetch>(async (input) => {
      const url = String(input);
      paths.push(new URL(url).pathname);
      if (url.endsWith('/execution-receipt-keys/bootstrap')) return response({ replayed: false }, 201);
      if (url.endsWith('/v1/billing/holds')) {
        const current = hold;
        hold = HOLD_TWO;
        return response({ hold: { id: current } }, 201);
      }
      if (url.endsWith('/release')) return response({ replayed: false });
      throw new Error(`unexpected URL: ${url}`);
    });
    const receiptSigner = signer();
    const coordinator = await create(fetchMock, receiptSigner);
    const releasedRequest = identity('request_edge_release');
    const released = await coordinator.reserve({ ...releasedRequest, reserveUnits: 500 });
    await coordinator.release({
      ...releasedRequest,
      reservation: released,
      reason: 'no_usable_route',
      occurredAtMs: NOW,
    });
    const uncertainRequest = identity('request_edge_uncertain');
    const uncertain = await coordinator.reserve({ ...uncertainRequest, reserveUnits: 500 });
    await coordinator.markUncertain({
      ...uncertainRequest,
      reservation: uncertain,
      routeId: 'route_primary',
      reason: 'stream_timed_out',
      occurredAtMs: NOW + 1_000,
    });
    expect(coordinator.operationalStatus()).toMatchObject({
      state: 'degraded',
      activeReservations: 0,
      recoveredReservations: 0,
      uncertainReservations: 1,
      pendingReleases: 0,
      pendingSettlements: 0,
      lastReceiptSequence: 0,
    });

    expect(paths.filter((path) => path.endsWith('/release'))).toHaveLength(1);
    const journal = await readFile(join(directory, 'billing.ndjson'), 'utf8');
    expect(journal).toContain('stream_timed_out');
    expect(journal).toContain('route_primary');
    expect(journal).not.toContain('messages');
    coordinator.close();
    const restarted = await create(fetchMock, receiptSigner);
    await expect(restarted.reserve({ ...releasedRequest, reserveUnits: 500 }))
      .rejects.toThrow('already finalized');
    await expect(restarted.reserve({ ...uncertainRequest, reserveUnits: 500 }))
      .rejects.toThrow('already finalized');
  });

  it('maps only a known insufficient-credit response to payment required', async () => {
    const insufficient = vi.fn<typeof fetch>(async (input) => String(input)
      .endsWith('/execution-receipt-keys/bootstrap')
      ? response({ replayed: false }, 201)
      : response({ error: { code: 'CREDIT_REQUIRED', message: 'insufficient available credits' } }, 402));
    const coordinator = await create(insufficient);
    await expect(coordinator.reserve({
      ...identity('request_edge_insufficient'), reserveUnits: 1_000,
    })).rejects.toEqual(expect.objectContaining({
      status: 402,
      code: 'EDGE_CREDIT_REQUIRED',
    }));

    for (const failure of ['transport', 'conflict'] as const) {
      const unavailable = vi.fn<typeof fetch>(async () => {
        if (failure === 'transport') throw new Error('connection reset');
        return response({ error: { code: 'CONFLICT' } }, 409);
      });
      const unavailableCoordinator = await create(
        unavailable,
        signer(),
        join(directory, `reserve-${failure}.ndjson`),
        { bootstrapReceiptKey: false },
      );
      await expect(unavailableCoordinator.reserve({
        ...identity(`request_edge_reserve_${failure}`), reserveUnits: 1_000,
      })).rejects.toEqual(expect.objectContaining({
        status: 503,
        code: 'EDGE_BILLING_UNAVAILABLE',
      }));
    }
  });

  it('rejects unsafe configuration before reading state or contacting Control', async () => {
    const receiptSigner = signer();
    const base: ControlEdgeBillingCoordinatorOptions = {
      controlBaseUrl: 'https://control.otto.test',
      binding: BINDING,
      leaseToken: LEASE_TOKEN,
      signer: receiptSigner,
      journalFile: join(directory, 'invalid.ndjson'),
      fetch: vi.fn<typeof fetch>(),
      bootstrapReceiptKey: false,
    };
    for (const controlBaseUrl of [
      'not-a-url',
      'http://control.otto.test',
      'https://user:pass@control.otto.test',
      'https://control.otto.test?tenant=bad',
      'https://control.otto.test/#bad',
    ]) {
      await expect(ControlEdgeBillingCoordinator.create({ ...base, controlBaseUrl }))
        .rejects.toThrow('Control URL or deployment binding');
    }
    for (const binding of [
      { ...BINDING, licenseId: '_bad' },
      { ...BINDING, deploymentId: 'bad value' },
      { ...BINDING, organizationId: '' },
      { ...BINDING, machineFingerprint: 'g'.repeat(64) },
      { ...BINDING, machineFingerprint: 'a'.repeat(65) },
    ]) {
      await expect(ControlEdgeBillingCoordinator.create({ ...base, binding }))
        .rejects.toThrow('Control URL or deployment binding');
    }
    for (const leaseToken of ['x'.repeat(31), 'x'.repeat(8_193), `x ${'y'.repeat(62)}`]) {
      await expect(ControlEdgeBillingCoordinator.create({ ...base, leaseToken }))
        .rejects.toThrow('lease token');
    }
    await expect(ControlEdgeBillingCoordinator.create({
      ...base,
      signer: {
        keyId: 'bad',
        publicKeyPem: receiptSigner.publicKeyPem,
        sign: receiptSigner.sign.bind(receiptSigner),
      },
    })).rejects.toThrow('key ID');
    await expect(ControlEdgeBillingCoordinator.create({ ...base, journalFile: ' ' }))
      .rejects.toThrow('journal path');
    for (const requestTimeoutMs of [499, 60_001, 1.5, Number.NaN]) {
      await expect(ControlEdgeBillingCoordinator.create({ ...base, requestTimeoutMs }))
        .rejects.toThrow('request timeout');
    }
    for (const retryIntervalMs of [999, 3_600_001, 1.5, Number.NaN]) {
      await expect(ControlEdgeBillingCoordinator.create({ ...base, retryIntervalMs }))
        .rejects.toThrow('retry interval');
    }
    expect(base.fetch).not.toHaveBeenCalled();
  });

  it('validates request identity, reservation units, and final evidence before money changes', async () => {
    const fetchMock = vi.fn<typeof fetch>(async (input) => String(input).endsWith('/v1/billing/holds')
      ? response({ hold: { id: HOLD_ONE } }, 201)
      : response({ replayed: false }, 201));
    const coordinator = await create(
      fetchMock, signer(), join(directory, 'validation.ndjson'),
      { bootstrapReceiptKey: false },
    );
    const valid = identity('request_edge_validation');
    for (const candidate of [
      { ...valid, deploymentId: 'dep_other' },
      { ...valid, organizationId: 'org_other' },
      { ...valid, requestId: '_bad' },
      { ...valid, requestId: '!valid' },
      { ...valid, requestId: 'valid!' },
      { ...valid, tokenId: 'bad value' },
      { ...valid, subjectId: '' },
      { ...valid, policyVersion: 'x'.repeat(161) },
      { ...valid, publicModel: '' },
      { ...valid, publicModel: '   ' },
      { ...valid, publicModel: 'x'.repeat(161) },
    ]) {
      await expect(coordinator.reserve({ ...candidate, reserveUnits: 1_000 }))
        .rejects.toThrow();
    }
    for (const reserveUnits of [0, -1, 1.5, 9_000_000_000_001, Number.NaN]) {
      await expect(coordinator.reserve({ ...valid, reserveUnits })).rejects.toThrow('reserve units');
    }
    expect(fetchMock).not.toHaveBeenCalled();

    await expect(coordinator.reserve({
      ...identity('x'.repeat(160)),
      tokenId: 'x'.repeat(160),
      publicModel: 'x'.repeat(160),
      reserveUnits: 1,
    })).resolves.toEqual({ reservationId: HOLD_ONE });

    const reservation = await coordinator.reserve({ ...valid, reserveUnits: 1_000 });
    for (const candidate of [
      { routeId: '_bad', usage: { inputTokens: 1, outputTokens: 1, totalTokens: 2 }, occurredAtMs: NOW },
      { routeId: 'route', usage: { inputTokens: -1, outputTokens: 1, totalTokens: 1 }, occurredAtMs: NOW },
      { routeId: 'route', usage: { inputTokens: 1, outputTokens: 1.5, totalTokens: 2.5 }, occurredAtMs: NOW },
      { routeId: 'route', usage: { inputTokens: 1, outputTokens: 1, totalTokens: 3 }, occurredAtMs: NOW },
      { routeId: 'route', usage: { inputTokens: 0, outputTokens: 0, totalTokens: 0 }, occurredAtMs: NOW },
      { routeId: 'route', usage: { inputTokens: 1, outputTokens: 1, totalTokens: 2 }, occurredAtMs: 0 },
    ]) {
      await expect(coordinator.settle({ ...valid, reservation, ...candidate }))
        .rejects.toThrow('settlement evidence');
    }
    await expect(coordinator.settle({
      ...valid,
      reservation: { reservationId: HOLD_TWO },
      routeId: 'route',
      usage: { inputTokens: 1, outputTokens: 1, totalTokens: 2 },
      occurredAtMs: NOW,
    })).rejects.toThrow('not active');
    await expect(coordinator.release({
      ...valid, reservation, reason: 'zero_usage', occurredAtMs: 0,
    })).rejects.toThrow('release evidence');
    await expect(coordinator.markUncertain({
      ...valid,
      reservation,
      routeId: '_bad',
      reason: 'provider_error',
      occurredAtMs: NOW,
    })).rejects.toThrow('uncertain evidence');
  });

  it('rejects missing, malformed, oversized, and ambiguous Control hold responses', async () => {
    const validHold = JSON.stringify({ hold: { id: HOLD_ONE } });
    const oversized = JSON.stringify({ hold: { id: HOLD_ONE }, padding: 'x'.repeat(262_145) });
    const candidates = [
      new Response(null, { status: 201 }),
      response([]),
      response({}),
      response({ hold: null }),
      response({ hold: [] }),
      response({ hold: {} }),
      response({ hold: { id: `x${HOLD_ONE}` } }),
      response({ hold: { id: `${HOLD_ONE}x` } }),
      response({ hold: { id: `hold_${'1'.repeat(31)}` } }),
      response({ hold: { id: `hold_${'g'.repeat(32)}` } }),
      new Response('{bad json', { status: 201 }),
      new Response(validHold, { status: 201, headers: { 'content-length': '-1' } }),
      new Response(validHold, { status: 201, headers: { 'content-length': '1.5' } }),
      new Response(validHold, { status: 201, headers: { 'content-length': 'NaN' } }),
      new Response(validHold, { status: 201, headers: { 'content-length': '262145' } }),
      new Response(oversized, { status: 201 }),
    ];
    const fetchMock = vi.fn<typeof fetch>();
    for (const candidate of candidates) fetchMock.mockResolvedValueOnce(candidate);
    const coordinator = await create(
      fetchMock, signer(), join(directory, 'responses.ndjson'),
      { bootstrapReceiptKey: false },
    );
    for (let index = 0; index < candidates.length; index += 1) {
      const assertion = expect(coordinator.reserve({
        ...identity(`request_bad_response_${index}`), reserveUnits: 100,
      })).rejects;
      if (index >= 1 && index <= 9) {
        await assertion.toThrow('Control hold response is invalid');
      }
      else await assertion.toThrow();
    }
    expect(fetchMock).toHaveBeenCalledTimes(candidates.length);
  });

  it('accepts the exact bounded Control response size declaration', async () => {
    const fetchMock = vi.fn<typeof fetch>(async () => new Response(
      JSON.stringify({ hold: { id: HOLD_ONE } }),
      { status: 201, headers: { 'content-length': '262144' } },
    ));
    const coordinator = await create(
      fetchMock, signer(), join(directory, 'response-boundary.ndjson'),
      { bootstrapReceiptKey: false },
    );
    await expect(coordinator.reserve({
      ...identity('request_response_boundary'), reserveUnits: 100,
    })).resolves.toEqual({ reservationId: HOLD_ONE });
  });

  it('aborts a stalled Control reservation request at the configured deadline', async () => {
    vi.useFakeTimers();
    try {
      let signal: AbortSignal | undefined;
      const fetchMock = vi.fn<typeof fetch>(async (_input, init) => {
        signal = init?.signal ?? undefined;
        return new Promise<Response>((_resolve, reject) => {
          signal?.addEventListener('abort', () => reject(signal?.reason), { once: true });
        });
      });
      const coordinator = await create(
        fetchMock, signer(), join(directory, 'timeout.ndjson'),
        { bootstrapReceiptKey: false, requestTimeoutMs: 500 },
      );
      const pending = coordinator.reserve({
        ...identity('request_edge_timeout'), reserveUnits: 100,
      });
      const rejection = expect(pending).rejects.toMatchObject({
        status: 503,
        code: 'EDGE_BILLING_UNAVAILABLE',
      });
      await vi.advanceTimersByTimeAsync(500);
      await rejection;
      expect(signal?.aborted).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it('clears the Control deadline after a successful response', async () => {
    vi.useFakeTimers();
    try {
      let signal: AbortSignal | undefined;
      const fetchMock = vi.fn<typeof fetch>(async (_input, init) => {
        signal = init?.signal ?? undefined;
        return response({ hold: { id: HOLD_ONE } }, 201);
      });
      const coordinator = await create(
        fetchMock, signer(), join(directory, 'cleared-timeout.ndjson'),
        { bootstrapReceiptKey: false, requestTimeoutMs: 500 },
      );
      await coordinator.reserve({
        ...identity('request_edge_cleared_timeout'), reserveUnits: 100,
      });
      await vi.advanceTimersByTimeAsync(500);
      expect(signal?.aborted).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });

  it('fails closed when the durable journal is truncated or its hash chain is changed', async () => {
    const journal = join(directory, 'billing.ndjson');
    await writeFile(journal, '{"version":1', 'utf8');
    const fetchMock = vi.fn<typeof fetch>();
    await expect(create(fetchMock, signer(), journal)).rejects.toThrow('truncated');

    await writeFile(journal, '{bad json}\n', 'utf8');
    await expect(create(fetchMock, signer(), journal)).rejects.toThrow('journal JSON');

    await writeFile(journal, `${JSON.stringify({
      version: 1,
      index: 1,
      previousHash: null,
      type: 'released',
      requestId: 'request_tampered',
      hash: '0'.repeat(64),
    })}\n`, 'utf8');
    await expect(create(fetchMock, signer(), journal)).rejects.toThrow('hash chain');
    await expect(create(fetchMock, signer(), directory, { bootstrapReceiptKey: false }))
      .rejects.toThrow();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('validates every durable journal event shape before replaying financial work', async () => {
    const journal = join(directory, 'event-validation.ndjson');
    const receiptSigner = signer();
    const fetchMock = vi.fn<typeof fetch>();
    const base = {
      version: 1,
      index: 1,
      previousHash: null,
      type: 'reserved',
      requestId: 'request_event_validation',
      reservationId: HOLD_ONE,
    };
    const record = (payload: Record<string, unknown>) => JSON.stringify({
      ...payload,
      hash: createHash('sha256').update(canonicalJson(payload)).digest('hex'),
    });
    const invalid: unknown[] = [
      null,
      [],
      'text',
      { ...base, version: 2 },
      { ...base, index: 2 },
      { ...base, previousHash: '0'.repeat(64) },
      { ...base, type: 'unknown' },
      { ...base, requestId: '_bad' },
      { ...base, reservationId: `x${HOLD_ONE}` },
      { ...base, type: 'settlement_pending', reservationId: HOLD_ONE, envelope: null },
      { ...base, type: 'settlement_pending', reservationId: 'bad', envelope: {} },
      {
        ...base,
        type: 'release_pending',
        reservationId: HOLD_ONE,
        idempotencyKey: '_bad',
        reason: 'no_usable_route',
      },
      {
        ...base,
        type: 'release_pending',
        reservationId: HOLD_ONE,
        idempotencyKey: 'edge-release:valid',
        reason: 'bad_reason',
      },
      {
        ...base,
        type: 'uncertain',
        routeId: '_bad',
        reason: 'provider_error',
        occurredAtMs: NOW,
      },
      {
        ...base,
        type: 'uncertain',
        routeId: 'route_primary',
        reason: 'bad_reason',
        occurredAtMs: NOW,
      },
      {
        ...base,
        type: 'uncertain',
        routeId: 'route_primary',
        reason: 'provider_error',
        occurredAtMs: 0,
      },
    ];
    for (const candidate of invalid) {
      const line = candidate && typeof candidate === 'object' && !Array.isArray(candidate)
        ? record(candidate as Record<string, unknown>)
        : JSON.stringify(candidate);
      await writeFile(journal, `${line}\n`, 'utf8');
      await expect(create(fetchMock, receiptSigner, journal, { bootstrapReceiptKey: false }))
        .rejects.toThrow('billing journal');
    }
    await writeFile(journal, `${JSON.stringify({ ...base, hash: 7 })}\n`, 'utf8');
    await expect(create(fetchMock, receiptSigner, journal, { bootstrapReceiptKey: false }))
      .rejects.toThrow('hash chain');
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

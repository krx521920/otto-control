import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import {
  EdgeRequestLedgerCorruptionError,
  FileEdgeRequestLedger,
  MemoryEdgeRequestLedger,
  hashEdgeRequest,
  type EdgeRequestAdmission,
  type EdgeRequestBinding,
} from '../src/edge-gateway/request-ledger.js';

const directories: string[] = [];

async function temporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), 'otto-edge-request-ledger-'));
  directories.push(directory);
  return directory;
}

afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) =>
    rm(directory, { recursive: true, force: true })));
});

const admission: EdgeRequestAdmission = {
  requestId: 'req_123',
  tenant: {
    deploymentId: 'deployment_alpha',
    organizationId: 'organization_alpha',
    subjectId: 'account_alpha',
  },
  requestHash: hashEdgeRequest('{"model":"public-chat","messages":[]}'),
  reservedUnits: 8_000,
};

const binding: EdgeRequestBinding = {
  requestId: admission.requestId,
  tenant: admission.tenant,
  requestHash: admission.requestHash,
};

describe('edge request idempotency ledger', () => {
  it('admits one logical request exactly once under concurrency', async () => {
    const ledger = new MemoryEdgeRequestLedger({ now: () => 1_000 });

    const results = await Promise.all(
      Array.from({ length: 32 }, () => ledger.admit(admission)),
    );

    expect(results.filter((result) => result.created)).toHaveLength(1);
    expect(results.every((result) => result.record.state === 'received')).toBe(true);
    expect(await ledger.lookup({ requestId: admission.requestId, tenant: admission.tenant }))
      .toMatchObject({ requestId: admission.requestId, reservedUnits: 8_000 });
  });

  it('fails closed when a request ID is reused across tenant, bytes, or reservation', async () => {
    const ledger = new MemoryEdgeRequestLedger();
    await ledger.admit(admission);

    await expect(ledger.admit({
      ...admission,
      tenant: { ...admission.tenant, organizationId: 'organization_beta' },
    })).rejects.toMatchObject({
      code: 'EDGE_REQUEST_TENANT_CONFLICT',
    });
    await expect(ledger.admit({
      ...admission,
      requestHash: hashEdgeRequest('different request'),
    })).rejects.toMatchObject({
      code: 'EDGE_REQUEST_HASH_CONFLICT',
    });
    await expect(ledger.admit({
      ...admission,
      reservedUnits: admission.reservedUnits + 1,
    })).rejects.toMatchObject({
      code: 'EDGE_REQUEST_RESERVATION_CONFLICT',
    });
    await expect(ledger.lookup({
      requestId: admission.requestId,
      tenant: { ...admission.tenant, subjectId: 'account_beta' },
    })).rejects.toMatchObject({
      code: 'EDGE_REQUEST_TENANT_CONFLICT',
    });
  });

  it('records provider evidence, locks unknown outcomes, and completes a new logical request', async () => {
    let now = 1_000;
    const ledger = new MemoryEdgeRequestLedger({ now: () => now });
    await ledger.admit(admission);
    now = 2_000;
    await ledger.beginAttempt({ ...binding, routeId: 'route_primary' });
    now = 2_100;
    await ledger.recordProviderRequestId({
      ...binding,
      providerRequestId: 'provider-request-primary',
    });
    now = 3_000;
    const unknown = await ledger.markUnknownOutcome(binding);
    expect(unknown).toMatchObject({
      state: 'unknown_outcome',
      routeId: 'route_primary',
      providerRequestId: 'provider-request-primary',
    });

    now = 4_000;
    await ledger.confirmFailover(binding);
    await expect(ledger.beginAttempt({ ...binding, routeId: 'route_fallback' }))
      .rejects.toMatchObject({ code: 'EDGE_REQUEST_STATE_CONFLICT' });

    const nextAdmission = { ...admission, requestId: 'req_new_after_unknown' };
    const nextBinding = { ...binding, requestId: nextAdmission.requestId };
    now = 5_000;
    await ledger.admit(nextAdmission);
    await ledger.beginAttempt({ ...nextBinding, routeId: 'route_fallback' });
    now = 6_000;
    const completed = await ledger.complete({
      ...nextBinding,
      providerRequestId: 'provider-request-fallback',
      actualUsage: { inputTokens: 250, outputTokens: 100, totalTokens: 350 },
    });
    expect(completed).toMatchObject({
      state: 'completed',
      actualUsage: { inputTokens: 250, outputTokens: 100, totalTokens: 350 },
      routeId: 'route_fallback',
      providerRequestId: 'provider-request-fallback',
      completedAtMs: 6_000,
    });
  });
  it('permits a safe retry only after an attempt is proved not sent', async () => {
    const ledger = new MemoryEdgeRequestLedger();
    await ledger.admit(admission);
    const initial = await ledger.lookup(binding);
    expect(initial?.state).toBe('received');
    await ledger.beginAttempt({ ...binding, routeId: 'route_primary' });
    expect((await ledger.markNotSent(binding)).state).toBe('not_sent');

    const replay = await ledger.admit(admission);
    expect(replay).toMatchObject({
      created: true,
      recoveredNotSentRequest: true,
      record: { state: 'received' },
    });
    const retry = await ledger.beginAttempt({ ...binding, routeId: 'route_primary' });
    expect(retry.attempts).toHaveLength(2);
  });

  it('does not treat a provider-acknowledged attempt as definitely not sent', async () => {
    const ledger = new MemoryEdgeRequestLedger();
    await ledger.admit(admission);
    await ledger.beginAttempt({ ...binding, routeId: 'route_primary' });
    await ledger.recordProviderRequestId({
      ...binding,
      providerRequestId: 'provider-request-acknowledged',
    });

    await expect(ledger.markNotSent(binding)).rejects.toMatchObject({
      code: 'EDGE_REQUEST_STATE_CONFLICT',
    });
    expect((await ledger.markUnknownOutcome(binding)).state).toBe('unknown_outcome');
  });

  it('never reopens an unknown outcome even after repeated confirmation', async () => {
    let now = 1_000;
    const ledger = new MemoryEdgeRequestLedger({ now: () => now });
    const request: EdgeRequestAdmission = {
      ...admission,
      requestId: 'req_unknown_never_replayed',
    };
    const requestBinding: EdgeRequestBinding = {
      requestId: request.requestId,
      tenant: request.tenant,
      requestHash: request.requestHash,
    };

    await ledger.admit(request);
    await ledger.beginAttempt({ ...requestBinding, routeId: 'route_primary' });
    now = 2_000;
    await ledger.markUnknownOutcome(requestBinding);
    for (const routeId of ['route_fallback_1', 'route_fallback_2']) {
      now += 1_000;
      await ledger.confirmFailover(requestBinding);
      await expect(ledger.beginAttempt({ ...requestBinding, routeId }))
        .rejects.toMatchObject({ code: 'EDGE_REQUEST_STATE_CONFLICT' });
    }
    expect(await ledger.lookup(requestBinding)).toMatchObject({
      state: 'unknown_outcome',
      attempts: [{ routeId: 'route_primary', outcome: 'unknown_outcome' }],
    });
  });
  it('fsyncs a hash-chain journal and recovers restart states conservatively', async () => {
    const directory = await temporaryDirectory();
    const journalFile = join(directory, 'request-ledger.ndjson');
    let now = 10_000;
    const first = await FileEdgeRequestLedger.create({ journalFile, now: () => now });
    await first.admit(admission);

    now = 11_000;
    const afterReceivedRestart = await FileEdgeRequestLedger.create({
      journalFile,
      now: () => now,
    });
    expect(await afterReceivedRestart.lookup({
      requestId: admission.requestId,
      tenant: admission.tenant,
    })).toMatchObject({ state: 'not_sent' });

    await afterReceivedRestart.admit(admission);
    now = 12_000;
    await afterReceivedRestart.beginAttempt({ ...binding, routeId: 'route_primary' });
    now = 13_000;
    await afterReceivedRestart.recordProviderRequestId({
      ...binding,
      providerRequestId: 'provider-request-1',
    });

    now = 14_000;
    const afterExecutingRestart = await FileEdgeRequestLedger.create({
      journalFile,
      now: () => now,
    });
    const recovered = await afterExecutingRestart.lookup({
      requestId: admission.requestId,
      tenant: admission.tenant,
    });
    expect(recovered).toMatchObject({
      state: 'unknown_outcome',
      providerRequestId: 'provider-request-1',
      attempts: [{ outcome: 'unknown_outcome', endedAtMs: 14_000 }],
    });

    const lines = (await readFile(journalFile, 'utf8')).trim().split('\n');
    expect(lines.length).toBeGreaterThanOrEqual(5);
    const records = lines.map((line) => JSON.parse(line) as {
      index: number;
      previousHash: string | null;
      hash: string;
    });
    expect(records[0]).toMatchObject({ index: 1, previousHash: null });
    for (let index = 1; index < records.length; index += 1) {
      expect(records[index]?.previousHash).toBe(records[index - 1]?.hash);
      expect(records[index]?.index).toBe(index + 1);
    }
  });

  it('fails closed for a truncated or tampered durable journal', async () => {
    const directory = await temporaryDirectory();
    const journalFile = join(directory, 'request-ledger.ndjson');
    const ledger = await FileEdgeRequestLedger.create({ journalFile });
    await ledger.admit(admission);
    const original = await readFile(journalFile, 'utf8');

    await writeFile(journalFile, original.trimEnd(), 'utf8');
    await expect(FileEdgeRequestLedger.create({ journalFile }))
      .rejects.toBeInstanceOf(EdgeRequestLedgerCorruptionError);

    await writeFile(journalFile, '', 'utf8');
    await expect(FileEdgeRequestLedger.create({ journalFile }))
      .rejects.toBeInstanceOf(EdgeRequestLedgerCorruptionError);

    const parsed = JSON.parse(original.trim()) as Record<string, unknown>;
    parsed.previousHash = '0'.repeat(64);
    await writeFile(journalFile, `${JSON.stringify(parsed)}\n`, 'utf8');
    await expect(FileEdgeRequestLedger.create({ journalFile }))
      .rejects.toBeInstanceOf(EdgeRequestLedgerCorruptionError);
  });

  it('serializes concurrent file admissions without duplicate journal records', async () => {
    const directory = await temporaryDirectory();
    const journalFile = join(directory, 'request-ledger.ndjson');
    const ledger = await FileEdgeRequestLedger.create({ journalFile, now: () => 1_000 });

    const results = await Promise.all(
      Array.from({ length: 16 }, () => ledger.admit(admission)),
    );

    expect(results.filter((result) => result.created)).toHaveLength(1);
    expect((await readFile(journalFile, 'utf8')).trim().split('\n')).toHaveLength(1);
  });
});

import pg from 'pg';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { PostgresEdgeRequestLedger } from '../src/edge-gateway/postgres-request-ledger.js';
import {
  hashEdgeRequest,
  type EdgeRequestAdmission,
  type EdgeRequestBinding,
} from '../src/edge-gateway/request-ledger.js';

const { Pool } = pg;
const DATABASE_URL = process.env.CONTROL_TEST_DATABASE_URL?.trim() || null;
const REQUIRE_DATABASE = process.env.CONTROL_REQUIRE_POSTGRES_TEST === 'true';
const postgresDescribe = DATABASE_URL ? describe.sequential : describe.skip;

if (REQUIRE_DATABASE && !DATABASE_URL) {
  throw new Error('CONTROL_TEST_DATABASE_URL is required for PostgreSQL ledger tests');
}

function assertDisposableDatabase(connectionString: string): void {
  const databaseName = decodeURIComponent(new URL(connectionString).pathname.slice(1));
  if (!databaseName.endsWith('_test')) {
    throw new Error('PostgreSQL ledger tests require a database name ending in _test');
  }
}

async function resetLedgerTable(connectionString: string): Promise<void> {
  assertDisposableDatabase(connectionString);
  const pool = new Pool({ connectionString, ssl: false, max: 1 });
  try {
    await pool.query('DROP TABLE IF EXISTS control_edge_request_ledger');
  } finally {
    await pool.end();
  }
}

const admission: EdgeRequestAdmission = {
  requestId: 'req_postgres_shared_123',
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

postgresDescribe('PostgreSQL edge request ledger', () => {
  const ledgers = new Set<PostgresEdgeRequestLedger>();
  let now = 1_000;
  let ownerSequence = 0;

  async function openLedger(
    ownerId = `edge-test-${++ownerSequence}`,
  ): Promise<PostgresEdgeRequestLedger> {
    const ledger = await PostgresEdgeRequestLedger.connect({
      connectionString: DATABASE_URL!,
      ssl: false,
      ownerId,
      leaseDurationMs: 100,
      now: () => now,
    });
    ledgers.add(ledger);
    return ledger;
  }

  beforeEach(async () => {
    await resetLedgerTable(DATABASE_URL!);
    now = 1_000;
    ownerSequence = 0;
  });

  afterEach(async () => {
    await Promise.all([...ledgers].map((ledger) => ledger.close()));
    ledgers.clear();
    await resetLedgerTable(DATABASE_URL!);
  });

  it('fails closed without migration privileges and connects after the schema exists', async () => {
    await expect(PostgresEdgeRequestLedger.connect({
      connectionString: DATABASE_URL!,
      ssl: false,
      ownerId: 'edge-least-privilege-before-migration',
      manageSchema: false,
    })).rejects.toThrow(/control_edge_request_ledger/u);

    const migrationOwner = await openLedger('edge-schema-migration-owner');
    await migrationOwner.healthCheck();
    const leastPrivilege = await PostgresEdgeRequestLedger.connect({
      connectionString: DATABASE_URL!,
      ssl: false,
      ownerId: 'edge-least-privilege-after-migration',
      manageSchema: false,
      now: () => now,
    });
    ledgers.add(leastPrivilege);

    await expect(leastPrivilege.healthCheck()).resolves.toBeUndefined();
  });

  it('uses the PostgreSQL clock for production lease deadlines', async () => {
    const ledger = await PostgresEdgeRequestLedger.connect({
      connectionString: DATABASE_URL!,
      ssl: false,
      ownerId: 'edge-database-clock',
      leaseDurationMs: 10_000,
    });
    ledgers.add(ledger);
    await ledger.admit({ ...admission, requestId: 'req_postgres_database_clock' });

    const pool = new Pool({ connectionString: DATABASE_URL!, ssl: false, max: 1 });
    try {
      const result = await pool.query<{ skew_ms: string }>(
        `SELECT abs(
           lease_until_ms
           - floor(extract(epoch from clock_timestamp()) * 1000)::bigint
           - 10000
         )::text AS skew_ms
         FROM control_edge_request_ledger
         WHERE request_id = $1`,
        ['req_postgres_database_clock'],
      );
      expect(Number(result.rows[0]?.skew_ms)).toBeLessThan(5_000);
    } finally {
      await pool.end();
    }
  });
  it('admits one request once across two concurrent ledger instances', async () => {
    const [first, second] = await Promise.all([openLedger(), openLedger()]);
    const results = await Promise.all(
      Array.from(
        { length: 32 },
        (_, index) => (index % 2 === 0 ? first : second).admit(admission),
      ),
    );

    expect(results.filter((result) => result.created)).toHaveLength(1);
    expect(results.every((result) => result.record.state === 'received')).toBe(true);

    const pool = new Pool({ connectionString: DATABASE_URL!, ssl: false, max: 1 });
    try {
      const count = await pool.query<{ count: string }>(
        'SELECT COUNT(*)::text AS count FROM control_edge_request_ledger',
      );
      expect(count.rows[0]?.count).toBe('1');
    } finally {
      await pool.end();
    }
  });

  it('fails closed for tenant, request hash, and reservation conflicts', async () => {
    const [first, second] = await Promise.all([openLedger(), openLedger()]);
    await first.admit(admission);

    await expect(second.admit({
      ...admission,
      tenant: { ...admission.tenant, organizationId: 'organization_beta' },
    })).rejects.toMatchObject({ code: 'EDGE_REQUEST_TENANT_CONFLICT' });
    await expect(second.admit({
      ...admission,
      requestHash: hashEdgeRequest('different request bytes'),
    })).rejects.toMatchObject({ code: 'EDGE_REQUEST_HASH_CONFLICT' });
    await expect(second.admit({
      ...admission,
      reservedUnits: admission.reservedUnits + 1,
    })).rejects.toMatchObject({ code: 'EDGE_REQUEST_RESERVATION_CONFLICT' });
  });

  it('makes every committed state transition visible across instances', async () => {
    const [first, second] = await Promise.all([openLedger(), openLedger()]);
    await first.admit(admission);
    expect(await second.lookup({
      requestId: admission.requestId,
      tenant: admission.tenant,
    })).toMatchObject({ state: 'received', attempts: [] });

    now = 2_000;
    await first.beginAttempt({ ...binding, routeId: 'route_primary' });
    expect(await first.lookup({
      requestId: admission.requestId,
      tenant: admission.tenant,
    })).toMatchObject({
      state: 'executing',
      routeId: 'route_primary',
      attempts: [{ attempt: 1, outcome: null }],
    });
  });

  it('allows only one concurrent beginAttempt across ledger instances', async () => {
    const [first, second] = await Promise.all([openLedger(), openLedger()]);
    await first.admit(admission);
    now = 2_000;

    const results = await Promise.allSettled([
      first.beginAttempt({ ...binding, routeId: 'route_primary' }),
      second.beginAttempt({ ...binding, routeId: 'route_primary' }),
    ]);

    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    const rejected = results.find((result) => result.status === 'rejected');
    expect(rejected).toMatchObject({
      status: 'rejected',
      reason: { code: 'EDGE_REQUEST_FENCING_CONFLICT' },
    });
    expect(await second.lookup({
      requestId: admission.requestId,
      tenant: admission.tenant,
    })).toMatchObject({ state: 'executing', attempts: [{ attempt: 1 }] });
  });

  it('returns the same completed record idempotently from either instance', async () => {
    const [first, second] = await Promise.all([openLedger(), openLedger()]);
    await first.admit(admission);
    now = 2_000;
    await first.beginAttempt({ ...binding, routeId: 'route_primary' });
    now = 3_000;
    const completed = await first.complete({
      ...binding,
      providerRequestId: 'provider-request-postgres-1',
      actualUsage: { inputTokens: 250, outputTokens: 100, totalTokens: 350 },
    });

    const replay = await first.admit(admission);
    const firstRead = await first.lookup({
      requestId: admission.requestId,
      tenant: admission.tenant,
    });
    const secondRead = await second.lookup({
      requestId: admission.requestId,
      tenant: admission.tenant,
    });
    expect(replay).toMatchObject({ created: false, record: { state: 'completed' } });
    expect(firstRead).toEqual(completed);
    expect(secondRead).toEqual(completed);
  });

  it('does not let a fresh instance take over an executing request', async () => {
    const first = await openLedger();
    await first.admit(admission);
    now = 2_000;
    await first.beginAttempt({ ...binding, routeId: 'route_primary' });

    const second = await openLedger();
    expect(await second.lookup({
      requestId: admission.requestId,
      tenant: admission.tenant,
    })).toMatchObject({ state: 'executing', routeId: 'route_primary' });
    await expect(second.beginAttempt({
      ...binding,
      routeId: 'route_fallback',
    })).rejects.toMatchObject({ code: 'EDGE_REQUEST_FENCING_CONFLICT' });
  });

  it('recovers an expired received lease and fences the old owner', async () => {
    const first = await openLedger('edge-first-received');
    await first.admit(admission);
    const second = await openLedger('edge-second-received');

    now = 1_101;
    const recovered = await second.admit(admission);
    expect(recovered).toMatchObject({
      created: true,
      recoveredNotSentRequest: true,
      record: { state: 'received' },
    });
    await expect(first.beginAttempt({
      ...binding,
      routeId: 'route_stale',
    })).rejects.toMatchObject({ code: 'EDGE_REQUEST_FENCING_CONFLICT' });
    await expect(second.beginAttempt({
      ...binding,
      routeId: 'route_recovered',
    })).resolves.toMatchObject({ state: 'executing', routeId: 'route_recovered' });
  });

  it('turns an expired executing lease into unknown outcome without replaying it', async () => {
    const first = await openLedger('edge-first-executing');
    await first.admit(admission);
    now = 1_050;
    await first.beginAttempt({ ...binding, routeId: 'route_primary' });

    const second = await openLedger('edge-second-executing');
    now = 1_151;
    const recovered = await second.admit(admission);
    expect(recovered).toMatchObject({
      created: false,
      record: { state: 'unknown_outcome', routeId: 'route_primary' },
    });
    await expect(first.complete({
      ...binding,
      actualUsage: { inputTokens: 1, outputTokens: 1, totalTokens: 2 },
    })).rejects.toMatchObject({ code: 'EDGE_REQUEST_FENCING_CONFLICT' });
    await expect(second.beginAttempt({
      ...binding,
      routeId: 'route_fallback',
    })).rejects.toMatchObject({ code: 'EDGE_REQUEST_STATE_CONFLICT' });
  });

  it('lets the current fenced owner finish after its lease deadline', async () => {
    const ledger = await openLedger('edge-long-running-owner');
    await ledger.admit(admission);
    now = 1_050;
    await ledger.beginAttempt({ ...binding, routeId: 'route_primary' });

    now = 1_500;
    await expect(ledger.complete({
      ...binding,
      providerRequestId: 'provider-long-running-1',
      actualUsage: { inputTokens: 5, outputTokens: 3, totalTokens: 8 },
    })).resolves.toMatchObject({ state: 'completed' });
  });

  it('closes owned pools idempotently and rejects later operations', async () => {
    const ledger = await openLedger();
    await ledger.close();
    await ledger.close();

    await expect(ledger.admit(admission)).rejects.toThrow(
      'PostgreSQL edge request ledger is closed',
    );
  });
});

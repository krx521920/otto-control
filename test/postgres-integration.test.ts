import { generateKeyPairSync } from 'node:crypto';

import pg from 'pg';
import { afterEach, describe, expect, it } from 'vitest';

import { LocalEd25519Signer } from '../src/crypto/signed-envelope.js';
import { ManagedSigningKeyring } from '../src/crypto/signing-keyring.js';
import { AuditService } from '../src/modules/audit/service.js';
import { BillingService } from '../src/modules/billing/service.js';
import { CommercialControlService } from '../src/modules/commercial-control/service.js';
import { ControlTokenIssuer } from '../src/modules/commercial-control/token-issuer.js';
import { PostgresControlStore } from '../src/storage/postgres-store.js';

const { Pool } = pg;
const DATABASE_URL = process.env.CONTROL_TEST_DATABASE_URL?.trim() || null;
const REQUIRE_DATABASE = process.env.CONTROL_REQUIRE_POSTGRES_TEST === 'true';
const TOKEN_SECRET = 'postgres-integration-token-secret-with-enough-entropy';
const NOW = Date.parse('2026-08-01T10:00:00.000Z');
const DEPLOYMENT_ID = 'dep_postgresintegration01';
const ORGANIZATION_ID = 'org_postgres_integration';
const FINGERPRINT = 'c'.repeat(64);

if (REQUIRE_DATABASE && !DATABASE_URL) {
  throw new Error('CONTROL_TEST_DATABASE_URL is required for PostgreSQL integration tests');
}

function assertDisposableDatabase(connectionString: string): void {
  const databaseName = decodeURIComponent(new URL(connectionString).pathname.slice(1));
  if (!databaseName.endsWith('_test')) {
    throw new Error('PostgreSQL integration tests require a database name ending in _test');
  }
}

async function resetDatabase(connectionString: string): Promise<void> {
  assertDisposableDatabase(connectionString);
  const pool = new Pool({ connectionString, ssl: false, max: 1 });
  try {
    await pool.query('DROP SCHEMA IF EXISTS public CASCADE');
    await pool.query('CREATE SCHEMA public');
  } finally {
    await pool.end();
  }
}

function signer(): LocalEd25519Signer {
  const keys = generateKeyPairSync('ed25519');
  return new LocalEd25519Signer(
    keys.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
  );
}

function service(store: PostgresControlStore, signing = signer()): CommercialControlService {
  return new CommercialControlService({
    store,
    signer: signing,
    tokenIssuer: new ControlTokenIssuer(TOKEN_SECRET),
    publicBaseUrl: 'https://control.integration.test',
    now: () => NOW,
  });
}

const postgresDescribe = DATABASE_URL ? describe.sequential : describe.skip;

postgresDescribe('PostgreSQL commercial control integration', () => {
  const openStores = new Set<PostgresControlStore>();

  async function openStore(): Promise<PostgresControlStore> {
    const store = await PostgresControlStore.connect({
      connectionString: DATABASE_URL!,
      ssl: false,
    });
    openStores.add(store);
    return store;
  }

  async function closeStore(store: PostgresControlStore): Promise<void> {
    if (!openStores.delete(store)) return;
    await store.close();
  }

  afterEach(async () => {
    await Promise.all([...openStores].map((store) => closeStore(store)));
    await resetDatabase(DATABASE_URL!);
  });

  it('reports bounded PostgreSQL pool state and database capacity', async () => {
    await resetDatabase(DATABASE_URL!);
    const store = await openStore();
    await store.ping();

    expect(store.poolSnapshot()).toMatchObject({
      totalConnections: 1,
      idleConnections: 1,
      waitingRequests: 0,
      errorsTotal: 0,
      maximumConnections: 10,
    });
    const capacity = await store.sampleCapacity();
    expect(capacity.sampledAtMs).toBeGreaterThan(0);
    expect(capacity.databaseBytes).toBeGreaterThan(0);
    expect(capacity.relations.control_deployments?.bytes).toBeGreaterThan(0);
  });

  it('serializes concurrent startup and records every migration once', async () => {
    await resetDatabase(DATABASE_URL!);
    const [first, second] = await Promise.all([openStore(), openStore()]);
    await Promise.all([first.ping(), second.ping()]);

    const pool = new Pool({ connectionString: DATABASE_URL!, ssl: false, max: 1 });
    try {
      const migrations = await pool.query<{ id: string }>(
        'SELECT id FROM control_schema_migrations ORDER BY id',
      );
      expect(migrations.rows.at(-1)?.id).toBe('020_managed_release_artifacts');
      expect(new Set(migrations.rows.map((row) => row.id)).size).toBe(migrations.rows.length);
      const billingPolicyColumn = await pool.query<{
        column_name: string;
        column_default: string;
        is_nullable: string;
      }>(
        `SELECT column_name, column_default, is_nullable
         FROM information_schema.columns
         WHERE table_schema = 'public'
           AND table_name = 'control_licenses'
           AND column_name = 'billing_enforcement'`,
      );
      expect(billingPolicyColumn.rows[0]).toMatchObject({
        column_name: 'billing_enforcement',
        is_nullable: 'NO',
      });
      expect(billingPolicyColumn.rows[0]?.column_default).toContain('disabled');
      const tables = await pool.query<{
        licenses: string;
        billing: string;
        witness: string;
        artifact_evidence: string;
      }>(
        `SELECT
          to_regclass('public.control_licenses')::text AS licenses,
          to_regclass('public.control_credit_transactions')::text AS billing,
          to_regclass('public.control_audit_witness_receipts')::text AS witness,
          to_regclass('public.control_release_artifact_evidence')::text AS artifact_evidence`,
      );
      expect(tables.rows[0]).toEqual({
        licenses: 'control_licenses',
        billing: 'control_credit_transactions',
        witness: 'control_audit_witness_receipts',
        artifact_evidence: 'control_release_artifact_evidence',
      });
    } finally {
      await pool.end();
    }
  });

  it('persists artifact metadata and storage evidence atomically across reconnects', async () => {
    await resetDatabase(DATABASE_URL!);
    const store = await openStore();
    const signing = signer();
    const keyring = await ManagedSigningKeyring.create({
      store,
      providers: [{ provider: 'local', signer: signing }],
    });
    await store.createUpdateDistribution({ id: 'otto', name: 'Otto desktop' });
    const release = await store.createUpdateRelease({
      id: 'rel_postgresartifact01',
      distributionId: 'otto',
      version: '2.1.0',
      sourceCommit: 'a'.repeat(40),
      channel: 'stable',
      rolloutPercent: 100,
      notes: 'PostgreSQL managed artifact fixture',
      fullManifestUrl: 'https://control.integration.test/v1/release-artifacts/art_postgresmanaged001/download',
      fullManifestSha256: 'e'.repeat(64),
      incrementalManifestUrl: null,
      incrementalManifestSha256: null,
    });
    const createdAt = new Date(NOW);
    const artifactId = 'art_postgresmanaged001';
    await store.createManagedReleaseArtifact({
      artifact: {
        id: artifactId,
        releaseId: release.id,
        distributionId: release.distributionId,
        releaseVersion: release.version,
        sourceCommit: release.sourceCommit,
        kind: 'update_manifest',
        platform: 'any',
        url: `https://control.integration.test/v1/release-artifacts/${artifactId}/download`,
        sha256: 'e'.repeat(64),
        sizeBytes: 4_096,
        signingKeyId: keyring.keyId,
        signature: 'ed25519:fixture',
        createdAt,
      },
      evidence: {
        objectKey: `releases/${release.id}/manifest.json`,
        objectVersionId: 'version-0001',
        verifiedAt: createdAt,
        serverSideEncryption: 'aws:kms',
        objectLockMode: 'COMPLIANCE',
        objectLockRetainUntil: new Date('2027-08-01T10:00:00.000Z'),
        codeSigning: null,
      },
    });

    await closeStore(store);
    const reopened = await openStore();
    await expect(reopened.getReleaseArtifact(artifactId)).resolves.toMatchObject({
      id: artifactId,
      sha256: 'e'.repeat(64),
    });
    await expect(reopened.getReleaseArtifactEvidence(artifactId)).resolves.toMatchObject({
      artifactId,
      objectVersionId: 'version-0001',
      serverSideEncryption: 'aws:kms',
      objectLockMode: 'COMPLIANCE',
    });
  });

  it('persists signed License, replay protection, and audit state across reconnects', async () => {
    await resetDatabase(DATABASE_URL!);
    const store = await openStore();
    const signing = signer();
    const control = service(store, signing);
    const customer = await control.createCustomer({ name: 'PostgreSQL Customer' }, 'admin:test');
    await control.createDeployment({
      deploymentId: DEPLOYMENT_ID,
      customerId: customer.id,
      organizationId: ORGANIZATION_ID,
      machineFingerprint: FINGERPRINT,
      name: 'PostgreSQL primary deployment',
    }, 'admin:test');
    const issued = await control.issueLicense({
      deploymentId: DEPLOYMENT_ID,
      plan: 'enterprise',
      expiresAt: '2027-08-01T10:00:00.000Z',
      seatLimit: 25,
      modules: ['enterprise_tree', 'direct_messages', 'park_service'],
    }, 'admin:test');
    const leaseRequest = {
      version: 1 as const,
      licenseId: issued.license.id,
      deploymentId: DEPLOYMENT_ID,
      organizationId: ORGANIZATION_ID,
      machineFingerprint: FINGERPRINT,
      nonce: 'postgres_lease_nonce_0001',
      activeSeatCount: 7,
    };
    await expect(control.issueLease(
      issued.license.id,
      leaseRequest,
      issued.license.leaseToken!,
    )).resolves.toMatchObject({ lease: { activeSeatCount: 7, seatStatus: 'within_limit' } });
    await expect(control.issueLease(
      issued.license.id,
      leaseRequest,
      issued.license.leaseToken!,
    )).rejects.toMatchObject({ code: 'CONFLICT' });
    await expect(control.renewLicense(issued.license.id, {
      expiresAt: '2028-08-01T10:00:00.000Z',
      gracePeriodDays: 10,
    }, 'admin:test')).resolves.toMatchObject({
      license: { revision: 2, gracePeriodMs: 10 * 24 * 60 * 60 * 1000 },
    });

    const audit = new AuditService({
      store,
      signer: signing,
      issuer: 'https://control.integration.test',
      now: () => NOW,
    });
    await expect(audit.verify()).resolves.toMatchObject({
      receipt: { valid: true, firstSequence: 1 },
    });

    const raw = new Pool({ connectionString: DATABASE_URL!, ssl: false, max: 1 });
    try {
      const stored = await raw.query('SELECT * FROM control_licenses WHERE id = $1', [
        issued.license.id,
      ]);
      const serialized = JSON.stringify(stored.rows[0]);
      expect(serialized).not.toContain(issued.license.leaseToken!);
      expect(serialized).not.toContain(issued.license.telemetryToken!);
    } finally {
      await raw.end();
    }

    await closeStore(store);
    const reopened = await openStore();
    const overview = await service(reopened).operatorOverview(10);
    expect(overview.counts).toMatchObject({
      customers: { total: 1, active: 1 },
      deployments: { total: 1, active: 1 },
      licenses: { total: 1, active: 1 },
    });
    await expect(service(reopened).licenseLifecycle(issued.license.id, 10)).resolves.toMatchObject([
      { revision: 2, changeType: 'renewed' },
    ]);
  });

  it('charges one PostgreSQL transaction for concurrent idempotent usage requests', async () => {
    await resetDatabase(DATABASE_URL!);
    const store = await openStore();
    const control = service(store);
    const customer = await control.createCustomer({ name: 'Billing Customer' }, 'admin:test');
    await control.createDeployment({
      deploymentId: DEPLOYMENT_ID,
      customerId: customer.id,
      organizationId: ORGANIZATION_ID,
      machineFingerprint: FINGERPRINT,
      name: 'Billing deployment',
    }, 'admin:test');
    const issued = await control.issueLicense({
      deploymentId: DEPLOYMENT_ID,
      plan: 'enterprise',
      expiresAt: '2027-08-01T10:00:00.000Z',
      seatLimit: 25,
      modules: ['enterprise_tree'],
    }, 'admin:test');
    const billing = new BillingService({
      store,
      tokenIssuer: new ControlTokenIssuer(TOKEN_SECRET),
      now: () => NOW,
    });
    await billing.setRate(customer.id, {
      module: 'model_gateway', unitSize: 1_000, creditsPerUnit: 3,
    }, 'admin:test');
    await billing.topUp(customer.id, {
      amount: 100,
      idempotencyKey: 'topup:postgres-integration',
      referenceId: 'invoice:postgres-integration',
    }, 'admin:test');
    const request = {
      licenseId: issued.license.id,
      deploymentId: DEPLOYMENT_ID,
      organizationId: ORGANIZATION_ID,
      machineFingerprint: FINGERPRINT,
      module: 'model_gateway' as const,
      units: 1_001,
      idempotencyKey: 'usage:postgres-concurrent',
      referenceId: 'request:postgres-concurrent',
    };
    const results = await Promise.all(Array.from(
      { length: 8 },
      () => billing.consumeUsage(request, issued.license.leaseToken!),
    ));
    expect(new Set(results.map((result) => result.transaction.id)).size).toBe(1);
    expect(results.filter((result) => !result.replayed)).toHaveLength(1);
    expect(await billing.account(customer.id)).toMatchObject({
      availableBalance: 94,
      totalConsumed: 6,
    });

    const raw = new Pool({ connectionString: DATABASE_URL!, ssl: false, max: 1 });
    try {
      const count = await raw.query<{ count: string }>(
        `SELECT COUNT(*)::text AS count FROM control_credit_transactions
         WHERE customer_id = $1 AND idempotency_key = $2`,
        [customer.id, request.idempotencyKey],
      );
      expect(count.rows[0]?.count).toBe('1');
    } finally {
      await raw.end();
    }
  });
});

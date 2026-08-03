import { createHash, generateKeyPairSync } from 'node:crypto';

import pg from 'pg';
import { afterEach, describe, expect, it } from 'vitest';

import { canonicalJson, LocalEd25519Signer } from '../src/crypto/signed-envelope.js';
import { ManagedSigningKeyring } from '../src/crypto/signing-keyring.js';
import { AuditService } from '../src/modules/audit/service.js';
import { BillingService } from '../src/modules/billing/service.js';
import { CommercialControlService } from '../src/modules/commercial-control/service.js';
import { ControlTokenIssuer } from '../src/modules/commercial-control/token-issuer.js';
import { PostgresFederationStore } from '../src/modules/federation/postgres-store.js';
import { FederationService } from '../src/modules/federation/service.js';
import { CONTROL_SCHEMA_MIGRATION_IDS } from '../src/storage/migrations.js';
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
      expect(migrations.rows.map((row) => row.id)).toEqual(CONTROL_SCHEMA_MIGRATION_IDS);
      expect(new Set(migrations.rows.map((row) => row.id)).size).toBe(migrations.rows.length);
      await expect(first.runDataRetention({
        telemetryBefore: new Date(NOW - 24 * 60 * 60 * 1_000),
        exportPayloadBefore: new Date(NOW - 24 * 60 * 60 * 1_000),
        now: new Date(NOW),
      })).resolves.toEqual({
        telemetryEventsDeleted: 0,
        expiredNoncesDeleted: 0,
        expiredExportPayloadsRestricted: 0,
      });
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
        execution_receipts: string;
        witness: string;
        artifact_evidence: string;
        witness_evidence: string;
      }>(
        `SELECT
          to_regclass('public.control_licenses')::text AS licenses,
          to_regclass('public.control_credit_transactions')::text AS billing,
          to_regclass('public.control_execution_receipts')::text AS execution_receipts,
          to_regclass('public.control_audit_witness_receipts')::text AS witness,
          to_regclass('public.control_release_artifact_evidence')::text AS artifact_evidence,
          to_regclass('public.control_audit_witness_evidence')::text AS witness_evidence`,
      );
      expect(tables.rows[0]).toEqual({
        licenses: 'control_licenses',
        billing: 'control_credit_transactions',
        execution_receipts: 'control_execution_receipts',
        witness: 'control_audit_witness_receipts',
        artifact_evidence: 'control_release_artifact_evidence',
        witness_evidence: 'control_audit_witness_evidence',
      });
    } finally {
      await pool.end();
    }
  });

  it('persists witness receipt and WORM outbox atomically and leases one worker', async () => {
    await resetDatabase(DATABASE_URL!);
    const store = await openStore();
    const signing = signer();
    await store.appendAuditEvent({
      actorId: 'admin:test', action: 'license.issue', targetType: 'license',
      targetId: 'lic_postgres_worm', detail: {},
    });
    const audit = new AuditService({
      store,
      signer: signing,
      issuer: 'https://source.integration.test',
      now: () => NOW,
    });
    const signed = await audit.verify();
    const fingerprint = createHash('sha256').update(canonicalJson({
      issuer: signed.receipt.issuer,
      lastSequence: signed.receipt.lastSequence,
      headHash: signed.receipt.headHash,
    })).digest('hex');
    const receivedAt = new Date(NOW);
    const receipt = {
      id: `witness_${'1'.padStart(32, '0')}`,
      sourceId: 'primary-control',
      anchorId: `anchor_${'1'.padStart(32, '0')}`,
      fingerprint,
      issuer: signed.receipt.issuer,
      chainSequence: signed.receipt.lastSequence,
      headHash: signed.receipt.headHash,
      signingKeyId: signed.signingKeyId,
      payload: {
        version: 1 as const,
        anchorId: `anchor_${'1'.padStart(32, '0')}`,
        fingerprint,
        evidence: signed,
      },
      receivedAt,
    };
    const evidence = {
      receiptId: receipt.id,
      sourceId: receipt.sourceId,
      chainSequence: receipt.chainSequence,
      objectKey: 'audit/primary-control/00000000000000000001.json',
      contentSha256: 'd'.repeat(64),
      sizeBytes: 512,
      status: 'pending' as const,
      attempts: 0,
      nextAttemptAt: receivedAt,
      leaseUntil: null,
      lastError: null,
      objectVersionId: null,
      serverSideEncryption: null,
      objectLockMode: null,
      objectLockRetainUntil: null,
      storedAt: null,
      verifiedAt: null,
      createdAt: receivedAt,
      updatedAt: receivedAt,
    };
    await store.ingestAuditWitnessReceipt({
      record: receipt,
      evidence,
      audit: {
        actorId: 'audit-source:primary-control', action: 'audit.witness.received',
        targetType: 'audit_witness_receipt', targetId: receipt.id, detail: {},
      },
    });
    const leaseUntil = new Date(NOW + 120_000);
    const [first, second] = await Promise.all([
      store.claimAuditWitnessEvidence({ now: receivedAt, leaseUntil }),
      store.claimAuditWitnessEvidence({ now: receivedAt, leaseUntil }),
    ]);
    expect([first, second].filter(Boolean)).toHaveLength(1);
    const claimed = first ?? second!;
    await expect(store.finishAuditWitnessEvidence({
      receiptId: receipt.id,
      expectedLeaseUntil: claimed.leaseUntil!,
      status: 'stored',
      nextAttemptAt: receivedAt,
      lastError: null,
      objectVersionId: 'version-1',
      serverSideEncryption: 'AES256',
      objectLockMode: 'COMPLIANCE',
      objectLockRetainUntil: new Date('2027-08-02T00:00:00.000Z'),
      storedAt: receivedAt,
      verifiedAt: receivedAt,
      updatedAt: receivedAt,
      audit: {
        actorId: 'system:audit-worm-worker', action: 'audit.witness.worm_stored',
        targetType: 'audit_witness_evidence', targetId: receipt.id, detail: {},
      },
    })).resolves.toMatchObject({ status: 'stored', objectVersionId: 'version-1' });
    await closeStore(store);
    const reopened = await openStore();
    await expect(reopened.getAuditWitnessReceipt(receipt.id)).resolves.toMatchObject({
      fingerprint,
    });
    await expect(reopened.summarizeAuditWitnessEvidence()).resolves.toMatchObject({
      counts: { stored: 1, failed: 0 },
    });
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
      organizationId: ORGANIZATION_ID,
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
    expect(await billing.account(customer.id, ORGANIZATION_ID)).toMatchObject({
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

  it('atomically verifies one signed execution receipt under concurrent delivery', async () => {
    await resetDatabase(DATABASE_URL!);
    const store = await openStore();
    const control = service(store);
    const customer = await control.createCustomer({ name: 'Receipt Customer' }, 'admin:test');
    await control.createDeployment({
      deploymentId: DEPLOYMENT_ID,
      customerId: customer.id,
      organizationId: ORGANIZATION_ID,
      machineFingerprint: FINGERPRINT,
      name: 'Receipt deployment',
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
    const receiptSigner = signer();
    await billing.registerExecutionReceiptKey(DEPLOYMENT_ID, {
      publicKeyPem: receiptSigner.publicKeyPem,
      expiresAt: '2027-08-01T00:00:00.000Z',
    }, 'security:test');
    await billing.setRate(customer.id, {
      module: 'model_gateway', unitSize: 1_000, creditsPerUnit: 3,
    }, 'admin:test');
    await billing.topUp(customer.id, {
      organizationId: ORGANIZATION_ID,
      amount: 100,
      idempotencyKey: 'topup:postgres-receipt',
      referenceId: 'invoice:postgres-receipt',
    }, 'admin:test');
    const receipt = {
      version: 2 as const,
      receiptId: 'exec_88888888888888888888888888888888',
      deploymentId: DEPLOYMENT_ID,
      organizationId: ORGANIZATION_ID,
      taskId: 'task_postgres_receipt',
      moduleId: 'model_gateway' as const,
      units: 1_001,
      model: 'deepseek-v3',
      issuedAtMs: NOW,
      expiresAtMs: NOW + 60 * 60 * 1000,
      sequence: 1,
      policyVersion: 'commercial-v2',
    };
    const request = {
      licenseId: issued.license.id,
      machineFingerprint: FINGERPRINT,
      envelope: {
        receipt,
        signingKeyId: receiptSigner.keyId,
        signature: await receiptSigner.sign(receipt),
      },
    };
    const results = await Promise.all(Array.from(
      { length: 8 },
      () => billing.consumeExecutionReceipt(request, issued.license.leaseToken!),
    ));
    expect(new Set(results.map((result) => result.transaction.id)).size).toBe(1);
    expect(results.filter((result) => !result.replayed)).toHaveLength(1);
    expect(await billing.account(customer.id, ORGANIZATION_ID)).toMatchObject({
      availableBalance: 94,
      totalConsumed: 6,
    });

    const raw = new Pool({ connectionString: DATABASE_URL!, ssl: false, max: 1 });
    try {
      const counts = await raw.query<{ receipts: string; transactions: string }>(
        `SELECT
          (SELECT COUNT(*) FROM control_execution_receipts WHERE customer_id = $1)::text
            AS receipts,
          (SELECT COUNT(*) FROM control_credit_transactions
             WHERE customer_id = $1 AND idempotency_key = $2)::text AS transactions`,
        [customer.id, `receipt:${receipt.receiptId}`],
      );
      expect(counts.rows[0]).toEqual({ receipts: '1', transactions: '1' });
    } finally {
      await raw.end();
    }
  });

  it('atomically consumes a federation A2A grant under concurrent delivery', async () => {
    await resetDatabase(DATABASE_URL!);
    const store = await PostgresFederationStore.connect({
      connectionString: DATABASE_URL!,
      ssl: false,
    });
    try {
      const federation = new FederationService({ store, now: () => NOW });
      const sender = signer();
      const recipient = signer();
      for (const [id, origin, key] of [
        ['deployment_federation_a', 'https://federation-a.test', sender],
        ['deployment_federation_b', 'https://federation-b.test', recipient],
      ] as const) {
        await federation.registerDeployment({
          id,
          displayName: id,
          origin,
          capabilities: ['federation.v1', 'a2a.e2ee'],
        });
        await federation.registerKey(id, { publicKeyPem: key.publicKeyPem });
      }
      const grantRequest = {
        version: 1 as const,
        deploymentId: 'deployment_federation_b',
        issuedAt: new Date(NOW).toISOString(),
        expiresAt: new Date(NOW + 60_000).toISOString(),
        nonce: 'nonce_grant_postgres_2026',
        grantId: 'fgrant_postgres_concurrency',
        requesterDeploymentId: 'deployment_federation_a',
        ownerPrincipalId: 'account_recipient',
        requesterPrincipalId: 'account_sender',
        scopes: ['worklog.read'],
        maxUses: 1,
        grantExpiresAt: new Date(NOW + 10 * 60_000).toISOString(),
      };
      await federation.createA2aGrant({
        request: grantRequest,
        signingKeyId: recipient.keyId,
        signature: await recipient.sign(grantRequest),
      });
      const envelopes = await Promise.all([1, 2].map(async (index) => {
        const envelope = {
          version: 1 as const,
          messageId: `fmsg_postgres_concurrent_${index}`,
          type: 'a2a.request' as const,
          senderDeploymentId: 'deployment_federation_a',
          recipientDeploymentId: 'deployment_federation_b',
          issuedAt: new Date(NOW).toISOString(),
          expiresAt: new Date(NOW + 60_000).toISOString(),
          nonce: `nonce_message_postgres_${index}_2026`,
          contentType: 'application/otto-e2ee+json' as const,
          ciphertext: `Y2lwaGVydGV4dF8${index}`,
          routing: {
            conversationId: 'conversation_postgres',
            senderPrincipalId: 'account_sender',
            recipientPrincipalId: 'account_recipient',
            a2aGrantId: 'fgrant_postgres_concurrency',
            a2aScope: 'worklog.read',
          },
        };
        return {
          envelope,
          signingKeyId: sender.keyId,
          signature: await sender.sign(envelope),
        };
      }));
      const results = await Promise.allSettled(envelopes.map((envelope) => federation.enqueue(envelope)));
      expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
      expect(results.filter((result) => result.status === 'rejected')).toHaveLength(1);

      const raw = new Pool({ connectionString: DATABASE_URL!, ssl: false, max: 1 });
      try {
        const grant = await raw.query<{ used_count: number }>(
          'SELECT used_count FROM control_federation_a2a_grants WHERE id = $1',
          ['fgrant_postgres_concurrency'],
        );
        const messages = await raw.query<{ count: string }>(
          `SELECT COUNT(*)::text AS count FROM control_federation_messages
           WHERE message_type = 'a2a.request'`,
        );
        expect(grant.rows[0]?.used_count).toBe(1);
        expect(messages.rows[0]?.count).toBe('1');
      } finally {
        await raw.end();
      }
    } finally {
      await store.close();
    }
  });

  it('keeps federation nonce, grant, and inbox capacity changes atomic under concurrency', async () => {
    await resetDatabase(DATABASE_URL!);
    const store = await PostgresFederationStore.connect({
      connectionString: DATABASE_URL!,
      ssl: false,
    });
    try {
      const federation = new FederationService({ store, now: () => NOW });
      const sender = signer();
      const recipient = signer();
      for (const [id, origin, key] of [
        ['deployment_atomic_a', 'https://atomic-a.test', sender],
        ['deployment_atomic_b', 'https://atomic-b.test', recipient],
      ] as const) {
        await federation.registerDeployment({
          id,
          displayName: id,
          origin,
          capabilities: ['federation.v1', 'chat.e2ee', 'a2a.e2ee'],
          maxPendingMessages: 100,
        });
        await federation.registerKey(id, { publicKeyPem: key.publicKeyPem });
      }

      const retryEnvelope = {
        version: 1 as const,
        messageId: 'fmsg_atomic_retry_2026',
        type: 'a2a.request' as const,
        senderDeploymentId: 'deployment_atomic_a',
        recipientDeploymentId: 'deployment_atomic_b',
        issuedAt: new Date(NOW).toISOString(),
        expiresAt: new Date(NOW + 60_000).toISOString(),
        nonce: 'nonce_atomic_retry_2026',
        contentType: 'application/otto-e2ee+json' as const,
        ciphertext: 'YXRvbWljLXJldHJ5',
        routing: {
          conversationId: 'conversation_atomic',
          senderPrincipalId: 'account_sender',
          recipientPrincipalId: 'account_recipient',
          a2aGrantId: 'fgrant_atomic_retry_2026',
          a2aScope: 'worklog.read',
        },
      };
      const signedRetryEnvelope = {
        envelope: retryEnvelope,
        signingKeyId: sender.keyId,
        signature: await sender.sign(retryEnvelope),
      };
      await expect(federation.enqueue(signedRetryEnvelope)).rejects.toThrow('A2A grant is invalid');

      const grantRequest = {
        version: 1 as const,
        deploymentId: 'deployment_atomic_b',
        issuedAt: new Date(NOW).toISOString(),
        expiresAt: new Date(NOW + 60_000).toISOString(),
        nonce: 'nonce_atomic_grant_2026',
        grantId: 'fgrant_atomic_retry_2026',
        requesterDeploymentId: 'deployment_atomic_a',
        ownerPrincipalId: 'account_recipient',
        requesterPrincipalId: 'account_sender',
        scopes: ['worklog.read'],
        maxUses: 1,
        grantExpiresAt: new Date(NOW + 10 * 60_000).toISOString(),
      };
      await federation.createA2aGrant({
        request: grantRequest,
        signingKeyId: recipient.keyId,
        signature: await recipient.sign(grantRequest),
      });
      await expect(federation.enqueue(signedRetryEnvelope)).resolves.toMatchObject({ duplicate: false });

      const chatEnvelopes = await Promise.all(Array.from({ length: 100 }, async (_, index) => {
        const envelope = {
          version: 1 as const,
          messageId: `fmsg_capacity_${index}_2026`,
          type: 'chat.message' as const,
          senderDeploymentId: 'deployment_atomic_a',
          recipientDeploymentId: 'deployment_atomic_b',
          issuedAt: new Date(NOW).toISOString(),
          expiresAt: new Date(NOW + 60_000).toISOString(),
          nonce: `nonce_capacity_${index}_2026`,
          contentType: 'application/otto-e2ee+json' as const,
          ciphertext: Buffer.from(`ciphertext-${index}`).toString('base64url'),
          routing: {
            conversationId: 'conversation_capacity',
            senderPrincipalId: 'account_sender',
            recipientPrincipalId: 'account_recipient',
          },
        };
        return {
          envelope,
          signingKeyId: sender.keyId,
          signature: await sender.sign(envelope),
        };
      }));
      const results = await Promise.allSettled(chatEnvelopes.map((envelope) => federation.enqueue(envelope)));
      expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(99);
      const rejectedIndex = results.findIndex((result) => result.status === 'rejected');
      expect(rejectedIndex).toBeGreaterThanOrEqual(0);

      const raw = new Pool({ connectionString: DATABASE_URL!, ssl: false, max: 1 });
      try {
        const pending = await raw.query<{ count: string }>(
          `SELECT COUNT(*)::text AS count FROM control_federation_messages
           WHERE recipient_deployment_id = $1 AND status IN ('pending', 'claimed')`,
          ['deployment_atomic_b'],
        );
        expect(pending.rows[0]?.count).toBe('100');
        await raw.query(
          `UPDATE control_federation_messages SET status = 'delivered', delivered_at = $2
           WHERE message_id = $1`,
          ['fmsg_atomic_retry_2026', new Date(NOW)],
        );
      } finally {
        await raw.end();
      }

      await expect(federation.enqueue(chatEnvelopes[rejectedIndex]!)).resolves.toMatchObject({ duplicate: false });
    } finally {
      await store.close();
    }
  });

  it('shares federation inbox leases and deployment rate budgets across three stores', async () => {
    await resetDatabase(DATABASE_URL!);
    const stores = await Promise.all(Array.from({ length: 3 }, () => PostgresFederationStore.connect({
      connectionString: DATABASE_URL!,
      ssl: false,
    })));
    try {
      const federations = stores.map((store) => new FederationService({ store, now: () => NOW }));
      const sender = signer();
      const recipient = signer();
      const rateSigner = signer();
      for (const [id, origin, key, rate] of [
        ['deployment_replica_a', 'https://replica-a.test', sender, 1_200],
        ['deployment_replica_b', 'https://replica-b.test', recipient, 1_200],
        ['deployment_replica_rate', 'https://replica-rate.test', rateSigner, 60],
      ] as const) {
        await federations[0]!.registerDeployment({
          id,
          displayName: id,
          origin,
          capabilities: ['federation.v1', 'chat.e2ee'],
          maxRequestsPerMinute: rate,
        });
        await federations[0]!.registerKey(id, { publicKeyPem: key.publicKeyPem });
      }

      const envelopes = await Promise.all(Array.from({ length: 6 }, async (_, index) => {
        const envelope = {
          version: 1 as const,
          messageId: `fmsg_three_replica_${index}`,
          type: 'chat.message' as const,
          senderDeploymentId: 'deployment_replica_a',
          recipientDeploymentId: 'deployment_replica_b',
          issuedAt: new Date(NOW).toISOString(),
          expiresAt: new Date(NOW + 60_000).toISOString(),
          nonce: `nonce_three_replica_message_${index}`,
          contentType: 'application/otto-e2ee+json' as const,
          ciphertext: Buffer.from(`three-replica-${index}`).toString('base64url'),
          routing: {
            conversationId: 'conversation_three_replica',
            senderPrincipalId: 'account_sender',
            recipientPrincipalId: 'account_recipient',
          },
        };
        return {
          envelope,
          signingKeyId: sender.keyId,
          signature: await sender.sign(envelope),
        };
      }));
      await Promise.all(envelopes.map((envelope, index) =>
        federations[index % federations.length]!.enqueue(envelope)));

      const claims = await Promise.all(federations.map(async (federation, index) => {
        const request = {
          version: 1 as const,
          deploymentId: 'deployment_replica_b',
          issuedAt: new Date(NOW).toISOString(),
          expiresAt: new Date(NOW + 60_000).toISOString(),
          nonce: `nonce_three_replica_claim_${index}`,
          limit: 10,
        };
        return federation.claim({
          request,
          signingKeyId: recipient.keyId,
          signature: await recipient.sign(request),
        });
      }));
      const claimed = claims.flatMap((result) => result.messages as Array<{
        envelope: { messageId: string };
        claimToken: string;
      }>);
      expect(claimed).toHaveLength(envelopes.length);
      expect(new Set(claimed.map((item) => item.envelope.messageId)).size).toBe(envelopes.length);

      await Promise.all(claimed.map(async (item, index) => {
        const request = {
          version: 1 as const,
          deploymentId: 'deployment_replica_b',
          issuedAt: new Date(NOW).toISOString(),
          expiresAt: new Date(NOW + 60_000).toISOString(),
          nonce: `nonce_three_replica_ack_${index}`,
          messageId: item.envelope.messageId,
          claimToken: item.claimToken,
        };
        return federations[(index + 1) % federations.length]!.acknowledge({
          request,
          signingKeyId: recipient.keyId,
          signature: await recipient.sign(request),
        });
      }));
      await expect(stores[2]!.queueStats()).resolves.toMatchObject({ delivered: envelopes.length });

      const rateResults = await Promise.all(Array.from({ length: 61 }, (_, index) =>
        stores[index % stores.length]!.consumeRateLimit('deployment_replica_rate', new Date(NOW))));
      expect(rateResults.filter(Boolean)).toHaveLength(60);
      expect(rateResults.filter((accepted) => !accepted)).toHaveLength(1);
    } finally {
      await Promise.all(stores.map((store) => store.close()));
    }
  });
});

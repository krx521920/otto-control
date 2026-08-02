import { createHash, generateKeyPairSync } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import type { AuditAnchorPayload } from '../src/contracts/audit-anchor.js';
import { canonicalJson, LocalEd25519Signer } from '../src/crypto/signed-envelope.js';
import { AuditService } from '../src/modules/audit/service.js';
import { AuditWitnessService } from '../src/modules/audit-witness/service.js';
import type { AuditWitnessSource } from '../src/modules/audit-witness/source-config.js';
import type {
  AuditWitnessWormObject,
  AuditWitnessWormObjectStore,
} from '../src/modules/audit-witness/worm-object-store.js';
import { MemoryControlStore } from './helpers/memory-store.js';

const TOKEN = 'worm-audit-source-token-with-enough-entropy';
const ISSUER = 'https://source.control.example.test';
const NOW = Date.parse('2026-08-02T00:00:00.000Z');

class MemoryWormStore implements AuditWitnessWormObjectStore {
  readonly prefix = 'audit-worm';
  readonly requiredLockMode = 'COMPLIANCE' as const;
  readonly requiredEncryption = 'AES256' as const;
  readonly objects = new Map<string, { body: Uint8Array; metadata: AuditWitnessWormObject }>();
  failWrites = false;

  async assertReady(): Promise<void> {}

  objectKey(sourceId: string, chainSequence: number): string {
    return `${this.prefix}/${sourceId}/${String(chainSequence).padStart(20, '0')}.json`;
  }

  async put(input: {
    objectKey: string;
    body: Uint8Array;
    sha256: string;
    retainUntil: Date;
  }): Promise<AuditWitnessWormObject> {
    if (this.failWrites) throw new Error('object storage unavailable');
    const existing = this.objects.get(input.objectKey);
    if (existing) {
      const digest = createHash('sha256').update(existing.body).digest('hex');
      if (digest !== input.sha256) throw new Error('immutable object conflict');
      return existing.metadata;
    }
    const metadata: AuditWitnessWormObject = {
      objectKey: input.objectKey,
      sizeBytes: input.body.byteLength,
      checksumSha256: input.sha256,
      versionId: 'version-1',
      serverSideEncryption: 'AES256',
      objectLockMode: 'COMPLIANCE',
      objectLockRetainUntil: input.retainUntil.toISOString(),
    };
    this.objects.set(input.objectKey, { body: Uint8Array.from(input.body), metadata });
    return metadata;
  }

  async inspect(objectKey: string): Promise<AuditWitnessWormObject> {
    const stored = this.objects.get(objectKey);
    if (!stored) throw new Error('object missing');
    return stored.metadata;
  }

  async read(objectKey: string): Promise<Uint8Array> {
    const stored = this.objects.get(objectKey);
    if (!stored) throw new Error('object missing');
    return stored.body;
  }

  async list(): Promise<{ objectKeys: string[]; continuationToken: null }> {
    return { objectKeys: [...this.objects.keys()].sort(), continuationToken: null };
  }
}

async function fixture(options: { maxAttempts?: number } = {}): Promise<{
  service: AuditWitnessService;
  sourceStore: MemoryControlStore;
  witnessStore: MemoryControlStore;
  wormStore: MemoryWormStore;
  audit: AuditService;
}> {
  const keys = generateKeyPairSync('ed25519');
  const signer = new LocalEd25519Signer(
    keys.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
  );
  const sourceStore = new MemoryControlStore();
  const witnessStore = new MemoryControlStore();
  const wormStore = new MemoryWormStore();
  const source: AuditWitnessSource = {
    id: 'primary-control',
    issuer: ISSUER,
    tokenHash: createHash('sha256').update(TOKEN).digest(),
    publicKeys: new Map([[signer.keyId, signer.publicKey]]),
  };
  const audit = new AuditService({ store: sourceStore, signer, issuer: ISSUER, now: () => NOW });
  return {
    sourceStore,
    witnessStore,
    wormStore,
    audit,
    service: new AuditWitnessService({
      store: witnessStore,
      sources: [source],
      wormStore,
      wormRequired: true,
      retentionDays: 365,
      maxAttempts: options.maxAttempts,
      now: () => NOW,
    }),
  };
}

async function anchor(audit: AuditService): Promise<AuditAnchorPayload> {
  const evidence = await audit.verify();
  const fingerprint = createHash('sha256').update(canonicalJson({
    issuer: evidence.receipt.issuer,
    lastSequence: evidence.receipt.lastSequence,
    headHash: evidence.receipt.headHash,
  })).digest('hex');
  return {
    version: 1,
    anchorId: `anchor_${'1'.padStart(32, '0')}`,
    fingerprint,
    evidence,
  };
}

describe('audit witness WORM evidence', () => {
  it('atomically queues, stores and byte-verifies immutable evidence', async () => {
    const values = await fixture();
    await values.sourceStore.appendAuditEvent({
      actorId: 'admin', action: 'license.issue', targetType: 'license', targetId: 'lic_1', detail: {},
    });
    const accepted = await values.service.ingest(await anchor(values.audit), TOKEN);
    expect(values.witnessStore.auditWitnessEvidence.get(accepted.receipt.id)?.status).toBe('pending');

    await expect(values.service.pollEvidenceOnce()).resolves.toMatchObject({
      enabled: true, processed: 1, stored: 1, failed: 0,
    });
    expect(values.witnessStore.auditWitnessEvidence.get(accepted.receipt.id)).toMatchObject({
      status: 'stored',
      objectVersionId: 'version-1',
      objectLockMode: 'COMPLIANCE',
      serverSideEncryption: 'AES256',
    });
    await expect(values.service.verifyEvidence(accepted.receipt.id)).resolves.toMatchObject({
      verified: true,
    });
    await expect(values.service.evidenceStatus()).resolves.toMatchObject({
      enabled: true, required: true, healthy: true, stored: 1, failed: 0,
    });
  });

  it('does not lose accepted receipts when storage fails and supports audited retry', async () => {
    const values = await fixture({ maxAttempts: 1 });
    values.wormStore.failWrites = true;
    const accepted = await values.service.ingest(await anchor(values.audit), TOKEN);
    await expect(values.service.pollEvidenceOnce()).resolves.toMatchObject({ failed: 1 });
    expect(values.witnessStore.auditWitnessReceipts).toHaveLength(1);
    expect(values.witnessStore.auditWitnessEvidence.get(accepted.receipt.id)?.status).toBe('failed');
    await expect(values.service.evidenceStatus()).resolves.toMatchObject({ healthy: false, failed: 1 });

    values.wormStore.failWrites = false;
    await values.service.retryEvidence(accepted.receipt.id, 'admin_security');
    await expect(values.service.pollEvidenceOnce()).resolves.toMatchObject({ stored: 1 });
    expect(values.witnessStore.audits.map((event) => event.action)).toEqual(expect.arrayContaining([
      'audit.witness.worm_failed',
      'audit.witness.worm_retried',
      'audit.witness.worm_stored',
    ]));
  });

  it('detects object-byte replacement even when metadata still claims the accepted digest', async () => {
    const values = await fixture();
    const accepted = await values.service.ingest(await anchor(values.audit), TOKEN);
    await values.service.pollEvidenceOnce();
    const evidence = values.witnessStore.auditWitnessEvidence.get(accepted.receipt.id)!;
    const stored = values.wormStore.objects.get(evidence.objectKey)!;
    stored.body = Buffer.from('{"tampered":true}', 'utf8');

    await expect(values.service.verifyEvidence(accepted.receipt.id)).rejects.toThrow(
      'object bytes do not match',
    );
  });

  it('rebuilds a deleted PostgreSQL witness index from signed WORM evidence', async () => {
    const values = await fixture();
    const accepted = await values.service.ingest(await anchor(values.audit), TOKEN);
    await values.service.pollEvidenceOnce();
    values.witnessStore.auditWitnessReceipts.length = 0;
    values.witnessStore.auditWitnessEvidence.clear();

    await expect(values.service.recoverEvidence({ limit: 100 }, 'admin_security')).resolves.toEqual({
      processed: 1,
      restored: 1,
      replayed: 0,
      continuationToken: null,
    });
    expect(values.witnessStore.auditWitnessReceipts[0]?.id).toBe(accepted.receipt.id);
    expect(values.witnessStore.auditWitnessEvidence.get(accepted.receipt.id)?.status).toBe('stored');
  });
});

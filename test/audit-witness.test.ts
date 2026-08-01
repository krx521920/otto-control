import { createHash, generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import type { AuditAnchorPayload } from '../src/contracts/audit-anchor.js';
import { canonicalJson, LocalEd25519Signer, signPayload } from '../src/crypto/signed-envelope.js';
import { AuditService } from '../src/modules/audit/service.js';
import { AuditWitnessService } from '../src/modules/audit-witness/service.js';
import {
  loadAuditWitnessSources,
  type AuditWitnessSource,
} from '../src/modules/audit-witness/source-config.js';
import { MemoryControlStore } from './helpers/memory-store.js';

const ISSUER = 'https://control.example.test';
const TOKEN = 'trusted-audit-source-token-with-enough-entropy';
const NOW = Date.parse('2026-08-01T12:00:00.000Z');

function fixture(): {
  signer: LocalEd25519Signer;
  sourceStore: MemoryControlStore;
  witnessStore: MemoryControlStore;
  audit: AuditService;
  source: AuditWitnessSource;
  witness: AuditWitnessService;
} {
  const keys = generateKeyPairSync('ed25519');
  const signer = new LocalEd25519Signer(
    keys.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
  );
  const sourceStore = new MemoryControlStore();
  const witnessStore = new MemoryControlStore();
  const source: AuditWitnessSource = {
    id: 'primary-control',
    issuer: ISSUER,
    tokenHash: createHash('sha256').update(TOKEN).digest(),
    publicKeys: new Map([[signer.keyId, signer.publicKey]]),
  };
  const audit = new AuditService({
    store: sourceStore,
    signer,
    issuer: ISSUER,
    now: () => NOW,
  });
  return {
    signer,
    sourceStore,
    witnessStore,
    source,
    audit,
    witness: new AuditWitnessService({ store: witnessStore, sources: [source], now: () => NOW }),
  };
}

async function payload(
  audit: AuditService,
  suffix: string,
): Promise<AuditAnchorPayload> {
  const evidence = await audit.verify();
  const fingerprint = createHash('sha256').update(canonicalJson({
    issuer: evidence.receipt.issuer,
    lastSequence: evidence.receipt.lastSequence,
    headHash: evidence.receipt.headHash,
  })).digest('hex');
  return {
    version: 1,
    anchorId: `anchor_${suffix.padStart(32, '0')}`,
    fingerprint,
    evidence,
  };
}

describe('independent audit witness', () => {
  it('authenticates, verifies, stores, and idempotently acknowledges signed receipts', async () => {
    const values = fixture();
    await values.sourceStore.appendAuditEvent({
      actorId: 'admin_alpha', action: 'license.issue', targetType: 'license',
      targetId: 'lic_1', detail: { plan: 'enterprise' },
    });
    const anchor = await payload(values.audit, '1');

    const created = await values.witness.ingest(anchor, TOKEN);
    expect(created).toMatchObject({
      replayed: false,
      receipt: {
        sourceId: 'primary-control',
        anchorId: anchor.anchorId,
        chainSequence: 1,
        signingKeyId: values.signer.keyId,
      },
    });
    const replayed = await values.witness.ingest(anchor, TOKEN);
    expect(replayed).toMatchObject({ replayed: true, receipt: { id: created.receipt.id } });
    expect(values.witnessStore.auditWitnessReceipts).toHaveLength(1);
    expect(values.witnessStore.audits.filter((event) => (
      event.action === 'audit.witness.received'
    ))).toHaveLength(1);
    await expect(values.witness.list({ sourceId: 'primary-control', limit: '10' }))
      .resolves.toMatchObject({
        enabled: true,
        sources: [{ id: 'primary-control', signingKeyIds: [values.signer.keyId] }],
        receipts: [{ id: created.receipt.id }],
      });
  });

  it('rejects untrusted tokens, altered evidence, rollbacks, and same-sequence forks', async () => {
    const values = fixture();
    await values.sourceStore.appendAuditEvent({
      actorId: 'admin_alpha', action: 'customer.create', targetType: 'customer',
      targetId: 'cus_1', detail: {},
    });
    const first = await payload(values.audit, '1');
    await expect(values.witness.ingest(first, 'wrong-token')).rejects.toMatchObject({
      statusCode: 401,
    });
    const altered = structuredClone(first);
    altered.evidence.receipt.legacyEventCount = 99;
    await expect(values.witness.ingest(altered, TOKEN)).rejects.toMatchObject({ statusCode: 400 });

    await values.sourceStore.appendAuditEvent({
      actorId: 'admin_alpha', action: 'deployment.create', targetType: 'deployment',
      targetId: 'dep_1', detail: {},
    });
    const second = await payload(values.audit, '2');
    await expect(values.witness.ingest(second, TOKEN)).resolves.toMatchObject({ replayed: false });
    await expect(values.witness.ingest(first, TOKEN)).rejects.toMatchObject({ statusCode: 409 });

    const forkReceipt = {
      ...second.evidence.receipt,
      headHash: 'f'.repeat(64),
    };
    const forkFingerprint = createHash('sha256').update(canonicalJson({
      issuer: forkReceipt.issuer,
      lastSequence: forkReceipt.lastSequence,
      headHash: forkReceipt.headHash,
    })).digest('hex');
    const fork: AuditAnchorPayload = {
      version: 1,
      anchorId: `anchor_${'3'.padStart(32, '0')}`,
      fingerprint: forkFingerprint,
      evidence: { receipt: forkReceipt, ...await signPayload(values.signer, forkReceipt) },
    };
    await expect(values.witness.ingest(fork, TOKEN)).rejects.toMatchObject({ statusCode: 409 });
  });

  it('loads isolated token and rotating Ed25519 public keys from a versioned manifest', () => {
    const directory = mkdtempSync(join(tmpdir(), 'otto-control-audit-witness-'));
    try {
      const first = generateKeyPairSync('ed25519');
      const second = generateKeyPairSync('ed25519');
      writeFileSync(join(directory, 'source-token'), TOKEN);
      writeFileSync(
        join(directory, 'current.pem'),
        first.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
      );
      writeFileSync(
        join(directory, 'next.pem'),
        second.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
      );
      const manifest = join(directory, 'sources.json');
      writeFileSync(manifest, JSON.stringify({
        version: 1,
        sources: [{
          id: 'primary-control',
          issuer: ISSUER,
          tokenFile: 'source-token',
          publicKeyFiles: ['current.pem', 'next.pem'],
        }],
      }));
      const sources = loadAuditWitnessSources(manifest);
      expect(sources).toHaveLength(1);
      expect(sources[0]).toMatchObject({ id: 'primary-control', issuer: ISSUER });
      expect(sources[0]!.publicKeys.size).toBe(2);
      expect(sources[0]!.tokenHash.equals(createHash('sha256').update(TOKEN).digest())).toBe(true);
      writeFileSync(manifest, 'null');
      expect(() => loadAuditWitnessSources(manifest)).toThrow(
        'audit witness sources file must contain a JSON object',
      );
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});

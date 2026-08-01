import { generateKeyPairSync, verify } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { canonicalJson, LocalEd25519Signer } from '../src/crypto/signed-envelope.js';
import { AuditService } from '../src/modules/audit/service.js';
import { MemoryControlStore } from './helpers/memory-store.js';

function fixture(): {
  store: MemoryControlStore;
  service: AuditService;
  signer: LocalEd25519Signer;
} {
  const keys = generateKeyPairSync('ed25519');
  const signer = new LocalEd25519Signer(
    keys.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
  );
  const store = new MemoryControlStore();
  return {
    store,
    signer,
    service: new AuditService({
      store,
      signer,
      now: () => Date.parse('2026-08-01T12:00:00.000Z'),
    }),
  };
}

describe('tamper-evident audit service', () => {
  it('filters, paginates, redacts, and exports audit events', async () => {
    const { store, service } = fixture();
    await store.appendAuditEvent({
      actorId: 'admin_alpha',
      action: 'license.issue',
      targetType: 'license',
      targetId: 'lic_1',
      detail: { plan: 'enterprise', leaseToken: 'must-not-leak' },
    });
    await store.appendAuditEvent({
      actorId: 'admin_beta',
      action: 'license.revoke',
      targetType: 'license',
      targetId: 'lic_2',
      detail: { reason: 'customer request', nested: { password: 'must-not-leak' } },
    });

    const first = await service.events({ targetType: 'license', limit: '1' });
    expect(first.events).toHaveLength(1);
    expect(first.nextBeforeId).toBe(2);
    expect(first.events[0]).toMatchObject({ action: 'license.revoke', chainSequence: 2 });
    expect(JSON.stringify(first.events[0])).not.toContain('must-not-leak');

    const second = await service.events({ beforeId: String(first.nextBeforeId), limit: '1' });
    expect(second).toMatchObject({
      events: [{ action: 'license.issue', detail: { plan: 'enterprise', leaseToken: '[REDACTED]' } }],
      nextBeforeId: null,
    });

    const csv = await service.exportCsv({ actorId: 'admin_alpha' });
    expect(csv).toContain('license.issue');
    expect(csv).toContain('[REDACTED]');
    expect(csv).not.toContain('must-not-leak');
    expect(csv).not.toContain('license.revoke');
  });

  it('signs a valid chain receipt and identifies the first tampered event', async () => {
    const { store, service, signer } = fixture();
    await store.appendAuditEvent({
      actorId: 'admin_alpha', action: 'customer.create', targetType: 'customer',
      targetId: 'cus_1', detail: { name: 'Example' },
    });
    await store.appendAuditEvent({
      actorId: 'admin_alpha', action: 'deployment.create', targetType: 'deployment',
      targetId: 'dep_1', detail: { customerId: 'cus_1' },
    });

    const valid = await service.verify();
    expect(valid).toMatchObject({
      signingKeyId: signer.keyId,
      receipt: { valid: true, checkedEvents: 2, lastSequence: 2, brokenAtSequence: null },
    });
    expect(verify(
      null,
      Buffer.from(canonicalJson(valid.receipt)),
      signer.publicKey,
      Buffer.from(valid.signature.slice('ed25519:'.length), 'base64url'),
    )).toBe(true);

    store.auditRecords[0]!.detail = { name: 'Tampered' };
    const invalid = await service.verify();
    expect(invalid.receipt).toMatchObject({
      valid: false,
      checkedEvents: 0,
      brokenAtSequence: 1,
    });
  });

  it('rejects malformed ranges and unsafe pagination values', async () => {
    const { service } = fixture();
    await expect(service.events({ limit: '201' })).rejects.toMatchObject({ statusCode: 400 });
    await expect(service.events({ beforeId: '-1' })).rejects.toMatchObject({ statusCode: 400 });
    await expect(service.events({
      from: '2026-08-02T00:00:00.000Z',
      to: '2026-08-01T00:00:00.000Z',
    })).rejects.toMatchObject({ statusCode: 400 });
  });
});

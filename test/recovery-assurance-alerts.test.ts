import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import type { AlertDeliveryPayload } from '../src/contracts/alert-delivery.js';
import { LocalEd25519Signer } from '../src/crypto/signed-envelope.js';
import { AlertDeliveryService } from '../src/modules/alert-delivery/service.js';
import { AuditService } from '../src/modules/audit/service.js';
import { AuditAnchorService } from '../src/modules/audit-anchor/service.js';
import { BackupStatusService } from '../src/modules/backup-status/service.js';
import { MemoryControlStore } from './helpers/memory-store.js';

function signer(): LocalEd25519Signer {
  const keys = generateKeyPairSync('ed25519');
  return new LocalEd25519Signer(
    keys.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
  );
}

function alertFixture() {
  const directory = mkdtempSync(join(tmpdir(), 'otto-recovery-alerts-'));
  const secretFile = join(directory, 'alert-secret');
  writeFileSync(secretFile, 'alert-secret-with-at-least-thirty-two-bytes');
  const payloads: AlertDeliveryPayload[] = [];
  return {
    directory,
    payloads,
    channels: [{
      id: 'security-operations',
      name: 'Security operations',
      url: 'https://alerts.example.test/recovery',
      secretFile,
      enabled: true,
      minimumSeverity: 'warning' as const,
    }],
    fetcher: async (_input: string | URL | globalThis.Request, init?: RequestInit) => {
      payloads.push(JSON.parse(String(init?.body)) as AlertDeliveryPayload);
      return new Response(null, { status: 204 });
    },
  };
}

describe('recovery assurance alerts', () => {
  it('persists and delivers a critical alert when the audit chain is modified', async () => {
    const fixture = alertFixture();
    try {
      const store = new MemoryControlStore();
      const audit = new AuditService({ store, signer: signer() });
      await store.appendAuditEvent({
        actorId: 'admin_security',
        action: 'license.issue',
        targetType: 'license',
        targetId: 'lic_recovery',
        detail: { plan: 'enterprise' },
      });
      store.auditRecords[0]!.detail = { plan: 'tampered' };
      const service = new AlertDeliveryService({
        store,
        backupStatus: new BackupStatusService({ reportDirectory: null }),
        audit,
        channels: fixture.channels,
        fetcher: fixture.fetcher,
      });

      await expect(service.pollOnce()).resolves.toMatchObject({ delivered: 2 });
      const payload = fixture.payloads.find((item) => item.source === 'audit_integrity');
      expect(payload).toMatchObject({
        eventType: 'audit.integrity.alert',
        severity: 'critical',
        condition: {
          reason: 'audit_chain_invalid',
          brokenAtSequence: 1,
        },
      });
      expect([...store.alertDeliveries.values()].some((item) => (
        item.source === 'audit_integrity' && item.status === 'delivered'
      ))).toBe(true);
    } finally {
      rmSync(fixture.directory, { recursive: true, force: true });
    }
  });

  it('alerts when an independent audit witness reaches terminal failure', async () => {
    const fixture = alertFixture();
    const tokenDirectory = mkdtempSync(join(tmpdir(), 'otto-witness-alerts-'));
    try {
      const store = new MemoryControlStore();
      const audit = new AuditService({ store, signer: signer() });
      const tokenFile = join(tokenDirectory, 'witness-token');
      writeFileSync(tokenFile, 'witness-token-with-at-least-thirty-two-bytes');
      const anchors = new AuditAnchorService({
        store,
        audit,
        url: 'https://witness.example.test/v1/audit-witness/anchors',
        tokenFile,
        maxAttempts: 1,
        fetcher: async () => new Response(null, { status: 503 }),
      });
      await expect(anchors.pollOnce('admin_security', true)).resolves.toMatchObject({
        failed: 1,
      });
      const service = new AlertDeliveryService({
        store,
        backupStatus: new BackupStatusService({ reportDirectory: null }),
        audit,
        auditAnchors: anchors,
        channels: fixture.channels,
        fetcher: fixture.fetcher,
      });

      await expect(service.pollOnce()).resolves.toMatchObject({ delivered: 2 });
      expect(fixture.payloads.find((item) => item.source === 'audit_witness')).toMatchObject({
        eventType: 'audit.witness.alert',
        severity: 'critical',
        condition: {
          reason: 'audit_witness_delivery_failed',
          failedCount: 1,
        },
      });
    } finally {
      rmSync(fixture.directory, { recursive: true, force: true });
      rmSync(tokenDirectory, { recursive: true, force: true });
    }
  });
});

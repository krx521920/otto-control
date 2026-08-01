import { createHmac } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it, vi } from 'vitest';

import type { BackupRunReport } from '../src/contracts/backup-status.js';
import { AlertDeliveryService } from '../src/modules/alert-delivery/service.js';
import { BackupStatusService } from '../src/modules/backup-status/service.js';
import { MemoryControlStore } from './helpers/memory-store.js';

function failedBackupReport(recordedAt: string): BackupRunReport {
  return {
    version: 1,
    backup: {
      name: 'otto-control-20260801T105500Z.dump.enc',
      sha256: 'a'.repeat(64),
      sizeBytes: 4096,
      createdAt: '2026-08-01T10:55:00.000Z',
      localVerifiedAt: recordedAt,
    },
    offsite: {
      status: 'failed',
      required: true,
      target: {
        provider: 's3',
        endpoint: 'https://objects.example.test',
        bucket: 'otto-backups',
        prefix: 'control/primary',
        addressingStyle: 'path',
      },
      objects: [],
      attempts: 4,
      verifiedAt: null,
      error: 'object store unavailable',
    },
    recordedAt,
  };
}

function fixture(): {
  directory: string;
  secretFile: string;
  reportDirectory: string;
  secret: string;
} {
  const directory = mkdtempSync(join(tmpdir(), 'otto-control-alerts-'));
  const secretFile = join(directory, 'webhook-secret');
  const reportDirectory = join(directory, 'reports');
  const secret = 'alert-delivery-test-secret-that-is-long-enough';
  writeFileSync(secretFile, secret);
  return { directory, secretFile, reportDirectory, secret };
}

describe('outbound recovery alert delivery', () => {
  it('signs, delivers, audits, and deduplicates a backup alert', async () => {
    const files = fixture();
    let now = Date.parse('2026-08-01T12:00:00.000Z');
    try {
      mkdirSync(files.reportDirectory);
      writeFileSync(
        join(files.reportDirectory, 'latest.json'),
        JSON.stringify(failedBackupReport('2026-08-01T11:00:00.000Z')),
      );
      const store = new MemoryControlStore();
      const fetcher = vi.fn(async (
        input: string | URL | Request,
        init?: RequestInit,
      ) => {
        void input;
        void init;
        return new Response(null, { status: 204 });
      });
      const service = new AlertDeliveryService({
        store,
        backupStatus: new BackupStatusService({
          reportDirectory: files.reportDirectory,
          now: () => now,
        }),
        webhookUrl: 'https://alerts.example.test/hooks/otto',
        webhookSecretFile: files.secretFile,
        now: () => now,
        fetcher: fetcher as unknown as typeof fetch,
      });

      await expect(service.pollOnce()).resolves.toMatchObject({
        enabled: true,
        observedStatus: 'failed',
        enqueued: true,
        processed: 1,
        delivered: 1,
      });
      expect(fetcher).toHaveBeenCalledTimes(1);
      const [url, request] = fetcher.mock.calls[0]!;
      expect(String(url)).toBe('https://alerts.example.test/hooks/otto');
      const body = String(request?.body);
      const headers = new Headers(request?.headers);
      expect(headers.get('x-otto-alert-signature')).toBe(
        `v1=${createHmac('sha256', files.secret).update(`${now}\n${body}`).digest('hex')}`,
      );
      expect(JSON.parse(body)).toMatchObject({
        eventType: 'backup.recovery.alert',
        severity: 'critical',
        condition: { reason: 'offsite_required_failed' },
      });
      expect(body).not.toContain('objects.example.test');
      expect(body).not.toContain(files.secret);

      now += 60_000;
      await expect(service.pollOnce()).resolves.toMatchObject({
        enqueued: false,
        processed: 0,
      });
      expect(fetcher).toHaveBeenCalledTimes(1);
      expect((await service.list()).deliveries[0]).toMatchObject({
        status: 'delivered',
        attempts: 1,
        lastError: null,
      });
      expect(store.audits.map((audit) => audit.action)).toEqual([
        'alert.delivery.enqueued',
        'alert.delivery.delivered',
      ]);
    } finally {
      rmSync(files.directory, { recursive: true, force: true });
    }
  });

  it('retries with backoff, redacts failures, and stops after the configured limit', async () => {
    const files = fixture();
    let now = Date.parse('2026-08-01T12:00:00.000Z');
    try {
      mkdirSync(files.reportDirectory);
      writeFileSync(
        join(files.reportDirectory, 'latest.json'),
        JSON.stringify(failedBackupReport('2026-08-01T11:00:00.000Z')),
      );
      const store = new MemoryControlStore();
      const fetcher = vi.fn(async (
        input: string | URL | Request,
        init?: RequestInit,
      ) => {
        void input;
        void init;
        return new Response(null, { status: 503 });
      });
      const service = new AlertDeliveryService({
        store,
        backupStatus: new BackupStatusService({
          reportDirectory: files.reportDirectory,
          now: () => now,
        }),
        webhookUrl: 'https://alerts.example.test/hooks/private-token',
        webhookSecretFile: files.secretFile,
        maxAttempts: 2,
        now: () => now,
        fetcher: fetcher as unknown as typeof fetch,
      });

      await expect(service.pollOnce()).resolves.toMatchObject({ retrying: 1, failed: 0 });
      let delivery = (await service.list()).deliveries[0]!;
      expect(delivery).toMatchObject({ status: 'retrying', attempts: 1 });
      expect(delivery.lastError).toBe('webhook returned HTTP 503');

      now += 31_000;
      await expect(service.pollOnce()).resolves.toMatchObject({ retrying: 0, failed: 1 });
      delivery = (await service.list()).deliveries[0]!;
      expect(delivery).toMatchObject({ status: 'failed', attempts: 2 });
      expect(JSON.stringify(delivery)).not.toContain('private-token');
      expect(JSON.stringify(delivery)).not.toContain(files.secret);
      expect(store.audits.at(-1)).toMatchObject({ action: 'alert.delivery.failed' });

      const retried = await service.retry(delivery.id, 'admin_test');
      expect(retried).toMatchObject({ status: 'pending', attempts: 0, lastError: null });
      expect(store.audits.at(-1)).toMatchObject({
        action: 'alert.delivery.retried',
        actorId: 'admin_test',
      });

      fetcher.mockResolvedValueOnce(new Response(null, { status: 204 }));
      await expect(service.pollOnce()).resolves.toMatchObject({ delivered: 1, failed: 0 });
      delivery = (await service.list()).deliveries[0]!;
      expect(delivery).toMatchObject({ status: 'delivered', attempts: 1, lastError: null });
      await expect(service.retry(delivery.id, 'admin_test')).rejects.toMatchObject({
        statusCode: 409,
      });

      now += 60 * 60_000;
      await expect(service.pollOnce()).resolves.toMatchObject({ processed: 0 });
      expect(fetcher).toHaveBeenCalledTimes(3);
    } finally {
      rmSync(files.directory, { recursive: true, force: true });
    }
  });

  it('stays inert when no webhook is configured', async () => {
    const store = new MemoryControlStore();
    const service = new AlertDeliveryService({
      store,
      backupStatus: new BackupStatusService({ reportDirectory: null }),
      webhookUrl: null,
      webhookSecretFile: null,
    });
    await expect(service.pollOnce()).resolves.toEqual({
      enabled: false,
      observedStatus: null,
      enqueued: false,
      processed: 0,
      delivered: 0,
      retrying: 0,
      failed: 0,
    });
    expect(await service.list()).toEqual({ enabled: false, deliveries: [] });
  });

  it('prunes only old terminal delivery records', async () => {
    const store = new MemoryControlStore();
    const old = new Date('2025-01-01T00:00:00.000Z');
    const recent = new Date('2026-08-01T00:00:00.000Z');
    const payload = {
      version: 1 as const,
      eventId: `alert_${'1'.repeat(32)}`,
      eventType: 'backup.recovery.alert' as const,
      source: 'backup_status' as const,
      severity: 'warning' as const,
      fingerprint: 'f'.repeat(64),
      observedAt: old.toISOString(),
      condition: {
        status: 'degraded' as const,
        reason: 'backup_stale' as const,
        ageHours: 72,
        backupName: 'backup.dump.enc',
        backupRecordedAt: old.toISOString(),
        alerts: [],
      },
    };
    await store.enqueueAlertDelivery({
      id: payload.eventId,
      source: payload.source,
      eventType: payload.eventType,
      fingerprint: payload.fingerprint,
      severity: payload.severity,
      payload,
      createdAt: old,
      audit: {
        actorId: 'system:test',
        action: 'alert.delivery.enqueued',
        targetType: 'alert_delivery',
        targetId: payload.eventId,
        detail: { source: payload.source },
      },
    });
    const claimed = await store.claimAlertDelivery({ now: old, leaseUntil: recent });
    expect(claimed).not.toBeNull();
    await store.finishAlertDelivery({
      id: payload.eventId,
      expectedLeaseUntil: recent,
      status: 'delivered',
      nextAttemptAt: old,
      lastError: null,
      deliveredAt: old,
      updatedAt: old,
      audit: null,
    });

    expect(await store.pruneAlertDeliveries(new Date('2026-01-01T00:00:00.000Z'))).toBe(1);
    expect(await store.getAlertDelivery(payload.eventId)).toBeNull();
  });
});

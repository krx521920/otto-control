import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import type { BackupRunReport } from '../src/contracts/backup-status.js';
import { BackupStatusService } from '../src/modules/backup-status/service.js';

const NOW = Date.parse('2026-08-01T12:00:00.000Z');

function report(overrides: Partial<BackupRunReport['offsite']> = {}, recordedAt = '2026-08-01T11:00:00.000Z'): BackupRunReport {
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
      status: 'verified',
      required: true,
      target: {
        provider: 's3',
        endpoint: 'https://objects.example.test',
        bucket: 'otto-backups',
        prefix: 'control/primary',
        addressingStyle: 'path',
      },
      objects: ['control/primary/otto-control-20260801T105500Z.dump.enc'],
      attempts: 1,
      verifiedAt: recordedAt,
      error: null,
      ...overrides,
    },
    recordedAt,
  };
}

function writeReport(directory: string, value: BackupRunReport): void {
  writeFileSync(join(directory, 'latest.json'), JSON.stringify(value));
  const timestamp = new Date(value.recordedAt).toISOString()
    .replace(/[-:]/gu, '')
    .replace(/\.\d{3}Z$/u, 'Z');
  writeFileSync(join(directory, `${value.backup.name}.${timestamp}.json`), JSON.stringify(value));
}

describe('backup inventory status', () => {
  it('reports a recent verified off-site backup as healthy', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'otto-control-backup-status-'));
    try {
      writeReport(directory, report());
      const status = await new BackupStatusService({
        reportDirectory: directory,
        maximumAgeHours: 48,
        now: () => NOW,
      }).status();
      expect(status).toMatchObject({ status: 'healthy', reason: 'backup_verified', ageHours: 1 });
      expect(status.history).toHaveLength(1);
      expect(status.alerts).toEqual([]);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('distinguishes optional and required off-site failures', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'otto-control-backup-failure-'));
    try {
      writeReport(directory, report({
        status: 'failed',
        required: false,
        verifiedAt: null,
        error: 'object store unavailable',
      }));
      const service = new BackupStatusService({ reportDirectory: directory, now: () => NOW });
      await expect(service.status()).resolves.toMatchObject({
        status: 'degraded',
        reason: 'offsite_failed',
      });

      writeReport(directory, report({
        status: 'failed',
        required: true,
        verifiedAt: null,
        error: 'object store unavailable',
      }, '2026-08-01T11:05:00.000Z'));
      await expect(service.status()).resolves.toMatchObject({
        status: 'failed',
        reason: 'offsite_required_failed',
      });
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('fails stale, missing, and unsafe latest reports explicitly', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'otto-control-backup-stale-'));
    try {
      writeReport(directory, report({}, '2026-07-29T11:00:00.000Z'));
      const service = new BackupStatusService({
        reportDirectory: directory,
        maximumAgeHours: 48,
        now: () => NOW,
      });
      await expect(service.status()).resolves.toMatchObject({
        status: 'failed',
        reason: 'backup_stale',
      });

      rmSync(join(directory, 'latest.json'));
      await expect(service.status()).resolves.toMatchObject({
        status: 'missing',
        reason: 'backup_report_missing',
      });

      writeFileSync(join(directory, 'latest.json'), '{not-json');
      await expect(service.status()).resolves.toMatchObject({
        status: 'failed',
        reason: 'backup_report_invalid',
      });
      await expect(service.status(0)).rejects.toMatchObject({ statusCode: 400 });
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('returns a non-secret not-configured status without touching the filesystem', async () => {
    await expect(new BackupStatusService({ reportDirectory: null }).status()).resolves.toMatchObject({
      status: 'not_configured',
      latest: null,
      history: [],
    });
  });

  it.runIf(process.platform !== 'win32')('rejects a replaced report-directory symlink', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'otto-control-backup-directory-'));
    const link = `${directory}-link`;
    try {
      symlinkSync(directory, link, 'dir');
      await expect(new BackupStatusService({ reportDirectory: link }).status()).resolves.toMatchObject({
        status: 'failed',
        reason: 'backup_report_directory_unreadable',
      });
    } finally {
      rmSync(link, { recursive: true, force: true });
      rmSync(directory, { recursive: true, force: true });
    }
  });
});

import { lstat, readFile, readdir } from 'node:fs/promises';
import { resolve } from 'node:path';

import type {
  BackupHealthStatus,
  BackupInventoryStatus,
  BackupRunReport,
  BackupStatusAlert,
} from '../../contracts/backup-status.js';
import { invalidRequest } from '../../errors.js';

const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const BACKUP_NAME_PATTERN = /^otto-control-[0-9]{8}T[0-9]{6}Z\.dump\.enc$/u;
const HISTORY_REPORT_PATTERN = /^otto-control-[0-9]{8}T[0-9]{6}Z\.dump\.enc\.[0-9]{8}T[0-9]{6}Z\.json$/u;
const MAX_REPORT_BYTES = 64 * 1024;
const MAX_HISTORY_FILES_EXAMINED = 1_000;

function objectValue(value: unknown, name: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${name} must be an object`);
  }
  return value as Record<string, unknown>;
}

function stringValue(value: unknown, name: string, maximum: number): string {
  if (typeof value !== 'string' || !value || value.length > maximum) {
    throw new Error(`${name} is invalid`);
  }
  return value;
}

function nullableString(value: unknown, name: string, maximum: number): string | null {
  return value === null ? null : stringValue(value, name, maximum);
}

function isoDate(value: unknown, name: string): string {
  const result = stringValue(value, name, 40);
  const timestamp = Date.parse(result);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== result) {
    throw new Error(`${name} is invalid`);
  }
  return result;
}

function positiveInteger(value: unknown, name: string, maximum: number): number {
  if (!Number.isSafeInteger(value) || Number(value) < 1 || Number(value) > maximum) {
    throw new Error(`${name} is invalid`);
  }
  return Number(value);
}

function parseReport(value: unknown): BackupRunReport {
  const report = objectValue(value, 'report');
  if (report.version !== 1) throw new Error('report version is invalid');
  const backup = objectValue(report.backup, 'backup');
  const name = stringValue(backup.name, 'backup.name', 160);
  if (!BACKUP_NAME_PATTERN.test(name)) throw new Error('backup.name is invalid');
  const sha256 = stringValue(backup.sha256, 'backup.sha256', 64);
  if (!SHA256_PATTERN.test(sha256)) throw new Error('backup.sha256 is invalid');
  const offsite = objectValue(report.offsite, 'offsite');
  if (offsite.status !== 'disabled' && offsite.status !== 'verified'
    && offsite.status !== 'failed') {
    throw new Error('offsite.status is invalid');
  }
  if (typeof offsite.required !== 'boolean') throw new Error('offsite.required is invalid');
  let target: BackupRunReport['offsite']['target'] = null;
  if (offsite.target !== null) {
    const rawTarget = objectValue(offsite.target, 'offsite.target');
    const endpoint = stringValue(rawTarget.endpoint, 'offsite.target.endpoint', 2048);
    const parsedEndpoint = new URL(endpoint);
    if (parsedEndpoint.protocol !== 'https:' || parsedEndpoint.origin !== endpoint) {
      throw new Error('offsite.target.endpoint is invalid');
    }
    if (rawTarget.provider !== 's3') throw new Error('offsite.target.provider is invalid');
    if (rawTarget.addressingStyle !== 'path' && rawTarget.addressingStyle !== 'virtual') {
      throw new Error('offsite.target.addressingStyle is invalid');
    }
    target = {
      provider: 's3',
      endpoint,
      bucket: stringValue(rawTarget.bucket, 'offsite.target.bucket', 63),
      prefix: stringValue(rawTarget.prefix, 'offsite.target.prefix', 512),
      addressingStyle: rawTarget.addressingStyle,
    };
  }
  if (!Array.isArray(offsite.objects) || offsite.objects.length > 10
    || offsite.objects.some((item) => typeof item !== 'string' || !item || item.length > 1024)) {
    throw new Error('offsite.objects is invalid');
  }
  const attempts = Number(offsite.attempts);
  if (!Number.isSafeInteger(attempts) || attempts < 0 || attempts > 10) {
    throw new Error('offsite.attempts is invalid');
  }
  const verifiedAt = offsite.verifiedAt === null
    ? null
    : isoDate(offsite.verifiedAt, 'offsite.verifiedAt');
  if ((offsite.status === 'verified') !== (verifiedAt !== null)) {
    throw new Error('offsite verification timestamp is inconsistent');
  }
  const error = nullableString(offsite.error, 'offsite.error', 1000);
  if (offsite.status === 'verified'
    && (!target || offsite.objects.length < 1 || attempts < 1 || error !== null)) {
    throw new Error('verified offsite report is inconsistent');
  }
  if (offsite.status === 'disabled'
    && (target || offsite.required || offsite.objects.length > 0 || attempts !== 0 || error !== null)) {
    throw new Error('disabled offsite report is inconsistent');
  }
  if (offsite.status === 'failed' && (!target || !error)) {
    throw new Error('failed offsite report is inconsistent');
  }
  return {
    version: 1,
    backup: {
      name,
      sha256,
      sizeBytes: positiveInteger(backup.sizeBytes, 'backup.sizeBytes', Number.MAX_SAFE_INTEGER),
      createdAt: isoDate(backup.createdAt, 'backup.createdAt'),
      localVerifiedAt: isoDate(backup.localVerifiedAt, 'backup.localVerifiedAt'),
    },
    offsite: {
      status: offsite.status,
      required: offsite.required,
      target,
      objects: [...offsite.objects] as string[],
      attempts,
      verifiedAt,
      error,
    },
    recordedAt: isoDate(report.recordedAt, 'recordedAt'),
  };
}

async function readReport(path: string): Promise<BackupRunReport> {
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > MAX_REPORT_BYTES) {
    throw new Error('backup report file is unsafe');
  }
  return parseReport(JSON.parse(await readFile(path, 'utf8')));
}

function resultState(
  report: BackupRunReport,
  now: number,
  maximumAgeHours: number,
): { status: BackupHealthStatus; reason: string; ageHours: number; alerts: BackupStatusAlert[] } {
  const recordedAt = Date.parse(report.recordedAt);
  const ageHours = Math.max(0, (now - recordedAt) / 3_600_000);
  if (recordedAt > now + 5 * 60_000) {
    return {
      status: 'failed',
      reason: 'future_report_timestamp',
      ageHours: 0,
      alerts: [{ severity: 'critical', code: 'future_report_timestamp', message: 'Latest backup report has a future timestamp.' }],
    };
  }
  if (ageHours > maximumAgeHours) {
    return {
      status: 'failed',
      reason: 'backup_stale',
      ageHours,
      alerts: [{ severity: 'critical', code: 'backup_stale', message: 'No verified backup has completed within the recovery window.' }],
    };
  }
  if (report.offsite.status === 'failed') {
    const critical = report.offsite.required;
    return {
      status: critical ? 'failed' : 'degraded',
      reason: critical ? 'offsite_required_failed' : 'offsite_failed',
      ageHours,
      alerts: [{
        severity: critical ? 'critical' : 'warning',
        code: critical ? 'offsite_required_failed' : 'offsite_failed',
        message: report.offsite.error || 'Off-site backup verification failed.',
      }],
    };
  }
  if (report.offsite.status === 'disabled') {
    return {
      status: 'degraded',
      reason: 'offsite_disabled',
      ageHours,
      alerts: [{ severity: 'warning', code: 'offsite_disabled', message: 'Only a local encrypted backup is available.' }],
    };
  }
  return { status: 'healthy', reason: 'backup_verified', ageHours, alerts: [] };
}

export interface BackupStatusServiceOptions {
  reportDirectory: string | null;
  maximumAgeHours?: number;
  now?: () => number;
}

export class BackupStatusService {
  readonly #reportDirectory: string | null;
  readonly #maximumAgeHours: number;
  readonly #now: () => number;

  constructor(options: BackupStatusServiceOptions) {
    this.#reportDirectory = options.reportDirectory ? resolve(options.reportDirectory) : null;
    this.#maximumAgeHours = options.maximumAgeHours ?? 48;
    this.#now = options.now ?? Date.now;
    if (!Number.isInteger(this.#maximumAgeHours)
      || this.#maximumAgeHours < 1 || this.#maximumAgeHours > 720) {
      throw new Error('backup status maximum age must be between 1 and 720 hours');
    }
  }

  async status(limit = 20): Promise<BackupInventoryStatus> {
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
      throw invalidRequest('backup history limit must be between 1 and 100');
    }
    const checkedAtMs = this.#now();
    const checkedAt = new Date(checkedAtMs).toISOString();
    if (!this.#reportDirectory) {
      return {
        status: 'not_configured',
        reason: 'report_directory_not_configured',
        maximumAgeHours: this.#maximumAgeHours,
        ageHours: null,
        latest: null,
        history: [],
        invalidHistoryCount: 0,
        alerts: [{ severity: 'warning', code: 'backup_status_not_configured', message: 'Backup report inventory is not configured.' }],
        checkedAt,
      };
    }
    let names: string[];
    try {
      const directoryMetadata = await lstat(this.#reportDirectory);
      if (!directoryMetadata.isDirectory() || directoryMetadata.isSymbolicLink()) {
        throw new Error('backup report directory is unsafe');
      }
      names = await readdir(this.#reportDirectory);
    } catch (error) {
      if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') {
        names = [];
      } else {
        return {
          status: 'failed',
          reason: 'backup_report_directory_unreadable',
          maximumAgeHours: this.#maximumAgeHours,
          ageHours: null,
          latest: null,
          history: [],
          invalidHistoryCount: 0,
          alerts: [{
            severity: 'critical',
            code: 'backup_report_directory_unreadable',
            message: 'The backup report directory is unreadable or unsafe.',
          }],
          checkedAt,
        };
      }
    }
    const history: BackupRunReport[] = [];
    let invalidHistoryCount = 0;
    for (const name of names
      .filter((item) => HISTORY_REPORT_PATTERN.test(item))
      .sort((left, right) => right.localeCompare(left))
      .slice(0, MAX_HISTORY_FILES_EXAMINED)) {
      if (history.length >= limit) break;
      try {
        history.push(await readReport(resolve(this.#reportDirectory, name)));
      } catch {
        invalidHistoryCount += 1;
      }
    }
    history.sort((left, right) => Date.parse(right.recordedAt) - Date.parse(left.recordedAt));
    const latestPath = resolve(this.#reportDirectory, 'latest.json');
    let latest: BackupRunReport;
    try {
      latest = await readReport(latestPath);
    } catch (error) {
      const missing = error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT';
      return {
        status: missing ? 'missing' : 'failed',
        reason: missing ? 'backup_report_missing' : 'backup_report_invalid',
        maximumAgeHours: this.#maximumAgeHours,
        ageHours: null,
        latest: null,
        history,
        invalidHistoryCount,
        alerts: [{
          severity: 'critical',
          code: missing ? 'backup_report_missing' : 'backup_report_invalid',
          message: missing ? 'No completed backup report is available.' : 'The latest backup report is invalid or unsafe.',
        }],
        checkedAt,
      };
    }
    return {
      ...resultState(latest, checkedAtMs, this.#maximumAgeHours),
      maximumAgeHours: this.#maximumAgeHours,
      latest,
      history,
      invalidHistoryCount,
      checkedAt,
    };
  }
}

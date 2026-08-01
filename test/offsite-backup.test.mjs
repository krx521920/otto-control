import { createHash } from 'node:crypto';
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  loadBackupConfig,
  objectUrl,
  replicateBackup,
  signS3Request,
} from '../scripts/replicate-backup-s3.mjs';

function secret(path, value) {
  writeFileSync(path, `${value}\n`, { encoding: 'utf8', mode: 0o600 });
  if (process.platform !== 'win32') chmodSync(path, 0o600);
}

describe('off-site encrypted backup replication', () => {
  it('loads S3 credentials only from restricted files and rejects insecure endpoints', () => {
    const directory = mkdtempSync(join(tmpdir(), 'otto-control-s3-config-'));
    try {
      secret(join(directory, 'access-key'), 'test-access-key');
      secret(join(directory, 'secret-key'), 'test-secret-key-value');
      const envFile = join(directory, '.env.production');
      writeFileSync(envFile, [
        'CONTROL_BACKUP_OFFSITE_REQUIRED=true',
        'CONTROL_BACKUP_S3_ENDPOINT=https://minio.example.test',
        'CONTROL_BACKUP_S3_BUCKET=otto-backups',
        'CONTROL_BACKUP_S3_REGION=cn-north-1',
        'CONTROL_BACKUP_S3_PREFIX=control/primary',
        'CONTROL_BACKUP_S3_ACCESS_KEY_ID_FILE=access-key',
        'CONTROL_BACKUP_S3_SECRET_ACCESS_KEY_FILE=secret-key',
        '',
      ].join('\n'));
      const config = loadBackupConfig({ envFile, environment: {} });
      expect(config).toMatchObject({
        enabled: true,
        required: true,
        bucket: 'otto-backups',
        region: 'cn-north-1',
        prefix: 'control/primary',
        accessKeyId: 'test-access-key',
        secretAccessKey: 'test-secret-key-value',
      });

      writeFileSync(envFile, readFileSync(envFile, 'utf8').replace('https://', 'http://'));
      expect(() => loadBackupConfig({ envFile, environment: {} })).toThrow('HTTPS origin');
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('fails configuration when remote replication is mandatory but absent', () => {
    const directory = mkdtempSync(join(tmpdir(), 'otto-control-s3-required-'));
    try {
      const envFile = join(directory, '.env.production');
      writeFileSync(envFile, 'CONTROL_BACKUP_OFFSITE_REQUIRED=true\n');
      expect(() => loadBackupConfig({ envFile, environment: {} })).toThrow(
        'required but S3 endpoint is not configured',
      );
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('binds SigV4 authorization to the endpoint, object path, and payload digest', () => {
    const config = {
      endpoint: new URL('https://minio.example.test'),
      bucket: 'otto-backups',
      region: 'us-east-1',
      addressingStyle: 'path',
      accessKeyId: 'AKIDEXAMPLE',
      secretAccessKey: 'test-signing-secret',
      sessionToken: null,
    };
    const url = objectUrl(config, 'control/backup.dump.enc');
    expect(url.toString()).toBe(
      'https://minio.example.test/otto-backups/control/backup.dump.enc',
    );
    const first = signS3Request(config, {
      method: 'PUT',
      url,
      payloadHash: 'a'.repeat(64),
      headers: { 'x-amz-meta-sha256': 'a'.repeat(64) },
      now: new Date('2026-08-01T12:34:56.000Z'),
    });
    const changed = signS3Request(config, {
      method: 'PUT',
      url,
      payloadHash: 'b'.repeat(64),
      headers: { 'x-amz-meta-sha256': 'b'.repeat(64) },
      now: new Date('2026-08-01T12:34:56.000Z'),
    });
    expect(first.authorization).toContain(
      'Credential=AKIDEXAMPLE/20260801/us-east-1/s3/aws4_request',
    );
    expect(first.authorization).not.toBe(changed.authorization);
    expect(first['x-amz-date']).toBe('20260801T123456Z');
  });

  it('matches the published AWS S3 Signature Version 4 test vector', () => {
    const headers = signS3Request({
      region: 'us-east-1',
      accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
      secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      sessionToken: null,
    }, {
      method: 'GET',
      url: new URL('https://examplebucket.s3.amazonaws.com/test.txt'),
      payloadHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      headers: { range: 'bytes=0-9' },
      now: new Date('2013-05-24T00:00:00.000Z'),
    });
    expect(headers.authorization).toBe(
      'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,'
      + 'SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,'
      + 'Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41',
    );
  });

  it('verifies the local encrypted archive and retries bounded remote transfers', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'otto-control-s3-transfer-'));
    try {
      const filePath = join(directory, 'otto-control-20260801T120000Z.dump.enc');
      const checksumPath = `${filePath}.sha256`;
      writeFileSync(filePath, 'already encrypted backup bytes');
      const digest = createHash('sha256').update(readFileSync(filePath)).digest('hex');
      writeFileSync(checksumPath, `${digest}  ${filePath.split(/[\\/]/u).at(-1)}\n`);
      const transferred = [];
      const waits = [];
      let calls = 0;
      const result = await replicateBackup({
        config: { enabled: true, prefix: 'otto-control/deployment-1', maxAttempts: 3 },
        filePath,
        checksumPath,
        transfer: async (_config, object) => {
          calls += 1;
          if (calls === 1) throw new Error('temporary object-store outage');
          transferred.push(object);
        },
        wait: async (milliseconds) => { waits.push(milliseconds); },
      });
      expect(result).toMatchObject({ status: 'replicated', attempt: 2 });
      expect(waits).toEqual([1000]);
      expect(transferred.map((object) => object.key)).toEqual([
        'otto-control/deployment-1/otto-control-20260801T120000Z.dump.enc',
        'otto-control/deployment-1/otto-control-20260801T120000Z.dump.enc.sha256',
      ]);
      expect(transferred[0]).toMatchObject({ sha256: digest });

      writeFileSync(filePath, 'tampered encrypted bytes');
      await expect(replicateBackup({
        config: { enabled: true, prefix: 'otto-control', maxAttempts: 3 },
        filePath,
        checksumPath,
        transfer: async () => { throw new Error('must not upload'); },
        wait: async () => {},
      })).rejects.toThrow('checksum does not match');
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});

import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

function cryptoCommand(args: string[]) {
  return spawnSync(process.execPath, ['scripts/backup-crypto.mjs', ...args], {
    cwd: process.cwd(),
    encoding: 'utf8',
  });
}

describe('backup encryption', () => {
  it('round-trips a backup with AES-256-GCM without exposing plaintext', () => {
    const directory = mkdtempSync(join(tmpdir(), 'otto-control-backup-crypto-'));
    try {
      const input = join(directory, 'input.dump');
      const encrypted = join(directory, 'backup.dump.enc');
      const output = join(directory, 'output.dump');
      const key = join(directory, 'backup-key');
      const content = randomBytes(256 * 1024);
      writeFileSync(input, content);
      writeFileSync(key, randomBytes(48).toString('base64url'));

      const encrypt = cryptoCommand([
        'encrypt', '--input', input, '--output', encrypted, '--key-file', key,
      ]);
      expect(encrypt.status, encrypt.stderr).toBe(0);
      expect(readFileSync(encrypted).includes(content.subarray(0, 64))).toBe(false);

      const decrypt = cryptoCommand([
        'decrypt', '--input', encrypted, '--output', output, '--key-file', key,
      ]);
      expect(decrypt.status, decrypt.stderr).toBe(0);
      expect(readFileSync(output)).toEqual(content);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  }, 15_000);

  it('rejects a modified encrypted backup and removes partial plaintext', () => {
    const directory = mkdtempSync(join(tmpdir(), 'otto-control-backup-tamper-'));
    try {
      const input = join(directory, 'input.dump');
      const encrypted = join(directory, 'backup.dump.enc');
      const output = join(directory, 'output.dump');
      const key = join(directory, 'backup-key');
      writeFileSync(input, 'commercial control data');
      writeFileSync(key, randomBytes(48).toString('base64url'));
      expect(cryptoCommand([
        'encrypt', '--input', input, '--output', encrypted, '--key-file', key,
      ]).status).toBe(0);

      const tampered = readFileSync(encrypted);
      tampered[Math.floor(tampered.length / 2)]! ^= 1;
      writeFileSync(encrypted, tampered);
      const decrypt = cryptoCommand([
        'decrypt', '--input', encrypted, '--output', output, '--key-file', key,
      ]);
      expect(decrypt.status).toBe(1);
      expect(() => readFileSync(output)).toThrow();
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});

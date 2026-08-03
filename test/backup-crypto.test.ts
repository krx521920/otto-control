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

  it('authenticates before streaming plaintext into a managed command', () => {
    const directory = mkdtempSync(join(tmpdir(), 'otto-control-backup-command-'));
    try {
      const input = join(directory, 'input.dump');
      const encrypted = join(directory, 'backup.dump.enc');
      const output = join(directory, 'command-output.dump');
      const key = join(directory, 'backup-key');
      const content = randomBytes(128 * 1024);
      writeFileSync(input, content);
      writeFileSync(key, randomBytes(48).toString('base64url'));
      expect(cryptoCommand([
        'encrypt', '--input', input, '--output', encrypted, '--key-file', key,
      ]).status).toBe(0);

      const command = cryptoCommand([
        'decrypt-run', '--input', encrypted, '--key-file', key,
        '--', process.execPath, '-e',
        "const fs=require('node:fs');const chunks=[];process.stdin.on('data',chunk=>chunks.push(chunk));process.stdin.on('end',()=>fs.writeFileSync(process.argv.at(-1),Buffer.concat(chunks)));",
        output,
      ]);
      expect(command.status, command.stderr).toBe(0);
      expect(readFileSync(output)).toEqual(content);

      const tampered = readFileSync(encrypted);
      tampered[Math.floor(tampered.length / 2)]! ^= 1;
      writeFileSync(encrypted, tampered);
      rmSync(output);
      const rejected = cryptoCommand([
        'decrypt-run', '--input', encrypted, '--key-file', key,
        '--', process.execPath, '-e',
        "require('node:fs').writeFileSync(process.argv.at(-1),'command-started');process.stdin.resume();",
        output,
      ]);
      expect(rejected.status).toBe(1);
      expect(() => readFileSync(output)).toThrow();
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  }, 15_000);

  it('fails when the managed restore command rejects the decrypted stream', () => {
    const directory = mkdtempSync(join(tmpdir(), 'otto-control-backup-command-failure-'));
    try {
      const input = join(directory, 'input.dump');
      const encrypted = join(directory, 'backup.dump.enc');
      const key = join(directory, 'backup-key');
      writeFileSync(input, randomBytes(64 * 1024));
      writeFileSync(key, randomBytes(48).toString('base64url'));
      expect(cryptoCommand([
        'encrypt', '--input', input, '--output', encrypted, '--key-file', key,
      ]).status).toBe(0);

      const command = cryptoCommand([
        'decrypt-run', '--input', encrypted, '--key-file', key,
        '--', process.execPath, '-e',
        "process.stdin.resume();process.stdin.on('end',()=>process.exit(7));",
      ]);
      expect(command.status).toBe(1);
      expect(command.stderr).toContain('exited with code 7');
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  }, 15_000);
});

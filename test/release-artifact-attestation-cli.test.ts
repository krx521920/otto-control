import {
  generateKeyPairSync,
  sign,
  verify,
} from 'node:crypto';
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import {
  canonicalJson,
  createAttestation,
} from '../scripts/attest-release-artifact.mjs';

const directories: string[] = [];

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), 'otto-artifact-attestation-'));
  directories.push(directory);
  return directory;
}

describe('release artifact signing attestation tool', () => {
  afterEach(() => {
    for (const directory of directories.splice(0)) {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('verifies a Linux package signature and signs exact artifact evidence', () => {
    const directory = temporaryDirectory();
    const artifact = join(directory, 'otto-enterprise.tar.gz');
    const signatureFile = join(directory, 'otto-enterprise.tar.gz.sig');
    const packagePublicKey = join(directory, 'package-public.pem');
    const attestationPrivateKey = join(directory, 'attestation-private.pem');
    const bytes = Buffer.from('immutable Otto enterprise archive fixture');
    const packageKeys = generateKeyPairSync('ed25519');
    const attestationKeys = generateKeyPairSync('ed25519');
    writeFileSync(artifact, bytes);
    writeFileSync(signatureFile, sign(null, bytes, packageKeys.privateKey).toString('base64url'));
    writeFileSync(packagePublicKey, packageKeys.publicKey.export({ format: 'pem', type: 'spki' }));
    writeFileSync(
      attestationPrivateKey,
      attestationKeys.privateKey.export({ format: 'pem', type: 'pkcs8' }),
    );

    const result = createAttestation({
      file: artifact,
      releaseId: 'rel_attestation_fixture',
      releaseVersion: '1.9.11',
      sourceCommit: 'a'.repeat(40),
      kind: 'enterprise_server',
      platform: 'linux-x64',
      attestationKeyId: 'release-runner-2026-01',
      attestationPrivateKeyFile: attestationPrivateKey,
      linuxSignature: signatureFile,
      linuxPublicKey: packagePublicKey,
    });

    expect(result.evidence).toMatchObject({
      releaseId: 'rel_attestation_fixture',
      releaseVersion: '1.9.11',
      sourceCommit: 'a'.repeat(40),
      kind: 'enterprise_server',
      platform: 'linux-x64',
      sizeBytes: bytes.length,
      system: 'linux_package',
      status: 'valid',
    });
    expect(result.evidence.sha256).toMatch(/^[a-f0-9]{64}$/u);
    expect(verify(
      null,
      Buffer.from(canonicalJson(result.evidence)),
      attestationKeys.publicKey,
      Buffer.from(result.signature.slice('ed25519:'.length), 'base64url'),
    )).toBe(true);
  });

  it('refuses a detached signature for different bytes', () => {
    const directory = temporaryDirectory();
    const artifact = join(directory, 'otto-enterprise.tar.gz');
    const signatureFile = join(directory, 'otto-enterprise.tar.gz.sig');
    const packagePublicKey = join(directory, 'package-public.pem');
    const attestationPrivateKey = join(directory, 'attestation-private.pem');
    const packageKeys = generateKeyPairSync('ed25519');
    const attestationKeys = generateKeyPairSync('ed25519');
    writeFileSync(artifact, 'actual archive');
    writeFileSync(
      signatureFile,
      sign(null, Buffer.from('different archive'), packageKeys.privateKey).toString('base64url'),
    );
    writeFileSync(packagePublicKey, packageKeys.publicKey.export({ format: 'pem', type: 'spki' }));
    writeFileSync(
      attestationPrivateKey,
      attestationKeys.privateKey.export({ format: 'pem', type: 'pkcs8' }),
    );

    expect(() => createAttestation({
      file: artifact,
      releaseId: 'rel_attestation_fixture',
      releaseVersion: '1.9.11',
      sourceCommit: 'a'.repeat(40),
      kind: 'enterprise_server',
      platform: 'linux-x64',
      attestationKeyId: 'release-runner-2026-01',
      attestationPrivateKeyFile: attestationPrivateKey,
      linuxSignature: signatureFile,
      linuxPublicKey: packagePublicKey,
    })).toThrow('detached signature is invalid');
  });
});

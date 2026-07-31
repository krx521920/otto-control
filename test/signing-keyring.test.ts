import { generateKeyPairSync, verify } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { canonicalJson, LocalEd25519Signer } from '../src/crypto/signed-envelope.js';
import { ManagedSigningKeyring } from '../src/crypto/signing-keyring.js';
import { MemoryControlStore } from './helpers/memory-store.js';

function localSigner(): LocalEd25519Signer {
  const pair = generateKeyPairSync('ed25519');
  return new LocalEd25519Signer(
    pair.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
  );
}

function verifies(payload: unknown, signature: string, publicKeyPem: string): boolean {
  return verify(
    null,
    Buffer.from(canonicalJson(payload)),
    publicKeyPem,
    Buffer.from(signature.slice('ed25519:'.length), 'base64url'),
  );
}

describe('managed signing keyring', () => {
  it('rotates keys while retaining retired public keys for historical License verification', async () => {
    const store = new MemoryControlStore();
    const first = localSigner();
    const second = localSigner();
    const keyring = await ManagedSigningKeyring.create({
      store,
      providers: [
        { signer: first, provider: 'local' },
        { signer: second, provider: 'local' },
      ],
      preferredActiveKeyId: first.keyId,
    });
    const historicalPayload = { licenseId: 'lic_historical', seats: 20 };
    const historicalSignature = await keyring.sign(historicalPayload);

    await keyring.activate(second.keyId);
    const keys = await keyring.list();
    expect(keys.find((key) => key.keyId === first.keyId)?.state).toBe('retired');
    expect(keys.find((key) => key.keyId === second.keyId)?.state).toBe('active');
    expect(verifies(historicalPayload, historicalSignature, first.publicKeyPem)).toBe(true);
    await expect(keyring.assertLicenseSigningKeyUsable(first.keyId)).resolves.toBeUndefined();

    const current = await keyring.signWithKey({ leaseId: 'lease_current' });
    expect(current.signingKeyId).toBe(second.keyId);
  });

  it('revokes a compromised key and atomically switches an active key to its replacement', async () => {
    const store = new MemoryControlStore();
    const first = localSigner();
    const replacement = localSigner();
    const keyring = await ManagedSigningKeyring.create({
      store,
      providers: [
        { signer: first, provider: 'local' },
        { signer: replacement, provider: 'local' },
      ],
    });

    await expect(keyring.revoke({
      keyId: first.keyId,
      replacementKeyId: null,
      reason: 'suspected compromise',
    })).rejects.toThrow('replacementKeyId');

    await keyring.revoke({
      keyId: first.keyId,
      replacementKeyId: replacement.keyId,
      reason: 'confirmed compromise',
    });
    expect(keyring.keyId).toBe(replacement.keyId);
    expect((await store.getSigningKey(first.keyId))?.state).toBe('revoked');
    await expect(keyring.assertLicenseSigningKeyUsable(first.keyId)).rejects.toThrow(
      'revoked or is unknown',
    );
    expect((await keyring.publicEnvelope()).keyring.keys).toEqual(expect.arrayContaining([
      expect.objectContaining({ keyId: first.keyId, state: 'revoked' }),
      expect.objectContaining({ keyId: replacement.keyId, state: 'active' }),
    ]));
  });

  it('reads the database active key before signing across control-plane replicas', async () => {
    const store = new MemoryControlStore();
    const first = localSigner();
    const second = localSigner();
    const providers = [
      { signer: first, provider: 'local' as const },
      { signer: second, provider: 'local' as const },
    ];
    const firstReplica = await ManagedSigningKeyring.create({ store, providers });
    const secondReplica = await ManagedSigningKeyring.create({ store, providers });

    await firstReplica.activate(second.keyId);
    const signedBySecondReplica = await secondReplica.signWithKey({ operation: 'lease' });
    expect(signedBySecondReplica.signingKeyId).toBe(second.keyId);
  });
});

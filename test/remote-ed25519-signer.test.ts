import { generateKeyPairSync, sign as ed25519Sign, verify } from 'node:crypto';

import { describe, expect, it, vi } from 'vitest';

import {
  HttpsRemoteSigningTransport,
  RemoteEd25519Signer,
  type RemoteSigningTransport,
} from '../src/crypto/remote-ed25519-signer.js';
import { canonicalJson } from '../src/crypto/signed-envelope.js';

function signerFixture(options: {
  transport?: RemoteSigningTransport;
  now?: () => number;
} = {}) {
  const pair = generateKeyPairSync('ed25519');
  const publicKeyPem = pair.publicKey.export({ format: 'pem', type: 'spki' }).toString();
  let responseKeyId = '';
  const transport: RemoteSigningTransport = options.transport ?? {
    async sign(request) {
      return {
        version: 1,
        requestId: request.requestId,
        keyId: responseKeyId,
        algorithm: 'ed25519',
        signature: ed25519Sign(
          null,
          Buffer.from(request.payload, 'base64'),
          pair.privateKey,
        ).toString('base64url'),
      };
    },
  };
  const signer = new RemoteEd25519Signer({
    provider: 'kms',
    keyRef: 'production/license-signing/2026-07',
    publicKeyPem,
    transport,
    now: options.now,
  });
  responseKeyId = signer.keyId;
  return { signer, pair };
}

describe('remote Ed25519 KMS/HSM signer', () => {
  it('requires HTTPS and an authenticated remote transport', () => {
    expect(() => new HttpsRemoteSigningTransport({
      endpoint: 'http://kms.internal.test/sign',
      bearerToken: async () => 'token',
    })).toThrow('HTTPS URL');
    expect(() => new HttpsRemoteSigningTransport({
      endpoint: 'https://kms.internal.test/sign',
    })).toThrow('requires a bearer token or mTLS');
    expect(() => new HttpsRemoteSigningTransport({
      endpoint: 'https://kms.internal.test/sign',
      certificate: 'certificate',
    })).toThrow('certificate and private key');
  });

  it('binds the request and verifies every returned signature locally', async () => {
    const { signer, pair } = signerFixture();
    const payload = { licenseId: 'lic_remote', modules: ['meeting_agent'] };
    expect(signer.health().state).toBe('unchecked');
    const signature = await signer.sign(payload);

    expect(signature.startsWith('ed25519:')).toBe(true);
    expect(verify(
      null,
      Buffer.from(canonicalJson(payload)),
      pair.publicKey,
      Buffer.from(signature.slice('ed25519:'.length), 'base64url'),
    )).toBe(true);
    expect(signer.health()).toEqual({
      state: 'available',
      consecutiveFailures: 0,
      circuitOpenUntil: null,
    });
  });

  it('rejects a response that is replayed, rebound, or signed by another key', async () => {
    const attacker = generateKeyPairSync('ed25519');
    let expectedKeyId = '';
    const transport: RemoteSigningTransport = {
      async sign(request) {
        return {
          version: 1,
          requestId: request.requestId,
          keyId: expectedKeyId,
          algorithm: 'ed25519',
          signature: ed25519Sign(
            null,
            Buffer.from(request.payload, 'base64'),
            attacker.privateKey,
          ).toString('base64url'),
        };
      },
    };
    const { signer } = signerFixture({ transport });
    expectedKeyId = signer.keyId;

    await expect(signer.sign({ licenseId: 'lic_tampered' })).rejects.toThrow(
      'failed local verification',
    );
    expect(signer.health().state).toBe('degraded');
  });

  it('opens a short fail-closed circuit after repeated provider failures', async () => {
    let now = Date.UTC(2026, 6, 31, 8, 0, 0);
    const remoteCall = vi.fn(async () => {
      throw new Error('HSM unavailable');
    });
    const { signer } = signerFixture({
      transport: { sign: remoteCall },
      now: () => now,
    });

    for (let attempt = 0; attempt < 3; attempt += 1) {
      await expect(signer.sign({ attempt })).rejects.toThrow('HSM unavailable');
    }
    expect(signer.health()).toMatchObject({
      state: 'circuit_open',
      consecutiveFailures: 3,
    });
    await expect(signer.sign({ attempt: 4 })).rejects.toThrow('circuit is open');
    expect(remoteCall).toHaveBeenCalledTimes(3);

    now += 30_001;
    await expect(signer.sign({ attempt: 5 })).rejects.toThrow('HSM unavailable');
    expect(remoteCall).toHaveBeenCalledTimes(4);
  });
});

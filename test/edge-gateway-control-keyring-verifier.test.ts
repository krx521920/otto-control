import { generateKeyPairSync } from 'node:crypto';

import { beforeEach, describe, expect, it, vi } from 'vitest';

import type {
  SignedKeyringEnvelope,
  SignedKeyringPayload,
} from '../src/crypto/signing-keyring.js';
import { LocalEd25519Signer } from '../src/crypto/signed-envelope.js';
import {
  ControlEdgeKeyringVerifier,
  EdgeControlKeyringError,
} from '../src/edge-gateway/control-keyring-verifier.js';

const NOW = Date.parse('2026-08-11T10:00:00.000Z');
const ISO_NOW = new Date(NOW).toISOString();

function localSigner(): LocalEd25519Signer {
  const { privateKey } = generateKeyPairSync('ed25519');
  return new LocalEd25519Signer(
    privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
  );
}

describe('Control edge keyring verifier', () => {
  let now: number;
  let first: LocalEd25519Signer;
  let second: LocalEd25519Signer;

  beforeEach(() => {
    now = NOW;
    first = localSigner();
    second = localSigner();
  });

  function key(
    signer: LocalEd25519Signer,
    state: SignedKeyringPayload['keys'][number]['state'],
  ): SignedKeyringPayload['keys'][number] {
    return {
      keyId: signer.keyId,
      algorithm: 'ed25519',
      publicKeyPem: signer.publicKeyPem,
      provider: 'local',
      state,
      activatedAt: state === 'standby' ? null : ISO_NOW,
      retiredAt: state === 'retired' || state === 'revoked' ? ISO_NOW : null,
      revokedAt: state === 'revoked' ? ISO_NOW : null,
    };
  }

  async function envelope(input: {
    signer: LocalEd25519Signer;
    keys: SignedKeyringPayload['keys'];
    activeKeyId?: string;
    revisionMs?: number;
    generatedAtMs?: number;
    expiresAtMs?: number;
  }): Promise<SignedKeyringEnvelope> {
    const generatedAtMs = input.generatedAtMs ?? now;
    const keyring: SignedKeyringPayload = {
      version: 1,
      activeKeyId: input.activeKeyId ?? input.signer.keyId,
      revisionMs: input.revisionMs ?? generatedAtMs,
      generatedAtMs,
      expiresAtMs: input.expiresAtMs ?? generatedAtMs + 10 * 60 * 1000,
      keys: input.keys,
    };
    return {
      keyring,
      signingKeyId: input.signer.keyId,
      signature: await input.signer.sign(keyring),
    };
  }

  function response(value: unknown): Response {
    return new Response(JSON.stringify(value), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }

  async function resign(
    value: SignedKeyringEnvelope,
    signer: LocalEd25519Signer = first,
  ): Promise<SignedKeyringEnvelope> {
    value.signingKeyId = signer.keyId;
    value.signature = await signer.sign(value.keyring);
    return value;
  }

  async function expectInvalid(
    mutate: (value: SignedKeyringEnvelope) => void,
  ): Promise<void> {
    const value = await envelope({ signer: first, keys: [key(first, 'active')] });
    mutate(value);
    await resign(value);
    await expect(verifier(vi.fn<typeof fetch>(async () => response(value))).refresh())
      .rejects.toMatchObject({ code: 'EDGE_KEYRING_INVALID' });
  }

  function verifier(
    fetchImplementation: typeof fetch,
    bootstrap: Record<string, string> = { [first.keyId]: first.publicKeyPem },
    overrides: {
      refreshIntervalMs?: number;
      refreshBeforeExpiryMs?: number;
      unknownKeyRetryMs?: number;
      failureRetryMs?: number;
      requestTimeoutMs?: number;
    } = {},
  ): ControlEdgeKeyringVerifier {
    return new ControlEdgeKeyringVerifier({
      controlBaseUrl: 'https://control.otto.test',
      bootstrapPublicKeys: bootstrap,
      fetch: fetchImplementation,
      now: () => now,
      refreshIntervalMs: overrides.refreshIntervalMs ?? 5_000,
      refreshBeforeExpiryMs: overrides.refreshBeforeExpiryMs ?? 5_000,
      unknownKeyRetryMs: overrides.unknownKeyRetryMs ?? 1_000,
      failureRetryMs: overrides.failureRetryMs ?? 1_000,
      requestTimeoutMs: overrides.requestTimeoutMs,
    });
  }

  it('loads a Control-signed keyring and verifies artifacts locally', async () => {
    const manifest = await envelope({ signer: first, keys: [key(first, 'active')] });
    const fetchMock = vi.fn<typeof fetch>(async (url, init) => {
      expect(url).toBe('https://control.otto.test/v1/signing-keyring');
      expect(init?.method).toBe('GET');
      expect(init?.redirect).toBe('error');
      expect(new Headers(init?.headers).get('cache-control')).toBe('no-cache');
      return response(manifest);
    });
    const payload = { purpose: 'edge-policy', revision: 1 };
    const signature = await first.sign(payload);
    const keyringVerifier = verifier(fetchMock);

    await expect(keyringVerifier.verify(payload, first.keyId, signature)).resolves.toBe(true);
    await expect(keyringVerifier.verify(payload, first.keyId, signature)).resolves.toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('performs a two-phase rotation after the replacement was learned as standby', async () => {
    const initial = await envelope({
      signer: first,
      keys: [key(first, 'active'), key(second, 'standby')],
      revisionMs: NOW,
    });
    const rotated = await envelope({
      signer: second,
      keys: [key(first, 'retired'), key(second, 'active')],
      revisionMs: NOW + 5_000,
      generatedAtMs: NOW + 5_000,
    });
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(response(initial))
      .mockResolvedValueOnce(response(rotated));
    const keyringVerifier = verifier(fetchMock);
    const payload = { policyId: 'edge_policy_rotated' };

    await expect(keyringVerifier.verify(payload, first.keyId, await first.sign(payload)))
      .resolves.toBe(true);
    await expect(keyringVerifier.verify(payload, second.keyId, await second.sign(payload)))
      .resolves.toBe(false);
    now += 5_000;
    await expect(keyringVerifier.verify(payload, second.keyId, await second.sign(payload)))
      .resolves.toBe(true);
    await expect(keyringVerifier.verify(payload, first.keyId, await first.sign(payload)))
      .resolves.toBe(false);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('rejects backdated online policies and access tokens signed by a retired key', async () => {
    const initial = await envelope({
      signer: first,
      keys: [key(first, 'active'), key(second, 'standby')],
      revisionMs: NOW,
    });
    const rotated = await envelope({
      signer: second,
      keys: [key(first, 'retired'), key(second, 'active')],
      revisionMs: NOW + 5_000,
      generatedAtMs: NOW + 5_000,
    });
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(response(initial))
      .mockResolvedValueOnce(response(rotated));
    const keyringVerifier = verifier(fetchMock);

    await keyringVerifier.refresh();
    now += 5_000;
    await keyringVerifier.refresh();

    const backdatedPolicy = {
      policyId: 'backdated-policy',
      issuedAtMs: NOW - 60_000,
      expiresAtMs: NOW + 60_000,
    };
    const backdatedToken = {
      tokenId: 'backdated-token',
      issuedAtMs: NOW - 60_000,
      expiresAtMs: NOW + 60_000,
    };
    for (const artifact of [backdatedPolicy, backdatedToken]) {
      await expect(keyringVerifier.verify(
        artifact,
        first.keyId,
        await first.sign(artifact),
      )).resolves.toBe(false);
      await expect(keyringVerifier.verify(
        artifact,
        second.keyId,
        await second.sign(artifact),
      )).resolves.toBe(true);
    }
  });

  it('rejects a new keyring signed by a key that was already retired', async () => {
    const initial = await envelope({
      signer: first,
      keys: [key(first, 'active'), key(second, 'standby')],
      revisionMs: NOW,
    });
    const rotated = await envelope({
      signer: second,
      keys: [key(first, 'retired'), key(second, 'active')],
      revisionMs: NOW + 5_000,
      generatedAtMs: NOW + 5_000,
    });
    const restoredByRetiredKey = await envelope({
      signer: first,
      keys: [key(first, 'active'), key(second, 'retired')],
      revisionMs: NOW + 10_000,
      generatedAtMs: NOW + 10_000,
    });
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(response(initial))
      .mockResolvedValueOnce(response(rotated))
      .mockResolvedValueOnce(response(restoredByRetiredKey));
    const keyringVerifier = verifier(fetchMock);

    await keyringVerifier.refresh();
    now += 5_000;
    await keyringVerifier.refresh();
    now += 5_000;
    await expect(keyringVerifier.refresh()).resolves.toBeUndefined();
    now = NOW + 5_001;
    const freshPayload = { policyId: 'retired-keyring-signer', issuedAtMs: now };
    await expect(keyringVerifier.verify(
      freshPayload,
      first.keyId,
      await first.sign(freshPayload),
    )).resolves.toBe(false);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it('rejects a lifecycle regression even when a current standby key signs it', async () => {
    const third = localSigner();
    const initial = await envelope({
      signer: first,
      keys: [key(first, 'active'), key(second, 'standby'), key(third, 'standby')],
      revisionMs: NOW,
    });
    const rotated = await envelope({
      signer: second,
      keys: [key(first, 'retired'), key(second, 'active'), key(third, 'standby')],
      revisionMs: NOW + 5_000,
      generatedAtMs: NOW + 5_000,
    });
    const regressed = await envelope({
      signer: third,
      keys: [key(first, 'retired'), key(second, 'standby'), key(third, 'active')],
      revisionMs: NOW + 10_000,
      generatedAtMs: NOW + 10_000,
    });
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(response(initial))
      .mockResolvedValueOnce(response(rotated))
      .mockResolvedValueOnce(response(regressed));
    const keyringVerifier = verifier(fetchMock);

    await keyringVerifier.refresh();
    now += 5_000;
    await keyringVerifier.refresh();
    now += 5_000;
    await expect(keyringVerifier.refresh()).resolves.toBeUndefined();
    now = NOW + 5_001;
    const payload = { policyId: 'lifecycle-regression', issuedAtMs: now };
    await expect(keyringVerifier.verify(
      payload,
      third.keyId,
      await third.sign(payload),
    )).resolves.toBe(false);
    await expect(keyringVerifier.verify(
      payload,
      second.keyId,
      await second.sign(payload),
    )).resolves.toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it('rejects activation of a standby key without a durable activation timestamp', async () => {
    const initial = await envelope({
      signer: first,
      keys: [key(first, 'active'), key(second, 'standby')],
      revisionMs: NOW,
    });
    const nextActive = key(second, 'active');
    nextActive.activatedAt = null;
    const invalidActivation = await envelope({
      signer: second,
      keys: [key(first, 'retired'), nextActive],
      revisionMs: NOW + 5_000,
      generatedAtMs: NOW + 5_000,
    });
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(response(initial))
      .mockResolvedValueOnce(response(invalidActivation));
    const keyringVerifier = verifier(fetchMock);

    await keyringVerifier.refresh();
    now += 5_000;
    await expect(keyringVerifier.refresh()).resolves.toBeUndefined();
    const payload = { policyId: 'missing-activation-time', issuedAtMs: now };
    await expect(keyringVerifier.verify(
      payload,
      second.keyId,
      await second.sign(payload),
    )).resolves.toBe(false);
  });

  it('rejects a rotation that skipped pre-distribution of the replacement key', async () => {
    const initial = await envelope({ signer: first, keys: [key(first, 'active')] });
    const unsafeRotation = await envelope({
      signer: second,
      keys: [key(first, 'retired'), key(second, 'active')],
      revisionMs: NOW + 5_000,
      generatedAtMs: NOW + 5_000,
    });
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(response(initial))
      .mockResolvedValue(response(unsafeRotation));
    const keyringVerifier = verifier(fetchMock);
    const payload = { policyId: 'edge_policy_unsafe_rotation' };
    await keyringVerifier.verify(payload, first.keyId, await first.sign(payload));

    now += 5_000;
    await expect(keyringVerifier.verify(payload, second.keyId, await second.sign(payload)))
      .resolves.toBe(false);
    now = NOW + 1;
    await expect(keyringVerifier.verify(payload, first.keyId, await first.sign(payload)))
      .resolves.toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('applies an emergency revocation and immediately rejects the compromised key', async () => {
    const initial = await envelope({
      signer: first,
      keys: [key(first, 'active'), key(second, 'standby')],
    });
    const revoked = await envelope({
      signer: second,
      keys: [key(first, 'revoked'), key(second, 'active')],
      revisionMs: NOW + 5_000,
      generatedAtMs: NOW + 5_000,
    });
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(response(initial))
      .mockResolvedValueOnce(response(revoked));
    const keyringVerifier = verifier(fetchMock);
    const payload = { policyId: 'edge_policy_revoked' };
    await keyringVerifier.verify(payload, first.keyId, await first.sign(payload));

    now += 5_000;
    await expect(keyringVerifier.verify(payload, first.keyId, await first.sign(payload)))
      .resolves.toBe(false);
    await expect(keyringVerifier.verify(payload, second.keyId, await second.sign(payload)))
      .resolves.toBe(true);
  });

  it('coalesces concurrent keyring refreshes', async () => {
    const manifest = await envelope({ signer: first, keys: [key(first, 'active')] });
    let release: ((value: Response) => void) | undefined;
    const fetchMock = vi.fn<typeof fetch>(() => new Promise<Response>((resolve) => {
      release = resolve;
    }));
    const keyringVerifier = verifier(fetchMock);
    const payload = { operation: 'concurrent' };
    const signature = await first.sign(payload);

    const one = keyringVerifier.verify(payload, first.keyId, signature);
    const two = keyringVerifier.verify(payload, first.keyId, signature);
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    release!(response(manifest));
    await expect(Promise.all([one, two])).resolves.toEqual([true, true]);
  });

  it('uses a signed keyring during a bounded outage and fails after it expires', async () => {
    const manifest = await envelope({
      signer: first,
      keys: [key(first, 'active')],
      expiresAtMs: NOW + 6_000,
    });
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(response(manifest))
      .mockRejectedValue(new Error('Control unavailable'));
    const keyringVerifier = verifier(fetchMock);
    const payload = { operation: 'outage' };
    const signature = await first.sign(payload);
    await expect(keyringVerifier.verify(payload, first.keyId, signature)).resolves.toBe(true);

    now += 5_000;
    await expect(keyringVerifier.verify(payload, first.keyId, signature)).resolves.toBe(true);
    await expect(keyringVerifier.verify(payload, first.keyId, signature)).resolves.toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    now += 1_000;
    await expect(keyringVerifier.verify(payload, first.keyId, signature))
      .rejects.toThrow('Control unavailable');
  });

  it('throttles unknown-key refreshes while allowing a bounded forced discovery', async () => {
    const manifest = await envelope({ signer: first, keys: [key(first, 'active')] });
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(response(manifest));
    const keyringVerifier = verifier(fetchMock);
    const payload = { operation: 'unknown-key' };
    const signature = await second.sign(payload);

    await expect(keyringVerifier.verify(payload, second.keyId, signature)).resolves.toBe(false);
    now += 999;
    await expect(keyringVerifier.verify(payload, second.keyId, signature)).resolves.toBe(false);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    now += 1;
    await expect(keyringVerifier.verify(payload, second.keyId, signature)).resolves.toBe(false);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('rejects rollback, same-revision equivocation, removal, and key restoration', async () => {
    const initial = await envelope({
      signer: second,
      keys: [key(first, 'revoked'), key(second, 'active')],
      revisionMs: NOW + 10,
    });
    const rollback = await envelope({
      signer: second,
      keys: [key(first, 'revoked'), key(second, 'active')],
      revisionMs: NOW + 9,
      generatedAtMs: NOW + 5_000,
    });
    const equivocation = await envelope({
      signer: second,
      keys: [key(first, 'revoked'), { ...key(second, 'active'), provider: 'hsm' }],
      revisionMs: NOW + 10,
      generatedAtMs: NOW + 10_000,
    });
    const removed = await envelope({
      signer: second,
      keys: [key(second, 'active')],
      revisionMs: NOW + 11,
      generatedAtMs: NOW + 15_000,
    });
    const restored = await envelope({
      signer: second,
      keys: [key(first, 'retired'), key(second, 'active')],
      revisionMs: NOW + 12,
      generatedAtMs: NOW + 20_000,
    });
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(response(initial))
      .mockResolvedValueOnce(response(rollback))
      .mockResolvedValueOnce(response(equivocation))
      .mockResolvedValueOnce(response(removed))
      .mockResolvedValueOnce(response(restored));
    const keyringVerifier = verifier(fetchMock, {
      [first.keyId]: first.publicKeyPem,
      [second.keyId]: second.publicKeyPem,
    });
    const payload = { operation: 'continuity' };
    const signature = await second.sign(payload);
    await expect(keyringVerifier.verify(payload, second.keyId, signature)).resolves.toBe(true);

    for (let index = 0; index < 4; index += 1) {
      now = NOW + (index + 1) * 5_000;
      await expect(keyringVerifier.refresh()).resolves.toBeUndefined();
      now = NOW + 1;
      await expect(keyringVerifier.verify(payload, second.keyId, signature)).resolves.toBe(true);
      await expect(keyringVerifier.verify(payload, first.keyId, await first.sign(payload)))
        .resolves.toBe(false);
    }
    expect(fetchMock).toHaveBeenCalledTimes(5);
  });

  it('accepts a refreshed expiry for identical state at the same revision', async () => {
    const initial = await envelope({
      signer: first,
      keys: [key(first, 'active')],
      revisionMs: NOW,
      expiresAtMs: NOW + 5_000,
    });
    const renewed = await envelope({
      signer: first,
      keys: [key(first, 'active')],
      revisionMs: NOW,
      generatedAtMs: NOW + 5_000,
    });
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(response(initial))
      .mockResolvedValueOnce(response(renewed));
    const keyringVerifier = verifier(fetchMock);
    const payload = { operation: 'renew' };
    const signature = await first.sign(payload);
    await keyringVerifier.verify(payload, first.keyId, signature);

    now += 5_000;
    await expect(keyringVerifier.verify(payload, first.keyId, signature)).resolves.toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('rejects forged, malformed, and oversized keyring responses', async () => {
    const forged = await envelope({ signer: first, keys: [key(first, 'active')] });
    forged.signature = `ed25519:${'a'.repeat(86)}`;
    await expect(verifier(vi.fn<typeof fetch>(async () => response(forged))).refresh())
      .rejects.toMatchObject({ code: 'EDGE_KEYRING_SIGNATURE_INVALID' });

    await expect(verifier(vi.fn<typeof fetch>(async () => response({ unexpected: true }))).refresh())
      .rejects.toMatchObject({ code: 'EDGE_KEYRING_INVALID' });

    await expect(verifier(vi.fn<typeof fetch>(async () => new Response('{}', {
      headers: { 'content-length': String(256 * 1024 + 1) },
    }))).refresh()).rejects.toMatchObject({ code: 'EDGE_KEYRING_INVALID' });
  });

  it.each([null, [], 'invalid', 42])('rejects a non-object keyring envelope: %j', async (value) => {
    await expect(verifier(vi.fn<typeof fetch>(async () => response(value))).refresh())
      .rejects.toMatchObject({ code: 'EDGE_KEYRING_INVALID' });
  });

  it.each([
    ['envelope extra field', (value: SignedKeyringEnvelope) => {
      (value as unknown as Record<string, unknown>).extra = true;
    }],
    ['keyring missing field', (value: SignedKeyringEnvelope) => {
      delete (value.keyring as unknown as Record<string, unknown>).revisionMs;
    }],
    ['keyring extra field', (value: SignedKeyringEnvelope) => {
      (value.keyring as unknown as Record<string, unknown>).extra = true;
    }],
    ['key missing field', (value: SignedKeyringEnvelope) => {
      delete (value.keyring.keys[0] as unknown as Record<string, unknown>).provider;
    }],
    ['key extra field', (value: SignedKeyringEnvelope) => {
      (value.keyring.keys[0] as unknown as Record<string, unknown>).extra = true;
    }],
  ] as const)('enforces exact fields: %s', async (_name, mutate) => {
    await expectInvalid(mutate);
  });

  it('rejects a keyring envelope with a missing field', async () => {
    const value = await envelope({ signer: first, keys: [key(first, 'active')] });
    delete (value as unknown as Record<string, unknown>).signature;
    await expect(verifier(vi.fn<typeof fetch>(async () => response(value))).refresh())
      .rejects.toMatchObject({ code: 'EDGE_KEYRING_INVALID' });
  });

  it.each([
    ['wrong version', (value: SignedKeyringEnvelope) => {
      (value.keyring as unknown as { version: number }).version = 2;
    }],
    ['non-array keys', (value: SignedKeyringEnvelope) => {
      (value.keyring as unknown as { keys: unknown }).keys = {};
    }],
    ['empty keys', (value: SignedKeyringEnvelope) => {
      value.keyring.keys = [];
    }],
    ['invalid active id', (value: SignedKeyringEnvelope) => {
      value.keyring.activeKeyId = 'invalid';
    }],
    ['different signing id', (value: SignedKeyringEnvelope) => {
      value.signingKeyId = second.keyId;
    }],
    ['malformed signature', (value: SignedKeyringEnvelope) => {
      value.signature = 'ed25519:bad';
    }],
  ] as const)('rejects invalid keyring identity: %s', async (_name, mutate) => {
    const value = await envelope({ signer: first, keys: [key(first, 'active')] });
    mutate(value);
    if (_name !== 'different signing id' && _name !== 'malformed signature') {
      value.signature = await first.sign(value.keyring);
    }
    await expect(verifier(vi.fn<typeof fetch>(async () => response(value))).refresh())
      .rejects.toMatchObject({ code: 'EDGE_KEYRING_INVALID' });
  });

  it('rejects a keyring with more than 64 keys', async () => {
    const signers = Array.from({ length: 65 }, localSigner);
    const keys = signers.map((signer, index) => key(signer, index === 0 ? 'active' : 'standby'));
    const value = await envelope({ signer: signers[0]!, keys });
    await expect(verifier(
      vi.fn<typeof fetch>(async () => response(value)),
      { [signers[0]!.keyId]: signers[0]!.publicKeyPem },
    ).refresh()).rejects.toMatchObject({ code: 'EDGE_KEYRING_INVALID' });
  });

  it.each([
    ['invalid key id', (value: SignedKeyringEnvelope) => {
      value.keyring.keys[0]!.keyId = `_${first.keyId}`;
    }],
    ['wrong algorithm', (value: SignedKeyringEnvelope) => {
      (value.keyring.keys[0] as unknown as { algorithm: string }).algorithm = 'rsa';
    }],
    ['wrong provider', (value: SignedKeyringEnvelope) => {
      (value.keyring.keys[0] as unknown as { provider: string }).provider = 'unknown';
    }],
    ['wrong state', (value: SignedKeyringEnvelope) => {
      (value.keyring.keys[0] as unknown as { state: string }).state = 'unknown';
    }],
    ['non-string timestamp', (value: SignedKeyringEnvelope) => {
      (value.keyring.keys[0] as unknown as { activatedAt: unknown }).activatedAt = 1;
    }],
    ['invalid timestamp', (value: SignedKeyringEnvelope) => {
      value.keyring.keys[0]!.activatedAt = 'not-a-date';
    }],
    ['non-canonical timestamp', (value: SignedKeyringEnvelope) => {
      value.keyring.keys[0]!.activatedAt = '2026-08-11T10:00:00Z';
    }],
    ['non-string public key', (value: SignedKeyringEnvelope) => {
      (value.keyring.keys[0] as unknown as { publicKeyPem: unknown }).publicKeyPem = 1;
    }],
    ['oversized public key', (value: SignedKeyringEnvelope) => {
      value.keyring.keys[0]!.publicKeyPem = 'x'.repeat(8_193);
    }],
    ['malformed public key', (value: SignedKeyringEnvelope) => {
      value.keyring.keys[0]!.publicKeyPem = 'not-a-public-key';
    }],
  ] as const)('rejects invalid key metadata: %s', async (_name, mutate) => {
    await expectInvalid(mutate);
  });

  it('rejects a non-Ed25519 public key and mismatched key id', async () => {
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey
      .export({ format: 'pem', type: 'spki' }).toString();
    await expectInvalid((value) => {
      value.keyring.keys[0]!.publicKeyPem = rsa;
    });
    await expectInvalid((value) => {
      value.keyring.keys[0]!.publicKeyPem = second.publicKeyPem;
    });
  });

  it.each([
    ['active with retired date', 'active', null, ISO_NOW],
    ['active with revoked date', 'active', ISO_NOW, null],
    ['standby with retired date', 'standby', null, ISO_NOW],
    ['retired without retired date', 'retired', null, null],
    ['retired with revoked date', 'retired', ISO_NOW, ISO_NOW],
    ['revoked without revoked date', 'revoked', null, ISO_NOW],
    ['revoked without retired date', 'revoked', ISO_NOW, null],
  ] as const)(
    'rejects invalid key lifecycle: %s',
    async (_name, state, revokedAt, retiredAt) => {
      await expectInvalid((value) => {
        const target = value.keyring.keys[0]!;
        target.state = state;
        target.revokedAt = revokedAt;
        target.retiredAt = retiredAt;
      });
    },
  );

  it.each([
    ['future activation', (value: SignedKeyringEnvelope) => {
      value.keyring.keys[0]!.activatedAt = new Date(NOW + 1).toISOString();
    }],
    ['retirement before activation', (value: SignedKeyringEnvelope) => {
      const target = value.keyring.keys[0]!;
      target.state = 'retired';
      target.activatedAt = ISO_NOW;
      target.retiredAt = new Date(NOW - 1).toISOString();
    }],
    ['revocation before retirement', (value: SignedKeyringEnvelope) => {
      const target = value.keyring.keys[0]!;
      target.state = 'revoked';
      target.activatedAt = new Date(NOW - 2).toISOString();
      target.retiredAt = ISO_NOW;
      target.revokedAt = new Date(NOW - 1).toISOString();
    }],
  ] as const)('rejects invalid lifecycle chronology: %s', async (_name, mutate) => {
    await expectInvalid(mutate);
  });

  it('accepts local, KMS, and HSM providers in valid lifecycle states', async () => {
    const manifest = await envelope({
      signer: first,
      keys: [
        key(first, 'active'),
        { ...key(second, 'standby'), provider: 'kms' },
        { ...key(localSigner(), 'retired'), provider: 'hsm' },
      ],
    });
    await expect(verifier(vi.fn<typeof fetch>(async () => response(manifest))).refresh())
      .resolves.toBeUndefined();
  });

  it.each([
    ['string revision', (value: SignedKeyringEnvelope) => {
      (value.keyring as unknown as { revisionMs: unknown }).revisionMs = String(NOW);
    }],
    ['zero revision', (value: SignedKeyringEnvelope) => {
      value.keyring.revisionMs = 0;
    }],
    ['future generated time', (value: SignedKeyringEnvelope) => {
      value.keyring.generatedAtMs = NOW + 5 * 60 * 1000 + 1;
    }],
    ['non-increasing expiry', (value: SignedKeyringEnvelope) => {
      value.keyring.generatedAtMs = NOW + 1_000;
      value.keyring.revisionMs = NOW + 1_000;
      value.keyring.expiresAtMs = value.keyring.generatedAtMs;
    }],
    ['excess duration', (value: SignedKeyringEnvelope) => {
      value.keyring.expiresAtMs = value.keyring.generatedAtMs + 15 * 60 * 1000 + 1;
    }],
    ['expired', (value: SignedKeyringEnvelope) => {
      value.keyring.generatedAtMs = NOW - 1;
      value.keyring.expiresAtMs = NOW;
    }],
    ['future revision', (value: SignedKeyringEnvelope) => {
      value.keyring.revisionMs = value.keyring.generatedAtMs + 5 * 60 * 1000 + 1;
    }],
  ] as const)('rejects invalid validity window: %s', async (_name, mutate) => {
    await expectInvalid(mutate);
  });

  it('accepts every exact validity boundary', async () => {
    now = NOW;
    const value = await envelope({
      signer: first,
      keys: [key(first, 'active')],
      revisionMs: NOW + 10 * 60 * 1000,
      generatedAtMs: NOW + 5 * 60 * 1000,
      expiresAtMs: NOW + 20 * 60 * 1000,
    });
    await expect(verifier(vi.fn<typeof fetch>(async () => response(value))).refresh())
      .resolves.toBeUndefined();
  });

  it('accepts the exact minimum revision and exact maximum key count', async () => {
    const signers = [first, ...Array.from({ length: 63 }, localSigner)];
    const value = await envelope({
      signer: first,
      keys: signers.map((signer, index) => key(signer, index === 0 ? 'active' : 'standby')),
      revisionMs: 1,
    });
    await expect(verifier(vi.fn<typeof fetch>(async () => response(value))).refresh())
      .resolves.toBeUndefined();
  });

  it('accepts a valid Ed25519 PEM padded to the exact field limit', async () => {
    const padded = first.publicKeyPem.padEnd(8_192, ' ');
    const value = await envelope({
      signer: first,
      keys: [{ ...key(first, 'active'), publicKeyPem: padded }],
    });
    await expect(verifier(
      vi.fn<typeof fetch>(async () => response(value)),
      { [first.keyId]: padded },
    ).refresh()).resolves.toBeUndefined();
  });

  it('rejects duplicate keys, missing active key, multiple active keys, and active-id mismatch', async () => {
    await expectInvalid((value) => {
      value.keyring.keys.push({ ...value.keyring.keys[0]! });
    });
    await expectInvalid((value) => {
      value.keyring.keys[0] = key(first, 'standby');
    });
    await expectInvalid((value) => {
      value.keyring.keys.push(key(second, 'active'));
    });
    await expectInvalid((value) => {
      value.keyring.activeKeyId = second.keyId;
    });
  });

  it('treats key ordering as irrelevant for an unchanged revision', async () => {
    const initial = await envelope({
      signer: first,
      keys: [key(first, 'active'), key(second, 'standby')],
    });
    const reordered = await envelope({
      signer: first,
      keys: [key(second, 'standby'), key(first, 'active')],
      revisionMs: NOW,
      generatedAtMs: NOW + 5_000,
    });
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(response(initial))
      .mockResolvedValueOnce(response(reordered));
    const keyringVerifier = verifier(fetchMock);
    await keyringVerifier.refresh();
    now += 5_000;
    await expect(keyringVerifier.refresh()).resolves.toBeUndefined();
  });

  it('fails closed on same-revision equivocation after the cached keyring expires', async () => {
    const initial = await envelope({
      signer: first,
      keys: [key(first, 'active')],
      expiresAtMs: NOW + 5_000,
    });
    const conflict = await envelope({
      signer: first,
      keys: [{ ...key(first, 'active'), provider: 'kms' }],
      revisionMs: NOW,
      generatedAtMs: NOW + 5_000,
    });
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(response(initial))
      .mockResolvedValueOnce(response(conflict));
    const keyringVerifier = verifier(fetchMock);
    await keyringVerifier.refresh();
    now += 5_000;
    await expect(keyringVerifier.refresh()).rejects.toMatchObject({
      code: 'EDGE_KEYRING_EQUIVOCATION',
    });
  });

  it('fails closed when an expired keyring is replaced without every trusted key', async () => {
    const initial = await envelope({
      signer: first,
      keys: [key(first, 'active'), key(second, 'standby')],
      expiresAtMs: NOW + 5_000,
    });
    const removed = await envelope({
      signer: second,
      keys: [key(second, 'active')],
      revisionMs: NOW + 5_000,
      generatedAtMs: NOW + 5_000,
    });
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(response(initial))
      .mockResolvedValueOnce(response(removed));
    const keyringVerifier = verifier(fetchMock);
    await keyringVerifier.refresh();
    now += 5_000;
    await expect(keyringVerifier.refresh()).rejects.toMatchObject({
      code: 'EDGE_KEYRING_CONTINUITY_BROKEN',
    });
  });

  it('rejects missing, invalid, and streamed oversized response bodies', async () => {
    await expect(verifier(vi.fn<typeof fetch>(async () => new Response(null))).refresh())
      .rejects.toMatchObject({ code: 'EDGE_KEYRING_INVALID' });
    await expect(verifier(vi.fn<typeof fetch>(async () => new Response('{'))).refresh())
      .rejects.toMatchObject({ code: 'EDGE_KEYRING_INVALID' });
    await expect(verifier(vi.fn<typeof fetch>(async () => new Response(
      'x'.repeat(256 * 1024 + 1),
    ))).refresh()).rejects.toMatchObject({ code: 'EDGE_KEYRING_INVALID' });
  });

  it('reassembles a valid multi-chunk response', async () => {
    const manifest = await envelope({ signer: first, keys: [key(first, 'active')] });
    const bytes = new TextEncoder().encode(JSON.stringify(manifest));
    const split = Math.floor(bytes.byteLength / 2);
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(bytes.slice(0, split));
        controller.enqueue(bytes.slice(split));
        controller.close();
      },
    });
    await expect(verifier(vi.fn<typeof fetch>(async () => new Response(body))).refresh())
      .resolves.toBeUndefined();
  });

  it.each(['-1', '1.5', 'invalid', String(256 * 1024 + 1)])(
    'rejects invalid declared response length %s',
    async (length) => {
      await expect(verifier(vi.fn<typeof fetch>(async () => new Response('{}', {
        headers: { 'content-length': length },
      }))).refresh()).rejects.toMatchObject({ code: 'EDGE_KEYRING_INVALID' });
    },
  );

  it('accepts the exact maximum declared response length', async () => {
    const manifest = await envelope({ signer: first, keys: [key(first, 'active')] });
    const result = response(manifest);
    result.headers.set('content-length', String(256 * 1024));
    await expect(verifier(vi.fn<typeof fetch>(async () => result)).refresh())
      .resolves.toBeUndefined();
  });

  it('accepts a zero declared length and an actual body at the exact byte limit', async () => {
    const manifest = await envelope({ signer: first, keys: [key(first, 'active')] });
    const zeroHeader = response(manifest);
    zeroHeader.headers.set('content-length', '0');
    await expect(verifier(vi.fn<typeof fetch>(async () => zeroHeader)).refresh())
      .resolves.toBeUndefined();

    const json = JSON.stringify(manifest);
    const exactBody = `${json}${' '.repeat(256 * 1024 - Buffer.byteLength(json))}`;
    await expect(verifier(vi.fn<typeof fetch>(async () => new Response(exactBody))).refresh())
      .resolves.toBeUndefined();
  });

  it('rejects HTTP errors without exposing or parsing their response body', async () => {
    await expect(verifier(vi.fn<typeof fetch>(async () => new Response('sensitive', {
      status: 503,
    }))).refresh()).rejects.toMatchObject({
      code: 'EDGE_KEYRING_UNAVAILABLE',
      message: 'Control rejected the keyring request',
    });
  });

  it('refreshes at the expiry window even when the normal interval is later', async () => {
    const initial = await envelope({
      signer: first,
      keys: [key(first, 'active')],
      expiresAtMs: NOW + 6_000,
    });
    const renewed = await envelope({
      signer: first,
      keys: [key(first, 'active')],
      generatedAtMs: NOW + 1_000,
      revisionMs: NOW,
    });
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(response(initial))
      .mockResolvedValueOnce(response(renewed));
    const keyringVerifier = verifier(fetchMock, undefined, {
      refreshIntervalMs: 600_000,
      refreshBeforeExpiryMs: 5_000,
    });
    await keyringVerifier.refresh();
    now += 999;
    await keyringVerifier.verify({}, first.keyId, await first.sign({}));
    expect(fetchMock).toHaveBeenCalledTimes(1);
    now += 1;
    await keyringVerifier.verify({}, first.keyId, await first.sign({}));
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('does not apply failure backoff after a successful refresh', async () => {
    const firstManifest = await envelope({
      signer: first,
      keys: [key(first, 'active')],
      expiresAtMs: NOW + 4_000,
    });
    const secondManifest = await envelope({
      signer: first,
      keys: [key(first, 'active')],
      revisionMs: NOW,
      generatedAtMs: NOW + 1,
    });
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(response(firstManifest))
      .mockResolvedValueOnce(response(secondManifest));
    const keyringVerifier = verifier(fetchMock);
    await keyringVerifier.refresh();
    now += 1;
    await keyringVerifier.verify({}, first.keyId, await first.sign({}));
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it.each([
    `x${'ed25519:'}${'a'.repeat(86)}`,
    `ed25519:${'a'.repeat(86)}x`,
    `ed25519:${'!'.repeat(86)}`,
  ])('rejects a malformed signature boundary: %s', async (signature) => {
    const value = await envelope({ signer: first, keys: [key(first, 'active')] });
    value.signature = signature;
    await expect(verifier(vi.fn<typeof fetch>(async () => response(value))).refresh())
      .rejects.toMatchObject({ code: 'EDGE_KEYRING_INVALID' });
  });

  it('aborts a stalled keyring request at the configured timeout', async () => {
    vi.useFakeTimers();
    try {
      const fetchMock = vi.fn<typeof fetch>((_url, init) => new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new DOMException(
          'aborted',
          'AbortError',
        )), { once: true });
      }));
      const keyringVerifier = verifier(fetchMock, undefined, { requestTimeoutMs: 500 });
      const pending = keyringVerifier.refresh();
      const rejection = expect(pending).rejects.toMatchObject({ code: 'EDGE_KEYRING_TIMEOUT' });
      await vi.advanceTimersByTimeAsync(500);
      await rejection;
    } finally {
      vi.useRealTimers();
    }
  });

  it('validates bootstrap trust roots and configuration boundaries', () => {
    const create = (input: Partial<ConstructorParameters<
      typeof ControlEdgeKeyringVerifier
    >[0]> = {}) => new ControlEdgeKeyringVerifier({
      controlBaseUrl: 'https://control.otto.test',
      bootstrapPublicKeys: { [first.keyId]: first.publicKeyPem },
      ...input,
    });
    expect(() => create({ controlBaseUrl: 'http://control.otto.test' }))
      .toThrow(EdgeControlKeyringError);
    expect(() => create({ controlBaseUrl: 'not a URL' })).toThrow(EdgeControlKeyringError);
    expect(() => create({ bootstrapPublicKeys: {} })).toThrow('bootstrap public keys');
    expect(() => create({ bootstrapPublicKeys: { invalid: first.publicKeyPem } }))
      .toThrow('bootstrap key id');
    expect(() => create({ bootstrapPublicKeys: { [first.keyId]: second.publicKeyPem } }))
      .toThrow('does not match');
    for (const refreshIntervalMs of [4_999, 600_001, 1.5, Number.NaN]) {
      expect(() => create({ refreshIntervalMs })).toThrow('refresh interval');
    }
    for (const unknownKeyRetryMs of [999, 60_001, 1.5, Number.NaN]) {
      expect(() => create({ unknownKeyRetryMs })).toThrow('unknown key retry');
    }
  });
});

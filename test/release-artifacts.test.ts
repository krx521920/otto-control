import { generateKeyPairSync, verify, type KeyObject } from 'node:crypto';

import { beforeEach, describe, expect, it } from 'vitest';

import { canonicalJson, LocalEd25519Signer } from '../src/crypto/signed-envelope.js';
import { ManagedSigningKeyring } from '../src/crypto/signing-keyring.js';
import { ReleaseArtifactService } from '../src/modules/release-artifacts/service.js';
import type { UpdateReleaseRecord } from '../src/storage/control-store.js';
import { MemoryControlStore } from './helpers/memory-store.js';

const ACTOR = 'release.admin';
const MANIFEST_URL = 'https://updates.example.test/otto/2.0.0/latest.json';
const MANIFEST_SHA = 'a'.repeat(64);

describe('signed release artifact service', () => {
  let store: MemoryControlStore;
  let service: ReleaseArtifactService;
  let release: UpdateReleaseRecord;
  let publicKey: KeyObject;
  let now: number;

  beforeEach(async () => {
    store = new MemoryControlStore();
    const keys = generateKeyPairSync('ed25519');
    publicKey = keys.publicKey;
    const localSigner = new LocalEd25519Signer(
      keys.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    );
    const signer = await ManagedSigningKeyring.create({
      store,
      providers: [{ signer: localSigner, provider: 'local' }],
    });
    now = Date.parse('2026-08-01T08:00:00.000Z');
    service = new ReleaseArtifactService({ store, signer, now: () => now });
    await store.createUpdateDistribution({ id: 'otto', name: 'Otto desktop' });
    release = await store.createUpdateRelease({
      id: 'rel_artifacts1234567890',
      distributionId: 'otto',
      version: '2.0.0',
      sourceCommit: 'abcdef1234567',
      channel: 'stable',
      rolloutPercent: 100,
      notes: 'Signed release',
      fullManifestUrl: MANIFEST_URL,
      fullManifestSha256: MANIFEST_SHA,
      incrementalManifestUrl: null,
      incrementalManifestSha256: null,
    });
  });

  async function registerReadyArtifacts(): Promise<{ installerId: string }> {
    await service.register(release.id, {
      kind: 'update_manifest',
      platform: 'any',
      url: MANIFEST_URL,
      sha256: MANIFEST_SHA,
      sizeBytes: 4096,
    }, ACTOR);
    const installer = await service.register(release.id, {
      kind: 'windows_installer',
      platform: 'windows-x64',
      url: 'https://updates.example.test/otto/2.0.0/Otto-Setup.exe',
      sha256: 'b'.repeat(64),
      sizeBytes: 125_000_000,
    }, ACTOR);
    return { installerId: installer.artifact.id };
  }

  it('signs immutable artifact metadata and verifies it before release activation', async () => {
    const { installerId } = await registerReadyArtifacts();
    const installer = (await service.list(release.id))
      .find((artifact) => artifact.artifact.id === installerId)!;
    expect(installer).toMatchObject({
      state: 'active',
      artifact: {
        releaseId: release.id,
        distributionId: 'otto',
        releaseVersion: '2.0.0',
        sourceCommit: 'abcdef1234567',
        kind: 'windows_installer',
        platform: 'windows-x64',
      },
    });
    expect(verify(
      null,
      Buffer.from(canonicalJson(installer.artifact)),
      publicKey,
      Buffer.from(installer.signature.slice('ed25519:'.length), 'base64url'),
    )).toBe(true);
    await expect(service.assertReleaseReady(release)).resolves.toBeUndefined();
    await expect(service.assertReleaseReady({
      ...release,
      sourceCommit: 'fedcba7654321',
    })).rejects.toThrow('not bound to the current release metadata');
  });

  it('fails closed for missing packages, mismatched manifests, and tampered signatures', async () => {
    await expect(service.assertReleaseReady(release)).rejects.toThrow('installable artifact');
    await service.register(release.id, {
      kind: 'update_manifest',
      platform: 'any',
      url: MANIFEST_URL,
      sha256: 'c'.repeat(64),
      sizeBytes: 4096,
    }, ACTOR);
    const installer = await service.register(release.id, {
      kind: 'windows_installer',
      platform: 'windows-x64',
      url: 'https://updates.example.test/otto/2.0.0/Otto-Setup.exe',
      sha256: 'd'.repeat(64),
      sizeBytes: 125_000_000,
    }, ACTOR);
    await expect(service.assertReleaseReady(release)).rejects.toThrow('release URL and digest');

    const record = store.releaseArtifacts.get(installer.artifact.id)!;
    store.releaseArtifacts.set(record.id, { ...record, signature: 'ed25519:AAAA' });
    const correctedRelease = { ...release, fullManifestSha256: 'c'.repeat(64) };
    await expect(service.assertReleaseReady(correctedRelease)).rejects.toThrow('signature is invalid');
  });

  it('validates platform and transport metadata before signing', async () => {
    await expect(service.register(release.id, {
      kind: 'windows_installer',
      platform: 'macos-universal',
      url: 'https://updates.example.test/Otto.exe',
      sha256: 'b'.repeat(64),
      sizeBytes: 100,
    }, ACTOR)).rejects.toThrow('Windows platform');
    await expect(service.register(release.id, {
      kind: 'macos_dmg',
      platform: 'macos-universal',
      url: 'http://updates.example.test/Otto.dmg',
      sha256: 'b'.repeat(64),
      sizeBytes: 100,
    }, ACTOR)).rejects.toThrow('HTTPS URL');
    await expect(service.register(release.id, {
      kind: 'macos_dmg',
      platform: 'macos-universal',
      url: 'https://updates.example.test/Otto.dmg',
      sha256: 'b'.repeat(64),
      sizeBytes: 0,
    }, ACTOR)).rejects.toThrow('positive safe integer');
  });

  it('revokes with a durable reason and pauses an affected active release', async () => {
    const { installerId } = await registerReadyArtifacts();
    await store.activateUpdateRelease(release.id, new Date(now));
    now += 1000;
    const result = await service.revoke(installerId, {
      reason: 'Upstream package was replaced after publication',
    }, ACTOR);
    expect(result.releasePaused).toBe(true);
    expect(result.artifact).toMatchObject({
      state: 'revoked',
      revokedBy: ACTOR,
      revocationReason: 'Upstream package was replaced after publication',
    });
    expect((await store.getUpdateRelease(release.id))?.state).toBe('paused');
    expect(store.audits.at(-1)).toMatchObject({
      action: 'release_artifact.revoked',
      detail: { releasePaused: true },
    });
  });
});

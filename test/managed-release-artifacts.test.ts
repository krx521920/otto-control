import { generateKeyPairSync, sign, type KeyObject } from 'node:crypto';

import Fastify from 'fastify';
import { beforeEach, describe, expect, it } from 'vitest';

import type {
  ArtifactCodeSigningEvidencePayload,
  SignedArtifactCodeSigningEvidence,
} from '../src/contracts/artifact-storage.js';
import { canonicalJson, LocalEd25519Signer } from '../src/crypto/signed-envelope.js';
import { ManagedSigningKeyring } from '../src/crypto/signing-keyring.js';
import { TrustedArtifactAttestationVerifier } from '../src/modules/release-artifacts/attestation.js';
import type { AdminIdentityService } from '../src/modules/admin-identity/service.js';
import type {
  ArtifactObjectIdentity,
  ArtifactObjectStore,
  ArtifactUploadTarget,
  StoredArtifactObject,
} from '../src/modules/release-artifacts/object-store.js';
import { ReleaseArtifactService } from '../src/modules/release-artifacts/service.js';
import { registerReleaseArtifactRoutes } from '../src/routes/release-artifacts.js';
import type { UpdateReleaseRecord } from '../src/storage/control-store.js';
import { MemoryControlStore } from './helpers/memory-store.js';

const ACTOR = 'release.admin';
const MANIFEST_SHA = 'a'.repeat(64);
const INSTALLER_SHA = 'b'.repeat(64);

class FakeArtifactObjectStore implements ArtifactObjectStore {
  readonly managed = true as const;
  readonly objects = new Map<string, StoredArtifactObject>();

  objectKey(identity: ArtifactObjectIdentity): string {
    return `releases/${identity.releaseId}/${identity.platform}/${identity.kind}-${identity.sha256}`;
  }

  async createUpload(input: {
    objectKey: string;
    sha256: string;
    sizeBytes: number;
    contentType: string;
    expiresAt: Date;
  }): Promise<ArtifactUploadTarget> {
    return {
      method: 'PUT',
      url: `https://storage.example.test/upload/${encodeURIComponent(input.objectKey)}?signature=secret`,
      headers: {
        'content-length': String(input.sizeBytes),
        'content-type': input.contentType,
        'x-amz-checksum-sha256': Buffer.from(input.sha256, 'hex').toString('base64'),
      },
      expiresAt: input.expiresAt.toISOString(),
    };
  }

  async inspect(objectKey: string): Promise<StoredArtifactObject> {
    const object = this.objects.get(objectKey);
    if (!object) throw new Error('object missing');
    return object;
  }

  async createDownloadUrl(objectKey: string): Promise<string> {
    return `https://cdn.example.test/${objectKey}?temporary=secret`;
  }

  store(ticket: { objectKey: string; sha256: string; sizeBytes: number }): void {
    this.objects.set(ticket.objectKey, {
      objectKey: ticket.objectKey,
      sizeBytes: ticket.sizeBytes,
      checksumSha256: ticket.sha256,
      versionId: `version-${ticket.sha256.slice(0, 8)}`,
      serverSideEncryption: 'AES256',
      objectLockMode: 'COMPLIANCE',
      objectLockRetainUntil: '2027-08-01T00:00:00.000Z',
    });
  }
}

describe('managed release artifact pipeline', () => {
  let store: MemoryControlStore;
  let objectStore: FakeArtifactObjectStore;
  let service: ReleaseArtifactService;
  let release: UpdateReleaseRecord;
  let attestationPrivateKey: KeyObject;
  let now: number;

  beforeEach(async () => {
    store = new MemoryControlStore();
    objectStore = new FakeArtifactObjectStore();
    now = Date.parse('2026-08-02T08:00:00.000Z');
    const controlKeys = generateKeyPairSync('ed25519');
    const signer = await ManagedSigningKeyring.create({
      store,
      providers: [{
        provider: 'local',
        signer: new LocalEd25519Signer(
          controlKeys.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
        ),
      }],
    });
    const attestationKeys = generateKeyPairSync('ed25519');
    attestationPrivateKey = attestationKeys.privateKey;
    const verifier = new TrustedArtifactAttestationVerifier(new Map([
      ['release-runner-1', attestationKeys.publicKey],
    ]));
    service = new ReleaseArtifactService({
      store,
      signer,
      objectStore,
      attestationVerifier: verifier,
      publicBaseUrl: 'https://control.example.test',
      storageRequired: true,
      objectLockRequired: true,
      now: () => now,
    });
    await store.createUpdateDistribution({ id: 'otto', name: 'Otto desktop' });
    release = await store.createUpdateRelease({
      id: 'rel_managed1234567890',
      distributionId: 'otto',
      version: '2.1.0',
      sourceCommit: 'abcdef1234567',
      channel: 'stable',
      rolloutPercent: 100,
      notes: 'Managed release',
      fullManifestUrl: null,
      fullManifestSha256: null,
      incrementalManifestUrl: null,
      incrementalManifestSha256: null,
    });
  });

  function codeSigning(
    ticket: Awaited<ReturnType<ReleaseArtifactService['createUpload']>>['ticket']['ticket'],
    overrides: Partial<ArtifactCodeSigningEvidencePayload> = {},
  ): SignedArtifactCodeSigningEvidence {
    const evidence: ArtifactCodeSigningEvidencePayload = {
      version: 1,
      releaseId: ticket.releaseId,
      releaseVersion: ticket.releaseVersion,
      sourceCommit: ticket.sourceCommit,
      kind: ticket.kind,
      platform: ticket.platform,
      sha256: ticket.sha256,
      sizeBytes: ticket.sizeBytes,
      system: 'authenticode',
      status: 'valid',
      signerIdentity: 'CN=Otto Release Signing',
      certificateSha256: 'c'.repeat(64),
      timestamped: true,
      notarized: false,
      verifier: 'windows-signing-runner-1',
      evidenceSha256: 'd'.repeat(64),
      verifiedAtMs: now,
      ...overrides,
    };
    return {
      evidence,
      attestationKeyId: 'release-runner-1',
      signature: `ed25519:${sign(
        null,
        Buffer.from(canonicalJson(evidence)),
        attestationPrivateKey,
      ).toString('base64url')}`,
    };
  }

  async function upload(input: {
    kind: 'windows_installer' | 'update_manifest';
    platform: 'windows-x64' | 'any';
    sha256: string;
    sizeBytes: number;
  }) {
    const created = await service.createUpload(release.id, input, ACTOR);
    objectStore.store(created.ticket.ticket);
    return created;
  }

  it('uploads directly, verifies storage and code signing, then completes idempotently', async () => {
    const manifest = await upload({
      kind: 'update_manifest', platform: 'any', sha256: MANIFEST_SHA, sizeBytes: 4096,
    });
    await service.completeUpload(release.id, { ticket: manifest.ticket }, ACTOR);
    const installer = await upload({
      kind: 'windows_installer', platform: 'windows-x64', sha256: INSTALLER_SHA, sizeBytes: 100_000,
    });
    const evidence = codeSigning(installer.ticket.ticket);
    const first = await service.completeUpload(release.id, {
      ticket: installer.ticket,
      codeSigning: evidence,
    }, ACTOR);
    const replay = await service.completeUpload(release.id, {
      ticket: installer.ticket,
      codeSigning: evidence,
    }, ACTOR);

    expect(replay.artifact.id).toBe(first.artifact.id);
    expect(store.releaseArtifacts).toHaveLength(2);
    expect(first).toMatchObject({
      storage: {
        objectVersionId: `version-${INSTALLER_SHA.slice(0, 8)}`,
        serverSideEncryption: 'AES256',
        objectLockMode: 'COMPLIANCE',
        codeSigning: { attestationKeyId: 'release-runner-1' },
      },
    });
    await expect(service.assertReleaseReady(release)).resolves.toBeUndefined();
    await expect(service.resolveDownload(first.artifact.id)).resolves.toMatchObject({
      url: expect.stringContaining('temporary=secret'),
    });
    expect(store.audits.some((event) => (
      event.action === 'release_artifact.upload_completed'
      && !JSON.stringify(event.detail).includes('temporary=secret')
      && !JSON.stringify(event.detail).includes('signature=secret')
    ))).toBe(true);
  });

  it('rejects missing bytes, checksum replacement and untrusted signing evidence before persistence', async () => {
    const created = await service.createUpload(release.id, {
      kind: 'windows_installer',
      platform: 'windows-x64',
      sha256: INSTALLER_SHA,
      sizeBytes: 100_000,
    }, ACTOR);
    await expect(service.completeUpload(release.id, {
      ticket: created.ticket,
      codeSigning: codeSigning(created.ticket.ticket),
    }, ACTOR)).rejects.toThrow('object missing');

    objectStore.store(created.ticket.ticket);
    objectStore.objects.set(created.ticket.ticket.objectKey, {
      ...objectStore.objects.get(created.ticket.ticket.objectKey)!,
      checksumSha256: 'e'.repeat(64),
    });
    await expect(service.completeUpload(release.id, {
      ticket: created.ticket,
      codeSigning: codeSigning(created.ticket.ticket),
    }, ACTOR)).rejects.toThrow('does not match');
    expect(store.releaseArtifacts.size).toBe(0);

    objectStore.store(created.ticket.ticket);
    const forged = codeSigning(created.ticket.ticket);
    forged.signature = 'ed25519:AAAA';
    await expect(service.completeUpload(release.id, {
      ticket: created.ticket,
      codeSigning: forged,
    }, ACTOR)).rejects.toThrow('signature is invalid');
    expect(store.releaseArtifacts.size).toBe(0);
  });

  it('requires platform-specific timestamp and notarization evidence', async () => {
    const installer = await upload({
      kind: 'windows_installer', platform: 'windows-x64', sha256: INSTALLER_SHA, sizeBytes: 100_000,
    });
    await expect(service.completeUpload(release.id, {
      ticket: installer.ticket,
      codeSigning: codeSigning(installer.ticket.ticket, { timestamped: false }),
    }, ACTOR)).rejects.toThrow('timestamped Authenticode');
  });

  it('detects object version and storage-control changes after completion', async () => {
    const installer = await upload({
      kind: 'windows_installer', platform: 'windows-x64', sha256: INSTALLER_SHA, sizeBytes: 100_000,
    });
    const evidence = codeSigning(installer.ticket.ticket);
    const artifact = await service.completeUpload(release.id, {
      ticket: installer.ticket,
      codeSigning: evidence,
    }, ACTOR);
    const stored = objectStore.objects.get(installer.ticket.ticket.objectKey)!;
    objectStore.objects.set(installer.ticket.ticket.objectKey, {
      ...stored,
      versionId: 'replacement-version',
    });
    await expect(service.completeUpload(release.id, {
      ticket: installer.ticket,
      codeSigning: evidence,
    }, ACTOR)).rejects.toThrow('object version changed');
    await expect(service.resolveDownload(artifact.artifact.id)).rejects.toThrow(
      'object version changed',
    );

    objectStore.objects.set(installer.ticket.ticket.objectKey, {
      ...stored,
      serverSideEncryption: 'aws:kms',
    });
    await expect(service.resolveDownload(artifact.artifact.id)).rejects.toThrow(
      'storage controls changed',
    );
  });

  it('stops managed downloads after revocation', async () => {
    const installer = await upload({
      kind: 'windows_installer', platform: 'windows-x64', sha256: INSTALLER_SHA, sizeBytes: 100_000,
    });
    const artifact = await service.completeUpload(release.id, {
      ticket: installer.ticket,
      codeSigning: codeSigning(installer.ticket.ticket),
    }, ACTOR);
    await service.revoke(artifact.artifact.id, {
      reason: 'Signing certificate was revoked by the publisher',
    }, ACTOR);
    await expect(service.resolveDownload(artifact.artifact.id)).rejects.toThrow('unavailable');
  });

  it('exposes the upload, completion, and stable download HTTP flow', async () => {
    const app = Fastify({ logger: false });
    const identity = {
      authenticate: async () => ({
        accountId: ACTOR,
        sessionId: 'session-release-route',
        username: ACTOR,
        displayName: 'Release Admin',
        roles: ['release_manager'],
        permissions: ['update_release.create', 'update_release.read', 'update_release.publish'],
        mfaVerifiedAt: new Date(now),
      }),
    } as unknown as AdminIdentityService;
    await registerReleaseArtifactRoutes(app, { service, identity });
    try {
      const issued = await app.inject({
        method: 'POST',
        url: `/v1/admin/update-releases/${release.id}/artifact-uploads`,
        headers: { authorization: 'Bearer test-release-session' },
        payload: {
          kind: 'windows_installer',
          platform: 'windows-x64',
          sha256: INSTALLER_SHA,
          sizeBytes: 100_000,
        },
      });
      expect(issued.statusCode).toBe(201);
      const uploadResult = issued.json() as Awaited<ReturnType<ReleaseArtifactService['createUpload']>>;
      expect(uploadResult.upload.url).toContain('signature=secret');
      objectStore.store(uploadResult.ticket.ticket);

      const completed = await app.inject({
        method: 'POST',
        url: `/v1/admin/update-releases/${release.id}/artifact-uploads/complete`,
        headers: { authorization: 'Bearer test-release-session' },
        payload: {
          ticket: uploadResult.ticket,
          codeSigning: codeSigning(uploadResult.ticket.ticket),
        },
      });
      expect(completed.statusCode).toBe(201);
      const artifactId = completed.json().artifact.artifact.id as string;

      const download = await app.inject({
        method: 'GET',
        url: `/v1/release-artifacts/${artifactId}/download`,
      });
      expect(download.statusCode).toBe(307);
      expect(download.headers.location).toContain('temporary=secret');
      expect(download.headers['cache-control']).toBe('no-store');
    } finally {
      await app.close();
    }
  });
});

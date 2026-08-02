import { createPublicKey, randomUUID, verify } from 'node:crypto';

import {
  RELEASE_ARTIFACT_KINDS,
  RELEASE_ARTIFACT_PLATFORMS,
  type ReleaseArtifactKind,
  type ReleaseArtifactPayload,
  type ReleaseArtifactPlatform,
  type ReleaseArtifactView,
  type SignedReleaseArtifactEnvelope,
} from '../../contracts/release-artifact.js';
import type {
  ArtifactStorageEvidence,
  ArtifactUploadTicketPayload,
  SignedArtifactCodeSigningEvidence,
  SignedArtifactUploadTicket,
} from '../../contracts/artifact-storage.js';
import {
  canonicalJson,
  ED25519_SIGNATURE_PREFIX,
  signPayload,
  type PayloadSigner,
} from '../../crypto/signed-envelope.js';
import { conflict, invalidRequest, notFound } from '../../errors.js';
import type {
  ControlStore,
  ReleaseArtifactRecord,
  ReleaseArtifactEvidenceRecord,
  UpdateReleaseRecord,
} from '../../storage/control-store.js';
import type { ArtifactAttestationVerifier } from './attestation.js';
import type { ArtifactObjectStore, StoredArtifactObject } from './object-store.js';

const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const ARTIFACT_ID_PATTERN = /^art_[a-zA-Z0-9_-]{16,64}$/u;
const UPLOAD_ID_PATTERN = /^upl_[a-zA-Z0-9_-]{16,64}$/u;
const INSTALLABLE_KINDS = new Set<ReleaseArtifactKind>([
  'windows_installer',
  'macos_dmg',
  'linux_archive',
  'enterprise_server',
]);

export interface ReleaseArtifactServiceOptions {
  store: ControlStore;
  signer: PayloadSigner;
  now?: () => number;
  objectStore?: ArtifactObjectStore | null;
  attestationVerifier?: ArtifactAttestationVerifier | null;
  publicBaseUrl?: string | null;
  uploadTtlSeconds?: number;
  downloadTtlSeconds?: number;
  storageRequired?: boolean;
  objectLockRequired?: boolean;
}

function objectValue(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw invalidRequest('request body must be an object');
  }
  return value as Record<string, unknown>;
}

function requiredString(
  body: Record<string, unknown>,
  key: string,
  maxLength: number,
): string {
  const value = body[key];
  if (typeof value !== 'string' || !value.trim() || value.trim().length > maxLength) {
    throw invalidRequest(`${key} is invalid`);
  }
  return value.trim();
}

function httpsUrl(value: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw invalidRequest('url must be an absolute HTTPS URL');
  }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.hash) {
    throw invalidRequest('url must be an HTTPS URL without credentials or fragments');
  }
  return parsed.toString();
}

function validateKindPlatform(
  kind: ReleaseArtifactKind,
  platform: ReleaseArtifactPlatform,
): void {
  if ((kind === 'update_manifest' || kind === 'incremental_manifest') && platform !== 'any') {
    throw invalidRequest('update manifests must use platform any');
  }
  if (kind === 'windows_installer' && !platform.startsWith('windows-')) {
    throw invalidRequest('windows installer must use a Windows platform');
  }
  if (kind === 'macos_dmg' && !platform.startsWith('macos-')) {
    throw invalidRequest('macOS DMG must use a macOS platform');
  }
  if ((kind === 'linux_archive' || kind === 'enterprise_server')
    && !platform.startsWith('linux-')) {
    throw invalidRequest(`${kind} must use a Linux platform`);
  }
}

function payloadFromRecord(record: ReleaseArtifactRecord): ReleaseArtifactPayload {
  return {
    version: 1,
    id: record.id,
    releaseId: record.releaseId,
    distributionId: record.distributionId,
    releaseVersion: record.releaseVersion,
    sourceCommit: record.sourceCommit,
    kind: record.kind,
    platform: record.platform,
    url: record.url,
    sha256: record.sha256,
    sizeBytes: record.sizeBytes,
    createdAtMs: record.createdAt.getTime(),
  };
}

function envelopeFromRecord(record: ReleaseArtifactRecord): SignedReleaseArtifactEnvelope {
  return {
    artifact: payloadFromRecord(record),
    signingKeyId: record.signingKeyId,
    signature: record.signature,
  };
}

function storageView(evidence: ReleaseArtifactEvidenceRecord): ArtifactStorageEvidence {
  return {
    artifactId: evidence.artifactId,
    objectKey: evidence.objectKey,
    objectVersionId: evidence.objectVersionId,
    verifiedAt: evidence.verifiedAt.toISOString(),
    serverSideEncryption: evidence.serverSideEncryption,
    objectLockMode: evidence.objectLockMode,
    objectLockRetainUntil: evidence.objectLockRetainUntil?.toISOString() ?? null,
    codeSigning: evidence.codeSigning,
  };
}

function viewFromRecord(
  record: ReleaseArtifactRecord,
  evidence?: ReleaseArtifactEvidenceRecord | null,
): ReleaseArtifactView {
  return {
    ...envelopeFromRecord(record),
    state: record.state,
    revokedAt: record.revokedAt?.toISOString() ?? null,
    revokedBy: record.revokedBy,
    revocationReason: record.revocationReason,
    storage: evidence ? storageView(evidence) : null,
  };
}

function contentTypeFor(kind: ReleaseArtifactKind, value: unknown): string {
  const defaults: Record<ReleaseArtifactKind, string> = {
    windows_installer: 'application/vnd.microsoft.portable-executable',
    macos_dmg: 'application/x-apple-diskimage',
    linux_archive: 'application/gzip',
    enterprise_server: 'application/gzip',
    update_manifest: 'application/json',
    incremental_manifest: 'application/json',
    skills_component: 'application/gzip',
    renderer_patch: 'application/gzip',
    server_runtime: 'application/gzip',
  };
  if (value === undefined || value === null || value === '') return defaults[kind];
  if (typeof value !== 'string'
    || !/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/iu.test(value)
    || value.length > 120) {
    throw invalidRequest('contentType is invalid');
  }
  return value.toLowerCase();
}

function signedUploadTicket(value: unknown): SignedArtifactUploadTicket {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw invalidRequest('upload ticket is invalid');
  }
  const envelope = value as Partial<SignedArtifactUploadTicket>;
  if (!envelope.ticket || typeof envelope.ticket !== 'object'
    || typeof envelope.signingKeyId !== 'string'
    || typeof envelope.signature !== 'string') {
    throw invalidRequest('upload ticket is invalid');
  }
  return envelope as SignedArtifactUploadTicket;
}

export class ReleaseArtifactService {
  readonly #store: ControlStore;
  readonly #signer: PayloadSigner;
  readonly #now: () => number;
  readonly #objectStore: ArtifactObjectStore | null;
  readonly #attestationVerifier: ArtifactAttestationVerifier | null;
  readonly #publicBaseUrl: string | null;
  readonly #uploadTtlSeconds: number;
  readonly #downloadTtlSeconds: number;
  readonly #storageRequired: boolean;
  readonly #objectLockRequired: boolean;

  constructor(options: ReleaseArtifactServiceOptions) {
    this.#store = options.store;
    this.#signer = options.signer;
    this.#now = options.now ?? Date.now;
    this.#objectStore = options.objectStore ?? null;
    this.#attestationVerifier = options.attestationVerifier ?? null;
    this.#publicBaseUrl = options.publicBaseUrl?.replace(/\/$/u, '') ?? null;
    this.#uploadTtlSeconds = options.uploadTtlSeconds ?? 900;
    this.#downloadTtlSeconds = options.downloadTtlSeconds ?? 300;
    this.#storageRequired = options.storageRequired ?? false;
    this.#objectLockRequired = options.objectLockRequired ?? false;
  }

  async register(releaseId: string, raw: unknown, actorId: string): Promise<ReleaseArtifactView> {
    if (this.#objectStore) {
      throw conflict('managed artifact storage is enabled; use the artifact upload flow');
    }
    const release = await this.#requireRelease(releaseId);
    if (release.state !== 'draft') {
      throw conflict('artifacts can only be added while the release is draft');
    }
    const body = objectValue(raw);
    const kind = requiredString(body, 'kind', 40) as ReleaseArtifactKind;
    const platform = requiredString(body, 'platform', 32) as ReleaseArtifactPlatform;
    const url = httpsUrl(requiredString(body, 'url', 2048));
    const sha256 = requiredString(body, 'sha256', 64).toLowerCase();
    const sizeBytes = Number(body.sizeBytes);
    if (!(RELEASE_ARTIFACT_KINDS as readonly string[]).includes(kind)) {
      throw invalidRequest('kind is not a supported release artifact kind');
    }
    if (!(RELEASE_ARTIFACT_PLATFORMS as readonly string[]).includes(platform)) {
      throw invalidRequest('platform is not supported');
    }
    validateKindPlatform(kind, platform);
    if (!SHA256_PATTERN.test(sha256)) {
      throw invalidRequest('sha256 must be a lowercase SHA-256 hex digest');
    }
    if (!Number.isSafeInteger(sizeBytes) || sizeBytes <= 0) {
      throw invalidRequest('sizeBytes must be a positive safe integer');
    }

    const createdAtMs = this.#now();
    const artifact: ReleaseArtifactPayload = {
      version: 1,
      id: `art_${randomUUID().replaceAll('-', '')}`,
      releaseId: release.id,
      distributionId: release.distributionId,
      releaseVersion: release.version,
      sourceCommit: release.sourceCommit,
      kind,
      platform,
      url,
      sha256,
      sizeBytes,
      createdAtMs,
    };
    const signed = await signPayload(this.#signer, artifact);
    const record = await this.#store.createReleaseArtifact({
      ...artifact,
      signingKeyId: signed.signingKeyId,
      signature: signed.signature,
      createdAt: new Date(createdAtMs),
    });
    await this.#store.appendAuditEvent({
      actorId,
      action: 'release_artifact.registered',
      targetType: 'release_artifact',
      targetId: record.id,
      detail: {
        releaseId,
        distributionId: release.distributionId,
        kind,
        platform,
        sha256,
        sizeBytes,
        signingKeyId: record.signingKeyId,
      },
    });
    return viewFromRecord(record);
  }

  async createUpload(releaseId: string, raw: unknown, actorId: string): Promise<{
    ticket: SignedArtifactUploadTicket;
    upload: Awaited<ReturnType<ArtifactObjectStore['createUpload']>>;
    artifactId: string;
    downloadUrl: string;
  }> {
    if (!this.#objectStore || !this.#publicBaseUrl) {
      throw conflict('managed artifact storage is not configured');
    }
    const release = await this.#requireRelease(releaseId);
    if (release.state !== 'draft') throw conflict('artifacts can only be added while the release is draft');
    const body = objectValue(raw);
    const kind = requiredString(body, 'kind', 40) as ReleaseArtifactKind;
    const platform = requiredString(body, 'platform', 32) as ReleaseArtifactPlatform;
    const sha256 = requiredString(body, 'sha256', 64).toLowerCase();
    const sizeBytes = Number(body.sizeBytes);
    if (!(RELEASE_ARTIFACT_KINDS as readonly string[]).includes(kind)) {
      throw invalidRequest('kind is not a supported release artifact kind');
    }
    if (!(RELEASE_ARTIFACT_PLATFORMS as readonly string[]).includes(platform)) {
      throw invalidRequest('platform is not supported');
    }
    validateKindPlatform(kind, platform);
    if (!SHA256_PATTERN.test(sha256)) {
      throw invalidRequest('sha256 must be a lowercase SHA-256 hex digest');
    }
    if (!Number.isSafeInteger(sizeBytes) || sizeBytes <= 0 || sizeBytes > 20 * 1024 ** 3) {
      throw invalidRequest('sizeBytes must be between 1 byte and 20 GiB');
    }
    const contentType = contentTypeFor(kind, body.contentType);
    const now = this.#now();
    const artifactId = `art_${randomUUID().replaceAll('-', '')}`;
    const objectKey = this.#objectStore.objectKey({
      releaseId: release.id,
      version: release.version,
      kind,
      platform,
      sha256,
    });
    const ticketPayload: ArtifactUploadTicketPayload = {
      version: 1,
      id: `upl_${randomUUID().replaceAll('-', '')}`,
      artifactId,
      releaseId: release.id,
      distributionId: release.distributionId,
      releaseVersion: release.version,
      sourceCommit: release.sourceCommit,
      kind,
      platform,
      objectKey,
      sha256,
      sizeBytes,
      contentType,
      createdBy: actorId,
      issuedAtMs: now,
      expiresAtMs: now + this.#uploadTtlSeconds * 1000,
    };
    const signed = await signPayload(this.#signer, ticketPayload);
    const ticket: SignedArtifactUploadTicket = {
      ticket: ticketPayload,
      signingKeyId: signed.signingKeyId,
      signature: signed.signature,
    };
    const upload = await this.#objectStore.createUpload({
      objectKey,
      sha256,
      sizeBytes,
      contentType,
      expiresAt: new Date(ticketPayload.expiresAtMs),
    });
    await this.#store.appendAuditEvent({
      actorId,
      action: 'release_artifact.upload_issued',
      targetType: 'release_artifact_upload',
      targetId: ticketPayload.id,
      detail: {
        artifactId,
        releaseId,
        kind,
        platform,
        sha256,
        sizeBytes,
        expiresAtMs: ticketPayload.expiresAtMs,
      },
    });
    return {
      ticket,
      upload,
      artifactId,
      downloadUrl: `${this.#publicBaseUrl}/v1/release-artifacts/${artifactId}/download`,
    };
  }

  async completeUpload(releaseId: string, raw: unknown, actorId: string): Promise<ReleaseArtifactView> {
    if (!this.#objectStore || !this.#publicBaseUrl) {
      throw conflict('managed artifact storage is not configured');
    }
    const body = objectValue(raw);
    const envelope = signedUploadTicket(body.ticket);
    const ticket = await this.#verifyUploadTicket(envelope, releaseId);
    const existing = (await this.#store.listReleaseArtifacts(releaseId)).find(
      (artifact) => artifact.kind === ticket.kind && artifact.platform === ticket.platform,
    );
    if (existing) {
      const evidence = await this.#store.getReleaseArtifactEvidence(existing.id);
      if (existing.id === ticket.artifactId
        && existing.sha256 === ticket.sha256
        && existing.sizeBytes === ticket.sizeBytes
        && evidence?.objectKey === ticket.objectKey) {
        await this.#assertManagedArtifact(existing, evidence);
        return viewFromRecord(existing, evidence);
      }
      throw conflict('release artifact already exists for this kind and platform');
    }
    const stored = await this.#objectStore.inspect(ticket.objectKey);
    this.#assertStoredObject(stored, ticket);
    let codeSigning: SignedArtifactCodeSigningEvidence | null = null;
    if (INSTALLABLE_KINDS.has(ticket.kind)) {
      if (!body.codeSigning || !this.#attestationVerifier) {
        throw conflict('installable artifact requires trusted code signing evidence');
      }
      codeSigning = body.codeSigning as SignedArtifactCodeSigningEvidence;
      this.#attestationVerifier.verify(codeSigning, {
        releaseId: ticket.releaseId,
        releaseVersion: ticket.releaseVersion,
        sourceCommit: ticket.sourceCommit,
        kind: ticket.kind,
        platform: ticket.platform,
        sha256: ticket.sha256,
        sizeBytes: ticket.sizeBytes,
        nowMs: this.#now(),
      });
    } else if (body.codeSigning) {
      if (!this.#attestationVerifier) throw conflict('artifact attestation verifier is not configured');
      codeSigning = body.codeSigning as SignedArtifactCodeSigningEvidence;
      this.#attestationVerifier.verify(codeSigning, {
        releaseId: ticket.releaseId,
        releaseVersion: ticket.releaseVersion,
        sourceCommit: ticket.sourceCommit,
        kind: ticket.kind,
        platform: ticket.platform,
        sha256: ticket.sha256,
        sizeBytes: ticket.sizeBytes,
        nowMs: this.#now(),
      });
    }
    const createdAtMs = this.#now();
    const artifact: ReleaseArtifactPayload = {
      version: 1,
      id: ticket.artifactId,
      releaseId: ticket.releaseId,
      distributionId: ticket.distributionId,
      releaseVersion: ticket.releaseVersion,
      sourceCommit: ticket.sourceCommit,
      kind: ticket.kind,
      platform: ticket.platform,
      url: `${this.#publicBaseUrl}/v1/release-artifacts/${ticket.artifactId}/download`,
      sha256: ticket.sha256,
      sizeBytes: ticket.sizeBytes,
      createdAtMs,
    };
    const signed = await signPayload(this.#signer, artifact);
    const result = await this.#store.createManagedReleaseArtifact({
      artifact: {
        ...artifact,
        signingKeyId: signed.signingKeyId,
        signature: signed.signature,
        createdAt: new Date(createdAtMs),
      },
      evidence: {
        objectKey: stored.objectKey,
        objectVersionId: stored.versionId,
        verifiedAt: new Date(createdAtMs),
        serverSideEncryption: stored.serverSideEncryption,
        objectLockMode: stored.objectLockMode,
        objectLockRetainUntil: stored.objectLockRetainUntil
          ? new Date(stored.objectLockRetainUntil)
          : null,
        codeSigning,
      },
    });
    await this.#store.appendAuditEvent({
      actorId,
      action: 'release_artifact.upload_completed',
      targetType: 'release_artifact',
      targetId: result.artifact.id,
      detail: {
        releaseId,
        kind: ticket.kind,
        platform: ticket.platform,
        sha256: ticket.sha256,
        sizeBytes: ticket.sizeBytes,
        objectVersionId: stored.versionId,
        codeSigningSystem: codeSigning?.evidence.system ?? null,
        attestationKeyId: codeSigning?.attestationKeyId ?? null,
      },
    });
    return viewFromRecord(result.artifact, result.evidence);
  }

  async resolveDownload(id: string): Promise<{ url: string; expiresAt: string }> {
    if (!ARTIFACT_ID_PATTERN.test(id)) throw invalidRequest('artifact id is invalid');
    if (!this.#objectStore) throw notFound('managed release artifact is unavailable');
    const artifact = await this.#store.getReleaseArtifact(id);
    if (!artifact || artifact.state !== 'active') throw notFound('release artifact is unavailable');
    const evidence = await this.#store.getReleaseArtifactEvidence(id);
    if (!evidence) throw notFound('managed release artifact is unavailable');
    await this.#assertManagedArtifact(artifact, evidence);
    const expiresAt = new Date(this.#now() + this.#downloadTtlSeconds * 1000);
    return {
      url: await this.#objectStore.createDownloadUrl(evidence.objectKey, expiresAt),
      expiresAt: expiresAt.toISOString(),
    };
  }

  async list(releaseId: string): Promise<ReleaseArtifactView[]> {
    await this.#requireRelease(releaseId);
    const records = await this.#store.listReleaseArtifacts(releaseId);
    return Promise.all(records.map(async (record) => viewFromRecord(
      record,
      await this.#store.getReleaseArtifactEvidence(record.id),
    )));
  }

  async revoke(id: string, raw: unknown, actorId: string): Promise<{
    artifact: ReleaseArtifactView;
    releasePaused: boolean;
  }> {
    if (!ARTIFACT_ID_PATTERN.test(id)) throw invalidRequest('artifact id is invalid');
    const body = objectValue(raw);
    const reason = requiredString(body, 'reason', 500);
    if (reason.length < 10) throw invalidRequest('revocation reason must be at least 10 characters');
    const current = await this.#store.getReleaseArtifact(id);
    if (!current) throw notFound('release artifact not found');
    if (current.state === 'revoked') throw conflict('release artifact is already revoked');
    const revokedAt = new Date(this.#now());
    const result = await this.#store.revokeReleaseArtifact({
      id,
      actorId,
      reason,
      revokedAt,
    });
    if (!result) throw conflict('release artifact is no longer active');
    const { artifact, releasePaused } = result;
    await this.#store.appendAuditEvent({
      actorId,
      action: 'release_artifact.revoked',
      targetType: 'release_artifact',
      targetId: id,
      detail: { releaseId: artifact.releaseId, reason, releasePaused },
    });
    return {
      artifact: viewFromRecord(
        artifact,
        await this.#store.getReleaseArtifactEvidence(artifact.id),
      ),
      releasePaused,
    };
  }

  async activeEnvelopes(releaseId: string): Promise<SignedReleaseArtifactEnvelope[]> {
    const records = (await this.#store.listReleaseArtifacts(releaseId))
      .filter((artifact) => artifact.state === 'active');
    await Promise.all(records.map((artifact) => this.#assertSignatureValid(artifact)));
    return records.map(envelopeFromRecord);
  }

  async assertReleaseReady(release: UpdateReleaseRecord): Promise<void> {
    const records = (await this.#store.listReleaseArtifacts(release.id))
      .filter((artifact) => artifact.state === 'active');
    for (const artifact of records) {
      if (artifact.releaseId !== release.id
        || artifact.distributionId !== release.distributionId
        || artifact.releaseVersion !== release.version
        || artifact.sourceCommit !== release.sourceCommit) {
        throw conflict(`artifact ${artifact.id} is not bound to the current release metadata`);
      }
      const evidence = await this.#store.getReleaseArtifactEvidence(artifact.id);
      if (evidence) {
        await this.#assertManagedArtifact(artifact, evidence);
      } else if (this.#storageRequired) {
        throw conflict(`artifact ${artifact.id} was not verified by managed object storage`);
      }
    }
    if (!records.some((artifact) => INSTALLABLE_KINDS.has(artifact.kind))) {
      throw conflict('release requires at least one signed installable artifact');
    }
    const requiredManifests = [
      {
        kind: 'update_manifest' as const,
        url: release.fullManifestUrl,
        sha256: release.fullManifestSha256,
      },
      {
        kind: 'incremental_manifest' as const,
        url: release.incrementalManifestUrl,
        sha256: release.incrementalManifestSha256,
      },
    ].filter((manifest) => manifest.url !== null);
    for (const manifest of requiredManifests) {
      const matched = records.find((artifact) => (
        artifact.kind === manifest.kind
        && artifact.platform === 'any'
        && artifact.url === manifest.url
        && artifact.sha256 === manifest.sha256
      ));
      if (!matched) {
        throw conflict(`${manifest.kind} must be registered with the release URL and digest`);
      }
    }
    await Promise.all(records.map((artifact) => this.#assertSignatureValid(artifact)));
  }

  async #verifyUploadTicket(
    envelope: SignedArtifactUploadTicket,
    expectedReleaseId: string,
  ): Promise<ArtifactUploadTicketPayload> {
    const ticket = envelope.ticket;
    const key = await this.#store.getSigningKey(envelope.signingKeyId);
    if (!key || key.state === 'revoked'
      || !envelope.signature.startsWith(ED25519_SIGNATURE_PREFIX)) {
      throw conflict('upload ticket uses a revoked or unknown signing key');
    }
    let valid = false;
    try {
      valid = verify(
        null,
        Buffer.from(canonicalJson(ticket)),
        createPublicKey(key.publicKeyPem),
        Buffer.from(envelope.signature.slice(ED25519_SIGNATURE_PREFIX.length), 'base64url'),
      );
    } catch {
      valid = false;
    }
    if (!valid) throw conflict('upload ticket signature is invalid');
    const now = this.#now();
    if (ticket.version !== 1
      || !UPLOAD_ID_PATTERN.test(ticket.id)
      || !ARTIFACT_ID_PATTERN.test(ticket.artifactId)
      || ticket.releaseId !== expectedReleaseId
      || !Number.isSafeInteger(ticket.issuedAtMs)
      || !Number.isSafeInteger(ticket.expiresAtMs)
      || ticket.issuedAtMs > now + 5 * 60_000
      || ticket.expiresAtMs <= now
      || ticket.expiresAtMs - ticket.issuedAtMs > this.#uploadTtlSeconds * 1000) {
      throw conflict('upload ticket is expired or invalid');
    }
    const release = await this.#requireRelease(expectedReleaseId);
    if (release.state !== 'draft'
      || ticket.distributionId !== release.distributionId
      || ticket.releaseVersion !== release.version
      || ticket.sourceCommit !== release.sourceCommit) {
      throw conflict('upload ticket is not bound to the current draft release');
    }
    if (!this.#objectStore || ticket.objectKey !== this.#objectStore.objectKey({
      releaseId: ticket.releaseId,
      version: ticket.releaseVersion,
      kind: ticket.kind,
      platform: ticket.platform,
      sha256: ticket.sha256,
    })) {
      throw conflict('upload ticket object key is invalid');
    }
    return ticket;
  }

  #assertStoredObject(
    stored: StoredArtifactObject,
    expected: { objectKey: string; sha256: string; sizeBytes: number },
  ): void {
    if (stored.objectKey !== expected.objectKey
      || stored.checksumSha256 !== expected.sha256
      || stored.sizeBytes !== expected.sizeBytes) {
      throw conflict('stored release artifact does not match the signed upload ticket');
    }
    if (!stored.serverSideEncryption) {
      throw conflict('stored release artifact is not encrypted at rest');
    }
    if (this.#objectLockRequired) {
      const retainedUntil = stored.objectLockRetainUntil
        ? Date.parse(stored.objectLockRetainUntil)
        : Number.NaN;
      if ((stored.objectLockMode !== 'COMPLIANCE' && stored.objectLockMode !== 'GOVERNANCE')
        || !Number.isFinite(retainedUntil)
        || retainedUntil <= this.#now()) {
        throw conflict('stored release artifact is not protected by active Object Lock');
      }
    }
  }

  async #assertManagedArtifact(
    artifact: ReleaseArtifactRecord,
    evidence: ReleaseArtifactEvidenceRecord,
  ): Promise<void> {
    if (!this.#objectStore) throw conflict('managed artifact storage is unavailable');
    const stored = await this.#objectStore.inspect(evidence.objectKey);
    this.#assertStoredObject(stored, {
      objectKey: evidence.objectKey,
      sha256: artifact.sha256,
      sizeBytes: artifact.sizeBytes,
    });
    if (evidence.objectVersionId && stored.versionId !== evidence.objectVersionId) {
      throw conflict(`artifact ${artifact.id} object version changed after verification`);
    }
    const expectedRetainUntil = evidence.objectLockRetainUntil?.toISOString() ?? null;
    if (stored.serverSideEncryption !== evidence.serverSideEncryption
      || stored.objectLockMode !== evidence.objectLockMode
      || stored.objectLockRetainUntil !== expectedRetainUntil) {
      throw conflict(`artifact ${artifact.id} storage controls changed after verification`);
    }
    if (INSTALLABLE_KINDS.has(artifact.kind)) {
      if (!evidence.codeSigning || !this.#attestationVerifier) {
        throw conflict(`artifact ${artifact.id} has no trusted code signing evidence`);
      }
      this.#attestationVerifier.verify(evidence.codeSigning, {
        releaseId: artifact.releaseId,
        releaseVersion: artifact.releaseVersion,
        sourceCommit: artifact.sourceCommit,
        kind: artifact.kind,
        platform: artifact.platform,
        sha256: artifact.sha256,
        sizeBytes: artifact.sizeBytes,
        nowMs: this.#now(),
      });
    }
  }

  async #assertSignatureValid(record: ReleaseArtifactRecord): Promise<void> {
    const key = await this.#store.getSigningKey(record.signingKeyId);
    if (!key || key.state === 'revoked') {
      throw conflict(`artifact ${record.id} uses a revoked or unknown signing key`);
    }
    if (!record.signature.startsWith(ED25519_SIGNATURE_PREFIX)) {
      throw conflict(`artifact ${record.id} signature format is invalid`);
    }
    let valid = false;
    try {
      valid = verify(
        null,
        Buffer.from(canonicalJson(payloadFromRecord(record))),
        createPublicKey(key.publicKeyPem),
        Buffer.from(record.signature.slice(ED25519_SIGNATURE_PREFIX.length), 'base64url'),
      );
    } catch {
      valid = false;
    }
    if (!valid) throw conflict(`artifact ${record.id} signature is invalid`);
  }

  async #requireRelease(id: string): Promise<UpdateReleaseRecord> {
    const release = await this.#store.getUpdateRelease(id);
    if (!release) throw notFound('update release not found');
    return release;
  }
}

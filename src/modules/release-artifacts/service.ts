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
  UpdateReleaseRecord,
} from '../../storage/control-store.js';

const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const ARTIFACT_ID_PATTERN = /^art_[a-zA-Z0-9_-]{16,64}$/u;
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

function viewFromRecord(record: ReleaseArtifactRecord): ReleaseArtifactView {
  return {
    ...envelopeFromRecord(record),
    state: record.state,
    revokedAt: record.revokedAt?.toISOString() ?? null,
    revokedBy: record.revokedBy,
    revocationReason: record.revocationReason,
  };
}

export class ReleaseArtifactService {
  readonly #store: ControlStore;
  readonly #signer: PayloadSigner;
  readonly #now: () => number;

  constructor(options: ReleaseArtifactServiceOptions) {
    this.#store = options.store;
    this.#signer = options.signer;
    this.#now = options.now ?? Date.now;
  }

  async register(releaseId: string, raw: unknown, actorId: string): Promise<ReleaseArtifactView> {
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

  async list(releaseId: string): Promise<ReleaseArtifactView[]> {
    await this.#requireRelease(releaseId);
    return (await this.#store.listReleaseArtifacts(releaseId)).map(viewFromRecord);
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
    return { artifact: viewFromRecord(artifact), releasePaused };
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

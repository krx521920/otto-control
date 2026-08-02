import { createPublicKey, verify, type KeyObject } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { dirname, isAbsolute, resolve } from 'node:path';

import type {
  ArtifactCodeSigningEvidencePayload,
  SignedArtifactCodeSigningEvidence,
} from '../../contracts/artifact-storage.js';
import type { ReleaseArtifactKind, ReleaseArtifactPlatform } from '../../contracts/release-artifact.js';
import { canonicalJson, ED25519_SIGNATURE_PREFIX } from '../../crypto/signed-envelope.js';
import { conflict, invalidRequest } from '../../errors.js';

interface AttestationKeyEntry {
  id: string;
  publicKeyFile: string;
}

interface AttestationKeyManifest {
  version: 1;
  keys: AttestationKeyEntry[];
}

export interface ArtifactAttestationVerifier {
  verify(input: SignedArtifactCodeSigningEvidence, expected: {
    releaseId: string;
    releaseVersion: string;
    sourceCommit: string;
    kind: ReleaseArtifactKind;
    platform: ReleaseArtifactPlatform;
    sha256: string;
    sizeBytes: number;
    nowMs: number;
  }): void;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function parseManifest(value: unknown): AttestationKeyManifest {
  if (!isObject(value) || value.version !== 1 || !Array.isArray(value.keys) || value.keys.length === 0) {
    throw new Error('artifact attestation key manifest must use version 1 and contain keys');
  }
  const seen = new Set<string>();
  const keys = value.keys.map((candidate) => {
    if (!isObject(candidate)
      || typeof candidate.id !== 'string'
      || !/^[a-zA-Z0-9_.-]{3,64}$/u.test(candidate.id)
      || typeof candidate.publicKeyFile !== 'string'
      || !candidate.publicKeyFile.trim()) {
      throw new Error('artifact attestation key manifest contains an invalid key');
    }
    if (seen.has(candidate.id)) throw new Error('artifact attestation key ids must be unique');
    seen.add(candidate.id);
    return { id: candidate.id, publicKeyFile: candidate.publicKeyFile.trim() };
  });
  return { version: 1, keys };
}

function resolveFile(manifestPath: string, configuredPath: string): string {
  return isAbsolute(configuredPath)
    ? configuredPath
    : resolve(dirname(manifestPath), configuredPath);
}

function requireEvidenceShape(value: unknown): SignedArtifactCodeSigningEvidence {
  if (!isObject(value) || !isObject(value.evidence)
    || typeof value.attestationKeyId !== 'string'
    || typeof value.signature !== 'string') {
    throw invalidRequest('codeSigning evidence is invalid');
  }
  return value as unknown as SignedArtifactCodeSigningEvidence;
}

function assertEvidenceBinding(
  evidence: ArtifactCodeSigningEvidencePayload,
  expected: Parameters<ArtifactAttestationVerifier['verify']>[1],
): void {
  if (evidence.version !== 1
    || evidence.status !== 'valid'
    || evidence.releaseId !== expected.releaseId
    || evidence.releaseVersion !== expected.releaseVersion
    || evidence.sourceCommit !== expected.sourceCommit
    || evidence.kind !== expected.kind
    || evidence.platform !== expected.platform
    || evidence.sha256 !== expected.sha256
    || evidence.sizeBytes !== expected.sizeBytes) {
    throw conflict('code signing evidence is not bound to the uploaded artifact');
  }
  if (!/^[a-f0-9]{64}$/u.test(evidence.certificateSha256)
    || !/^[a-f0-9]{64}$/u.test(evidence.evidenceSha256)
    || !evidence.signerIdentity.trim()
    || !evidence.verifier.trim()
    || !Number.isSafeInteger(evidence.verifiedAtMs)
    || evidence.verifiedAtMs > expected.nowMs + 5 * 60_000
    || expected.nowMs - evidence.verifiedAtMs > 30 * 24 * 60 * 60_000) {
    throw conflict('code signing evidence metadata is invalid or stale');
  }
  if (expected.kind === 'windows_installer'
    && (evidence.system !== 'authenticode' || !evidence.timestamped)) {
    throw conflict('Windows installer requires timestamped Authenticode evidence');
  }
  if (expected.kind === 'macos_dmg'
    && (evidence.system !== 'apple_developer_id' || !evidence.notarized || !evidence.timestamped)) {
    throw conflict('macOS DMG requires Developer ID and notarization evidence');
  }
  if ((expected.kind === 'linux_archive' || expected.kind === 'enterprise_server')
    && evidence.system !== 'sigstore'
    && evidence.system !== 'linux_package') {
    throw conflict('Linux and enterprise packages require Sigstore or package-signing evidence');
  }
}

export class TrustedArtifactAttestationVerifier implements ArtifactAttestationVerifier {
  readonly #keys: ReadonlyMap<string, KeyObject>;

  constructor(keys: ReadonlyMap<string, KeyObject>) {
    this.#keys = keys;
  }

  verify(raw: SignedArtifactCodeSigningEvidence, expected: Parameters<ArtifactAttestationVerifier['verify']>[1]): void {
    const input = requireEvidenceShape(raw);
    assertEvidenceBinding(input.evidence, expected);
    const key = this.#keys.get(input.attestationKeyId);
    if (!key || !input.signature.startsWith(ED25519_SIGNATURE_PREFIX)) {
      throw conflict('code signing evidence uses an untrusted attestation key');
    }
    let valid = false;
    try {
      valid = verify(
        null,
        Buffer.from(canonicalJson(input.evidence)),
        key,
        Buffer.from(input.signature.slice(ED25519_SIGNATURE_PREFIX.length), 'base64url'),
      );
    } catch {
      valid = false;
    }
    if (!valid) throw conflict('code signing evidence signature is invalid');
  }
}

export async function loadArtifactAttestationVerifier(
  manifestFile: string | null,
): Promise<ArtifactAttestationVerifier | null> {
  if (!manifestFile) return null;
  const manifestPath = resolve(manifestFile);
  const manifest = parseManifest(JSON.parse(await readFile(manifestPath, 'utf8')) as unknown);
  const keys = new Map<string, KeyObject>();
  for (const entry of manifest.keys) {
    const key = createPublicKey(await readFile(resolveFile(manifestPath, entry.publicKeyFile), 'utf8'));
    if (key.asymmetricKeyType !== 'ed25519') {
      throw new Error(`artifact attestation key ${entry.id} must be Ed25519`);
    }
    keys.set(entry.id, key);
  }
  return new TrustedArtifactAttestationVerifier(keys);
}


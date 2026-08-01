import { createHash, randomUUID } from 'node:crypto';

import type {
  OttoSignedUpdatePolicyEnvelope,
  OttoUpdatePolicyPayload,
  UpdateChannel,
  UpdateManifestReference,
} from '../../contracts/update-policy.js';
import { UPDATE_CHANNELS } from '../../contracts/update-policy.js';
import { secureTextMatches, signTelemetryRequest } from '../../crypto/telemetry-request.js';
import { signPayload, type PayloadSigner } from '../../crypto/signed-envelope.js';
import { conflict, invalidRequest, notFound, unauthorized } from '../../errors.js';
import type {
  ControlStore,
  DeploymentUpdateAssignmentRecord,
  UpdateDistributionRecord,
  UpdateReleaseRecord,
  UpdateReleaseTransition,
} from '../../storage/control-store.js';
import type { ControlTokenIssuer } from '../commercial-control/token-issuer.js';
import type { ReleaseArtifactService } from '../release-artifacts/service.js';

const DISTRIBUTION_ID_PATTERN = /^[a-z0-9][a-z0-9_.-]{1,63}$/u;
const DEPLOYMENT_ID_PATTERN = /^dep_[a-zA-Z0-9_-]{8,64}$/u;
const MACHINE_FINGERPRINT_PATTERN = /^[a-f0-9]{64}$/u;
const SOURCE_COMMIT_PATTERN = /^[a-f0-9]{7,64}$/u;
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const NONCE_PATTERN = /^[a-zA-Z0-9_-]{16,128}$/u;
const SEMVER_PATTERN = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/u;
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;

interface ParsedSemver {
  major: number;
  minor: number;
  patch: number;
  prerelease: string[];
}

export interface UpdatePolicyAuthentication {
  authorization?: string;
  timestamp?: string;
  nonce?: string;
  signature?: string;
}

export interface UpdatePolicyServiceOptions {
  store: ControlStore;
  signer: PayloadSigner;
  tokenIssuer: ControlTokenIssuer;
  releaseArtifacts: ReleaseArtifactService;
  policyDurationMs?: number;
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

function bearerToken(value: string | undefined): string {
  return /^Bearer\s+(.+)$/iu.exec(value?.trim() || '')?.[1] || '';
}

function manifestReference(value: unknown, name: string): UpdateManifestReference | null {
  if (value === undefined || value === null) return null;
  const body = objectValue(value);
  const url = requiredString(body, 'url', 2048);
  const sha256 = requiredString(body, 'sha256', 64).toLowerCase();
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw invalidRequest(`${name}.url must be an absolute HTTPS URL`);
  }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password) {
    throw invalidRequest(`${name}.url must be an HTTPS URL without credentials`);
  }
  if (!SHA256_PATTERN.test(sha256)) {
    throw invalidRequest(`${name}.sha256 must be a lowercase SHA-256 hex digest`);
  }
  return { url: parsed.toString(), sha256 };
}

function parseSemver(value: string): ParsedSemver | null {
  const match = SEMVER_PATTERN.exec(value.trim());
  if (!match) return null;
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
    prerelease: match[4] ? match[4].split('.') : [],
  };
}

export function compareVersions(left: string, right: string): number | null {
  const a = parseSemver(left);
  const b = parseSemver(right);
  if (!a || !b) return null;
  for (const key of ['major', 'minor', 'patch'] as const) {
    if (a[key] !== b[key]) return a[key] < b[key] ? -1 : 1;
  }
  if (a.prerelease.length === 0 && b.prerelease.length === 0) return 0;
  if (a.prerelease.length === 0) return 1;
  if (b.prerelease.length === 0) return -1;
  const length = Math.max(a.prerelease.length, b.prerelease.length);
  for (let index = 0; index < length; index += 1) {
    const x = a.prerelease[index];
    const y = b.prerelease[index];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const xNumber = /^\d+$/u.test(x);
    const yNumber = /^\d+$/u.test(y);
    if (xNumber && yNumber) {
      const difference = Number(x) - Number(y);
      if (difference !== 0) return difference < 0 ? -1 : 1;
    } else if (xNumber !== yNumber) {
      return xNumber ? -1 : 1;
    } else if (x !== y) {
      return x < y ? -1 : 1;
    }
  }
  return 0;
}

/** Stable 1..100 cohort shared by every check from the same deployment. */
export function updateCohortPercent(
  distributionId: string,
  releaseId: string,
  deploymentId: string,
): number {
  const digest = createHash('sha256')
    .update(`${distributionId}\0${releaseId}\0${deploymentId}`, 'utf8')
    .digest();
  return (digest.readUInt32BE(0) % 100) + 1;
}

function releasePayload(
  release: UpdateReleaseRecord,
  artifacts: NonNullable<OttoUpdatePolicyPayload['release']>['artifacts'],
): NonNullable<OttoUpdatePolicyPayload['release']> {
  return {
    id: release.id,
    version: release.version,
    sourceCommit: release.sourceCommit,
    channel: release.channel,
    mandatory: release.channel === 'required',
    rolloutPercent: release.rolloutPercent,
    notes: release.notes,
    fullManifest: release.fullManifestUrl ? {
      url: release.fullManifestUrl,
      sha256: release.fullManifestSha256!,
    } : null,
    incrementalManifest: release.incrementalManifestUrl ? {
      url: release.incrementalManifestUrl,
      sha256: release.incrementalManifestSha256!,
    } : null,
    artifacts,
    publishedAt: release.publishedAt!.toISOString(),
  };
}

export class UpdatePolicyService {
  readonly #store: ControlStore;
  readonly #signer: PayloadSigner;
  readonly #tokens: ControlTokenIssuer;
  readonly #releaseArtifacts: ReleaseArtifactService;
  readonly #policyDurationMs: number;
  readonly #now: () => number;

  constructor(options: UpdatePolicyServiceOptions) {
    this.#store = options.store;
    this.#signer = options.signer;
    this.#tokens = options.tokenIssuer;
    this.#releaseArtifacts = options.releaseArtifacts;
    this.#policyDurationMs = options.policyDurationMs ?? 5 * 60 * 1000;
    this.#now = options.now ?? Date.now;
    if (this.#policyDurationMs < 60_000 || this.#policyDurationMs > 60 * 60 * 1000) {
      throw new Error('update policy duration must be between one minute and one hour');
    }
  }

  async createDistribution(raw: unknown, actorId: string): Promise<UpdateDistributionRecord> {
    const body = objectValue(raw);
    const id = requiredString(body, 'id', 64).toLowerCase();
    const name = requiredString(body, 'name', 160);
    if (!DISTRIBUTION_ID_PATTERN.test(id)) throw invalidRequest('distribution id is invalid');
    const distribution = await this.#store.createUpdateDistribution({ id, name });
    await this.#store.appendAuditEvent({
      actorId,
      action: 'update_distribution.created',
      targetType: 'update_distribution',
      targetId: id,
      detail: { name },
    });
    return distribution;
  }

  async assignDeployment(
    deploymentId: string,
    raw: unknown,
    actorId: string,
  ): Promise<DeploymentUpdateAssignmentRecord> {
    if (!DEPLOYMENT_ID_PATTERN.test(deploymentId)) throw invalidRequest('deploymentId is invalid');
    const body = objectValue(raw);
    const distributionId = requiredString(body, 'distributionId', 64).toLowerCase();
    if (!DISTRIBUTION_ID_PATTERN.test(distributionId)) {
      throw invalidRequest('distributionId is invalid');
    }
    const deployment = await this.#store.getDeployment(deploymentId);
    if (!deployment) throw notFound('deployment not found');
    const distribution = await this.#store.getUpdateDistribution(distributionId);
    if (!distribution) throw notFound('update distribution not found');
    if (distribution.status !== 'active') throw conflict('update distribution is suspended');
    const assignment = await this.#store.assignDeploymentUpdateDistribution({
      deploymentId,
      distributionId,
      updatedAt: new Date(this.#now()),
    });
    await this.#store.appendAuditEvent({
      actorId,
      action: 'deployment.update_distribution_assigned',
      targetType: 'deployment',
      targetId: deploymentId,
      detail: { distributionId },
    });
    return assignment;
  }

  async createRelease(raw: unknown, actorId: string): Promise<UpdateReleaseRecord> {
    const body = objectValue(raw);
    const distributionId = requiredString(body, 'distributionId', 64).toLowerCase();
    const version = requiredString(body, 'version', 80).replace(/^v/u, '');
    const sourceCommit = requiredString(body, 'sourceCommit', 64).toLowerCase();
    const channel = requiredString(body, 'channel', 16) as UpdateChannel;
    const rolloutPercent = Number(body.rolloutPercent ?? 100);
    const notes = typeof body.notes === 'string' ? body.notes.trim() : '';
    if (!DISTRIBUTION_ID_PATTERN.test(distributionId)) {
      throw invalidRequest('distributionId is invalid');
    }
    if (!parseSemver(version)) throw invalidRequest('version must be valid semantic version');
    if (!SOURCE_COMMIT_PATTERN.test(sourceCommit)) throw invalidRequest('sourceCommit is invalid');
    if (!(UPDATE_CHANNELS as readonly string[]).includes(channel)) {
      throw invalidRequest('channel must be canary, stable, or required');
    }
    if (!Number.isInteger(rolloutPercent) || rolloutPercent < 1 || rolloutPercent > 100) {
      throw invalidRequest('rolloutPercent must be an integer between 1 and 100');
    }
    if (channel !== 'canary' && rolloutPercent !== 100) {
      throw invalidRequest('stable and required releases must use 100 percent rollout');
    }
    if (notes.length > 4000) throw invalidRequest('notes is too long');
    const fullManifest = manifestReference(body.fullManifest, 'fullManifest');
    const incrementalManifest = manifestReference(body.incrementalManifest, 'incrementalManifest');
    if (!fullManifest && !incrementalManifest) {
      throw invalidRequest('at least one full or incremental manifest is required');
    }
    const distribution = await this.#store.getUpdateDistribution(distributionId);
    if (!distribution) throw notFound('update distribution not found');
    if (distribution.status !== 'active') throw conflict('update distribution is suspended');
    const release = await this.#store.createUpdateRelease({
      id: `rel_${randomUUID().replaceAll('-', '')}`,
      distributionId,
      version,
      sourceCommit,
      channel,
      rolloutPercent,
      notes,
      fullManifestUrl: fullManifest?.url ?? null,
      fullManifestSha256: fullManifest?.sha256 ?? null,
      incrementalManifestUrl: incrementalManifest?.url ?? null,
      incrementalManifestSha256: incrementalManifest?.sha256 ?? null,
    });
    await this.#store.appendAuditEvent({
      actorId,
      action: 'update_release.created',
      targetType: 'update_release',
      targetId: release.id,
      detail: { distributionId, version, channel, rolloutPercent },
    });
    return release;
  }

  async listReleases(distributionId: string): Promise<UpdateReleaseRecord[]> {
    if (!DISTRIBUTION_ID_PATTERN.test(distributionId)) {
      throw invalidRequest('distributionId is invalid');
    }
    if (!await this.#store.getUpdateDistribution(distributionId)) {
      throw notFound('update distribution not found');
    }
    return this.#store.listUpdateReleases(distributionId);
  }

  async activateRelease(id: string, actorId: string): Promise<UpdateReleaseTransition> {
    const current = await this.#store.getUpdateRelease(id);
    if (!current) throw notFound('update release not found');
    if (current.state === 'active') throw conflict('update release is already active');
    if (current.state === 'rolled_back') throw conflict('rolled-back release cannot be reactivated');
    await this.#releaseArtifacts.assertReleaseReady(current);
    const transition = await this.#store.activateUpdateRelease(id, new Date(this.#now()));
    if (!transition) throw notFound('update release not found');
    await this.#store.appendAuditEvent({
      actorId,
      action: 'update_release.activated',
      targetType: 'update_release',
      targetId: id,
      detail: { previousReleaseId: transition.fallback?.id ?? null },
    });
    return transition;
  }

  async pauseRelease(id: string, actorId: string): Promise<UpdateReleaseRecord> {
    const current = await this.#store.getUpdateRelease(id);
    if (!current) throw notFound('update release not found');
    if (current.state !== 'active') throw conflict('only an active update release can be paused');
    const release = await this.#store.pauseUpdateRelease(id, new Date(this.#now()));
    if (!release) throw conflict('update release is no longer active');
    await this.#store.appendAuditEvent({
      actorId,
      action: 'update_release.paused',
      targetType: 'update_release',
      targetId: id,
      detail: {},
    });
    return release;
  }

  async rollbackRelease(id: string, actorId: string): Promise<UpdateReleaseTransition> {
    const current = await this.#store.getUpdateRelease(id);
    if (!current) throw notFound('update release not found');
    if (current.state !== 'active' && current.state !== 'paused') {
      throw conflict('only an active or paused update release can be rolled back');
    }
    if (current.previousReleaseId) {
      const fallback = await this.#store.getUpdateRelease(current.previousReleaseId);
      if (fallback) await this.#releaseArtifacts.assertReleaseReady(fallback);
    }
    const transition = await this.#store.rollbackUpdateRelease(id, new Date(this.#now()));
    if (!transition) throw notFound('update release not found');
    await this.#store.appendAuditEvent({
      actorId,
      action: 'update_release.rolled_back',
      targetType: 'update_release',
      targetId: id,
      detail: { restoredReleaseId: transition.fallback?.id ?? null },
    });
    return transition;
  }

  async resolve(
    raw: unknown,
    authentication: UpdatePolicyAuthentication,
  ): Promise<OttoSignedUpdatePolicyEnvelope> {
    const body = objectValue(raw);
    if (body.version !== 1) throw invalidRequest('update policy request version is invalid');
    const licenseId = requiredString(body, 'licenseId', 68);
    const deploymentId = requiredString(body, 'deploymentId', 68);
    const machineFingerprint = requiredString(body, 'machineFingerprint', 64).toLowerCase();
    const distributionId = requiredString(body, 'distributionId', 64).toLowerCase();
    const currentVersion = requiredString(body, 'currentVersion', 80).replace(/^v/u, '');
    if (!DEPLOYMENT_ID_PATTERN.test(deploymentId)) throw invalidRequest('deploymentId is invalid');
    if (!MACHINE_FINGERPRINT_PATTERN.test(machineFingerprint)) {
      throw invalidRequest('machineFingerprint is invalid');
    }
    if (!DISTRIBUTION_ID_PATTERN.test(distributionId)) {
      throw invalidRequest('distributionId is invalid');
    }
    if (!parseSemver(currentVersion)) throw invalidRequest('currentVersion is invalid');
    const now = this.#now();
    const license = await this.#store.getLicense(licenseId);
    if (!license) throw notFound('license not found');
    if (license.offline) throw unauthorized('offline License cannot resolve online update policy');
    if (license.deploymentId !== deploymentId || license.machineFingerprint !== machineFingerprint) {
      throw unauthorized('update policy deployment binding is invalid');
    }
    if (license.revokedAtMs !== null) throw unauthorized('License has been revoked');
    if (license.expiresAtMs <= now) throw unauthorized('License has expired');
    const deployment = await this.#store.getDeployment(deploymentId);
    if (!deployment || deployment.status !== 'active') throw unauthorized('deployment is not active');
    const assigned = await this.#store.hasDeploymentUpdateAssignment(
      deploymentId,
      distributionId,
    );
    if (!assigned) {
      throw unauthorized('deployment is not assigned to this update distribution');
    }
    const distribution = await this.#store.getUpdateDistribution(distributionId);
    if (!distribution || distribution.status !== 'active') {
      throw unauthorized('update distribution is not active');
    }
    const leaseToken = this.#tokens.issue({
      purpose: 'lease',
      licenseId,
      deploymentId,
      version: license.tokenVersion,
    });
    if (!this.#tokens.matches(bearerToken(authentication.authorization), leaseToken)) {
      throw unauthorized('update policy token is invalid');
    }
    const timestamp = Number(authentication.timestamp);
    const nonce = authentication.nonce?.trim() || '';
    const signature = authentication.signature?.trim() || '';
    if (!Number.isFinite(timestamp) || Math.abs(now - timestamp) > MAX_CLOCK_SKEW_MS) {
      throw unauthorized('update policy request timestamp is invalid');
    }
    if (!NONCE_PATTERN.test(nonce)) throw invalidRequest('update policy nonce is invalid');
    const expectedSignature = signTelemetryRequest({ token: leaseToken, timestamp, nonce, body });
    if (!secureTextMatches(signature, expectedSignature)) {
      throw unauthorized('update policy request signature is invalid');
    }
    const accepted = await this.#store.consumeUpdatePolicyNonce({
      deploymentId,
      nonce,
      expiresAtMs: now + MAX_CLOCK_SKEW_MS * 2,
    });
    if (!accepted) throw conflict('update policy request replay detected');

    const releases = await this.#store.getActiveUpdateReleases(distributionId);
    let selected: UpdateReleaseRecord | null = null;
    let outsideRollout = false;
    for (const release of releases) {
      const comparison = compareVersions(currentVersion, release.version);
      if (comparison === null) throw conflict('stored update release version is invalid');
      if (comparison >= 0) continue;
      if (release.channel === 'canary') {
        const cohort = updateCohortPercent(distributionId, release.id, deploymentId);
        if (cohort > release.rolloutPercent) {
          outsideRollout = true;
          continue;
        }
      }
      selected = release;
      break;
    }
    if (selected && !selected.publishedAt) {
      throw conflict('stored active update release is missing publishedAt');
    }
    if (selected) await this.#releaseArtifacts.assertReleaseReady(selected);
    const reason = selected
      ? 'update_available'
      : releases.length === 0
        ? 'no_active_release'
        : outsideRollout
          ? 'outside_rollout'
          : 'up_to_date';
    const artifacts = selected
      ? await this.#releaseArtifacts.activeEnvelopes(selected.id)
      : [];
    const policy: OttoUpdatePolicyPayload = {
      version: 1,
      deploymentId,
      distributionId,
      currentVersion,
      decision: selected ? 'update' : 'none',
      reason,
      release: selected ? releasePayload(selected, artifacts) : null,
      issuedAtMs: now,
      expiresAtMs: now + this.#policyDurationMs,
    };
    return { policy, ...await signPayload(this.#signer, policy) };
  }
}

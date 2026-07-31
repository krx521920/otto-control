import { randomUUID } from 'node:crypto';

import {
  isOttoLicenseCapability,
  type IssueLicenseInput,
  type OttoLeasePayload,
  type OttoLeaseRequest,
  type OttoLicensePayload,
  type OttoSeatEnforcement,
  type OttoSignedLeaseEnvelope,
  type OttoSignedLicenseEnvelope,
} from '../../contracts/license.js';
import type {
  DeploymentTelemetrySummary,
  OttoTelemetryBatch,
  OttoTelemetryEvent,
  OttoTelemetryReceipt,
  TelemetryRequestAuthentication,
} from '../../contracts/telemetry.js';
import {
  secureTextMatches,
  signTelemetryRequest,
  telemetryIntegrityHash,
} from '../../crypto/telemetry-request.js';
import { signPayload, type PayloadSigner } from '../../crypto/signed-envelope.js';
import type {
  ManagedSigningKeyring,
  PublicSigningKey,
  SignedKeyringEnvelope,
} from '../../crypto/signing-keyring.js';
import { conflict, invalidRequest, notFound, unauthorized } from '../../errors.js';
import type {
  ControlStore,
  LicenseLifecycleChangeType,
  LicenseLifecycleEventRecord,
  CustomerRecord,
  DeploymentRecord,
  LicenseRecord,
  LicenseSeatUsageRecord,
} from '../../storage/control-store.js';
import type { ControlTokenIssuer } from './token-issuer.js';

const ID_PART_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{1,127}$/u;
const DEPLOYMENT_ID_PATTERN = /^dep_[a-zA-Z0-9]{16,64}$/u;
const MACHINE_FINGERPRINT_PATTERN = /^[a-f0-9]{64}$/u;
const SIGNING_KEY_ID_PATTERN = /^[a-f0-9]{16}$/u;
const NONCE_PATTERN = /^[a-zA-Z0-9._:-]{16,128}$/u;
const MAX_LICENSE_DURATION_MS = 5 * 366 * 24 * 60 * 60 * 1000;
const DEFAULT_GRACE_PERIOD_MS = 7 * 24 * 60 * 60 * 1000;
const TELEMETRY_MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
const TELEMETRY_MAX_EVENT_BYTES = 64 * 1024;
const FORBIDDEN_TELEMETRY_KEYS = new Set([
  'message',
  'messages',
  'content',
  'file',
  'files',
  'attachment',
  'attachments',
  'audio',
  'meetingaudio',
  'transcript',
  'prompt',
  'completion',
  'document',
  'documents',
]);

function objectValue(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw invalidRequest('request body must be an object');
  }
  return value as Record<string, unknown>;
}

function requiredString(
  object: Record<string, unknown>,
  key: string,
  maxLength = 160,
): string {
  const value = typeof object[key] === 'string' ? object[key].trim() : '';
  if (!value) throw invalidRequest(`${key} is required`);
  if (value.length > maxLength) throw invalidRequest(`${key} is too long`);
  return value;
}

function prefixedId(prefix: string): string {
  return `${prefix}_${randomUUID().replace(/-/gu, '')}`;
}

function bearerToken(authorization: string | undefined): string {
  return /^Bearer\s+(.+)$/iu.exec(authorization?.trim() || '')?.[1] || '';
}

function telemetryContainsContent(value: unknown, depth = 0): boolean {
  if (depth > 8) return true;
  if (Array.isArray(value)) {
    return value.some((item) => telemetryContainsContent(item, depth + 1));
  }
  if (!value || typeof value !== 'object') return false;
  return Object.entries(value as Record<string, unknown>).some(([key, item]) => (
    FORBIDDEN_TELEMETRY_KEYS.has(key.toLowerCase().replace(/[_-]/gu, '')) ||
    telemetryContainsContent(item, depth + 1)
  ));
}

function telemetryEvent(
  raw: unknown,
  batch: Pick<OttoTelemetryBatch, 'deploymentId'>,
  now: number,
  retentionBeforeMs: number,
): OttoTelemetryEvent {
  const event = objectValue(raw);
  const id = requiredString(event, 'id', 68);
  const eventType = requiredString(event, 'eventType', 80);
  const createdAtMs = Number(event.createdAtMs);
  const integrity = requiredString(event, 'integrity', 128);
  const organizationId = event.organizationId === null
    ? null
    : requiredString(event, 'organizationId', 128);
  const payload = objectValue(event.payload);
  if (!/^tel_[a-zA-Z0-9]{16,64}$/u.test(id)) throw invalidRequest('telemetry event id is invalid');
  if (!/^[a-zA-Z0-9_.:-]{2,80}$/u.test(eventType)) {
    throw invalidRequest('telemetry event type is invalid');
  }
  if (!Number.isFinite(createdAtMs) || createdAtMs <= retentionBeforeMs || createdAtMs > now + 5 * 60 * 1000) {
    throw invalidRequest('telemetry event timestamp is outside the retention window');
  }
  if (Buffer.byteLength(JSON.stringify(payload), 'utf8') > TELEMETRY_MAX_EVENT_BYTES) {
    throw invalidRequest('telemetry event payload exceeds 64 KiB');
  }
  if (telemetryContainsContent(payload)) {
    throw invalidRequest('telemetry content payload is forbidden');
  }
  if (
    payload.deploymentId !== batch.deploymentId ||
    payload.organizationId !== organizationId ||
    payload.eventType !== eventType ||
    Number(payload.createdAtMs) !== createdAtMs ||
    !payload.payload ||
    typeof payload.payload !== 'object' ||
    Array.isArray(payload.payload)
  ) {
    throw invalidRequest('telemetry event envelope binding is invalid');
  }
  if (!secureTextMatches(telemetryIntegrityHash(payload), integrity)) {
    throw invalidRequest('telemetry event integrity is invalid');
  }
  return { id, organizationId, eventType, createdAtMs, payload, integrity };
}

function licensePayload(
  license: LicenseRecord,
  tokens: ControlTokenIssuer,
): OttoLicensePayload {
  const payload: OttoLicensePayload = {
    id: license.id,
    revision: license.revision,
    deploymentId: license.deploymentId,
    organizationId: license.organizationId,
    machineFingerprint: license.machineFingerprint,
    customerName: license.customerName,
    plan: license.plan,
    issuedAtMs: license.issuedAtMs,
    expiresAtMs: license.expiresAtMs,
    seatLimit: license.seatLimit,
    gracePeriodMs: license.gracePeriodMs,
    seatEnforcement: license.seatEnforcement,
    modules: license.modules,
    offline: license.offline,
    telemetryAllowed: license.telemetryAllowed,
  };
  if (!license.offline) {
    payload.leaseEndpoint = license.leaseEndpoint!;
    payload.billingEndpoint = new URL('/v1/billing/usage/consume', license.leaseEndpoint!).toString();
    payload.leaseToken = tokens.issue({
      purpose: 'lease',
      licenseId: license.id,
      deploymentId: license.deploymentId,
      version: license.tokenVersion,
    });
  }
  if (license.telemetryAllowed) {
    payload.telemetryToken = tokens.issue({
      purpose: 'telemetry',
      licenseId: license.id,
      deploymentId: license.deploymentId,
      version: license.tokenVersion,
    });
  }
  return payload;
}

export interface CommercialControlServiceOptions {
  store: ControlStore;
  signer: PayloadSigner;
  keyring?: ManagedSigningKeyring;
  tokenIssuer: ControlTokenIssuer;
  publicBaseUrl: string;
  leaseDurationMs?: number;
  telemetryRetentionDays?: number;
  now?: () => number;
}

export class CommercialControlService {
  readonly #store: ControlStore;
  readonly #signer: PayloadSigner;
  readonly #keyring: ManagedSigningKeyring | null;
  readonly #tokens: ControlTokenIssuer;
  readonly #publicBaseUrl: string;
  readonly #leaseDurationMs: number;
  readonly #telemetryRetentionMs: number;
  readonly #now: () => number;

  constructor(options: CommercialControlServiceOptions) {
    this.#store = options.store;
    this.#signer = options.signer;
    this.#keyring = options.keyring ?? null;
    this.#tokens = options.tokenIssuer;
    this.#publicBaseUrl = options.publicBaseUrl.replace(/\/$/u, '');
    this.#leaseDurationMs = options.leaseDurationMs ?? 10 * 60 * 1000;
    const telemetryRetentionDays = options.telemetryRetentionDays ?? 90;
    if (!Number.isInteger(telemetryRetentionDays) || telemetryRetentionDays < 1 || telemetryRetentionDays > 3650) {
      throw new Error('telemetry retention must be between 1 and 3650 days');
    }
    this.#telemetryRetentionMs = telemetryRetentionDays * 24 * 60 * 60 * 1000;
    this.#now = options.now ?? Date.now;
    if (this.#leaseDurationMs < 2 * 60 * 1000 || this.#leaseDurationMs > 24 * 60 * 60 * 1000) {
      throw new Error('lease duration must be between 2 minutes and 24 hours');
    }
  }

  async ready(): Promise<void> {
    await this.#store.ping();
  }

  async close(): Promise<void> {
    await this.#store.close();
  }

  async signingKey(): Promise<{
    keyId: string;
    algorithm: 'ed25519';
    publicKeyPem: string;
  }> {
    if (this.#keyring) {
      const active = (await this.#keyring.list()).find((key) => key.state === 'active');
      if (!active) throw conflict('signing keyring has no active key');
      return {
        keyId: active.keyId,
        algorithm: active.algorithm,
        publicKeyPem: active.publicKeyPem,
      };
    }
    return {
      keyId: this.#signer.keyId,
      algorithm: 'ed25519',
      publicKeyPem: this.#signer.publicKeyPem,
    };
  }

  async signingKeys(): Promise<PublicSigningKey[]> {
    if (this.#keyring) return this.#keyring.list();
    const now = new Date();
    return [{
      keyId: this.#signer.keyId,
      algorithm: 'ed25519',
      publicKeyPem: this.#signer.publicKeyPem,
      provider: 'local',
      state: 'active',
      createdAt: now,
      activatedAt: now,
      retiredAt: null,
      revokedAt: null,
      revocationReason: null,
      updatedAt: now,
      canSign: true,
      providerHealth: this.#signer.health?.() ?? {
        state: 'available',
        consecutiveFailures: 0,
        circuitOpenUntil: null,
      },
    }];
  }

  async publicSigningKeyring(): Promise<SignedKeyringEnvelope> {
    if (this.#keyring) return this.#keyring.publicEnvelope(this.#now());
    const generatedAtMs = this.#now();
    const keyring = {
      version: 1 as const,
      activeKeyId: this.#signer.keyId,
      revisionMs: generatedAtMs,
      generatedAtMs,
      expiresAtMs: generatedAtMs + 10 * 60 * 1000,
      keys: [{
        keyId: this.#signer.keyId,
        algorithm: 'ed25519' as const,
        publicKeyPem: this.#signer.publicKeyPem,
        provider: 'local' as const,
        state: 'active' as const,
        activatedAt: null,
        retiredAt: null,
        revokedAt: null,
      }],
    };
    return {
      keyring,
      signingKeyId: this.#signer.keyId,
      signature: await this.#signer.sign(keyring),
    };
  }

  async activateSigningKey(keyId: string, actorId: string): Promise<PublicSigningKey[]> {
    if (!this.#keyring) throw conflict('managed signing keyring is not configured');
    if (!SIGNING_KEY_ID_PATTERN.test(keyId)) throw invalidRequest('signing key id is invalid');
    const transition = await this.#keyring.activate(keyId);
    await this.#store.appendAuditEvent({
      actorId,
      action: 'signing_key.activated',
      targetType: 'signing_key',
      targetId: keyId,
      detail: { previousActiveKeyId: transition.previousActiveKey?.keyId ?? null },
    });
    return this.#keyring.list();
  }

  async retireSigningKey(keyId: string, actorId: string): Promise<PublicSigningKey[]> {
    if (!this.#keyring) throw conflict('managed signing keyring is not configured');
    if (!SIGNING_KEY_ID_PATTERN.test(keyId)) throw invalidRequest('signing key id is invalid');
    await this.#keyring.retire(keyId);
    await this.#store.appendAuditEvent({
      actorId,
      action: 'signing_key.retired',
      targetType: 'signing_key',
      targetId: keyId,
      detail: {},
    });
    return this.#keyring.list();
  }

  async revokeSigningKey(
    keyId: string,
    raw: unknown,
    actorId: string,
  ): Promise<PublicSigningKey[]> {
    if (!this.#keyring) throw conflict('managed signing keyring is not configured');
    if (!SIGNING_KEY_ID_PATTERN.test(keyId)) throw invalidRequest('signing key id is invalid');
    const body = objectValue(raw);
    const reason = requiredString(body, 'reason', 500);
    const replacementKeyId = body.replacementKeyId === undefined || body.replacementKeyId === null
      ? null
      : requiredString(body, 'replacementKeyId', 64);
    if (replacementKeyId && !SIGNING_KEY_ID_PATTERN.test(replacementKeyId)) {
      throw invalidRequest('replacementKeyId is invalid');
    }
    const transition = await this.#keyring.revoke({ keyId, replacementKeyId, reason });
    await this.#store.appendAuditEvent({
      actorId,
      action: 'signing_key.revoked',
      targetType: 'signing_key',
      targetId: keyId,
      detail: {
        reason,
        replacementKeyId: transition.activeKey?.keyId ?? replacementKeyId,
      },
    });
    return this.#keyring.list();
  }

  async createCustomer(raw: unknown, actorId: string): Promise<CustomerRecord> {
    const body = objectValue(raw);
    const name = requiredString(body, 'name', 160);
    const id = typeof body.id === 'string' && body.id.trim()
      ? body.id.trim()
      : prefixedId('cus');
    if (!ID_PART_PATTERN.test(id)) throw invalidRequest('customer id is invalid');
    const customer = await this.#store.createCustomer({ id, name });
    await this.#store.appendAuditEvent({
      actorId,
      action: 'customer.created',
      targetType: 'customer',
      targetId: customer.id,
      detail: { name: customer.name },
    });
    return customer;
  }

  async createDeployment(raw: unknown, actorId: string): Promise<DeploymentRecord> {
    const body = objectValue(raw);
    const id = requiredString(body, 'deploymentId', 68);
    const customerId = requiredString(body, 'customerId', 128);
    const organizationId = requiredString(body, 'organizationId', 128);
    const machineFingerprint = requiredString(body, 'machineFingerprint', 64).toLowerCase();
    const name = requiredString(body, 'name', 160);
    if (!DEPLOYMENT_ID_PATTERN.test(id)) throw invalidRequest('deploymentId is invalid');
    if (!ID_PART_PATTERN.test(customerId)) throw invalidRequest('customerId is invalid');
    if (!ID_PART_PATTERN.test(organizationId)) throw invalidRequest('organizationId is invalid');
    if (!MACHINE_FINGERPRINT_PATTERN.test(machineFingerprint)) {
      throw invalidRequest('machineFingerprint must be a SHA-256 hex digest');
    }
    const deployment = await this.#store.createDeployment({
      id,
      customerId,
      organizationId,
      machineFingerprint,
      name,
    });
    await this.#store.appendAuditEvent({
      actorId,
      action: 'deployment.created',
      targetType: 'deployment',
      targetId: deployment.id,
      detail: { customerId, organizationId },
    });
    return deployment;
  }

  async #changeLicense(
    existing: LicenseRecord,
    changes: Partial<LicenseRecord>,
    actorId: string,
    changeType: LicenseLifecycleChangeType,
    changeDetail: Record<string, unknown>,
    options: {
      rotateTokens?: boolean;
      deploymentMachineFingerprint?: {
        deploymentId: string;
        expectedFingerprint: string;
        newFingerprint: string;
      };
      resetSeatUsage?: boolean;
    } = {},
  ): Promise<OttoSignedLicenseEnvelope> {
    if (existing.revokedAtMs !== null) throw conflict('revoked License cannot be changed');
    const now = this.#now();
    const candidate: LicenseRecord = {
      ...existing,
      ...changes,
      revision: existing.revision + 1,
      tokenVersion: existing.tokenVersion + (options.rotateTokens ? 1 : 0),
      signature: '',
      signingKeyId: '',
      updatedAt: new Date(now),
    };
    const signed = await signPayload(this.#signer, licensePayload(candidate, this.#tokens));
    const stored = await this.#store.updateLicense({
      id: candidate.id,
      revision: candidate.revision,
      deploymentId: candidate.deploymentId,
      customerName: candidate.customerName,
      organizationId: candidate.organizationId,
      machineFingerprint: candidate.machineFingerprint,
      plan: candidate.plan,
      issuedAtMs: candidate.issuedAtMs,
      expiresAtMs: candidate.expiresAtMs,
      seatLimit: candidate.seatLimit,
      gracePeriodMs: candidate.gracePeriodMs,
      seatEnforcement: candidate.seatEnforcement,
      modules: candidate.modules,
      offline: candidate.offline,
      telemetryAllowed: candidate.telemetryAllowed,
      leaseEndpoint: candidate.leaseEndpoint,
      tokenVersion: candidate.tokenVersion,
      signature: signed.signature,
      signingKeyId: signed.signingKeyId,
      revokedAtMs: candidate.revokedAtMs,
      expectedRevision: existing.revision,
      actorId,
      changeType,
      changeDetail,
      deploymentMachineFingerprint: options.deploymentMachineFingerprint,
      resetSeatUsage: options.resetSeatUsage,
    });
    if (!stored) throw conflict('License changed concurrently; reload and retry');
    await this.#store.appendAuditEvent({
      actorId,
      action: `license.${changeType}`,
      targetType: 'license',
      targetId: stored.id,
      detail: { revision: stored.revision, ...changeDetail },
    });
    return {
      license: licensePayload(stored, this.#tokens),
      signingKeyId: stored.signingKeyId,
      signature: stored.signature,
    };
  }

  async renewLicense(
    id: string,
    raw: unknown,
    actorId: string,
  ): Promise<OttoSignedLicenseEnvelope> {
    const body = objectValue(raw);
    const expiresAt = requiredString(body, 'expiresAt', 64);
    const expiresAtMs = Date.parse(expiresAt);
    const license = await this.#store.getLicense(id);
    if (!license) throw notFound('license not found');
    if (!Number.isFinite(expiresAtMs) || expiresAtMs <= license.expiresAtMs) {
      throw invalidRequest('renewal expiresAt must be later than the current expiry');
    }
    if (expiresAtMs - this.#now() > MAX_LICENSE_DURATION_MS) {
      throw invalidRequest('renewal cannot extend more than five years from now');
    }
    let gracePeriodMs = license.gracePeriodMs;
    if (body.gracePeriodDays !== undefined) {
      const days = Number(body.gracePeriodDays);
      if (!Number.isInteger(days) || days < 0 || days > 30) {
        throw invalidRequest('gracePeriodDays must be an integer between 0 and 30');
      }
      gracePeriodMs = days * 24 * 60 * 60 * 1000;
    }
    return this.#changeLicense(
      license,
      { expiresAtMs, gracePeriodMs },
      actorId,
      'renewed',
      {
        previousExpiresAtMs: license.expiresAtMs,
        expiresAtMs,
        previousGracePeriodMs: license.gracePeriodMs,
        gracePeriodMs,
      },
    );
  }

  async resizeLicense(
    id: string,
    raw: unknown,
    actorId: string,
  ): Promise<OttoSignedLicenseEnvelope> {
    const body = objectValue(raw);
    const seatLimit = Number(body.seatLimit);
    if (!Number.isInteger(seatLimit) || seatLimit < 1 || seatLimit > 100_000) {
      throw invalidRequest('seatLimit must be an integer between 1 and 100000');
    }
    const license = await this.#store.getLicense(id);
    if (!license) throw notFound('license not found');
    if (seatLimit === license.seatLimit && body.seatEnforcement === undefined) {
      throw invalidRequest('seatLimit or seatEnforcement must change');
    }
    const seatEnforcement: OttoSeatEnforcement = body.seatEnforcement === undefined
      ? license.seatEnforcement
      : body.seatEnforcement as OttoSeatEnforcement;
    if (!['monitor', 'enforce'].includes(seatEnforcement)) {
      throw invalidRequest('seatEnforcement must be monitor or enforce');
    }
    if (license.offline && seatEnforcement === 'enforce') {
      throw invalidRequest('offline License cannot enforce real-time seat usage');
    }
    let gracePeriodMs = license.gracePeriodMs;
    if (body.gracePeriodDays !== undefined) {
      const days = Number(body.gracePeriodDays);
      if (!Number.isInteger(days) || days < 0 || days > 30) {
        throw invalidRequest('gracePeriodDays must be an integer between 0 and 30');
      }
      gracePeriodMs = days * 24 * 60 * 60 * 1000;
    }
    const changeType: LicenseLifecycleChangeType = seatLimit === license.seatLimit
      ? 'terms_changed'
      : seatLimit > license.seatLimit
        ? 'expanded'
        : 'downgraded';
    const envelope = await this.#changeLicense(
      license,
      { seatLimit, seatEnforcement, gracePeriodMs },
      actorId,
      changeType,
      {
        previousSeatLimit: license.seatLimit,
        seatLimit,
        previousSeatEnforcement: license.seatEnforcement,
        seatEnforcement,
        previousGracePeriodMs: license.gracePeriodMs,
        gracePeriodMs,
      },
    );
    const existingUsage = await this.#store.getLicenseSeatUsage(id);
    if (existingUsage) {
      const usage = await this.#store.recordLicenseSeatUsage({
        licenseId: id,
        deploymentId: envelope.license.deploymentId,
        activeSeats: existingUsage.activeSeats,
        seatLimit,
        gracePeriodMs,
        enforcement: seatEnforcement,
        reportedAtMs: this.#now(),
      });
      if (usage.status !== existingUsage.status || usage.seatLimit !== existingUsage.seatLimit) {
        await this.#store.appendAuditEvent({
          actorId,
          action: 'license.seat_status_changed',
          targetType: 'license',
          targetId: id,
          detail: {
            previousStatus: existingUsage.status,
            status: usage.status,
            activeSeats: usage.activeSeats,
            previousSeatLimit: existingUsage.seatLimit,
            seatLimit: usage.seatLimit,
            graceExpiresAtMs: usage.graceExpiresAtMs,
          },
        });
      }
    }
    return envelope;
  }

  async transferLicenseMachine(
    id: string,
    raw: unknown,
    actorId: string,
  ): Promise<OttoSignedLicenseEnvelope> {
    const body = objectValue(raw);
    const machineFingerprint = requiredString(body, 'machineFingerprint', 64).toLowerCase();
    if (!MACHINE_FINGERPRINT_PATTERN.test(machineFingerprint)) {
      throw invalidRequest('machineFingerprint must be a SHA-256 hex digest');
    }
    const license = await this.#store.getLicense(id);
    if (!license) throw notFound('license not found');
    if (machineFingerprint === license.machineFingerprint) {
      throw invalidRequest('machineFingerprint is unchanged');
    }
    return this.#changeLicense(
      license,
      { machineFingerprint },
      actorId,
      'machine_transferred',
      {
        previousMachineFingerprint: license.machineFingerprint,
        machineFingerprint,
      },
      {
        rotateTokens: true,
        deploymentMachineFingerprint: {
          deploymentId: license.deploymentId,
          expectedFingerprint: license.machineFingerprint,
          newFingerprint: machineFingerprint,
        },
        resetSeatUsage: true,
      },
    );
  }

  async rebindLicenseDeployment(
    id: string,
    raw: unknown,
    actorId: string,
  ): Promise<OttoSignedLicenseEnvelope> {
    const body = objectValue(raw);
    const deploymentId = requiredString(body, 'deploymentId', 68);
    if (!DEPLOYMENT_ID_PATTERN.test(deploymentId)) throw invalidRequest('deploymentId is invalid');
    const license = await this.#store.getLicense(id);
    if (!license) throw notFound('license not found');
    if (deploymentId === license.deploymentId) throw invalidRequest('deploymentId is unchanged');
    const [currentDeployment, targetDeployment] = await Promise.all([
      this.#store.getDeployment(license.deploymentId),
      this.#store.getDeployment(deploymentId),
    ]);
    if (!currentDeployment) throw conflict('current deployment no longer exists');
    if (!targetDeployment) throw notFound('target deployment not found');
    if (targetDeployment.status !== 'active') throw conflict('target deployment is suspended');
    if (targetDeployment.customerId !== currentDeployment.customerId) {
      throw conflict('License can only be rebound within the same customer');
    }
    return this.#changeLicense(
      license,
      {
        deploymentId: targetDeployment.id,
        customerName: targetDeployment.customerName,
        organizationId: targetDeployment.organizationId,
        machineFingerprint: targetDeployment.machineFingerprint,
      },
      actorId,
      'deployment_rebound',
      {
        previousDeploymentId: license.deploymentId,
        deploymentId: targetDeployment.id,
        previousOrganizationId: license.organizationId,
        organizationId: targetDeployment.organizationId,
      },
      { rotateTokens: true, resetSeatUsage: true },
    );
  }

  async licenseLifecycle(id: string, limit: number): Promise<LicenseLifecycleEventRecord[]> {
    if (!Number.isInteger(limit) || limit < 1 || limit > 200) {
      throw invalidRequest('limit must be an integer between 1 and 200');
    }
    if (!await this.#store.getLicense(id)) throw notFound('license not found');
    return this.#store.listLicenseLifecycleEvents(id, limit);
  }

  async licenseSeatUsage(id: string): Promise<LicenseSeatUsageRecord | null> {
    if (!await this.#store.getLicense(id)) throw notFound('license not found');
    return this.#store.getLicenseSeatUsage(id);
  }

  async issueLicense(raw: unknown, actorId: string): Promise<OttoSignedLicenseEnvelope> {
    const body = objectValue(raw);
    const deploymentId = requiredString(body, 'deploymentId', 68);
    const plan = requiredString(body, 'plan', 80);
    const expiresAt = requiredString(body, 'expiresAt', 64);
    const seatLimit = Number(body.seatLimit);
    if (!DEPLOYMENT_ID_PATTERN.test(deploymentId)) throw invalidRequest('deploymentId is invalid');
    if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{1,79}$/u.test(plan)) throw invalidRequest('plan is invalid');
    if (!Number.isInteger(seatLimit) || seatLimit < 1 || seatLimit > 100_000) {
      throw invalidRequest('seatLimit must be an integer between 1 and 100000');
    }
    if (!Array.isArray(body.modules) || body.modules.length === 0) {
      throw invalidRequest('modules must contain at least one capability');
    }
    const requestedModules = body.modules.map((module) => String(module));
    const unknownModule = requestedModules.find((module) => !isOttoLicenseCapability(module));
    if (unknownModule) throw invalidRequest(`unknown License capability: ${unknownModule}`);
    const modules = [...new Set(requestedModules)] as IssueLicenseInput['modules'];
    const issuedAtMs = this.#now();
    const expiresAtMs = Date.parse(expiresAt);
    if (!Number.isFinite(expiresAtMs) || expiresAtMs <= issuedAtMs) {
      throw invalidRequest('expiresAt must be a future ISO date');
    }
    if (expiresAtMs - issuedAtMs > MAX_LICENSE_DURATION_MS) {
      throw invalidRequest('License duration cannot exceed five years');
    }
    const deployment = await this.#store.getDeployment(deploymentId);
    if (!deployment) throw notFound('deployment not found');
    if (deployment.status !== 'active') throw conflict('deployment is suspended');
    const offline = body.offline === true;
    const telemetryAllowed = body.telemetryAllowed !== false;
    const gracePeriodDays = body.gracePeriodDays === undefined
      ? DEFAULT_GRACE_PERIOD_MS / (24 * 60 * 60 * 1000)
      : Number(body.gracePeriodDays);
    if (!Number.isInteger(gracePeriodDays) || gracePeriodDays < 0 || gracePeriodDays > 30) {
      throw invalidRequest('gracePeriodDays must be an integer between 0 and 30');
    }
    const gracePeriodMs = gracePeriodDays * 24 * 60 * 60 * 1000;
    const seatEnforcement: OttoSeatEnforcement = body.seatEnforcement === undefined
      ? 'monitor'
      : body.seatEnforcement as OttoSeatEnforcement;
    if (!['monitor', 'enforce'].includes(seatEnforcement)) {
      throw invalidRequest('seatEnforcement must be monitor or enforce');
    }
    if (offline && seatEnforcement === 'enforce') {
      throw invalidRequest('offline License cannot enforce real-time seat usage');
    }
    const id = prefixedId('lic');
    const leaseEndpoint = offline
      ? null
      : `${this.#publicBaseUrl}/v1/licenses/${encodeURIComponent(id)}/lease`;
    const unsigned: LicenseRecord = {
      id,
      revision: 1,
      deploymentId,
      customerName: deployment.customerName,
      organizationId: deployment.organizationId,
      machineFingerprint: deployment.machineFingerprint,
      plan,
      issuedAtMs,
      expiresAtMs,
      seatLimit,
      gracePeriodMs,
      seatEnforcement,
      modules,
      offline,
      telemetryAllowed,
      leaseEndpoint,
      tokenVersion: 1,
      signature: '',
      signingKeyId: '',
      revokedAtMs: null,
      createdAt: new Date(issuedAtMs),
      updatedAt: new Date(issuedAtMs),
    };
    const payload = licensePayload(unsigned, this.#tokens);
    const signed = await signPayload(this.#signer, payload);
    const stored = await this.#store.createLicense({
      ...unsigned,
      signature: signed.signature,
      signingKeyId: signed.signingKeyId,
    });
    await this.#store.appendAuditEvent({
      actorId,
      action: 'license.issued',
      targetType: 'license',
      targetId: stored.id,
      detail: {
        deploymentId,
        plan,
        seatLimit,
        gracePeriodDays,
        seatEnforcement,
        modules,
        offline,
        expiresAtMs,
      },
    });
    return {
      license: licensePayload(stored, this.#tokens),
      signingKeyId: stored.signingKeyId,
      signature: stored.signature,
    };
  }

  async getLicenseEnvelope(id: string): Promise<OttoSignedLicenseEnvelope> {
    const license = await this.#store.getLicense(id);
    if (!license) throw notFound('license not found');
    return {
      license: licensePayload(license, this.#tokens),
      signingKeyId: license.signingKeyId,
      signature: license.signature,
    };
  }

  async revokeLicense(id: string, actorId: string): Promise<LicenseRecord> {
    const revokedAtMs = this.#now();
    const license = await this.#store.revokeLicense(id, revokedAtMs);
    if (!license) throw notFound('license not found');
    await this.#store.appendAuditEvent({
      actorId,
      action: 'license.revoked',
      targetType: 'license',
      targetId: id,
      detail: { deploymentId: license.deploymentId, revokedAtMs },
    });
    return license;
  }

  async issueLease(
    licenseId: string,
    raw: unknown,
    bearerToken: string,
  ): Promise<OttoSignedLeaseEnvelope> {
    const license = await this.#store.getLicense(licenseId);
    if (!license) throw notFound('license not found');
    if (license.offline) throw invalidRequest('offline License does not use online leases');
    const expectedToken = this.#tokens.issue({
      purpose: 'lease',
      licenseId: license.id,
      deploymentId: license.deploymentId,
      version: license.tokenVersion,
    });
    if (!this.#tokens.matches(bearerToken, expectedToken)) {
      throw unauthorized('License lease token is invalid');
    }
    const body = objectValue(raw) as Partial<OttoLeaseRequest>;
    if (body.version !== 1) throw invalidRequest('lease request version is invalid');
    if (body.licenseId !== license.id) throw invalidRequest('licenseId mismatch');
    if (body.deploymentId !== license.deploymentId) throw invalidRequest('deploymentId mismatch');
    if (body.organizationId !== license.organizationId) throw invalidRequest('organizationId mismatch');
    if (body.machineFingerprint !== license.machineFingerprint) {
      throw invalidRequest('machineFingerprint mismatch');
    }
    if (typeof body.nonce !== 'string' || !NONCE_PATTERN.test(body.nonce)) {
      throw invalidRequest('nonce is invalid');
    }
    const issuedAtMs = this.#now();
    if (license.revokedAtMs !== null) throw unauthorized('License has been revoked');
    const expirationGraceExpiresAtMs = license.expiresAtMs + license.gracePeriodMs;
    if (issuedAtMs >= expirationGraceExpiresAtMs) {
      throw unauthorized('License and its grace period have expired');
    }
    await this.#keyring?.assertLicenseSigningKeyUsable(license.signingKeyId);
    const nonceAccepted = await this.#store.consumeLeaseNonce({
      deploymentId: license.deploymentId,
      nonce: body.nonce,
      expiresAtMs: issuedAtMs + 20 * 60 * 1000,
    });
    if (!nonceAccepted) throw conflict('lease request replay detected');
    let activeSeatCount: number | null = null;
    let seatStatus: OttoLeasePayload['seatStatus'] = 'unreported';
    let seatGraceExpiresAtMs: number | null = null;
    if (body.activeSeatCount === undefined) {
      if (license.seatEnforcement === 'enforce') {
        throw invalidRequest('activeSeatCount is required when seat enforcement is enabled');
      }
    } else {
      activeSeatCount = Number(body.activeSeatCount);
      if (!Number.isInteger(activeSeatCount) || activeSeatCount < 0 || activeSeatCount > 10_000_000) {
        throw invalidRequest('activeSeatCount must be an integer between 0 and 10000000');
      }
      const previousUsage = await this.#store.getLicenseSeatUsage(license.id);
      const usage = await this.#store.recordLicenseSeatUsage({
        licenseId: license.id,
        deploymentId: license.deploymentId,
        activeSeats: activeSeatCount,
        seatLimit: license.seatLimit,
        gracePeriodMs: license.gracePeriodMs,
        enforcement: license.seatEnforcement,
        reportedAtMs: issuedAtMs,
      });
      seatStatus = usage.status;
      seatGraceExpiresAtMs = usage.graceExpiresAtMs;
      if (
        previousUsage?.status !== usage.status ||
        previousUsage?.seatLimit !== usage.seatLimit
      ) {
        await this.#store.appendAuditEvent({
          actorId: `deployment:${license.deploymentId}`,
          action: 'license.seat_status_changed',
          targetType: 'license',
          targetId: license.id,
          detail: {
            previousStatus: previousUsage?.status ?? 'unreported',
            status: usage.status,
            activeSeats: usage.activeSeats,
            seatLimit: usage.seatLimit,
            graceExpiresAtMs: usage.graceExpiresAtMs,
          },
        });
      }
      if (usage.status === 'blocked') {
        throw unauthorized('active seats exceed the licensed limit and grace period');
      }
    }
    const graceReasons: OttoLeasePayload['graceReasons'] = [];
    const graceDeadlines: number[] = [];
    if (issuedAtMs >= license.expiresAtMs) {
      graceReasons.push('expiration');
      graceDeadlines.push(expirationGraceExpiresAtMs);
    }
    if (seatStatus === 'overage_grace' && seatGraceExpiresAtMs !== null) {
      graceReasons.push('seat_overage');
      graceDeadlines.push(seatGraceExpiresAtMs);
    }
    const graceExpiresAtMs = graceDeadlines.length > 0 ? Math.min(...graceDeadlines) : null;
    const lease: OttoLeasePayload = {
      id: prefixedId('lease'),
      licenseId: license.id,
      deploymentId: license.deploymentId,
      machineFingerprint: license.machineFingerprint,
      licenseRevision: license.revision,
      issuedAtMs,
      expiresAtMs: Math.min(
        issuedAtMs + this.#leaseDurationMs,
        graceExpiresAtMs ?? license.expiresAtMs,
      ),
      seatLimit: license.seatLimit,
      activeSeatCount,
      seatStatus,
      graceReasons,
      graceExpiresAtMs,
    };
    const signed = await signPayload(this.#signer, lease);
    return {
      lease,
      ...signed,
      licenseEnvelope: {
        license: licensePayload(license, this.#tokens),
        signingKeyId: license.signingKeyId,
        signature: license.signature,
      },
    };
  }

  async ingestTelemetry(
    raw: unknown,
    authentication: TelemetryRequestAuthentication,
  ): Promise<OttoTelemetryReceipt> {
    const body = objectValue(raw);
    if (body.version !== 1) throw invalidRequest('telemetry version is invalid');
    const deploymentId = requiredString(body, 'deploymentId', 68);
    const machineFingerprint = requiredString(body, 'machineFingerprint', 64).toLowerCase();
    const licenseId = requiredString(body, 'licenseId', 68);
    if (!DEPLOYMENT_ID_PATTERN.test(deploymentId)) throw invalidRequest('deploymentId is invalid');
    if (!MACHINE_FINGERPRINT_PATTERN.test(machineFingerprint)) {
      throw invalidRequest('machineFingerprint is invalid');
    }
    const license = await this.#store.getLicense(licenseId);
    if (!license) throw notFound('license not found');
    if (license.deploymentId !== deploymentId || license.machineFingerprint !== machineFingerprint) {
      throw unauthorized('telemetry deployment binding is invalid');
    }
    const now = this.#now();
    if (license.revokedAtMs !== null) throw unauthorized('License has been revoked');
    if (license.expiresAtMs + license.gracePeriodMs <= now) {
      throw unauthorized('License and its grace period have expired');
    }
    if (!license.telemetryAllowed) throw unauthorized('License does not allow telemetry');
    const deployment = await this.#store.getDeployment(deploymentId);
    if (!deployment || deployment.status !== 'active') {
      throw unauthorized('deployment is not active');
    }
    const telemetryToken = this.#tokens.issue({
      purpose: 'telemetry',
      licenseId,
      deploymentId,
      version: license.tokenVersion,
    });
    if (!this.#tokens.matches(bearerToken(authentication.authorization), telemetryToken)) {
      throw unauthorized('telemetry token is invalid');
    }
    const timestamp = Number(authentication.timestamp);
    const nonce = authentication.nonce?.trim() || '';
    const signature = authentication.signature?.trim() || '';
    if (!Number.isFinite(timestamp) || Math.abs(now - timestamp) > TELEMETRY_MAX_CLOCK_SKEW_MS) {
      throw unauthorized('telemetry request timestamp is invalid');
    }
    if (!NONCE_PATTERN.test(nonce)) throw invalidRequest('telemetry nonce is invalid');
    const expectedSignature = signTelemetryRequest({
      token: telemetryToken,
      timestamp,
      nonce,
      body,
    });
    if (!secureTextMatches(signature, expectedSignature)) {
      throw unauthorized('telemetry request signature is invalid');
    }
    if (telemetryContainsContent(body)) {
      throw invalidRequest('telemetry content payload is forbidden');
    }
    if (!Array.isArray(body.events) || body.events.length === 0 || body.events.length > 100) {
      throw invalidRequest('telemetry events must contain between 1 and 100 items');
    }
    const retentionBeforeMs = now - this.#telemetryRetentionMs;
    const events = body.events.map((event) => telemetryEvent(
      event,
      { deploymentId },
      now,
      retentionBeforeMs,
    ));
    const receipt = await this.#store.ingestTelemetryBatch({
      deploymentId,
      licenseId,
      nonce,
      nonceExpiresAtMs: now + TELEMETRY_MAX_CLOCK_SKEW_MS * 2,
      retentionBeforeMs,
      receivedAtMs: now,
      events,
    });
    if (!receipt) throw conflict('telemetry request replay detected');
    return receipt;
  }

  async deploymentHealth(deploymentId: string, hours: number): Promise<DeploymentTelemetrySummary> {
    if (!DEPLOYMENT_ID_PATTERN.test(deploymentId)) throw invalidRequest('deploymentId is invalid');
    if (!Number.isInteger(hours) || hours < 1 || hours > 24 * 365) {
      throw invalidRequest('hours must be an integer between 1 and 8760');
    }
    const deployment = await this.#store.getDeployment(deploymentId);
    if (!deployment) throw notFound('deployment not found');
    return this.#store.getDeploymentTelemetrySummary({
      deploymentId,
      sinceMs: this.#now() - hours * 60 * 60 * 1000,
    });
  }
}

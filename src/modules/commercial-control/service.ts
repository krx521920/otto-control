import { randomUUID } from 'node:crypto';

import {
  isOttoLicenseCapability,
  type IssueLicenseInput,
  type OttoLeaseRequest,
  type OttoLicensePayload,
  type OttoSignedLeaseEnvelope,
  type OttoSignedLicenseEnvelope,
} from '../../contracts/license.js';
import type { PayloadSigner } from '../../crypto/signed-envelope.js';
import { conflict, invalidRequest, notFound, unauthorized } from '../../errors.js';
import type {
  ControlStore,
  CustomerRecord,
  DeploymentRecord,
  LicenseRecord,
} from '../../storage/control-store.js';
import type { ControlTokenIssuer } from './token-issuer.js';

const ID_PART_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{1,127}$/u;
const DEPLOYMENT_ID_PATTERN = /^dep_[a-zA-Z0-9]{16,64}$/u;
const MACHINE_FINGERPRINT_PATTERN = /^[a-f0-9]{64}$/u;
const NONCE_PATTERN = /^[a-zA-Z0-9._:-]{16,128}$/u;
const MAX_LICENSE_DURATION_MS = 5 * 366 * 24 * 60 * 60 * 1000;

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

function licensePayload(
  license: LicenseRecord,
  tokens: ControlTokenIssuer,
): OttoLicensePayload {
  const payload: OttoLicensePayload = {
    id: license.id,
    deploymentId: license.deploymentId,
    organizationId: license.organizationId,
    machineFingerprint: license.machineFingerprint,
    customerName: license.customerName,
    plan: license.plan,
    issuedAtMs: license.issuedAtMs,
    expiresAtMs: license.expiresAtMs,
    seatLimit: license.seatLimit,
    modules: license.modules,
    offline: license.offline,
    telemetryAllowed: license.telemetryAllowed,
  };
  if (!license.offline) {
    payload.leaseEndpoint = license.leaseEndpoint!;
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
  tokenIssuer: ControlTokenIssuer;
  publicBaseUrl: string;
  leaseDurationMs?: number;
  now?: () => number;
}

export class CommercialControlService {
  readonly #store: ControlStore;
  readonly #signer: PayloadSigner;
  readonly #tokens: ControlTokenIssuer;
  readonly #publicBaseUrl: string;
  readonly #leaseDurationMs: number;
  readonly #now: () => number;

  constructor(options: CommercialControlServiceOptions) {
    this.#store = options.store;
    this.#signer = options.signer;
    this.#tokens = options.tokenIssuer;
    this.#publicBaseUrl = options.publicBaseUrl.replace(/\/$/u, '');
    this.#leaseDurationMs = options.leaseDurationMs ?? 10 * 60 * 1000;
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

  signingKey(): { keyId: string; algorithm: 'ed25519'; publicKeyPem: string } {
    return {
      keyId: this.#signer.keyId,
      algorithm: 'ed25519',
      publicKeyPem: this.#signer.publicKeyPem,
    };
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
    const id = prefixedId('lic');
    const leaseEndpoint = offline
      ? null
      : `${this.#publicBaseUrl}/v1/licenses/${encodeURIComponent(id)}/lease`;
    const unsigned: LicenseRecord = {
      id,
      deploymentId,
      customerName: deployment.customerName,
      organizationId: deployment.organizationId,
      machineFingerprint: deployment.machineFingerprint,
      plan,
      issuedAtMs,
      expiresAtMs,
      seatLimit,
      modules,
      offline,
      telemetryAllowed,
      leaseEndpoint,
      tokenVersion: 1,
      signature: '',
      signingKeyId: this.#signer.keyId,
      revokedAtMs: null,
      createdAt: new Date(issuedAtMs),
      updatedAt: new Date(issuedAtMs),
    };
    const payload = licensePayload(unsigned, this.#tokens);
    const signature = await this.#signer.sign(payload);
    const stored = await this.#store.createLicense({
      ...unsigned,
      signature,
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
        modules,
        offline,
        expiresAtMs,
      },
    });
    return { license: licensePayload(stored, this.#tokens), signature: stored.signature };
  }

  async getLicenseEnvelope(id: string): Promise<OttoSignedLicenseEnvelope> {
    const license = await this.#store.getLicense(id);
    if (!license) throw notFound('license not found');
    return { license: licensePayload(license, this.#tokens), signature: license.signature };
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
    if (license.expiresAtMs <= issuedAtMs) throw unauthorized('License has expired');
    const nonceAccepted = await this.#store.consumeLeaseNonce({
      deploymentId: license.deploymentId,
      nonce: body.nonce,
      expiresAtMs: issuedAtMs + 20 * 60 * 1000,
    });
    if (!nonceAccepted) throw conflict('lease request replay detected');
    const lease = {
      id: prefixedId('lease'),
      licenseId: license.id,
      deploymentId: license.deploymentId,
      machineFingerprint: license.machineFingerprint,
      issuedAtMs,
      expiresAtMs: Math.min(issuedAtMs + this.#leaseDurationMs, license.expiresAtMs),
    };
    const signature = await this.#signer.sign(lease);
    return { lease, signature };
  }
}

import type { OttoLicenseCapability } from '../contracts/license.js';
import type {
  DeploymentTelemetrySummary,
  OttoTelemetryEvent,
  OttoTelemetryReceipt,
} from '../contracts/telemetry.js';
import type { UpdateChannel, UpdateReleaseState } from '../contracts/update-policy.js';

export type RecordStatus = 'active' | 'suspended';

export interface CustomerRecord {
  id: string;
  name: string;
  status: RecordStatus;
  createdAt: Date;
  updatedAt: Date;
}

export interface DeploymentRecord {
  id: string;
  customerId: string;
  customerName: string;
  organizationId: string;
  machineFingerprint: string;
  name: string;
  status: RecordStatus;
  createdAt: Date;
  updatedAt: Date;
}

export interface LicenseRecord {
  id: string;
  deploymentId: string;
  customerName: string;
  organizationId: string;
  machineFingerprint: string;
  plan: string;
  issuedAtMs: number;
  expiresAtMs: number;
  seatLimit: number;
  modules: OttoLicenseCapability[];
  offline: boolean;
  telemetryAllowed: boolean;
  leaseEndpoint: string | null;
  tokenVersion: number;
  signature: string;
  signingKeyId: string;
  revokedAtMs: number | null;
  createdAt: Date;
  updatedAt: Date;
}

export type CreateLicenseRecordInput = Omit<LicenseRecord, 'createdAt' | 'updatedAt'>;

export interface AuditEventInput {
  actorId: string;
  action: string;
  targetType: string;
  targetId: string;
  detail: Record<string, unknown>;
}

export interface UpdateDistributionRecord {
  id: string;
  name: string;
  status: RecordStatus;
  createdAt: Date;
  updatedAt: Date;
}

export interface UpdateReleaseRecord {
  id: string;
  distributionId: string;
  version: string;
  sourceCommit: string;
  channel: UpdateChannel;
  rolloutPercent: number;
  state: UpdateReleaseState;
  notes: string;
  fullManifestUrl: string | null;
  fullManifestSha256: string | null;
  incrementalManifestUrl: string | null;
  incrementalManifestSha256: string | null;
  previousReleaseId: string | null;
  publishedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export type CreateUpdateReleaseRecordInput = Omit<
  UpdateReleaseRecord,
  'state' | 'previousReleaseId' | 'publishedAt' | 'createdAt' | 'updatedAt'
>;

export interface UpdateReleaseTransition {
  release: UpdateReleaseRecord;
  fallback: UpdateReleaseRecord | null;
}

export interface DeploymentUpdateAssignmentRecord {
  deploymentId: string;
  distributionId: string;
  updatedAt: Date;
}

export interface ControlStore {
  ping(): Promise<void>;
  close(): Promise<void>;
  createCustomer(input: { id: string; name: string }): Promise<CustomerRecord>;
  createDeployment(input: {
    id: string;
    customerId: string;
    organizationId: string;
    machineFingerprint: string;
    name: string;
  }): Promise<DeploymentRecord>;
  getDeployment(id: string): Promise<DeploymentRecord | null>;
  createLicense(input: CreateLicenseRecordInput): Promise<LicenseRecord>;
  getLicense(id: string): Promise<LicenseRecord | null>;
  revokeLicense(id: string, revokedAtMs: number): Promise<LicenseRecord | null>;
  consumeLeaseNonce(input: {
    deploymentId: string;
    nonce: string;
    expiresAtMs: number;
  }): Promise<boolean>;
  ingestTelemetryBatch(input: {
    deploymentId: string;
    licenseId: string;
    nonce: string;
    nonceExpiresAtMs: number;
    retentionBeforeMs: number;
    receivedAtMs: number;
    events: OttoTelemetryEvent[];
  }): Promise<OttoTelemetryReceipt | null>;
  getDeploymentTelemetrySummary(input: {
    deploymentId: string;
    sinceMs: number;
  }): Promise<DeploymentTelemetrySummary>;
  createUpdateDistribution(input: { id: string; name: string }): Promise<UpdateDistributionRecord>;
  getUpdateDistribution(id: string): Promise<UpdateDistributionRecord | null>;
  assignDeploymentUpdateDistribution(input: {
    deploymentId: string;
    distributionId: string;
    updatedAt: Date;
  }): Promise<DeploymentUpdateAssignmentRecord>;
  getDeploymentUpdateAssignment(
    deploymentId: string,
  ): Promise<DeploymentUpdateAssignmentRecord | null>;
  createUpdateRelease(input: CreateUpdateReleaseRecordInput): Promise<UpdateReleaseRecord>;
  getUpdateRelease(id: string): Promise<UpdateReleaseRecord | null>;
  listUpdateReleases(distributionId: string): Promise<UpdateReleaseRecord[]>;
  activateUpdateRelease(id: string, publishedAt: Date): Promise<UpdateReleaseTransition | null>;
  pauseUpdateRelease(id: string, updatedAt: Date): Promise<UpdateReleaseRecord | null>;
  rollbackUpdateRelease(id: string, updatedAt: Date): Promise<UpdateReleaseTransition | null>;
  getActiveUpdateReleases(distributionId: string): Promise<UpdateReleaseRecord[]>;
  consumeUpdatePolicyNonce(input: {
    deploymentId: string;
    nonce: string;
    expiresAtMs: number;
  }): Promise<boolean>;
  appendAuditEvent(input: AuditEventInput): Promise<void>;
}

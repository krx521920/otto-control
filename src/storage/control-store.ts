import type { OttoLicenseCapability } from '../contracts/license.js';
import type {
  DeploymentTelemetrySummary,
  OttoTelemetryEvent,
  OttoTelemetryReceipt,
} from '../contracts/telemetry.js';

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
  appendAuditEvent(input: AuditEventInput): Promise<void>;
}

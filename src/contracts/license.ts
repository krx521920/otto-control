export const OTTO_LICENSE_CAPABILITIES = [
  'enterprise_tree',
  'park_service',
  'feishu_auto_reply',
  'direct_messages',
  'atoa',
  'knowledge',
  'skill_market',
] as const;

export type OttoLicenseCapability = (typeof OTTO_LICENSE_CAPABILITIES)[number];

export interface OttoLicensePayload {
  id: string;
  deploymentId: string;
  organizationId: string;
  machineFingerprint: string;
  customerName: string;
  plan: string;
  issuedAtMs: number;
  expiresAtMs: number;
  seatLimit: number;
  modules: OttoLicenseCapability[];
  offline: boolean;
  telemetryAllowed: boolean;
  leaseEndpoint?: string;
  leaseToken?: string;
  telemetryToken?: string;
}

export interface OttoSignedLicenseEnvelope {
  license: OttoLicensePayload;
  signature: string;
}

export interface OttoLeaseRequest {
  version: 1;
  licenseId: string;
  deploymentId: string;
  organizationId: string;
  machineFingerprint: string;
  nonce: string;
}

export interface OttoLeasePayload {
  id: string;
  licenseId: string;
  deploymentId: string;
  machineFingerprint: string;
  issuedAtMs: number;
  expiresAtMs: number;
}

export interface OttoSignedLeaseEnvelope {
  lease: OttoLeasePayload;
  signature: string;
}

export interface IssueLicenseInput {
  deploymentId: string;
  plan: string;
  expiresAt: string;
  seatLimit: number;
  modules: OttoLicenseCapability[];
  offline?: boolean;
  telemetryAllowed?: boolean;
}

export function isOttoLicenseCapability(value: string): value is OttoLicenseCapability {
  return (OTTO_LICENSE_CAPABILITIES as readonly string[]).includes(value);
}

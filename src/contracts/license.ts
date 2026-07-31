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
export type OttoSeatEnforcement = 'monitor' | 'enforce';
export type OttoSeatStatus =
  | 'unreported'
  | 'within_limit'
  | 'over_limit_monitor'
  | 'overage_grace'
  | 'blocked';

export interface OttoLicensePayload {
  id: string;
  revision: number;
  deploymentId: string;
  organizationId: string;
  machineFingerprint: string;
  customerName: string;
  plan: string;
  issuedAtMs: number;
  expiresAtMs: number;
  seatLimit: number;
  gracePeriodMs: number;
  seatEnforcement: OttoSeatEnforcement;
  modules: OttoLicenseCapability[];
  offline: boolean;
  telemetryAllowed: boolean;
  leaseEndpoint?: string;
  billingEndpoint?: string;
  leaseToken?: string;
  telemetryToken?: string;
}

export interface OttoSignedLicenseEnvelope {
  license: OttoLicensePayload;
  signingKeyId: string;
  signature: string;
}

export interface OttoLeaseRequest {
  version: 1;
  licenseId: string;
  deploymentId: string;
  organizationId: string;
  machineFingerprint: string;
  nonce: string;
  activeSeatCount?: number;
}

export interface OttoLeasePayload {
  id: string;
  licenseId: string;
  deploymentId: string;
  machineFingerprint: string;
  licenseRevision: number;
  issuedAtMs: number;
  expiresAtMs: number;
  seatLimit: number;
  activeSeatCount: number | null;
  seatStatus: OttoSeatStatus;
  graceReasons: Array<'expiration' | 'seat_overage'>;
  graceExpiresAtMs: number | null;
}

export interface OttoSignedLeaseEnvelope {
  lease: OttoLeasePayload;
  signingKeyId: string;
  signature: string;
  licenseEnvelope: OttoSignedLicenseEnvelope;
}

export interface IssueLicenseInput {
  deploymentId: string;
  plan: string;
  expiresAt: string;
  seatLimit: number;
  gracePeriodDays?: number;
  seatEnforcement?: OttoSeatEnforcement;
  modules: OttoLicenseCapability[];
  offline?: boolean;
  telemetryAllowed?: boolean;
}

export function isOttoLicenseCapability(value: string): value is OttoLicenseCapability {
  return (OTTO_LICENSE_CAPABILITIES as readonly string[]).includes(value);
}

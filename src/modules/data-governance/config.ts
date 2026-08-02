import type { ControlEnvironment } from '../../config.js';
import type { DataGovernanceConfig } from '../../contracts/data-governance.js';

const REGION_PATTERN = /^[A-Z]{2}-[A-Z0-9]{2,24}$/u;
const VERSION_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/u;

function booleanValue(value: string | undefined, fallback: boolean, name: string): boolean {
  if (value === undefined || value.trim() === '') return fallback;
  if (value === 'true') return true;
  if (value === 'false') return false;
  throw new Error(`${name} must be true or false`);
}

function boundedDays(
  value: string | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
  name: string,
): number {
  const normalized = value?.trim() || String(fallback);
  if (!/^\d+$/u.test(normalized)) throw new Error(`${name} must be an integer`);
  const days = Number(normalized);
  if (days < minimum || days > maximum) {
    throw new Error(`${name} must be between ${minimum} and ${maximum}`);
  }
  return days;
}

function isoTimestamp(value: string | undefined, fallback: string, name: string): string {
  const normalized = value?.trim() || fallback;
  const timestamp = Date.parse(normalized);
  if (!Number.isFinite(timestamp)) throw new Error(`${name} must be an ISO timestamp`);
  return new Date(timestamp).toISOString();
}

function region(value: string | undefined, fallback: string, name: string): string {
  const normalized = (value?.trim() || fallback).toUpperCase();
  if (!REGION_PATTERN.test(normalized)) {
    throw new Error(`${name} must look like CN-BJ or CN-SH`);
  }
  return normalized;
}

export function loadDataGovernanceConfig(
  env: NodeJS.ProcessEnv,
  environment: ControlEnvironment,
): DataGovernanceConfig {
  const dataRegion = region(env.CONTROL_DATA_REGION, 'CN-BJ', 'CONTROL_DATA_REGION');
  const allowedRegions = [...new Set((env.CONTROL_ALLOWED_DATA_REGIONS || dataRegion)
    .split(',')
    .map((item) => region(item, dataRegion, 'CONTROL_ALLOWED_DATA_REGIONS')))];
  if (!allowedRegions.includes(dataRegion)) {
    throw new Error('CONTROL_ALLOWED_DATA_REGIONS must include CONTROL_DATA_REGION');
  }
  const crossBorderEnabled = booleanValue(
    env.CONTROL_CROSS_BORDER_ENABLED,
    false,
    'CONTROL_CROSS_BORDER_ENABLED',
  );
  const crossBorderAssessmentId = env.CONTROL_CROSS_BORDER_ASSESSMENT_ID?.trim() || null;
  if (crossBorderEnabled && (!crossBorderAssessmentId || allowedRegions.length < 2)) {
    throw new Error(
      'cross-border processing requires CONTROL_CROSS_BORDER_ASSESSMENT_ID and multiple allowed regions',
    );
  }
  const policyVersion = env.CONTROL_PRIVACY_POLICY_VERSION?.trim() || '2026-08-01';
  if (!VERSION_PATTERN.test(policyVersion)) {
    throw new Error('CONTROL_PRIVACY_POLICY_VERSION is invalid');
  }
  const controllerName = env.CONTROL_PRIVACY_CONTROLLER?.trim() || 'Otto Control operator';
  const privacyContact = env.CONTROL_PRIVACY_CONTACT?.trim() || 'privacy@example.invalid';
  if (environment === 'production') {
    if (!env.CONTROL_DATA_REGION?.trim()) {
      throw new Error('CONTROL_DATA_REGION is required in production');
    }
    if (!env.CONTROL_PRIVACY_CONTROLLER?.trim() || !env.CONTROL_PRIVACY_CONTACT?.trim()) {
      throw new Error(
        'CONTROL_PRIVACY_CONTROLLER and CONTROL_PRIVACY_CONTACT are required in production',
      );
    }
  }
  return {
    dataRegion,
    allowedRegions,
    crossBorderEnabled,
    crossBorderAssessmentId,
    policyVersion,
    policyEffectiveAt: isoTimestamp(
      env.CONTROL_PRIVACY_POLICY_EFFECTIVE_AT,
      '2026-08-01T00:00:00.000Z',
      'CONTROL_PRIVACY_POLICY_EFFECTIVE_AT',
    ),
    controllerName,
    privacyContact,
    customerErasureGraceDays: boundedDays(
      env.CONTROL_CUSTOMER_ERASURE_GRACE_DAYS,
      14,
      0,
      90,
      'CONTROL_CUSTOMER_ERASURE_GRACE_DAYS',
    ),
    billingRetentionDays: boundedDays(
      env.CONTROL_BILLING_RETENTION_DAYS,
      1_095,
      365,
      3_650,
      'CONTROL_BILLING_RETENTION_DAYS',
    ),
    auditRetentionDays: boundedDays(
      env.CONTROL_GOVERNANCE_AUDIT_RETENTION_DAYS,
      2_555,
      365,
      3_650,
      'CONTROL_GOVERNANCE_AUDIT_RETENTION_DAYS',
    ),
    exportRecordRetentionDays: boundedDays(
      env.CONTROL_DATA_EXPORT_RECORD_RETENTION_DAYS,
      30,
      1,
      365,
      'CONTROL_DATA_EXPORT_RECORD_RETENTION_DAYS',
    ),
    retentionPollIntervalMs: boundedDays(
      env.CONTROL_DATA_RETENTION_POLL_INTERVAL_HOURS,
      24,
      1,
      168,
      'CONTROL_DATA_RETENTION_POLL_INTERVAL_HOURS',
    ) * 60 * 60 * 1_000,
  };
}

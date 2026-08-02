import { describe, expect, it } from 'vitest';

import type { ControlConfig } from '../src/config.js';
import { createCommercialControlRuntime } from '../src/runtime.js';

const baseConfig: Readonly<ControlConfig> = {
  environment: 'development',
  host: '127.0.0.1',
  port: 7788,
  logLevel: 'silent',
  trustProxy: false,
  publicBaseUrl: null,
  version: '0.2.0-test',
  databaseUrl: null,
  databaseSsl: false,
  adminToken: null,
  tokenSecret: null,
  signerPrivateKeyFile: null,
  signerKeyringFile: null,
  leaseDurationMs: 600_000,
  telemetryRetentionDays: 90,
  updatePolicyDurationMs: 300_000,
  backupReportDirectory: null,
  backupStatusMaximumAgeHours: 48,
  alertChannelsFile: null,
  alertWebhookUrl: null,
  alertWebhookSecretFile: null,
  alertPollIntervalMs: 60_000,
  alertWebhookTimeoutMs: 10_000,
  alertWebhookMaxAttempts: 8,
  alertRetentionDays: 365,
  auditAnchorUrl: null,
  auditAnchorTokenFile: null,
  auditAnchorIntervalMs: 900_000,
  auditAnchorPollIntervalMs: 60_000,
  auditAnchorTimeoutMs: 10_000,
  auditAnchorMaxAttempts: 8,
  auditWitnessSourcesFile: null,
  auditWitnessWormStorage: null,
  auditWitnessWormRequired: false,
  metricsToken: 'test-metrics-token-that-is-at-least-32-bytes',
  slowRequestThresholdMs: 1_000,
  capacitySampleIntervalMs: 60_000,
  sloAvailabilityTarget: 0.999,
  sloLatencyTargetMs: 500,
  artifactStorage: null,
  artifactStorageRequired: false,
  artifactAttestationKeysFile: null,
};

describe('commercial control runtime configuration', () => {
  it('allows a health-only development process', async () => {
    await expect(createCommercialControlRuntime(baseConfig)).resolves.toBeNull();
  });

  it('fails closed when production commercial settings are missing', async () => {
    await expect(createCommercialControlRuntime({
      ...baseConfig,
      environment: 'production',
    })).rejects.toThrow('commercial control configuration is incomplete');
  });

  it('rejects partially configured development runtimes', async () => {
    await expect(createCommercialControlRuntime({
      ...baseConfig,
      publicBaseUrl: 'https://control.otto.test',
    })).rejects.toThrow('CONTROL_DATABASE_URL');
  });
});

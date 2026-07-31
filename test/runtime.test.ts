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

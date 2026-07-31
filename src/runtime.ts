import { readFile } from 'node:fs/promises';

import type { ControlConfig } from './config.js';
import { LocalEd25519Signer } from './crypto/signed-envelope.js';
import { CommercialControlService } from './modules/commercial-control/service.js';
import { ControlTokenIssuer } from './modules/commercial-control/token-issuer.js';
import { PostgresControlStore } from './storage/postgres-store.js';

export interface CommercialControlRuntime {
  adminToken: string;
  service: CommercialControlService;
}

function missingConfiguration(config: Readonly<ControlConfig>): string[] {
  const missing: string[] = [];
  if (!config.databaseUrl) missing.push('CONTROL_DATABASE_URL');
  if (!config.publicBaseUrl) missing.push('CONTROL_PUBLIC_BASE_URL');
  if (!config.adminToken) missing.push('CONTROL_ADMIN_TOKEN');
  if (!config.tokenSecret) missing.push('CONTROL_TOKEN_SECRET');
  if (!config.signerPrivateKeyFile) missing.push('CONTROL_SIGNER_PRIVATE_KEY_FILE');
  return missing;
}

export async function createCommercialControlRuntime(
  config: Readonly<ControlConfig>,
): Promise<CommercialControlRuntime | null> {
  const missing = missingConfiguration(config);
  const configured = missing.length < 5;
  if (!configured && config.environment !== 'production') return null;
  if (missing.length > 0) {
    throw new Error(`commercial control configuration is incomplete: ${missing.join(', ')}`);
  }

  const store = await PostgresControlStore.connect({
    connectionString: config.databaseUrl!,
    ssl: config.databaseSsl,
  });
  try {
    // The path should be a read-only Docker/Kubernetes secret mount in production.
    const privateKey = await readFile(config.signerPrivateKeyFile!, 'utf8');
    const signer = new LocalEd25519Signer(privateKey);
    return {
      adminToken: config.adminToken!,
      service: new CommercialControlService({
        store,
        signer,
        tokenIssuer: new ControlTokenIssuer(config.tokenSecret!),
        publicBaseUrl: config.publicBaseUrl!,
        leaseDurationMs: config.leaseDurationMs,
        telemetryRetentionDays: config.telemetryRetentionDays,
      }),
    };
  } catch (error) {
    await store.close();
    throw error;
  }
}

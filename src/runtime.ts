import type { ControlConfig } from './config.js';
import { ManagedSigningKeyring } from './crypto/signing-keyring.js';
import { loadSigningProviders } from './crypto/signing-provider-config.js';
import { CommercialControlService } from './modules/commercial-control/service.js';
import { ControlTokenIssuer } from './modules/commercial-control/token-issuer.js';
import { UpdatePolicyService } from './modules/update-policy/service.js';
import { PostgresControlStore } from './storage/postgres-store.js';

export interface CommercialControlRuntime {
  adminToken: string;
  service: CommercialControlService;
  updatePolicy: UpdatePolicyService;
}

function missingConfiguration(config: Readonly<ControlConfig>): string[] {
  const missing: string[] = [];
  if (!config.databaseUrl) missing.push('CONTROL_DATABASE_URL');
  if (!config.publicBaseUrl) missing.push('CONTROL_PUBLIC_BASE_URL');
  if (!config.adminToken) missing.push('CONTROL_ADMIN_TOKEN');
  if (!config.tokenSecret) missing.push('CONTROL_TOKEN_SECRET');
  if (!config.signerPrivateKeyFile && !config.signerKeyringFile) {
    missing.push('CONTROL_SIGNER_PRIVATE_KEY_FILE or CONTROL_SIGNER_KEYRING_FILE');
  }
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
    // Local files should be read-only secret mounts. KMS/HSM adapters implement
    // PayloadSigner and can be registered without changing either service.
    const providerConfig = await loadSigningProviders(config);
    const signer = await ManagedSigningKeyring.create({
      store,
      ...providerConfig,
    });
    const tokenIssuer = new ControlTokenIssuer(config.tokenSecret!);
    return {
      adminToken: config.adminToken!,
      service: new CommercialControlService({
        store,
        signer,
        keyring: signer,
        tokenIssuer,
        publicBaseUrl: config.publicBaseUrl!,
        leaseDurationMs: config.leaseDurationMs,
        telemetryRetentionDays: config.telemetryRetentionDays,
      }),
      updatePolicy: new UpdatePolicyService({
        store,
        signer,
        tokenIssuer,
        policyDurationMs: config.updatePolicyDurationMs,
      }),
    };
  } catch (error) {
    await store.close();
    throw error;
  }
}

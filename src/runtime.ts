import type { ControlConfig } from './config.js';
import { ManagedSigningKeyring } from './crypto/signing-keyring.js';
import { loadSigningProviders } from './crypto/signing-provider-config.js';
import { CommercialControlService } from './modules/commercial-control/service.js';
import { ControlTokenIssuer } from './modules/commercial-control/token-issuer.js';
import { AdminIdentityService } from './modules/admin-identity/service.js';
import { UpdatePolicyService } from './modules/update-policy/service.js';
import { BillingService } from './modules/billing/service.js';
import { ReleaseArtifactService } from './modules/release-artifacts/service.js';
import { S3ArtifactObjectStore } from './modules/release-artifacts/s3-object-store.js';
import { loadArtifactAttestationVerifier } from './modules/release-artifacts/attestation.js';
import { BackupStatusService } from './modules/backup-status/service.js';
import { AlertDeliveryService } from './modules/alert-delivery/service.js';
import { AuditService } from './modules/audit/service.js';
import { AuditAnchorService } from './modules/audit-anchor/service.js';
import { AuditWitnessService } from './modules/audit-witness/service.js';
import { loadAuditWitnessSources } from './modules/audit-witness/source-config.js';
import { S3AuditWitnessWormObjectStore } from './modules/audit-witness/s3-worm-object-store.js';
import { DataGovernanceService } from './modules/data-governance/service.js';
import { loadDataGovernanceConfig } from './modules/data-governance/config.js';
import { CommercialDeliveryService } from './modules/commercial-delivery/service.js';
import { EdgeGatewayControlService } from './modules/edge-gateway/service.js';
import { PostgresControlStore } from './storage/postgres-store.js';
import type { DatabaseObservabilitySource } from './observability/contracts.js';

export interface CommercialControlRuntime {
  adminToken: string;
  service: CommercialControlService;
  updatePolicy: UpdatePolicyService;
  identity: AdminIdentityService;
  billing?: BillingService;
  releaseArtifacts: ReleaseArtifactService;
  backupStatus: BackupStatusService;
  alerts: AlertDeliveryService;
  audit?: AuditService;
  auditAnchors?: AuditAnchorService;
  auditWitness?: AuditWitnessService;
  dataGovernance?: DataGovernanceService;
  commercialDelivery?: CommercialDeliveryService;
  edgeGateway?: EdgeGatewayControlService;
  observability?: DatabaseObservabilitySource;
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
    onPoolError: (error) => {
      process.stderr.write(
        `${JSON.stringify({
          level: 'error',
          event: 'postgres_idle_client_error',
          message: error.message,
        })}\n`,
      );
    },
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
    const identity = new AdminIdentityService({
      store,
      controlSecret: config.tokenSecret!,
    });
    const objectStore = config.artifactStorage
      ? new S3ArtifactObjectStore(config.artifactStorage)
      : null;
    const attestationVerifier = await loadArtifactAttestationVerifier(
      config.artifactAttestationKeysFile,
    );
    const auditWitnessWormStore = config.auditWitnessWormStorage
      ? new S3AuditWitnessWormObjectStore(config.auditWitnessWormStorage)
      : null;
    const releaseArtifacts = new ReleaseArtifactService({
      store,
      signer,
      objectStore,
      attestationVerifier,
      publicBaseUrl: config.publicBaseUrl,
      uploadTtlSeconds: config.artifactStorage?.uploadTtlSeconds,
      downloadTtlSeconds: config.artifactStorage?.downloadTtlSeconds,
      storageRequired: config.artifactStorageRequired,
      objectLockRequired: config.artifactStorage?.objectLockRequired,
    });
    const backupStatus = new BackupStatusService({
      reportDirectory: config.backupReportDirectory,
      maximumAgeHours: config.backupStatusMaximumAgeHours,
    });
    const audit = new AuditService({
      store,
      signer,
      issuer: config.publicBaseUrl!,
    });
    const dataGovernance = new DataGovernanceService({
      store,
      signer,
      audit,
      config: config.dataGovernance ?? loadDataGovernanceConfig({}, config.environment),
      telemetryRetentionDays: config.telemetryRetentionDays,
    });
    await dataGovernance.initialize();
    const billing = new BillingService({
      store,
      tokenIssuer,
      allowLegacyUsageReports: config.legacyUsageReportsAllowed
        ?? config.environment !== 'production',
    });
    const edgeGateway = new EdgeGatewayControlService({
      store,
      signer,
      tokenIssuer,
    });
    const commercialDelivery = new CommercialDeliveryService({
      store,
      billing,
      governance: dataGovernance,
      signer,
      config: config.dataGovernance ?? loadDataGovernanceConfig({}, config.environment),
    });
    const auditWitness = new AuditWitnessService({
      store,
      sources: loadAuditWitnessSources(config.auditWitnessSourcesFile),
      wormStore: auditWitnessWormStore,
      wormRequired: config.auditWitnessWormRequired,
      retentionDays: config.auditWitnessWormStorage?.retentionDays,
      pollIntervalMs: config.auditWitnessWormStorage?.pollIntervalMs,
      maxAttempts: config.auditWitnessWormStorage?.maxAttempts,
    });
    await auditWitness.assertWormReady();
    const auditAnchors = new AuditAnchorService({
      store,
      audit,
      url: config.auditAnchorUrl,
      tokenFile: config.auditAnchorTokenFile,
      anchorIntervalMs: config.auditAnchorIntervalMs,
      pollIntervalMs: config.auditAnchorPollIntervalMs,
      timeoutMs: config.auditAnchorTimeoutMs,
      maxAttempts: config.auditAnchorMaxAttempts,
    });
    const alerts = new AlertDeliveryService({
      store,
      backupStatus,
      audit,
      auditAnchors,
      auditWitness,
      channelsFile: config.alertChannelsFile,
      webhookUrl: config.alertWebhookUrl,
      webhookSecretFile: config.alertWebhookSecretFile,
      pollIntervalMs: config.alertPollIntervalMs,
      assuranceIntervalMs: config.recoveryAssuranceIntervalMs,
      timeoutMs: config.alertWebhookTimeoutMs,
      maxAttempts: config.alertWebhookMaxAttempts,
      retentionDays: config.alertRetentionDays,
    });
    return {
      adminToken: config.adminToken!,
      identity,
      billing,
      edgeGateway,
      commercialDelivery,
      releaseArtifacts,
      backupStatus,
      alerts,
      audit,
      auditAnchors,
      auditWitness,
      dataGovernance,
      observability: store,
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
        releaseArtifacts,
        policyDurationMs: config.updatePolicyDurationMs,
      }),
    };
  } catch (error) {
    await store.close();
    throw error;
  }
}

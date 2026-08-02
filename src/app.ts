import { randomUUID } from 'node:crypto';

import rateLimit from '@fastify/rate-limit';
import Fastify, { type FastifyError, type FastifyInstance, type FastifyServerOptions } from 'fastify';

import { loadControlConfig, type ControlConfig } from './config.js';
import { ControlPlaneError } from './errors.js';
import type { CommercialControlRuntime } from './runtime.js';
import { registerAdminIdentityRoutes } from './routes/admin-identity.js';
import { registerCommercialControlRoutes } from './routes/commercial-control.js';
import { registerPlatformRoutes } from './routes/platform.js';
import { registerUpdatePolicyRoutes } from './routes/update-policy.js';
import { registerBillingRoutes } from './routes/billing.js';
import { registerReleaseArtifactRoutes } from './routes/release-artifacts.js';
import { registerBackupStatusRoutes } from './routes/backup-status.js';
import { registerAlertDeliveryRoutes } from './routes/alert-delivery.js';
import { registerOperatorConsoleRoutes } from './routes/operator-console.js';
import { registerAuditRoutes } from './routes/audit.js';
import { registerAuditAnchorRoutes } from './routes/audit-anchor.js';
import { registerAuditWitnessRoutes } from './routes/audit-witness.js';
import { ControlMetrics } from './observability/metrics.js';
import { traceLogContext } from './observability/tracing.js';

export interface BuildControlAppOptions {
  config?: Readonly<ControlConfig>;
  logger?: FastifyServerOptions['logger'];
  commercialControl?: CommercialControlRuntime | null;
}

function fastifyError(error: unknown): FastifyError | null {
  return error instanceof Error ? error as FastifyError : null;
}

function statusCodeFor(error: unknown): number {
  if (error instanceof ControlPlaneError) return error.statusCode;
  const candidate = fastifyError(error);
  if (candidate?.validation) return 400;
  const statusCode = candidate?.statusCode ?? 500;
  return statusCode >= 400 && statusCode <= 599 ? statusCode : 500;
}

export async function buildControlApp(
  options: BuildControlAppOptions = {},
): Promise<FastifyInstance> {
  const config = options.config ?? loadControlConfig();
  const commercialControl = options.commercialControl ?? null;
  const logger = options.logger ?? {
    level: config.logLevel,
    mixin: traceLogContext,
    redact: {
      paths: [
        'req.headers.authorization',
        'req.headers.cookie',
        'req.headers.x-api-key',
        'req.body.password',
        'req.body.token',
        'req.body.totpCode',
        'req.body.recoveryCode',
        'req.body.enrollmentToken',
        'req.body.leaseToken',
        'req.body.telemetryToken',
      ],
      censor: '[REDACTED]',
    },
  };
  const app = Fastify({
    logger,
    bodyLimit: 1024 * 1024,
    connectionTimeout: 10_000,
    requestTimeout: 30_000,
    keepAliveTimeout: 72_000,
    routerOptions: {
      maxParamLength: 256,
    },
    trustProxy: config.trustProxy,
    genReqId: () => randomUUID(),
  });

  await app.register(rateLimit, {
    global: false,
    max: 300,
    timeWindow: '1 minute',
    hook: 'onRequest',
    skipOnError: false,
  });

  const metrics = new ControlMetrics(config, commercialControl?.observability);
  await metrics.register(app);

  app.addHook('onRequest', async (request, reply) => {
    reply
      .header('cache-control', 'no-store')
      .header('content-security-policy', "default-src 'none'; frame-ancestors 'none'")
      .header('permissions-policy', 'camera=(), microphone=(), geolocation=()')
      .header('referrer-policy', 'no-referrer')
      .header('strict-transport-security', 'max-age=31536000; includeSubDomains')
      .header('x-content-type-options', 'nosniff')
      .header('x-frame-options', 'DENY')
      .header('x-request-id', request.id);
  });

  app.setNotFoundHandler(async (request, reply) => {
    await reply.code(404).send({
      error: {
        code: 'NOT_FOUND',
        message: 'Route not found',
        requestId: request.id,
      },
    });
  });

  app.setErrorHandler(async (error, request, reply) => {
    const statusCode = statusCodeFor(error);
    const candidate = fastifyError(error);
    if (statusCode >= 500) request.log.error({ err: error }, 'request failed');
    await reply.code(statusCode).send({
      error: {
        code: error instanceof ControlPlaneError
          ? error.code
          : statusCode === 400 ? 'INVALID_REQUEST' : 'REQUEST_FAILED',
        message: statusCode >= 500
          ? 'Internal server error'
          : candidate?.message || 'Invalid request',
        requestId: request.id,
      },
    });
  });

  const capabilities = ['health', 'prometheus_metrics', 'service_level_objectives'];
  if (commercialControl) {
    capabilities.push(
      'customer_deployment',
      'license_authority',
      'signing_key_rotation',
      'lease_revocation',
      'telemetry_health',
      'update_policy',
      'signed_release_artifacts',
      'backup_inventory',
      'outbound_alert_delivery',
      'operator_console',
    );
    if (config.artifactStorage) {
      capabilities.push(
        'managed_release_artifact_storage',
        'release_artifact_code_signing_attestation',
      );
    }
    capabilities.push('admin_identity', 'admin_rbac', 'admin_mfa', 'dual_control_approval');
    await registerAdminIdentityRoutes(app, {
      adminToken: commercialControl.adminToken,
      identity: commercialControl.identity,
    });
    await registerCommercialControlRoutes(app, commercialControl);
    await registerUpdatePolicyRoutes(app, {
      service: commercialControl.updatePolicy,
      identity: commercialControl.identity,
    });
    await registerReleaseArtifactRoutes(app, {
      service: commercialControl.releaseArtifacts,
      identity: commercialControl.identity,
    });
    await registerBackupStatusRoutes(app, {
      service: commercialControl.backupStatus,
      identity: commercialControl.identity,
    });
    await registerAlertDeliveryRoutes(app, {
      service: commercialControl.alerts,
      identity: commercialControl.identity,
    });
    if (commercialControl.audit) {
      capabilities.push('tamper_evident_audit');
      await registerAuditRoutes(app, {
        service: commercialControl.audit,
        identity: commercialControl.identity,
      });
    }
    if (commercialControl.auditAnchors) {
      capabilities.push('external_audit_anchoring');
      await registerAuditAnchorRoutes(app, {
        service: commercialControl.auditAnchors,
        identity: commercialControl.identity,
      });
    }
    if (commercialControl.auditWitness) {
      capabilities.push('external_audit_witness');
      if (commercialControl.auditWitness.wormEnabled) {
        capabilities.push('immutable_audit_witness_evidence');
      }
      await registerAuditWitnessRoutes(app, {
        service: commercialControl.auditWitness,
        identity: commercialControl.identity,
      });
    }
    await registerOperatorConsoleRoutes(app);
    if (commercialControl.billing) {
      capabilities.push('credit_billing', 'billing_statement_export');
      await registerBillingRoutes(app, {
        service: commercialControl.billing,
        identity: commercialControl.identity,
      });
    }
    app.addHook('onReady', async () => {
      commercialControl.alerts.start((error) => {
        app.log.error({ err: error }, 'alert delivery poll failed');
      });
      commercialControl.auditAnchors?.start((error) => {
        app.log.error({ err: error }, 'audit anchor poll failed');
      });
      commercialControl.auditWitness?.start((error) => {
        app.log.error({ err: error }, 'audit WORM evidence poll failed');
      });
    });
    app.addHook('onClose', async () => {
      try {
        await Promise.all([
          commercialControl.alerts.close(),
          commercialControl.auditAnchors?.close(),
          commercialControl.auditWitness?.close(),
        ]);
      } finally {
        await commercialControl.service.close();
      }
    });
  }
  await registerPlatformRoutes(app, config, {
    capabilities,
    readiness: commercialControl ? () => commercialControl.service.ready() : undefined,
  });
  return app;
}

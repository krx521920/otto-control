import type { FastifyInstance } from 'fastify';

import { buildFederationApp } from './federation-app.js';
import { loadFederationConfig } from './federation-config.js';
import { PostgresFederationStore } from './modules/federation/postgres-store.js';
import { FederationService } from './modules/federation/service.js';

let app: FastifyInstance | null = null;
let closing = false;

async function close(signal: string): Promise<void> {
  if (closing) return;
  closing = true;
  app?.log.info({ signal }, 'shutting down otto-federation');
  await app?.close();
}

try {
  const config = loadFederationConfig();
  if (!config.databaseUrl) throw new Error('FEDERATION_DATABASE_URL is required');
  const store = await PostgresFederationStore.connect({
    connectionString: config.databaseUrl,
    ssl: config.databaseSsl,
    onPoolError: (error) => process.stderr.write(`${JSON.stringify({
      level: 'error', event: 'federation_postgres_idle_client_error', message: error.message,
    })}\n`),
  });
  const service = new FederationService({
    store,
    maximumClockSkewMs: config.maximumClockSkewMs,
    maximumEnvelopeTtlMs: config.maximumEnvelopeTtlMs,
    maximumCiphertextBytes: config.maximumCiphertextBytes,
    claimTtlMs: config.claimTtlMs,
    deliveredRetentionMs: config.deliveredRetentionMs,
  });
  app = await buildFederationApp({ config, service });
  process.once('SIGINT', () => void close('SIGINT'));
  process.once('SIGTERM', () => void close('SIGTERM'));
  const address = await app.listen({ host: config.host, port: config.port });
  app.log.info({ address }, 'otto-federation started');
} catch (error) {
  if (app) app.log.fatal({ err: error }, 'otto-federation failed to start');
  else process.stderr.write(`${JSON.stringify({
    level: 'fatal', event: 'federation_start_failed',
    message: error instanceof Error ? error.message : 'unknown startup error',
  })}\n`);
  process.exitCode = 1;
  await close('startup_error');
}

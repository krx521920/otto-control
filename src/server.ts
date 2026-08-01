import type { FastifyInstance } from 'fastify';

import {
  startTracingFromEnvironment,
  type TracingRuntime,
} from './observability/tracing.js';

let tracing: TracingRuntime | null = null;
let app: FastifyInstance | null = null;
let closing = false;

async function close(signal: string): Promise<void> {
  if (closing) return;
  closing = true;
  app?.log.info({ signal }, 'shutting down otto-control');
  try {
    await app?.close();
  } finally {
    await tracing?.shutdown();
  }
}

try {
  tracing = startTracingFromEnvironment();
  const [{ buildControlApp }, { loadControlConfig }, { createCommercialControlRuntime }] =
    await Promise.all([
      import('./app.js'),
      import('./config.js'),
      import('./runtime.js'),
    ]);
  const config = loadControlConfig();
  const commercialControl = await createCommercialControlRuntime(config);
  app = await buildControlApp({ config, commercialControl });
  process.once('SIGINT', () => void close('SIGINT'));
  process.once('SIGTERM', () => void close('SIGTERM'));
  const address = await app.listen({ host: config.host, port: config.port });
  app.log.info({ address, environment: config.environment }, 'otto-control started');
} catch (error) {
  if (app) {
    app.log.fatal({ err: error }, 'otto-control failed to start');
  } else {
    process.stderr.write(`${JSON.stringify({
      level: 'fatal',
      event: 'control_start_failed',
      message: error instanceof Error ? error.message : 'unknown startup error',
    })}\n`);
  }
  process.exitCode = 1;
  await close('startup_error');
}

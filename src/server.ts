import { buildControlApp } from './app.js';
import { loadControlConfig } from './config.js';

const config = loadControlConfig();
const app = await buildControlApp({ config });
let closing = false;

async function close(signal: string): Promise<void> {
  if (closing) return;
  closing = true;
  app.log.info({ signal }, 'shutting down otto-control');
  await app.close();
}

process.once('SIGINT', () => void close('SIGINT'));
process.once('SIGTERM', () => void close('SIGTERM'));

try {
  const address = await app.listen({ host: config.host, port: config.port });
  app.log.info({ address, environment: config.environment }, 'otto-control started');
} catch (error) {
  app.log.fatal({ err: error }, 'otto-control failed to start');
  process.exitCode = 1;
  await app.close();
}

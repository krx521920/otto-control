export type ControlEnvironment = 'development' | 'test' | 'production';
export type ControlLogLevel = 'fatal' | 'error' | 'warn' | 'info' | 'debug' | 'trace' | 'silent';

export interface ControlConfig {
  environment: ControlEnvironment;
  host: string;
  port: number;
  logLevel: ControlLogLevel;
  trustProxy: boolean;
  publicBaseUrl: string | null;
  version: string;
}

const LOG_LEVELS = new Set<ControlLogLevel>([
  'fatal',
  'error',
  'warn',
  'info',
  'debug',
  'trace',
  'silent',
]);

function parseEnvironment(value: string | undefined): ControlEnvironment {
  const normalized = value?.trim() || 'development';
  if (normalized === 'development' || normalized === 'test' || normalized === 'production') {
    return normalized;
  }
  throw new Error('NODE_ENV must be development, test, or production');
}

function parsePort(value: string | undefined): number {
  const normalized = value?.trim() || '7788';
  if (!/^\d{1,5}$/u.test(normalized)) throw new Error('CONTROL_PORT must be an integer');
  const port = Number(normalized);
  if (port < 1 || port > 65_535) throw new Error('CONTROL_PORT must be between 1 and 65535');
  return port;
}

function parseBoolean(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined || value.trim() === '') return fallback;
  if (value === 'true') return true;
  if (value === 'false') return false;
  throw new Error('CONTROL_TRUST_PROXY must be true or false');
}

function parseLogLevel(value: string | undefined): ControlLogLevel {
  const normalized = (value?.trim() || 'info') as ControlLogLevel;
  if (!LOG_LEVELS.has(normalized)) throw new Error('CONTROL_LOG_LEVEL is invalid');
  return normalized;
}

function parsePublicBaseUrl(value: string | undefined, environment: ControlEnvironment): string | null {
  const normalized = value?.trim();
  if (!normalized) return null;
  let url: URL;
  try {
    url = new URL(normalized);
  } catch {
    throw new Error('CONTROL_PUBLIC_BASE_URL must be an absolute URL');
  }
  if (environment === 'production' && url.protocol !== 'https:') {
    throw new Error('CONTROL_PUBLIC_BASE_URL must use HTTPS in production');
  }
  return url.toString().replace(/\/$/u, '');
}

export function loadControlConfig(
  env: NodeJS.ProcessEnv = process.env,
): Readonly<ControlConfig> {
  const environment = parseEnvironment(env.NODE_ENV);
  return Object.freeze({
    environment,
    host: env.CONTROL_HOST?.trim() || '127.0.0.1',
    port: parsePort(env.CONTROL_PORT),
    logLevel: parseLogLevel(env.CONTROL_LOG_LEVEL),
    trustProxy: parseBoolean(env.CONTROL_TRUST_PROXY, false),
    publicBaseUrl: parsePublicBaseUrl(env.CONTROL_PUBLIC_BASE_URL, environment),
    version: env.OTTO_CONTROL_VERSION?.trim() || '0.1.0',
  });
}

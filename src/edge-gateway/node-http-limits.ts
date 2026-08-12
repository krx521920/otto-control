import type { Server, ServerOptions } from 'node:http';

export interface EdgeNodeHttpLimits {
  headersTimeoutMs: number;
  requestTimeoutMs: number;
  keepAliveTimeoutMs: number;
  maximumHeaderBytes: number;
  maximumHeaders: number;
  maximumRequestsPerSocket: number;
}

type EdgeNodeHttpLimitServer = Pick<
  Server,
  | 'headersTimeout'
  | 'requestTimeout'
  | 'keepAliveTimeout'
  | 'maxHeadersCount'
  | 'maxRequestsPerSocket'
>;

function integerEnvironment(
  name: string,
  environment: NodeJS.ProcessEnv,
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  const raw = environment[name]?.trim();
  if (!raw) return fallback;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} must be an integer between ${minimum} and ${maximum}`);
  }
  return value;
}

export function loadEdgeNodeHttpLimits(
  environment: NodeJS.ProcessEnv = process.env,
): EdgeNodeHttpLimits {
  const requestTimeoutMs = integerEnvironment(
    'OTTO_EDGE_HTTP_REQUEST_TIMEOUT_MS', environment, 120_000, 1_000, 900_000,
  );
  const headersTimeoutMs = integerEnvironment(
    'OTTO_EDGE_HTTP_HEADERS_TIMEOUT_MS', environment, 15_000, 1_000, 120_000,
  );
  if (headersTimeoutMs > requestTimeoutMs) {
    throw new Error(
      'OTTO_EDGE_HTTP_HEADERS_TIMEOUT_MS cannot exceed OTTO_EDGE_HTTP_REQUEST_TIMEOUT_MS',
    );
  }
  return {
    headersTimeoutMs,
    requestTimeoutMs,
    keepAliveTimeoutMs: integerEnvironment(
      'OTTO_EDGE_HTTP_KEEP_ALIVE_TIMEOUT_MS', environment, 5_000, 500, 60_000,
    ),
    maximumHeaderBytes: integerEnvironment(
      'OTTO_EDGE_HTTP_MAX_HEADER_BYTES', environment, 16_384, 4_096, 65_536,
    ),
    maximumHeaders: integerEnvironment(
      'OTTO_EDGE_HTTP_MAX_HEADERS_COUNT', environment, 100, 1, 2_000,
    ),
    maximumRequestsPerSocket: integerEnvironment(
      'OTTO_EDGE_HTTP_MAX_REQUESTS_PER_SOCKET', environment, 1_000, 1, 1_000_000,
    ),
  };
}

export function edgeNodeHttpServerOptions(
  limits: EdgeNodeHttpLimits,
): Pick<ServerOptions, 'maxHeaderSize'> {
  return { maxHeaderSize: limits.maximumHeaderBytes };
}

export function applyEdgeNodeHttpLimits(
  server: EdgeNodeHttpLimitServer,
  limits: EdgeNodeHttpLimits,
): void {
  server.headersTimeout = limits.headersTimeoutMs;
  server.requestTimeout = limits.requestTimeoutMs;
  server.keepAliveTimeout = limits.keepAliveTimeoutMs;
  server.maxHeadersCount = limits.maximumHeaders;
  server.maxRequestsPerSocket = limits.maximumRequestsPerSocket;
}

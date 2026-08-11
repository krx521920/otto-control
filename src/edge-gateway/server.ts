import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { readFile } from 'node:fs/promises';
import { Readable } from 'node:stream';
import { pathToFileURL } from 'node:url';

import { createOttoEdgeGateway } from './gateway.js';
import { createEdgeSignatureVerifier } from './protocol.js';
import { InMemoryEdgeRateLimiter } from './rate-limit.js';

interface EdgeServerConfiguration {
  host: string;
  port: number;
  policyFile: string;
  publicKeysFile: string;
}

function requiredEnvironment(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function configuration(): EdgeServerConfiguration {
  const port = Number(process.env.OTTO_EDGE_PORT ?? 7790);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
    throw new Error('OTTO_EDGE_PORT must be a valid TCP port');
  }
  return {
    host: process.env.OTTO_EDGE_HOST?.trim() || '127.0.0.1',
    port,
    policyFile: requiredEnvironment('OTTO_EDGE_POLICY_FILE'),
    publicKeysFile: requiredEnvironment('OTTO_EDGE_CONTROL_PUBLIC_KEYS_FILE'),
  };
}

function absoluteRequestUrl(request: IncomingMessage): string {
  const host = request.headers.host || 'localhost';
  return `http://${host}${request.url || '/'}`;
}

function webRequest(request: IncomingMessage, signal: AbortSignal): Request {
  const method = request.method || 'GET';
  const headers = new Headers();
  for (const [name, raw] of Object.entries(request.headers)) {
    if (Array.isArray(raw)) {
      for (const value of raw) headers.append(name, value);
    } else if (raw !== undefined) {
      headers.set(name, raw);
    }
  }
  const init: RequestInit & { duplex?: 'half' } = { method, headers, signal };
  if (method !== 'GET' && method !== 'HEAD') {
    init.body = Readable.toWeb(request) as ReadableStream<Uint8Array>;
    init.duplex = 'half';
  }
  return new Request(absoluteRequestUrl(request), init);
}

async function writeResponse(response: Response, target: ServerResponse): Promise<void> {
  target.statusCode = response.status;
  target.statusMessage = response.statusText;
  response.headers.forEach((value, name) => target.setHeader(name, value));
  if (!response.body) {
    target.end();
    return;
  }
  const stream = Readable.fromWeb(response.body as never);
  await new Promise<void>((resolve, reject) => {
    stream.once('error', reject);
    target.once('error', reject);
    target.once('finish', resolve);
    stream.pipe(target);
  });
}

export async function startEdgeGatewayServer(): Promise<void> {
  const config = configuration();
  const publicKeys = JSON.parse(await readFile(config.publicKeysFile, 'utf8')) as unknown;
  if (!publicKeys || typeof publicKeys !== 'object' || Array.isArray(publicKeys)) {
    throw new Error('OTTO_EDGE_CONTROL_PUBLIC_KEYS_FILE must contain a JSON object');
  }
  const gateway = createOttoEdgeGateway({
    policySource: {
      async load() {
        return JSON.parse(await readFile(config.policyFile, 'utf8')) as unknown;
      },
    },
    verifier: createEdgeSignatureVerifier(publicKeys as Record<string, string>),
    secretResolver: {
      async get(binding) {
        const value = process.env[binding]?.trim();
        return value || null;
      },
    },
    rateLimiter: new InMemoryEdgeRateLimiter(),
  });
  const server = createServer((request, response) => {
    const controller = new AbortController();
    const abort = () => controller.abort(
      new DOMException('downstream connection closed', 'AbortError'),
    );
    const cleanup = () => {
      request.removeListener('aborted', abort);
      response.removeListener('close', handleClose);
      response.removeListener('finish', cleanup);
    };
    const handleClose = () => {
      if (!response.writableFinished) abort();
      cleanup();
    };
    request.once('aborted', abort);
    response.once('close', handleClose);
    response.once('finish', cleanup);
    if (request.aborted) abort();
    void gateway.fetch(webRequest(request, controller.signal))
      .then((result) => writeResponse(result, response))
      .catch(() => {
        if (response.headersSent) {
          response.destroy();
          return;
        }
        response.writeHead(500, {
          'cache-control': 'no-store',
          'content-type': 'application/json; charset=utf-8',
        });
        response.end(JSON.stringify({
          error: { code: 'EDGE_INTERNAL_ERROR', message: 'internal gateway error' },
        }));
      });
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(config.port, config.host, resolve);
  });
  process.stdout.write(`otto-edge-gateway listening on ${config.host}:${config.port}\n`);
}

const entry = process.argv[1] ? pathToFileURL(process.argv[1]).href : '';
if (entry === import.meta.url) await startEdgeGatewayServer();

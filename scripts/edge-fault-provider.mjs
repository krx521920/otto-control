import { timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:https';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const MAX_REQUEST_BYTES = 1024 * 1024;
const SCENARIO_PREFIX = 'OTTO_EDGE_ACCEPTANCE:';

function boundedInteger(value, fallback, minimum, maximum, name) {
  const parsed = value === undefined ? fallback : Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${name} is invalid`);
  }
  return parsed;
}

function requiredEnvironment(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function secretMatches(authorization, expected) {
  const supplied = /^Bearer\s+([^\s]+)$/u.exec(authorization?.trim() ?? '')?.[1] ?? '';
  const suppliedBytes = Buffer.from(supplied);
  const expectedBytes = Buffer.from(expected);
  return suppliedBytes.length === expectedBytes.length
    && timingSafeEqual(suppliedBytes, expectedBytes);
}

export function edgeFaultScenario(value) {
  const serialized = JSON.stringify(value);
  const match = new RegExp(`${SCENARIO_PREFIX}(success|timeout|slow_stream|429|500|503)`, 'u')
    .exec(serialized);
  return match?.[1] ?? null;
}

function json(response, status, body, headers = {}) {
  response.writeHead(status, {
    'cache-control': 'no-store',
    'content-type': 'application/json; charset=utf-8',
    ...headers,
  });
  response.end(JSON.stringify(body));
}

async function requestBody(request) {
  const chunks = [];
  let length = 0;
  for await (const chunk of request) {
    length += chunk.length;
    if (length > MAX_REQUEST_BYTES) throw new Error('request body is too large');
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

export function createEdgeFaultProviderHandler(input) {
  return async (request, response) => {
    if (request.method === 'GET' && request.url === '/healthz') {
      json(response, 200, { service: 'otto-edge-fault-provider', status: 'ok' });
      return;
    }
    if (request.method !== 'POST'
      || !['/v1/chat/completions', '/v1/responses'].includes(request.url ?? '')) {
      json(response, 404, { error: { code: 'NOT_FOUND' } });
      return;
    }
    if (!secretMatches(request.headers.authorization, input.secret)) {
      json(response, 401, { error: { code: 'UNAUTHORIZED' } });
      return;
    }
    let body;
    try {
      body = await requestBody(request);
    } catch {
      json(response, 400, { error: { code: 'INVALID_REQUEST' } });
      return;
    }
    const scenario = edgeFaultScenario(body);
    if (!scenario) {
      json(response, 400, { error: { code: 'SCENARIO_REQUIRED' } });
      return;
    }
    if (scenario === 'timeout') {
      const timer = setTimeout(() => {
        if (!response.destroyed) json(response, 504, { error: { code: 'FAULT_TIMEOUT' } });
      }, input.timeoutDelayMs);
      timer.unref();
      response.once('close', () => clearTimeout(timer));
      return;
    }
    if (scenario === 'slow_stream') {
      response.writeHead(200, {
        'cache-control': 'no-store',
        'content-type': 'text/event-stream; charset=utf-8',
      });
      response.write('data: {"id":"slow"');
      const timer = setTimeout(() => {
        if (!response.destroyed) response.end(',"done":true}\n\n');
      }, input.slowStreamDelayMs);
      timer.unref();
      response.once('close', () => clearTimeout(timer));
      return;
    }
    if (scenario === '429') {
      json(response, 429, { error: { code: 'RATE_LIMITED' } }, { 'retry-after': '2' });
      return;
    }
    if (scenario === '500' || scenario === '503') {
      json(response, Number(scenario), { error: { code: `FAULT_${scenario}` } });
      return;
    }
    json(response, 200, {
      id: 'edge-acceptance-success',
      object: 'chat.completion',
      choices: [{ index: 0, message: { role: 'assistant', content: 'ok' } }],
      usage: { prompt_tokens: 4, completion_tokens: 1, total_tokens: 5 },
    });
  };
}

export function startEdgeFaultProvider(input) {
  const server = createServer({
    cert: readFileSync(input.certificateFile),
    key: readFileSync(input.privateKeyFile),
  }, createEdgeFaultProviderHandler(input));
  server.listen(input.port, input.host, () => {
    process.stdout.write(`otto-edge-fault-provider listening on ${input.host}:${input.port}\n`);
  });
  return server;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  startEdgeFaultProvider({
    host: process.env.OTTO_EDGE_FAULT_PROVIDER_HOST?.trim() || '127.0.0.1',
    port: boundedInteger(process.env.OTTO_EDGE_FAULT_PROVIDER_PORT, 9443, 1, 65_535, 'port'),
    certificateFile: requiredEnvironment('OTTO_EDGE_FAULT_PROVIDER_TLS_CERT_FILE'),
    privateKeyFile: requiredEnvironment('OTTO_EDGE_FAULT_PROVIDER_TLS_KEY_FILE'),
    secret: requiredEnvironment('OTTO_EDGE_FAULT_PROVIDER_SECRET'),
    timeoutDelayMs: boundedInteger(
      process.env.OTTO_EDGE_FAULT_PROVIDER_TIMEOUT_MS, 70_000, 1_000, 600_000, 'timeout delay',
    ),
    slowStreamDelayMs: boundedInteger(
      process.env.OTTO_EDGE_FAULT_PROVIDER_SLOW_STREAM_MS, 70_000, 1_000, 600_000,
      'slow-stream delay',
    ),
  });
}

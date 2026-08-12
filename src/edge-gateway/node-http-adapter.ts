import type { IncomingMessage } from 'node:http';
import { Readable } from 'node:stream';

const EDGE_NODE_INTERNAL_ORIGIN = 'http://edge.invalid';
const EDGE_NODE_REQUEST_TARGET_MAX_LENGTH = 8_192;

export function edgeNodeRequestUrl(requestTarget: string | undefined): string {
  if (!requestTarget
    || requestTarget.length > EDGE_NODE_REQUEST_TARGET_MAX_LENGTH) {
    throw new Error('edge request target is invalid');
  }
  try {
    decodeURIComponent(requestTarget);
  } catch {
    throw new Error('edge request target is invalid');
  }
  const parsed = new URL(requestTarget, EDGE_NODE_INTERNAL_ORIGIN);
  if (`${parsed.pathname}${parsed.search}` !== requestTarget) {
    throw new Error('edge request target is invalid');
  }
  return parsed.toString();
}

export function createEdgeNodeWebRequest(
  request: IncomingMessage,
  signal: AbortSignal,
): Request {
  const method = request.method || 'GET';
  const headers = new Headers();
  for (const [name, raw] of Object.entries(request.headers)) {
    if (name.toLowerCase() === 'host') continue;
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
  return new Request(edgeNodeRequestUrl(request.url), init);
}

export type EdgeNodeRequestConversion =
  | { ok: true; request: Request }
  | { ok: false; response: Response };

export function convertEdgeNodeWebRequest(
  request: IncomingMessage,
  signal: AbortSignal,
): EdgeNodeRequestConversion {
  try {
    return { ok: true, request: createEdgeNodeWebRequest(request, signal) };
  } catch {
    return {
      ok: false,
      response: new Response(JSON.stringify({
        error: { code: 'EDGE_INVALID_HTTP_REQUEST', message: 'invalid HTTP request' },
      }), {
        status: 400,
        headers: {
          'cache-control': 'no-store',
          'content-type': 'application/json; charset=utf-8',
        },
      }),
    };
  }
}

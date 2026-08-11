import type {
  EdgeAccessTokenV1,
  EdgeGatewayEndpoint,
  EdgeGatewayOutcomeV1,
  EdgeGatewayPolicyV1,
  EdgeModelRouteV1,
} from '../contracts/edge-gateway.js';
import type { EdgeRateLimiter } from './rate-limit.js';
import {
  decodeEdgeAccessTokenEnvelope,
  EdgeGatewayProtocolError,
  normalizeSignedEdgeGatewayPolicy,
  type EdgeSignatureVerifier,
  verifyEdgeAccessToken,
  verifyGatewayPolicy,
} from './protocol.js';

const ENDPOINT_PATHS: Readonly<Record<string, EdgeGatewayEndpoint>> = {
  '/v1/chat/completions': 'chat_completions',
  '/v1/responses': 'responses',
};
const RETRYABLE_UPSTREAM_STATUSES = new Set([429, 502, 503, 504]);
const RATE_LIMIT_WINDOW_MS = 60_000;
const CLIENT_ROUTING_FIELDS = new Set([
  'apiKey', 'api_key', 'authentication', 'headers', 'providerSecret',
  'secretBinding', 'upstreamUrl', 'upstream_url',
]);

export interface EdgeGatewayPolicySource {
  load(): Promise<unknown>;
}

export interface EdgeGatewaySecretResolver {
  get(binding: string): Promise<string | null>;
}

export interface EdgeGatewayOutcomeSink {
  record(outcome: EdgeGatewayOutcomeV1): Promise<void>;
}

export interface EdgeGatewayBackgroundContext {
  waitUntil?(task: Promise<unknown>): void;
}

export interface OttoEdgeGatewayOptions {
  policySource: EdgeGatewayPolicySource;
  verifier: EdgeSignatureVerifier;
  secretResolver: EdgeGatewaySecretResolver;
  rateLimiter: EdgeRateLimiter;
  outcomeSink?: EdgeGatewayOutcomeSink;
  fetch?: typeof fetch;
  now?: () => number;
  requestId?: () => string;
}

interface AuthorizedRequest {
  policy: EdgeGatewayPolicyV1;
  token: EdgeAccessTokenV1;
  endpoint: EdgeGatewayEndpoint;
  publicModel: string;
  upstreamBody: Record<string, unknown>;
}

interface RequestEvidence {
  requestId: string;
  startedAt: number;
  endpoint: EdgeGatewayEndpoint;
  publicModel: string;
  token: EdgeAccessTokenV1;
}

type EdgeStreamCompletion =
  | 'completed'
  | 'client_cancelled'
  | 'stream_timed_out'
  | 'stream_failed';

interface EdgeUpstreamConnection {
  response: Response;
  controller: AbortController;
}

function jsonResponse(
  status: number,
  code: string,
  message: string,
  extraHeaders?: Readonly<Record<string, string>>,
): Response {
  return new Response(JSON.stringify({ error: { code, message } }), {
    status,
    headers: {
      'cache-control': 'no-store',
      'content-type': 'application/json; charset=utf-8',
      ...extraHeaders,
    },
  });
}

function bearerToken(value: string | null): string {
  return /^Bearer\s+([^\s]+)$/iu.exec(value?.trim() || '')?.[1] || '';
}

async function readRequestBody(request: Request, maximumBytes: number): Promise<Uint8Array> {
  const declaredLength = request.headers.get('content-length');
  if (declaredLength !== null) {
    const parsed = Number(declaredLength);
    if (!Number.isSafeInteger(parsed) || parsed < 0) {
      throw new EdgeGatewayProtocolError(400, 'EDGE_INVALID_REQUEST', 'content-length is invalid');
    }
    if (parsed > maximumBytes) {
      throw new EdgeGatewayProtocolError(413, 'EDGE_REQUEST_TOO_LARGE', 'request body is too large');
    }
  }
  if (!request.body) return new Uint8Array();
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) break;
      length += result.value.byteLength;
      if (length > maximumBytes) {
        await reader.cancel();
        throw new EdgeGatewayProtocolError(
          413,
          'EDGE_REQUEST_TOO_LARGE',
          'request body is too large',
        );
      }
      chunks.push(result.value);
    }
  } finally {
    reader.releaseLock();
  }
  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

function requestObject(bytes: Uint8Array): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown;
  } catch {
    throw new EdgeGatewayProtocolError(400, 'EDGE_INVALID_REQUEST', 'request body must be JSON');
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new EdgeGatewayProtocolError(400, 'EDGE_INVALID_REQUEST', 'request body must be an object');
  }
  return value as Record<string, unknown>;
}

function requestedModel(body: Record<string, unknown>): string {
  if (Object.keys(body).some((field) => CLIENT_ROUTING_FIELDS.has(field))) {
    throw new EdgeGatewayProtocolError(
      400,
      'EDGE_ROUTING_OVERRIDE_FORBIDDEN',
      'client routing and provider credential fields are forbidden',
    );
  }
  const value = typeof body.model === 'string' ? body.model.trim() : '';
  if (!value || value.length > 160) {
    throw new EdgeGatewayProtocolError(400, 'EDGE_INVALID_REQUEST', 'model is invalid');
  }
  return value;
}

function matchingRoutes(
  policy: EdgeGatewayPolicyV1,
  endpoint: EdgeGatewayEndpoint,
  publicModel: string,
): EdgeModelRouteV1[] {
  return policy.routes
    .filter((route) => route.endpoint === endpoint && route.publicModel === publicModel)
    .sort((left, right) => left.priority - right.priority || left.id.localeCompare(right.id));
}

function upstreamHeaders(
  route: EdgeModelRouteV1,
  secret: string,
  requestId: string,
  accept: string | null,
): Headers {
  const headers = new Headers({
    'content-type': 'application/json',
    'x-otto-edge-request-id': requestId,
  });
  if (accept) headers.set('accept', accept);
  if (route.authentication.type === 'bearer') {
    headers.set('authorization', `Bearer ${secret}`);
  } else {
    headers.set(route.authentication.headerName, secret);
  }
  return headers;
}

function clientResponse(
  upstream: Response,
  body: ReadableStream<Uint8Array> | null,
  requestId: string,
  remaining: number,
): Response {
  const headers = new Headers({
    'cache-control': 'no-store',
    'x-otto-edge-request-id': requestId,
    'x-ratelimit-remaining': String(remaining),
  });
  const contentType = upstream.headers.get('content-type');
  if (contentType) headers.set('content-type', contentType);
  const providerRequestId = upstream.headers.get('x-request-id');
  if (providerRequestId) headers.set('x-upstream-request-id', providerRequestId);
  return new Response(body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers,
  });
}

async function fetchWithConnectTimeout(
  fetchImplementation: typeof fetch,
  route: EdgeModelRouteV1,
  init: RequestInit,
  timeoutMs: number,
  clientSignal: AbortSignal,
): Promise<EdgeUpstreamConnection> {
  const controller = new AbortController();
  const abort = () => controller.abort();
  if (clientSignal.aborted) controller.abort();
  else clientSignal.addEventListener('abort', abort, { once: true });
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImplementation(
      route.upstreamUrl,
      { ...init, signal: controller.signal },
    );
    return { response, controller };
  } finally {
    clearTimeout(timer);
    clientSignal.removeEventListener('abort', abort);
  }
}

function managedUpstreamBody(
  body: ReadableStream<Uint8Array> | null,
  upstreamController: AbortController,
  clientSignal: AbortSignal,
  idleTimeoutMs: number,
  onComplete: (completion: EdgeStreamCompletion) => void,
): ReadableStream<Uint8Array> | null {
  if (!body) {
    onComplete('completed');
    return null;
  }
  const reader = body.getReader();
  let completed = false;
  let idleTimer: ReturnType<typeof setTimeout> | undefined;
  let streamController: ReadableStreamDefaultController<Uint8Array> | undefined;

  const clearIdleTimer = () => {
    if (idleTimer !== undefined) clearTimeout(idleTimer);
    idleTimer = undefined;
  };
  const complete = (completion: EdgeStreamCompletion) => {
    if (completed) return;
    completed = true;
    clearIdleTimer();
    clientSignal.removeEventListener('abort', abortForClient);
    onComplete(completion);
  };
  const cancelReader = (reason: unknown) => {
    void reader.cancel(reason).catch(() => undefined);
  };
  const abortForClient = () => {
    if (completed) return;
    const reason = clientSignal.reason
      ?? new DOMException('client disconnected', 'AbortError');
    upstreamController.abort(reason);
    cancelReader(reason);
    complete('client_cancelled');
    try {
      streamController?.error(reason);
    } catch {
      // The downstream may already have cancelled its stream.
    }
  };

  return new ReadableStream<Uint8Array>({
    start(controller) {
      streamController = controller;
      if (clientSignal.aborted) abortForClient();
      else clientSignal.addEventListener('abort', abortForClient, { once: true });
    },
    async pull(controller) {
      if (completed) return;
      const idleError = new DOMException('upstream response stream timed out', 'TimeoutError');
      idleTimer = setTimeout(() => {
        if (completed) return;
        upstreamController.abort(idleError);
        cancelReader(idleError);
        complete('stream_timed_out');
        try {
          controller.error(idleError);
        } catch {
          // A concurrent downstream cancellation already closed the stream.
        }
      }, idleTimeoutMs);
      try {
        const result = await reader.read();
        clearIdleTimer();
        if (completed) return;
        if (result.done) {
          complete('completed');
          controller.close();
        } else {
          controller.enqueue(result.value);
        }
      } catch (error) {
        clearIdleTimer();
        if (completed) return;
        complete(clientSignal.aborted ? 'client_cancelled' : 'stream_failed');
        controller.error(error);
      }
    },
    async cancel(reason) {
      if (!completed) {
        upstreamController.abort(reason);
        complete('client_cancelled');
      }
      try {
        await reader.cancel(reason);
      } catch {
        // Cancellation is best-effort after the upstream has already failed.
      }
    },
  });
}

function scheduleOutcome(
  sink: EdgeGatewayOutcomeSink | undefined,
  context: EdgeGatewayBackgroundContext | undefined,
  outcome: EdgeGatewayOutcomeV1,
): void {
  if (!sink) return;
  const task = sink.record(outcome).catch(() => undefined);
  if (context?.waitUntil) context.waitUntil(task);
  else void task;
}

async function authorize(
  request: Request,
  endpoint: EdgeGatewayEndpoint,
  options: OttoEdgeGatewayOptions,
  now: number,
): Promise<AuthorizedRequest & { remaining: number }> {
  const rawPolicy = await options.policySource.load();
  const policyEnvelope = normalizeSignedEdgeGatewayPolicy(rawPolicy, now);
  const policy = await verifyGatewayPolicy(policyEnvelope, options.verifier);
  const tokenEnvelope = decodeEdgeAccessTokenEnvelope(
    bearerToken(request.headers.get('authorization')),
    now,
  );
  const token = await verifyEdgeAccessToken(tokenEnvelope, options.verifier);
  if (token.deploymentId !== policy.deploymentId
    || token.organizationId !== policy.organizationId
    || token.policyVersion !== policy.policyVersion) {
    throw new EdgeGatewayProtocolError(
      403,
      'EDGE_POLICY_BINDING_MISMATCH',
      'access token is not bound to the active gateway policy',
    );
  }
  const contentType = request.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase();
  if (contentType !== 'application/json') {
    throw new EdgeGatewayProtocolError(
      415,
      'EDGE_UNSUPPORTED_MEDIA_TYPE',
      'content-type must be application/json',
    );
  }
  const rate = await options.rateLimiter.consume({
    key: `${token.deploymentId}\0${token.organizationId}\0${token.subjectId}`,
    limit: policy.limits.requestsPerMinute,
    windowMs: RATE_LIMIT_WINDOW_MS,
    now,
  });
  if (!rate.allowed) {
    throw new EdgeGatewayProtocolError(
      429,
      'EDGE_RATE_LIMITED',
      String(rate.retryAfterSeconds),
    );
  }
  const body = requestObject(await readRequestBody(request, policy.limits.maxRequestBytes));
  const publicModel = requestedModel(body);
  if (!token.allowedModels.includes(publicModel)) {
    throw new EdgeGatewayProtocolError(403, 'EDGE_MODEL_FORBIDDEN', 'model is not allowed');
  }
  if (matchingRoutes(policy, endpoint, publicModel).length === 0) {
    throw new EdgeGatewayProtocolError(503, 'EDGE_MODEL_UNAVAILABLE', 'model has no active route');
  }
  return {
    policy,
    token,
    endpoint,
    publicModel,
    upstreamBody: body,
    remaining: rate.remaining,
  };
}

export function createOttoEdgeGateway(options: OttoEdgeGatewayOptions): {
  fetch(request: Request, context?: EdgeGatewayBackgroundContext): Promise<Response>;
} {
  const fetchImplementation = options.fetch ?? fetch;
  const now = options.now ?? Date.now;
  const requestId = options.requestId ?? (() => crypto.randomUUID());

  return {
    async fetch(request, context) {
      const startedAt = now();
      const id = requestId();
      const url = new URL(request.url);
      if (request.method === 'GET' && url.pathname === '/healthz') {
        return new Response(JSON.stringify({ status: 'ok', service: 'otto-edge-gateway' }), {
          status: 200,
          headers: {
            'cache-control': 'no-store',
            'content-type': 'application/json; charset=utf-8',
          },
        });
      }
      const endpoint = ENDPOINT_PATHS[url.pathname];
      if (!endpoint) return jsonResponse(404, 'EDGE_NOT_FOUND', 'route not found');
      if (request.method !== 'POST') {
        return jsonResponse(405, 'EDGE_METHOD_NOT_ALLOWED', 'method not allowed', {
          allow: 'POST',
        });
      }

      let authorized: Awaited<ReturnType<typeof authorize>>;
      try {
        authorized = await authorize(request, endpoint, options, startedAt);
      } catch (error) {
        if (error instanceof EdgeGatewayProtocolError) {
          const headers: Record<string, string> = { 'x-otto-edge-request-id': id };
          let message = error.message;
          if (error.code === 'EDGE_RATE_LIMITED') {
            headers['retry-after'] = error.message;
            message = 'request rate limit exceeded';
          }
          return jsonResponse(error.status, error.code, message, headers);
        }
        return jsonResponse(
          503,
          'EDGE_POLICY_UNAVAILABLE',
          'gateway policy is unavailable',
          { 'x-otto-edge-request-id': id },
        );
      }

      const evidence: RequestEvidence = {
        requestId: id,
        startedAt,
        endpoint,
        publicModel: authorized.publicModel,
        token: authorized.token,
      };
      const routes = matchingRoutes(
        authorized.policy,
        endpoint,
        authorized.publicModel,
      ).slice(0, authorized.policy.limits.maxRouteAttempts);
      let lastStatus: number | null = null;
      let lastRouteId: string | null = null;

      for (let index = 0; index < routes.length; index += 1) {
        const route = routes[index]!;
        lastRouteId = route.id;
        let secret: string | null;
        try {
          secret = await options.secretResolver.get(route.authentication.secretBinding);
        } catch {
          secret = null;
        }
        if (!secret) continue;
        let connection: EdgeUpstreamConnection;
        try {
          connection = await fetchWithConnectTimeout(
            fetchImplementation,
            route,
            {
              method: 'POST',
              headers: upstreamHeaders(route, secret, id, request.headers.get('accept')),
              body: JSON.stringify({ ...authorized.upstreamBody, model: route.upstreamModel }),
              redirect: 'error',
            },
            authorized.policy.limits.upstreamConnectTimeoutMs,
            request.signal,
          );
        } catch {
          continue;
        }
        const upstream = connection.response;
        lastStatus = upstream.status;
        const hasFallback = index + 1 < routes.length;
        if (hasFallback && RETRYABLE_UPSTREAM_STATUSES.has(upstream.status)) {
          connection.controller.abort();
          try {
            await upstream.body?.cancel();
          } catch {
            // The abort may have already errored the upstream response body.
          }
          continue;
        }
        const body = managedUpstreamBody(
          upstream.body,
          connection.controller,
          request.signal,
          authorized.policy.limits.upstreamIdleTimeoutMs,
          (completion) => {
            const completedAt = now();
            scheduleOutcome(options.outcomeSink, context, {
              version: 1,
              requestId: evidence.requestId,
              tokenId: evidence.token.tokenId,
              deploymentId: evidence.token.deploymentId,
              organizationId: evidence.token.organizationId,
              subjectId: evidence.token.subjectId,
              endpoint: evidence.endpoint,
              publicModel: evidence.publicModel,
              routeId: route.id,
              upstreamStatus: upstream.status,
              outcome: completion === 'completed'
                ? (upstream.ok ? 'succeeded' : 'upstream_failed')
                : completion === 'client_cancelled'
                  ? 'client_cancelled'
                  : completion === 'stream_timed_out'
                    ? 'stream_timed_out'
                    : 'upstream_failed',
              durationMs: Math.max(0, completedAt - evidence.startedAt),
              occurredAtMs: completedAt,
            });
          },
        );
        return clientResponse(upstream, body, id, authorized.remaining);
      }

      scheduleOutcome(options.outcomeSink, context, {
        version: 1,
        requestId: evidence.requestId,
        tokenId: evidence.token.tokenId,
        deploymentId: evidence.token.deploymentId,
        organizationId: evidence.token.organizationId,
        subjectId: evidence.token.subjectId,
        endpoint: evidence.endpoint,
        publicModel: evidence.publicModel,
        routeId: lastRouteId,
        upstreamStatus: lastStatus,
        outcome: 'upstream_failed',
        durationMs: Math.max(0, now() - evidence.startedAt),
        occurredAtMs: now(),
      });
      return jsonResponse(
        502,
        'EDGE_UPSTREAM_UNAVAILABLE',
        'all model routes are unavailable',
        { 'x-otto-edge-request-id': id },
      );
    },
  };
}

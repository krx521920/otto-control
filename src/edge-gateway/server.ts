import { createHash, timingSafeEqual } from 'node:crypto';
import {
  createServer,
  type ServerResponse,
} from 'node:http';
import { readFile } from 'node:fs/promises';
import { Readable } from 'node:stream';
import { pathToFileURL } from 'node:url';
import { createClient, type RedisClientOptions } from 'redis';

import { LocalEd25519Signer } from '../crypto/signed-envelope.js';
import {
  type EdgeGatewayBackgroundTaskWaiter,
  InMemoryEdgeGatewayBackgroundTasks,
} from './background-tasks.js';
import type { EdgeBillingCoordinator } from './billing-coordinator.js';
import {
  type EdgeConcurrencyLimiter,
  InMemoryEdgeConcurrencyLimiter,
} from './concurrency-limit.js';
import {
  type EdgeRouteCircuitBreaker,
  InMemoryEdgeRouteCircuitBreaker,
} from './circuit-breaker.js';
import { ControlEdgeBillingCoordinator } from './control-billing-coordinator.js';
import { ControlEdgeKeyringVerifier } from './control-keyring-verifier.js';
import { ControlEdgeGatewayPolicySource, type EdgeControlPolicyBinding } from './control-policy-source.js';
import {
  createOttoEdgeGateway,
  type EdgeGatewayPolicySource,
  type EdgeGatewayReadinessProbe,
} from './gateway.js';
import {
  type EdgeGatewayLifecycle,
  type EdgeGatewayLifecycleLease,
  InMemoryEdgeGatewayLifecycle,
} from './lifecycle.js';
import { convertEdgeNodeWebRequest } from './node-http-adapter.js';
import {
  applyEdgeNodeHttpLimits,
  edgeNodeHttpServerOptions,
  type EdgeNodeHttpLimits,
  loadEdgeNodeHttpLimits,
} from './node-http-limits.js';
import { createEdgeSignatureVerifier } from './protocol.js';
import { normalizeEdgeProviderSecret } from './provider-secret.js';
import { type EdgeRateLimiter, InMemoryEdgeRateLimiter } from './rate-limit.js';
import {
  createNodeRedisEdgeRateLimiter,
  type RedisEdgeClientLike,
} from './redis-rate-limit.js';
import {
  drainEdgeGatewayServer,
  isEdgeDrainExemptRequest,
} from './server-lifecycle.js';
import {
  type EdgeRequestLimits,
  loadEdgeRequestLimits,
} from './request-limits.js';
import {
  type EdgeUpstreamResponseLimits,
  loadEdgeUpstreamResponseLimits,
} from './upstream-response-limits.js';
import {
  normalizeEdgeUpstreamOriginPolicy,
  type StaticEdgeUpstreamOriginPolicy,
} from './upstream-origin-policy.js';

type EdgePolicyConfiguration =
  | { type: 'file'; policyFile: string }
  | {
      type: 'control';
      controlBaseUrl: string;
      identityFile: string;
      leaseTokenFile: string;
      refreshBeforeExpiryMs?: number;
      requestTimeoutMs?: number;
      keyringRefreshIntervalMs?: number;
      keyringRefreshBeforeExpiryMs?: number;
      unknownKeyRetryMs?: number;
      keyringFailureRetryMs?: number;
    };

type EdgeRateLimitConfiguration =
  | { type: 'memory'; maximumEntries?: number }
  | {
      type: 'redis';
      connectionString: string;
      keySecretFile: string;
      passwordFile?: string;
      tlsCaFile?: string;
      tlsServerName?: string;
      keyPrefix?: string;
      connectTimeoutMs?: number;
      banThreshold?: number;
      strikeWindowMs?: number;
      banMs?: number;
      allowInsecure: boolean;
    };

type EdgeBillingConfiguration =
  | { type: 'none' }
  | {
      type: 'control';
      receiptPrivateKeyFile: string;
      journalFile: string;
      nodeId?: string;
      retryIntervalMs?: number;
    };

export interface EdgeServerConfiguration {
  host: string;
  port: number;
  publicKeysFile: string;
  upstreamOriginsFile: string;
  policy: EdgePolicyConfiguration;
  rateLimit: EdgeRateLimitConfiguration;
  concurrency: {
    globalLimit: number;
    perSubjectLimit: number;
  };
  circuitBreaker: {
    failureThreshold: number;
    cooldownMs: number;
    maximumEntries: number;
  };
  http: EdgeNodeHttpLimits;
  request: EdgeRequestLimits;
  upstreamResponse: EdgeUpstreamResponseLimits;
  shutdownGraceMs: number;
  billing: EdgeBillingConfiguration;
  operationsTokenFile?: string;
}

function requiredEnvironment(name: string, environment: NodeJS.ProcessEnv): string {
  const value = environment[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function optionalInteger(
  name: string,
  environment: NodeJS.ProcessEnv,
  minimum: number,
  maximum: number,
): number | undefined {
  const raw = environment[name]?.trim();
  if (!raw) return undefined;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} must be an integer between ${minimum} and ${maximum}`);
  }
  return value;
}

function optionalBoolean(
  name: string,
  environment: NodeJS.ProcessEnv,
  fallback: boolean,
): boolean {
  const raw = environment[name]?.trim();
  if (!raw) return fallback;
  if (raw === 'true') return true;
  if (raw === 'false') return false;
  throw new Error(`${name} must be true or false`);
}

function rateLimitConfiguration(environment: NodeJS.ProcessEnv): EdgeRateLimitConfiguration {
  const backend = environment.OTTO_EDGE_RATE_LIMIT_BACKEND?.trim() || 'memory';
  if (backend === 'memory') {
    const redisConfiguration = [
      'OTTO_EDGE_REDIS_URL',
      'OTTO_EDGE_REDIS_PASSWORD_FILE',
      'OTTO_EDGE_REDIS_CA_FILE',
      'OTTO_EDGE_REDIS_SERVER_NAME',
    ].find((name) => environment[name]?.trim());
    if (redisConfiguration) {
      throw new Error(`${redisConfiguration} requires OTTO_EDGE_RATE_LIMIT_BACKEND=redis`);
    }
    return {
      type: 'memory',
      maximumEntries: optionalInteger(
        'OTTO_EDGE_RATE_LIMIT_MAXIMUM_ENTRIES',
        environment,
        1,
        1_000_000,
      ),
    };
  }
  if (backend !== 'redis') {
    throw new Error('OTTO_EDGE_RATE_LIMIT_BACKEND must be memory or redis');
  }
  const keyPrefix = environment.OTTO_EDGE_RATE_LIMIT_PREFIX?.trim() || undefined;
  if (keyPrefix && !/^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,63}$/u.test(keyPrefix)) {
    throw new Error('OTTO_EDGE_RATE_LIMIT_PREFIX is invalid');
  }
  return {
    type: 'redis',
    connectionString: requiredEnvironment('OTTO_EDGE_REDIS_URL', environment),
    keySecretFile: requiredEnvironment('OTTO_EDGE_RATE_LIMIT_KEY_FILE', environment),
    ...(environment.OTTO_EDGE_REDIS_PASSWORD_FILE?.trim()
      ? { passwordFile: environment.OTTO_EDGE_REDIS_PASSWORD_FILE.trim() }
      : {}),
    ...(environment.OTTO_EDGE_REDIS_CA_FILE?.trim()
      ? { tlsCaFile: environment.OTTO_EDGE_REDIS_CA_FILE.trim() }
      : {}),
    ...(environment.OTTO_EDGE_REDIS_SERVER_NAME?.trim()
      ? { tlsServerName: environment.OTTO_EDGE_REDIS_SERVER_NAME.trim() }
      : {}),
    keyPrefix,
    connectTimeoutMs: optionalInteger(
      'OTTO_EDGE_REDIS_CONNECT_TIMEOUT_MS', environment, 500, 120_000,
    ),
    banThreshold: optionalInteger(
      'OTTO_EDGE_RATE_LIMIT_BAN_THRESHOLD', environment, 1, 1_000,
    ),
    strikeWindowMs: optionalInteger(
      'OTTO_EDGE_RATE_LIMIT_STRIKE_WINDOW_MS', environment, 60_000, 86_400_000,
    ),
    banMs: optionalInteger(
      'OTTO_EDGE_RATE_LIMIT_BAN_MS', environment, 60_000, 604_800_000,
    ),
    allowInsecure: optionalBoolean(
      'OTTO_EDGE_REDIS_ALLOW_INSECURE', environment, false,
    ),
  };
}

function billingConfiguration(
  environment: NodeJS.ProcessEnv,
  managedControl: boolean,
): EdgeBillingConfiguration {
  const backend = environment.OTTO_EDGE_BILLING_BACKEND?.trim() || 'none';
  if (backend === 'none') {
    if (environment.OTTO_EDGE_EXECUTION_RECEIPT_KEY_FILE?.trim()
      || environment.OTTO_EDGE_BILLING_JOURNAL_FILE?.trim()
      || environment.OTTO_EDGE_BILLING_NODE_ID?.trim()) {
      throw new Error('Edge billing files require OTTO_EDGE_BILLING_BACKEND=control');
    }
    return { type: 'none' };
  }
  if (backend !== 'control') {
    throw new Error('OTTO_EDGE_BILLING_BACKEND must be none or control');
  }
  if (!managedControl) {
    throw new Error('Control billing requires OTTO_EDGE_CONTROL_URL managed policy mode');
  }
  const nodeId = environment.OTTO_EDGE_BILLING_NODE_ID?.trim() || undefined;
  if (nodeId && !/^edge_[a-f0-9]{32}$/u.test(nodeId)) {
    throw new Error('OTTO_EDGE_BILLING_NODE_ID must be edge_ followed by 32 lowercase hex characters');
  }
  return {
    type: 'control',
    receiptPrivateKeyFile: requiredEnvironment(
      'OTTO_EDGE_EXECUTION_RECEIPT_KEY_FILE', environment,
    ),
    journalFile: requiredEnvironment('OTTO_EDGE_BILLING_JOURNAL_FILE', environment),
    nodeId,
    retryIntervalMs: optionalInteger(
      'OTTO_EDGE_BILLING_RETRY_INTERVAL_MS', environment, 1_000, 60 * 60 * 1000,
    ),
  };
}

export function loadEdgeGatewayServerConfiguration(
  environment: NodeJS.ProcessEnv = process.env,
): EdgeServerConfiguration {
  const port = Number(environment.OTTO_EDGE_PORT ?? 7790);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
    throw new Error('OTTO_EDGE_PORT must be a valid TCP port');
  }
  const controlBaseUrl = environment.OTTO_EDGE_CONTROL_URL?.trim();
  const policyFile = environment.OTTO_EDGE_POLICY_FILE?.trim();
  if (controlBaseUrl && policyFile) {
    throw new Error('OTTO_EDGE_CONTROL_URL and OTTO_EDGE_POLICY_FILE cannot both be set');
  }
  const policy: EdgePolicyConfiguration = controlBaseUrl
    ? {
        type: 'control',
        controlBaseUrl,
        identityFile: requiredEnvironment('OTTO_EDGE_DEPLOYMENT_IDENTITY_FILE', environment),
        leaseTokenFile: requiredEnvironment('OTTO_EDGE_LEASE_TOKEN_FILE', environment),
        refreshBeforeExpiryMs: optionalInteger(
          'OTTO_EDGE_POLICY_REFRESH_BEFORE_EXPIRY_MS',
          environment,
          5_000,
          60 * 60 * 1000,
        ),
        requestTimeoutMs: optionalInteger(
          'OTTO_EDGE_CONTROL_TIMEOUT_MS',
          environment,
          500,
          60_000,
        ),
        keyringRefreshIntervalMs: optionalInteger(
          'OTTO_EDGE_KEYRING_REFRESH_INTERVAL_MS',
          environment,
          5_000,
          10 * 60 * 1000,
        ),
        keyringRefreshBeforeExpiryMs: optionalInteger(
          'OTTO_EDGE_KEYRING_REFRESH_BEFORE_EXPIRY_MS',
          environment,
          5_000,
          10 * 60 * 1000,
        ),
        unknownKeyRetryMs: optionalInteger(
          'OTTO_EDGE_UNKNOWN_KEY_RETRY_MS',
          environment,
          1_000,
          60_000,
        ),
        keyringFailureRetryMs: optionalInteger(
          'OTTO_EDGE_KEYRING_FAILURE_RETRY_MS',
          environment,
          1_000,
          60_000,
        ),
      }
    : {
        type: 'file',
        policyFile: requiredEnvironment('OTTO_EDGE_POLICY_FILE', environment),
      };
  const globalConcurrency = optionalInteger(
    'OTTO_EDGE_MAX_CONCURRENT_REQUESTS', environment, 1, 1_000_000,
  ) ?? 256;
  const perSubjectConcurrency = optionalInteger(
    'OTTO_EDGE_MAX_CONCURRENT_REQUESTS_PER_SUBJECT', environment, 1, 1_000_000,
  ) ?? 8;
  if (perSubjectConcurrency > globalConcurrency) {
    throw new Error(
      'OTTO_EDGE_MAX_CONCURRENT_REQUESTS_PER_SUBJECT cannot exceed '
      + 'OTTO_EDGE_MAX_CONCURRENT_REQUESTS',
    );
  }
  const circuitBreaker = {
    failureThreshold: optionalInteger(
      'OTTO_EDGE_CIRCUIT_BREAKER_FAILURE_THRESHOLD', environment, 1, 1_000,
    ) ?? 5,
    cooldownMs: optionalInteger(
      'OTTO_EDGE_CIRCUIT_BREAKER_COOLDOWN_MS', environment, 1_000, 3_600_000,
    ) ?? 30_000,
    maximumEntries: optionalInteger(
      'OTTO_EDGE_CIRCUIT_BREAKER_MAXIMUM_ENTRIES', environment, 1, 1_000_000,
    ) ?? 10_000,
  };
  return {
    host: environment.OTTO_EDGE_HOST?.trim() || '127.0.0.1',
    port,
    publicKeysFile: requiredEnvironment('OTTO_EDGE_CONTROL_PUBLIC_KEYS_FILE', environment),
    upstreamOriginsFile: requiredEnvironment('OTTO_EDGE_UPSTREAM_ORIGINS_FILE', environment),
    policy,
    rateLimit: rateLimitConfiguration(environment),
    concurrency: {
      globalLimit: globalConcurrency,
      perSubjectLimit: perSubjectConcurrency,
    },
    circuitBreaker,
    http: loadEdgeNodeHttpLimits(environment),
    request: loadEdgeRequestLimits(environment),
    upstreamResponse: loadEdgeUpstreamResponseLimits(environment),
    shutdownGraceMs: optionalInteger(
      'OTTO_EDGE_SHUTDOWN_GRACE_MS', environment, 1_000, 300_000,
    ) ?? 30_000,
    billing: billingConfiguration(environment, Boolean(controlBaseUrl)),
    ...(environment.OTTO_EDGE_OPERATIONS_TOKEN_FILE?.trim()
      ? { operationsTokenFile: environment.OTTO_EDGE_OPERATIONS_TOKEN_FILE.trim() }
      : {}),
  };
}

function exactIdentity(value: unknown): EdgeControlPolicyBinding {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('OTTO_EDGE_DEPLOYMENT_IDENTITY_FILE must contain a JSON object');
  }
  const body = value as Record<string, unknown>;
  const fields = new Set([
    'licenseId', 'deploymentId', 'organizationId', 'machineFingerprint',
  ]);
  if (Object.keys(body).some((field) => !fields.has(field))
    || [...fields].some((field) => typeof body[field] !== 'string')) {
    throw new Error('OTTO_EDGE_DEPLOYMENT_IDENTITY_FILE fields are invalid');
  }
  return body as unknown as EdgeControlPolicyBinding;
}

async function policySource(
  config: EdgePolicyConfiguration,
  verifier: ReturnType<typeof createEdgeSignatureVerifier>,
): Promise<EdgeGatewayPolicySource> {
  if (config.type === 'file') {
    return {
      async load() {
        return JSON.parse(await readFile(config.policyFile, 'utf8')) as unknown;
      },
    };
  }
  const identity = exactIdentity(
    JSON.parse(await readFile(config.identityFile, 'utf8')) as unknown,
  );
  const leaseToken = (await readFile(config.leaseTokenFile, 'utf8')).trim();
  return new ControlEdgeGatewayPolicySource({
    controlBaseUrl: config.controlBaseUrl,
    binding: identity,
    leaseToken,
    verifier,
    refreshBeforeExpiryMs: config.refreshBeforeExpiryMs,
    requestTimeoutMs: config.requestTimeoutMs,
  });
}

async function upstreamOriginPolicy(file: string): Promise<StaticEdgeUpstreamOriginPolicy> {
  let value: unknown;
  try {
    value = JSON.parse(await readFile(file, 'utf8')) as unknown;
  } catch {
    throw new Error('OTTO_EDGE_UPSTREAM_ORIGINS_FILE could not be read as JSON');
  }
  try {
    return normalizeEdgeUpstreamOriginPolicy(value);
  } catch {
    throw new Error('OTTO_EDGE_UPSTREAM_ORIGINS_FILE is invalid');
  }
}

interface EdgeRateLimiterResource {
  rateLimiter: EdgeRateLimiter;
  close(): Promise<void>;
  forceClose(): void;
}

async function edgeRateLimiter(config: EdgeRateLimitConfiguration): Promise<EdgeRateLimiterResource> {
  if (config.type === 'memory') {
    return {
      rateLimiter: new InMemoryEdgeRateLimiter(config.maximumEntries),
      async close() {},
      forceClose() {},
    };
  }
  let keySecret: Buffer;
  try {
    keySecret = Buffer.from(await readFile(config.keySecretFile));
  } catch {
    throw new Error('OTTO_EDGE_RATE_LIMIT_KEY_FILE could not be read');
  }
  if (keySecret.byteLength < 32 || keySecret.byteLength > 4_096) {
    throw new Error('OTTO_EDGE_RATE_LIMIT_KEY_FILE must contain 32 to 4096 bytes');
  }
  let password: string | undefined;
  if (config.passwordFile) {
    try {
      password = (await readFile(config.passwordFile, 'utf8')).trim();
    } catch {
      throw new Error('OTTO_EDGE_REDIS_PASSWORD_FILE could not be read');
    }
    if (!password || password.length > 4_096 || /[\r\n]/u.test(password)) {
      throw new Error('OTTO_EDGE_REDIS_PASSWORD_FILE is invalid');
    }
  }
  let tlsCa: Buffer | undefined;
  if (config.tlsCaFile) {
    try {
      tlsCa = Buffer.from(await readFile(config.tlsCaFile));
    } catch {
      throw new Error('OTTO_EDGE_REDIS_CA_FILE could not be read');
    }
    if (tlsCa.byteLength === 0 || tlsCa.byteLength > 1024 * 1024) {
      throw new Error('OTTO_EDGE_REDIS_CA_FILE is invalid');
    }
  }
  let client: RedisEdgeClientLike | undefined;
  const limiter = await createNodeRedisEdgeRateLimiter({
    connectionString: config.connectionString,
    keySecret,
    password,
    tlsCa,
    tlsServerName: config.tlsServerName,
    keyPrefix: config.keyPrefix,
    connectTimeoutMs: config.connectTimeoutMs,
    banThreshold: config.banThreshold,
    strikeWindowMs: config.strikeWindowMs,
    banMs: config.banMs,
    allowInsecure: config.allowInsecure,
    clientFactory(options: RedisClientOptions) {
      client = createClient(options) as unknown as RedisEdgeClientLike;
      return client;
    },
  });
  let closed = false;
  return {
    rateLimiter: limiter,
    async close() {
      if (closed || !client) return;
      closed = true;
      try {
        await client.quit();
      } catch (error) {
        try {
          client.disconnect();
        } catch {
          // The graceful-close failure remains authoritative.
        }
        throw error;
      }
    },
    forceClose() {
      if (!client) return;
      closed = true;
      client.disconnect();
    },
  };
}

export async function resolveEdgeProviderSecret(
  binding: string,
  environment: NodeJS.ProcessEnv = process.env,
): Promise<string | null> {
  const inlineValue = environment[binding];
  const fileName = environment[`${binding}_FILE`]?.trim();
  if (inlineValue?.trim() && fileName) return null;
  if (fileName) {
    try {
      return normalizeEdgeProviderSecret(await readFile(fileName, 'utf8'));
    } catch {
      return null;
    }
  }
  return normalizeEdgeProviderSecret(inlineValue);
}

export function createEdgeGatewayReadinessProbe(input: {
  policySource: EdgeGatewayPolicySource;
  rateLimiter: EdgeRateLimiter;
  billingCoordinator?: EdgeBillingCoordinator;
  lifecycle?: EdgeGatewayLifecycle;
  backgroundTasks?: EdgeGatewayBackgroundTaskWaiter;
}): EdgeGatewayReadinessProbe {
  return {
    async check() {
      try {
        if (input.lifecycle && !input.lifecycle.isAccepting()) return 'unavailable';
        const backgroundState = input.backgroundTasks?.snapshot().state;
        if (backgroundState === 'unavailable') return 'unavailable';
        await input.policySource.load();
        await input.rateLimiter.healthCheck?.();
        const billingState = input.billingCoordinator?.operationalStatus?.().state ?? 'ready';
        return backgroundState === 'degraded' && billingState === 'ready'
          ? 'degraded'
          : billingState;
      } catch {
        return 'unavailable';
      }
    },
  };
}

const OPERATIONS_PREFIX = '/v1/operations/';

function operationsAuthorized(request: Request, expectedToken: string): boolean {
  const supplied = /^Bearer\s+([^\s]+)$/u.exec(
    request.headers.get('authorization')?.trim() ?? '',
  )?.[1] ?? '';
  const suppliedDigest = createHash('sha256').update(supplied).digest();
  const expectedDigest = createHash('sha256').update(expectedToken).digest();
  return timingSafeEqual(suppliedDigest, expectedDigest);
}

function operationsResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'cache-control': 'no-store',
      'content-type': 'application/json; charset=utf-8',
    },
  });
}

export async function loadEdgeOperationsToken(file: string): Promise<string> {
  let token: string;
  try {
    token = (await readFile(file, 'utf8')).trim();
  } catch {
    throw new Error('OTTO_EDGE_OPERATIONS_TOKEN_FILE could not be read');
  }
  if (!/^[a-zA-Z0-9._~-]{32,8192}$/u.test(token)) {
    throw new Error('OTTO_EDGE_OPERATIONS_TOKEN_FILE is invalid');
  }
  return token;
}

export async function handleEdgeOperationsRequest(
  request: Request,
  input: {
    token: string;
    billingCoordinator?: EdgeBillingCoordinator;
    concurrencyLimiter?: EdgeConcurrencyLimiter;
    circuitBreaker?: EdgeRouteCircuitBreaker;
    lifecycle?: EdgeGatewayLifecycle;
    backgroundTasks?: EdgeGatewayBackgroundTaskWaiter;
  },
): Promise<Response | null> {
  const url = new URL(request.url);
  if (!url.pathname.startsWith(OPERATIONS_PREFIX)) return null;
  if (!operationsAuthorized(request, input.token)) {
    const response = operationsResponse(401, {
      error: { code: 'EDGE_OPERATIONS_UNAUTHORIZED', message: 'authorization required' },
    });
    response.headers.set('www-authenticate', 'Bearer');
    return response;
  }
  if (request.method === 'GET' && url.pathname === '/v1/operations/status') {
    try {
      return operationsResponse(200, {
        service: 'otto-edge-gateway',
        billing: input.billingCoordinator?.operationalStatus?.() ?? null,
        concurrency: input.concurrencyLimiter?.snapshot() ?? null,
        circuits: input.circuitBreaker?.snapshot() ?? null,
        lifecycle: input.lifecycle?.snapshot() ?? null,
        backgroundTasks: input.backgroundTasks?.snapshot() ?? null,
      });
    } catch {
      return operationsResponse(503, {
        error: { code: 'EDGE_OPERATIONS_UNAVAILABLE', message: 'status is unavailable' },
      });
    }
  }
  if (request.method === 'POST' && url.pathname === '/v1/operations/billing/retry') {
    if (!input.billingCoordinator?.flushPending) {
      return operationsResponse(409, {
        error: { code: 'EDGE_BILLING_NOT_CONFIGURED', message: 'billing is not configured' },
      });
    }
    try {
      await input.billingCoordinator.flushPending();
    } catch {
      return operationsResponse(503, {
        error: { code: 'EDGE_BILLING_UNAVAILABLE', message: 'billing retry failed' },
      });
    }
    const billingStatus = input.billingCoordinator.operationalStatus?.() ?? null;
    return operationsResponse(billingStatus?.state === 'unavailable' ? 503 : 200, {
      service: 'otto-edge-gateway',
      billing: billingStatus,
    });
  }
  return operationsResponse(404, {
    error: { code: 'EDGE_OPERATIONS_NOT_FOUND', message: 'operation not found' },
  });
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

export { drainEdgeGatewayServer, isEdgeDrainExemptRequest };

export async function startEdgeGatewayServer(): Promise<void> {
  const config = loadEdgeGatewayServerConfiguration();
  const publicKeys = JSON.parse(await readFile(config.publicKeysFile, 'utf8')) as unknown;
  if (!publicKeys || typeof publicKeys !== 'object' || Array.isArray(publicKeys)) {
    throw new Error('OTTO_EDGE_CONTROL_PUBLIC_KEYS_FILE must contain a JSON object');
  }
  const bootstrapPublicKeys = publicKeys as Record<string, string>;
  const verifier = config.policy.type === 'control'
    ? new ControlEdgeKeyringVerifier({
        controlBaseUrl: config.policy.controlBaseUrl,
        bootstrapPublicKeys,
        requestTimeoutMs: config.policy.requestTimeoutMs,
        refreshIntervalMs: config.policy.keyringRefreshIntervalMs,
        refreshBeforeExpiryMs: config.policy.keyringRefreshBeforeExpiryMs,
        unknownKeyRetryMs: config.policy.unknownKeyRetryMs,
        failureRetryMs: config.policy.keyringFailureRetryMs,
      })
    : createEdgeSignatureVerifier(bootstrapPublicKeys);
  let billingCoordinator: ControlEdgeBillingCoordinator | undefined;
  if (config.billing.type === 'control' && config.policy.type === 'control') {
    const identity = exactIdentity(
      JSON.parse(await readFile(config.policy.identityFile, 'utf8')) as unknown,
    );
    const leaseToken = (await readFile(config.policy.leaseTokenFile, 'utf8')).trim();
    let privateKey: string;
    try {
      privateKey = await readFile(config.billing.receiptPrivateKeyFile, 'utf8');
    } catch {
      throw new Error('OTTO_EDGE_EXECUTION_RECEIPT_KEY_FILE could not be read');
    }
    billingCoordinator = await ControlEdgeBillingCoordinator.create({
      controlBaseUrl: config.policy.controlBaseUrl,
      binding: identity,
      leaseToken,
      signer: new LocalEd25519Signer(privateKey),
      journalFile: config.billing.journalFile,
      requestTimeoutMs: config.policy.requestTimeoutMs,
      retryIntervalMs: config.billing.retryIntervalMs,
      nodeId: config.billing.nodeId,
    });
  }
  const operationsToken = config.operationsTokenFile
    ? await loadEdgeOperationsToken(config.operationsTokenFile)
    : undefined;
  const configuredPolicySource = await policySource(config.policy, verifier);
  const configuredUpstreamOriginPolicy = await upstreamOriginPolicy(config.upstreamOriginsFile);
  const rateLimiterResource = await edgeRateLimiter(config.rateLimit);
  const rateLimiter = rateLimiterResource.rateLimiter;
  const concurrencyLimiter = new InMemoryEdgeConcurrencyLimiter(
    config.concurrency.globalLimit,
    config.concurrency.perSubjectLimit,
  );
  const circuitBreaker = new InMemoryEdgeRouteCircuitBreaker(config.circuitBreaker);
  const lifecycle = new InMemoryEdgeGatewayLifecycle();
  const backgroundTasks = new InMemoryEdgeGatewayBackgroundTasks();
  const gateway = createOttoEdgeGateway({
    policySource: configuredPolicySource,
    verifier,
    secretResolver: {
      get: resolveEdgeProviderSecret,
    },
    rateLimiter,
    concurrencyLimiter,
    circuitBreaker,
    lifecycle,
    billingCoordinator,
    readinessProbe: createEdgeGatewayReadinessProbe({
      policySource: configuredPolicySource,
      rateLimiter,
      billingCoordinator,
      lifecycle,
      backgroundTasks,
    }),
    requestLimits: config.request,
    responseLimits: config.upstreamResponse,
    upstreamOriginPolicy: configuredUpstreamOriginPolicy,
  });
  const server = createServer(edgeNodeHttpServerOptions(config.http), (request, response) => {
    let lifecycleLease: EdgeGatewayLifecycleLease | null = null;
    if (!isEdgeDrainExemptRequest(request.method, request.url)) {
      const backgroundAccepting = backgroundTasks.isAccepting();
      try {
        lifecycleLease = backgroundAccepting ? lifecycle.acquire() : null;
      } catch {
        lifecycleLease = null;
      }
      if (!lifecycleLease) {
        response.writeHead(503, {
          'cache-control': 'no-store',
          'content-type': 'application/json; charset=utf-8',
          'retry-after': '1',
        });
        response.end(JSON.stringify({
          error: backgroundAccepting
            ? { code: 'EDGE_GATEWAY_DRAINING', message: 'gateway is draining' }
            : {
                code: 'EDGE_BACKGROUND_TASKS_UNAVAILABLE',
                message: 'gateway background processing is unavailable',
              },
        }));
        return;
      }
    }
    const controller = new AbortController();
    const abort = () => controller.abort(
      new DOMException('downstream connection closed', 'AbortError'),
    );
    const cleanup = () => {
      request.removeListener('aborted', abort);
      response.removeListener('close', handleClose);
      response.removeListener('finish', cleanup);
      lifecycleLease?.release();
    };
    const handleClose = () => {
      if (!response.writableFinished) abort();
      cleanup();
    };
    request.once('aborted', abort);
    response.once('close', handleClose);
    response.once('finish', cleanup);
    if (request.aborted) abort();
    const conversion = convertEdgeNodeWebRequest(request, controller.signal);
    if (!conversion.ok) {
      void writeResponse(conversion.response, response).catch(() => response.destroy());
      return;
    }
    const convertedRequest = conversion.request;
    const result = operationsToken
      ? handleEdgeOperationsRequest(convertedRequest, {
          token: operationsToken,
          billingCoordinator,
          concurrencyLimiter,
          circuitBreaker,
          lifecycle,
          backgroundTasks,
        })
        .then((operationsResponseResult) => operationsResponseResult
          ?? gateway.fetch(convertedRequest, backgroundTasks))
      : gateway.fetch(convertedRequest, backgroundTasks);
    void result
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
  applyEdgeNodeHttpLimits(server, config.http);
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(config.port, config.host, resolve);
  });
  process.stdout.write(`otto-edge-gateway listening on ${config.host}:${config.port}\n`);
  let shutdown: Promise<boolean> | null = null;
  let forcedBySignal = false;
  const handleShutdown = () => {
    if (shutdown) {
      forcedBySignal = true;
      server.closeAllConnections();
      return;
    }
    shutdown = drainEdgeGatewayServer({
      server,
      lifecycle,
      backgroundTasks,
      resources: [
        ...(billingCoordinator ? [{
          close: async () => {
            billingCoordinator.close();
            await billingCoordinator.flushPending();
          },
          forceClose: () => billingCoordinator.close(),
        }] : []),
        rateLimiterResource,
      ],
      timeoutMs: config.shutdownGraceMs,
    });
    void shutdown
      .then((drained) => {
        const graceful = drained && !forcedBySignal;
        process.stdout.write(`otto-edge-gateway ${graceful ? 'drained' : 'forced'} shutdown\n`);
        if (!graceful) process.exitCode = 1;
      })
      .catch(() => {
        lifecycle.markStopped();
        server.closeAllConnections();
        process.exitCode = 1;
      });
  };
  process.once('SIGTERM', handleShutdown);
  process.once('SIGINT', handleShutdown);
  server.once('close', () => {
    process.removeListener('SIGTERM', handleShutdown);
    process.removeListener('SIGINT', handleShutdown);
  });
}

const entry = process.argv[1] ? pathToFileURL(process.argv[1]).href : '';
if (entry === import.meta.url) await startEdgeGatewayServer();

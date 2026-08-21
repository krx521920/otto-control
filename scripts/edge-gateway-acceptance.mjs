import { createWriteStream, readFileSync } from 'node:fs';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { monitorEventLoopDelay, performance } from 'node:perf_hooks';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import { issueEdgeAcceptanceCredential } from './drill-edge-runtime-failures.mjs';
import {
  classifyEvidenceEnvironment,
  elapsedEvidence,
  fileEvidence,
  immutableReleaseEvidence,
  productionProvenance,
} from './edge-live-evidence.mjs';

export const EDGE_ACCEPTANCE_CONFIRMATION = 'RUN_REAL_EDGE_ACCEPTANCE';

export const EDGE_ACCEPTANCE_PROFILES = Object.freeze({
  'ci-smoke': Object.freeze({
    durationSeconds: 5,
    concurrency: 4,
    requestsPerSecond: 10,
    maxRequests: 25,
    requestTimeoutMs: 5_000,
    sampleIntervalMs: 1_000,
    maxErrorRate: 0,
    maxP99LatencyMs: 5_000,
  }),
  'soak-24h': Object.freeze({
    durationSeconds: 24 * 60 * 60,
    concurrency: 8,
    requestsPerSecond: 2,
    maxRequests: Number.POSITIVE_INFINITY,
    requestTimeoutMs: 60_000,
    sampleIntervalMs: 30_000,
    maxErrorRate: 0.01,
    maxP99LatencyMs: 30_000,
  }),
  'cost-load': Object.freeze({
    durationSeconds: 5 * 60,
    concurrency: 128,
    requestsPerSecond: 200,
    maxRequests: Number.POSITIVE_INFINITY,
    requestTimeoutMs: 60_000,
    sampleIntervalMs: 5_000,
    maxErrorRate: 0.02,
    maxP99LatencyMs: 30_000,
  }),
});

function numberArgument(value, name, { minimum = 0, integer = false } = {}) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < minimum || (integer && !Number.isInteger(parsed))) {
    throw new Error(`${name} must be ${integer ? 'an integer' : 'a number'} >= ${minimum}`);
  }
  return parsed;
}

function optionMap(argv) {
  const options = new Map();
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (!argument?.startsWith('--')) throw new Error(`unexpected argument: ${argument}`);
    const equals = argument.indexOf('=');
    if (equals !== -1) {
      options.set(argument.slice(2, equals), argument.slice(equals + 1));
      continue;
    }
    const name = argument.slice(2);
    const next = argv[index + 1];
    if (next && !next.startsWith('--')) {
      options.set(name, next);
      index += 1;
    } else {
      options.set(name, 'true');
    }
  }
  return options;
}

function optionalNumber(options, name, fallback, constraints) {
  return options.has(name)
    ? numberArgument(options.get(name), `--${name}`, constraints)
    : fallback;
}

function requiredUrl(value, name) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${name} must be an absolute URL`);
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error(`${name} must use HTTP or HTTPS`);
  if (parsed.username || parsed.password || parsed.search || parsed.hash
    || (parsed.pathname !== '/' && parsed.pathname !== '')) {
    throw new Error(`${name} must be an origin without credentials, path, query, or fragment`);
  }
  parsed.pathname = '';
  return parsed;
}

function identityFile(path) {
  const value = JSON.parse(readFileSync(resolve(path), 'utf8'));
  const fields = ['licenseId', 'deploymentId', 'organizationId', 'machineFingerprint'];
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).some((field) => !fields.includes(field))
    || fields.some((field) => typeof value[field] !== 'string' || !value[field].trim())) {
    throw new Error('--identity-file is invalid');
  }
  return value;
}

export function parseEdgeAcceptanceArguments(argv, environment = process.env) {
  const options = optionMap(argv);
  const profile = options.get('profile') ?? 'ci-smoke';
  const defaults = EDGE_ACCEPTANCE_PROFILES[profile];
  if (!defaults) throw new Error(`--profile must be one of ${Object.keys(EDGE_ACCEPTANCE_PROFILES).join(', ')}`);
  const endpoint = options.get('endpoint') ?? '/v1/chat/completions';
  if (!['/v1/chat/completions', '/v1/responses'].includes(endpoint)) {
    throw new Error('--endpoint must be /v1/chat/completions or /v1/responses');
  }
  const outputDirectory = resolve(options.get('output') ?? join('reports', 'edge-acceptance'));
  const baseUrlValue = options.get('base-url') ?? environment.OTTO_EDGE_ACCEPTANCE_BASE_URL;
  const planOnly = options.get('plan-only') === 'true';
  if (!baseUrlValue && !planOnly) throw new Error('--base-url or OTTO_EDGE_ACCEPTANCE_BASE_URL is required');
  const controlUrlValue = options.get('control-url') ?? environment.OTTO_EDGE_ACCEPTANCE_CONTROL_URL;
  const config = {
    profile,
    baseUrl: baseUrlValue ? requiredUrl(baseUrlValue, '--base-url') : null,
    endpoint,
    model: options.get('model') ?? environment.OTTO_EDGE_ACCEPTANCE_MODEL ?? 'otto-acceptance-model',
    prompt: options.get('prompt') ?? 'Reply with exactly: OTTO_EDGE_OK',
    durationSeconds: optionalNumber(options, 'duration-seconds', defaults.durationSeconds, { minimum: 0.05 }),
    concurrency: optionalNumber(options, 'concurrency', defaults.concurrency, { minimum: 1, integer: true }),
    requestsPerSecond: optionalNumber(options, 'rps', defaults.requestsPerSecond, { minimum: 0.01 }),
    maxRequests: optionalNumber(options, 'max-requests', defaults.maxRequests, { minimum: 1, integer: true }),
    requestTimeoutMs: optionalNumber(options, 'request-timeout-ms', defaults.requestTimeoutMs, { minimum: 100, integer: true }),
    sampleIntervalMs: optionalNumber(options, 'sample-interval-ms', defaults.sampleIntervalMs, { minimum: 100, integer: true }),
    maxErrorRate: optionalNumber(options, 'max-error-rate', defaults.maxErrorRate, { minimum: 0 }),
    maxP99LatencyMs: optionalNumber(options, 'max-p99-latency-ms', defaults.maxP99LatencyMs, { minimum: 1 }),
    maxOutputTokens: optionalNumber(options, 'max-output-tokens', 32, { minimum: 1, integer: true }),
    estimatedInputTokens: optionalNumber(options, 'estimated-input-tokens', 32, { minimum: 1, integer: true }),
    inputPricePerMillionUsd: optionalNumber(options, 'input-price-per-million-usd', 0, { minimum: 0 }),
    outputPricePerMillionUsd: optionalNumber(options, 'output-price-per-million-usd', 0, { minimum: 0 }),
    budgetUsd: optionalNumber(options, 'budget-usd', 0, { minimum: 0 }),
    accessToken: environment.OTTO_EDGE_ACCEPTANCE_TOKEN?.trim() || null,
    accessTokenFile: options.get('access-token-file') ?? null,
    controlUrl: controlUrlValue ? requiredUrl(controlUrlValue, '--control-url') : null,
    identityFile: options.get('identity-file') ?? null,
    leaseTokenFile: options.get('lease-token-file') ?? null,
    subjectId: options.get('subject-id') ?? 'edge_acceptance_operator',
    tokenRefreshBeforeMs: optionalNumber(
      options, 'token-refresh-before-ms', 60_000, { minimum: 5_000, integer: true },
    ),
    operationsToken: environment.OTTO_EDGE_OPERATIONS_TOKEN?.trim() || null,
    operationsTokenFile: options.get('operations-token-file') ?? null,
    outputDirectory,
    repositoryRoot: resolve(options.get('repository-root') ?? process.cwd()),
    releaseCandidate: options.get('release-candidate') ?? null,
    releaseArtifact: options.get('release-artifact') ?? null,
    confirmation: options.get('confirm') ?? environment.OTTO_EDGE_ACCEPTANCE_CONFIRM ?? '',
    planOnly,
  };
  if (config.maxErrorRate > 1) throw new Error('--max-error-rate must be <= 1');
  const renewalInputs = [config.controlUrl, config.identityFile, config.leaseTokenFile];
  if (renewalInputs.some(Boolean) && !renewalInputs.every(Boolean)) {
    throw new Error('Control-backed token renewal requires control URL, identity file, and lease token file');
  }
  if (['soak-24h', 'cost-load'].includes(profile)) {
    if (options.has('duration-seconds') && config.durationSeconds !== defaults.durationSeconds) {
      throw new Error(`${profile} duration is fixed at ${defaults.durationSeconds} seconds`);
    }
    if (config.budgetUsd <= 0) throw new Error(`${profile} requires --budget-usd`);
    if (config.inputPricePerMillionUsd <= 0 || config.outputPricePerMillionUsd <= 0) {
      throw new Error(`${profile} requires non-zero input and output token prices`);
    }
    if (!config.controlUrl || !config.identityFile || !config.leaseTokenFile) {
      throw new Error(`${profile} requires Control-backed short-lived token renewal`);
    }
    if (!config.releaseCandidate || !config.releaseArtifact) {
      throw new Error(`${profile} requires --release-candidate and --release-artifact`);
    }
    if (config.baseUrl && config.baseUrl.protocol !== 'https:') {
      throw new Error(`${profile} requires an HTTPS Edge Gateway URL`);
    }
    if (config.controlUrl.protocol !== 'https:') {
      throw new Error(`${profile} requires an HTTPS Control URL`);
    }
  }
  if (!planOnly && config.confirmation !== EDGE_ACCEPTANCE_CONFIRMATION) {
    throw new Error(`execution requires --confirm=${EDGE_ACCEPTANCE_CONFIRMATION}`);
  }
  return config;
}

async function secret(inline, file, name) {
  const value = inline ?? (file ? (await readFile(file, 'utf8')).trim() : '');
  if (!value) throw new Error(`${name} is required and must be supplied through an environment variable or file`);
  return value;
}

function tokenSource(config, injected = {}) {
  if (!config.controlUrl) {
    return {
      async get() {
        return secret(config.accessToken, config.accessTokenFile, 'Edge access token');
      },
    };
  }
  const identity = identityFile(config.identityFile);
  let current = null;
  let refreshing = null;
  return {
    async get() {
      const now = injected.now?.() ?? Date.now();
      if (current && now < current.expiresAtMs - config.tokenRefreshBeforeMs) {
        return current.encodedToken;
      }
      if (!refreshing) {
        refreshing = (async () => {
          const leaseToken = await secret(null, config.leaseTokenFile, 'Edge lease token');
          const issue = injected.issueCredential ?? issueEdgeAcceptanceCredential;
          const credential = await issue({
            controlUrl: config.controlUrl,
            identity,
            leaseToken,
            subjectId: config.subjectId,
            model: config.model,
            requestTimeoutMs: config.requestTimeoutMs,
          });
          if (credential.expiresAtMs <= (injected.now?.() ?? Date.now())
            + config.tokenRefreshBeforeMs) {
            throw new Error('Control issued an acceptance token with insufficient remaining lifetime');
          }
          current = credential;
          return credential.encodedToken;
        })().finally(() => { refreshing = null; });
      }
      return refreshing;
    },
  };
}

function quantile(values, percentile) {
  if (values.length === 0) return null;
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.min(sorted.length - 1, Math.ceil(percentile * sorted.length) - 1)];
}

class BoundedSamples {
  #capacity;
  #seen = 0;
  #values = [];

  constructor(capacity = 250_000) {
    this.#capacity = capacity;
  }

  add(value) {
    this.#seen += 1;
    if (this.#values.length < this.#capacity) this.#values.push(value);
    else {
      const replacement = Math.floor(Math.random() * this.#seen);
      if (replacement < this.#capacity) this.#values[replacement] = value;
    }
  }

  summary() {
    return {
      count: this.#seen,
      sampled: this.#values.length,
      approximate: this.#seen > this.#values.length,
      p50Ms: quantile(this.#values, 0.5),
      p95Ms: quantile(this.#values, 0.95),
      p99Ms: quantile(this.#values, 0.99),
      maxMs: this.#values.length ? Math.max(...this.#values) : null,
    };
  }
}

function responseUsage(body) {
  const usage = body && typeof body === 'object' ? body.usage : null;
  if (!usage || typeof usage !== 'object') return null;
  const input = Number(usage.input_tokens ?? usage.prompt_tokens);
  const output = Number(usage.output_tokens ?? usage.completion_tokens);
  if (!Number.isFinite(input) || input < 0 || !Number.isFinite(output) || output < 0) return null;
  return { inputTokens: input, outputTokens: output, totalTokens: input + output };
}

function requestBody(config) {
  if (config.endpoint === '/v1/responses') {
    return { model: config.model, input: config.prompt, max_output_tokens: config.maxOutputTokens, stream: false };
  }
  return {
    model: config.model,
    messages: [{ role: 'user', content: config.prompt }],
    max_tokens: config.maxOutputTokens,
    stream: false,
  };
}

async function probe(baseUrl, path, token) {
  const started = performance.now();
  try {
    const response = await fetch(new URL(path, `${baseUrl}/`), {
      headers: token ? { authorization: `Bearer ${token}` } : {},
      signal: AbortSignal.timeout(5_000),
    });
    const text = await response.text();
    let body = null;
    try { body = text ? JSON.parse(text) : null; } catch { body = null; }
    return { checkedAt: new Date().toISOString(), status: response.status, latencyMs: performance.now() - started, body };
  } catch (error) {
    return { checkedAt: new Date().toISOString(), status: 0, latencyMs: performance.now() - started, error: error instanceof Error ? error.name : 'Error' };
  }
}

function sleep(milliseconds, signal) {
  if (milliseconds <= 0) return Promise.resolve();
  return new Promise((resolvePromise) => {
    const timer = setTimeout(resolvePromise, milliseconds);
    signal?.addEventListener('abort', () => { clearTimeout(timer); resolvePromise(); }, { once: true });
  });
}

function endStream(stream) {
  return new Promise((resolvePromise, reject) => {
    stream.once('error', reject);
    stream.end(resolvePromise);
  });
}

function safePlan(config) {
  const worstCost = (
    config.estimatedInputTokens * config.inputPricePerMillionUsd
    + config.maxOutputTokens * config.outputPricePerMillionUsd
  ) / 1_000_000;
  const durationLimit = Math.ceil(config.durationSeconds * config.requestsPerSecond);
  const configuredLimit = Math.min(config.maxRequests, durationLimit);
  const budgetLimit = worstCost > 0 && config.budgetUsd > 0
    ? Math.floor(config.budgetUsd / worstCost)
    : Number.POSITIVE_INFINITY;
  const requestLimit = Math.min(configuredLimit, budgetLimit);
  return {
    worstCostPerRequestUsd: worstCost,
    durationRequestLimit: durationLimit,
    budgetRequestLimit: Number.isFinite(budgetLimit) ? budgetLimit : null,
    requestLimit: Number.isFinite(requestLimit) ? requestLimit : null,
    maximumReservedCostUsd: worstCost * requestLimit,
  };
}

export async function runEdgeAcceptance(config, options = {}) {
  if (!config.baseUrl) throw new Error('base URL is required for execution');
  const productionProfile = config.profile === 'soak-24h' || config.profile === 'cost-load';
  const classified = classifyEvidenceEnvironment(options.environment);
  let provenance = {
    schemaVersion: 1,
    evidenceClass: classified.evidenceClass,
    generator: 'scripts/edge-gateway-acceptance.mjs',
    releaseCandidate: null,
    releaseArtifact: null,
    runner: classified.runner,
  };
  if (productionProfile) {
    if (classified.evidenceClass !== 'production-live') {
      throw new Error(
        `${config.profile} formal evidence must run through workflow_dispatch on a self-hosted runner`,
      );
    }
    const release = immutableReleaseEvidence({
      root: config.repositoryRoot,
      releaseCandidate: config.releaseCandidate,
      artifactPath: config.releaseArtifact,
    });
    provenance = productionProvenance({
      environment: options.environment,
      generator: 'scripts/edge-gateway-acceptance.mjs',
      release,
    });
  }
  const accessTokens = tokenSource(config, options);
  const operationsToken = config.operationsToken || config.operationsTokenFile
    ? await secret(config.operationsToken, config.operationsTokenFile, 'Edge operations token')
    : null;
  const plan = safePlan(config);
  if (!plan.requestLimit || plan.requestLimit < 1) throw new Error('budget cannot reserve one bounded request');
  await mkdir(config.outputDirectory, { recursive: true });
  const runId = `edge-${config.profile}-${new Date().toISOString().replace(/[:.]/gu, '-')}`;
  const ledgerFile = join(config.outputDirectory, `${runId}.ndjson`);
  const reportFile = join(config.outputDirectory, `${runId}.json`);
  const ledger = createWriteStream(ledgerFile, { flags: 'wx', encoding: 'utf8' });
  const abortController = new AbortController();
  options.signal?.addEventListener('abort', () => abortController.abort(options.signal.reason), { once: true });
  const eventLoop = monitorEventLoopDelay({ resolution: 20 });
  eventLoop.enable();
  const startedAtMs = Date.now();
  const monotonicStartedAtMs = performance.now();
  const endsAtMs = startedAtMs + config.durationSeconds * 1_000;
  const startedAt = new Date(startedAtMs).toISOString();
  const latency = new BoundedSamples();
  const counters = { launched: 0, completed: 0, succeeded: 0, failed: 0, inFlight: 0, peakInFlight: 0 };
  const statusCodes = {};
  const errors = {};
  const tokens = { input: 0, output: 0, reportedResponses: 0 };
  const resources = [];
  const readiness = [];
  const operationsStart = operationsToken
    ? await probe(config.baseUrl, '/v1/operations/status', operationsToken)
    : null;
  const initialCpu = process.cpuUsage();
  const sample = async () => {
    const memory = process.memoryUsage();
    resources.push({
      sampledAt: new Date().toISOString(),
      rssBytes: memory.rss,
      heapUsedBytes: memory.heapUsed,
      externalBytes: memory.external,
      inFlight: counters.inFlight,
    });
    readiness.push(await probe(config.baseUrl, '/readyz', null));
  };
  await sample();
  const sampleTimer = setInterval(() => { void sample(); }, config.sampleIntervalMs);
  sampleTimer.unref();
  const intervalMs = 1_000 / config.requestsPerSecond;
  const body = JSON.stringify(requestBody(config));

  async function worker() {
    while (!abortController.signal.aborted) {
      const sequence = counters.launched;
      if (sequence >= plan.requestLimit) return;
      const scheduledAt = startedAtMs + sequence * intervalMs;
      if (scheduledAt >= endsAtMs) return;
      counters.launched += 1;
      await sleep(scheduledAt - Date.now(), abortController.signal);
      if (abortController.signal.aborted || Date.now() >= endsAtMs) return;
      const requestStarted = performance.now();
      counters.inFlight += 1;
      counters.peakInFlight = Math.max(counters.peakInFlight, counters.inFlight);
      let status = 0;
      let errorCode = null;
      let usage = null;
      let edgeRequestId = null;
      let upstreamRequestId = null;
      try {
        const accessToken = await accessTokens.get();
        const response = await fetch(new URL(config.endpoint, `${config.baseUrl}/`), {
          method: 'POST',
          headers: {
            authorization: `Bearer ${accessToken}`,
            'content-type': 'application/json',
            'x-otto-acceptance-run': runId,
          },
          body,
          signal: AbortSignal.any([abortController.signal, AbortSignal.timeout(config.requestTimeoutMs)]),
        });
        status = response.status;
        edgeRequestId = response.headers.get('x-otto-edge-request-id');
        upstreamRequestId = response.headers.get('x-upstream-request-id');
        const text = await response.text();
        let parsed = null;
        try { parsed = text ? JSON.parse(text) : null; } catch { parsed = null; }
        usage = responseUsage(parsed);
        if (response.ok) counters.succeeded += 1;
        else counters.failed += 1;
      } catch (error) {
        counters.failed += 1;
        errorCode = error instanceof Error ? error.name : 'Error';
        errors[errorCode] = (errors[errorCode] ?? 0) + 1;
      } finally {
        const elapsed = performance.now() - requestStarted;
        latency.add(elapsed);
        counters.inFlight -= 1;
        counters.completed += 1;
        statusCodes[status] = (statusCodes[status] ?? 0) + 1;
        if (usage) {
          tokens.input += usage.inputTokens;
          tokens.output += usage.outputTokens;
          tokens.reportedResponses += 1;
        }
        ledger.write(`${JSON.stringify({
          sequence,
          completedAt: new Date().toISOString(),
          status,
          latencyMs: elapsed,
          error: errorCode,
          edgeRequestId,
          upstreamRequestId,
          usage,
        })}\n`);
      }
    }
  }

  await Promise.all(Array.from({ length: config.concurrency }, () => worker()));
  clearInterval(sampleTimer);
  await sample();
  const operationsEnd = operationsToken
    ? await probe(config.baseUrl, '/v1/operations/status', operationsToken)
    : null;
  eventLoop.disable();
  await endStream(ledger);
  const completedAtMs = Date.now();
  const timing = elapsedEvidence(
    startedAtMs,
    completedAtMs,
    performance.now() - monotonicStartedAtMs,
  );
  const durationSeconds = Math.max((completedAtMs - startedAtMs) / 1_000, 0.001);
  const latencySummary = latency.summary();
  const errorRate = counters.completed ? counters.failed / counters.completed : 1;
  const actualCostUsd = (
    tokens.input * config.inputPricePerMillionUsd
    + tokens.output * config.outputPricePerMillionUsd
  ) / 1_000_000;
  const violations = [];
  if (counters.completed === 0) violations.push('no requests completed');
  if (errorRate > config.maxErrorRate) violations.push(`error rate ${errorRate} exceeds ${config.maxErrorRate}`);
  if (latencySummary.p99Ms !== null && latencySummary.p99Ms > config.maxP99LatencyMs) {
    violations.push(`p99 latency ${latencySummary.p99Ms}ms exceeds ${config.maxP99LatencyMs}ms`);
  }
  const readinessFailures = readiness.filter((item) => item.status !== 200).length;
  if (readinessFailures > 0) violations.push(`${readinessFailures} readiness checks failed`);
  if (operationsStart && operationsStart.status !== 200) violations.push('initial operations capacity probe failed');
  if (operationsEnd && operationsEnd.status !== 200) violations.push('final operations capacity probe failed');
  if (abortController.signal.aborted) violations.push('run was aborted');
  if (productionProfile && durationSeconds + 1 < config.durationSeconds) {
    violations.push(`actual duration ${durationSeconds}s is shorter than required ${config.durationSeconds}s`);
  }
  if (productionProfile && tokens.reportedResponses !== counters.succeeded) {
    violations.push('not every successful provider response included trustworthy token usage');
  }
  if (productionProfile && actualCostUsd <= 0) {
    violations.push('real provider usage did not produce a positive metered cost');
  }
  const cpu = process.cpuUsage(initialCpu);
  const achievedRps = counters.completed / durationSeconds;
  const ledgerEvidence = productionProfile
    ? fileEvidence(config.repositoryRoot, ledgerFile, 'acceptance request ledger')
    : null;
  const report = {
    version: 2,
    kind: 'otto_edge_gateway_acceptance',
    runId,
    result: violations.length === 0 ? 'passed' : 'failed',
    startedAt,
    completedAt: new Date(completedAtMs).toISOString(),
    durationSeconds,
    timing,
    provenance,
    profile: config.profile,
    configuration: {
      baseUrl: config.baseUrl.origin,
      endpoint: config.endpoint,
      model: config.model,
      requestedDurationSeconds: config.durationSeconds,
      concurrency: config.concurrency,
      requestsPerSecond: config.requestsPerSecond,
      maxRequests: Number.isFinite(config.maxRequests) ? config.maxRequests : null,
      requestTimeoutMs: config.requestTimeoutMs,
      maxOutputTokens: config.maxOutputTokens,
    },
    traffic: {
      ...counters,
      achievedRequestsPerSecond: achievedRps,
      errorRate,
      statusCodes,
      errors,
    },
    latency: latencySummary,
    tokens: { ...tokens, total: tokens.input + tokens.output },
    cost: {
      currency: 'USD',
      inputPricePerMillion: config.inputPricePerMillionUsd,
      outputPricePerMillion: config.outputPricePerMillionUsd,
      usageReportedFraction: counters.completed ? tokens.reportedResponses / counters.completed : 0,
      meteredEstimateUsd: actualCostUsd,
      reservedWorstCaseUsd: plan.worstCostPerRequestUsd * counters.launched,
      budgetUsd: config.budgetUsd || null,
      projectedThirtyDayUsdAtObservedRate: actualCostUsd > 0
        ? actualCostUsd / durationSeconds * 30 * 24 * 60 * 60
        : null,
    },
    capacity: {
      observedConcurrency: counters.peakInFlight,
      configuredConcurrency: config.concurrency,
      targetRequestsPerSecond: config.requestsPerSecond,
      achievedRequestsPerSecond: achievedRps,
      recommendedCeilingWithThirtyPercentHeadroom: achievedRps * 0.7,
      scope: 'observed acceptance load; not a hard platform limit',
      operationsStart,
      operationsEnd,
    },
    availability: { checks: readiness.length, failures: readinessFailures, samples: readiness },
    resources: {
      samples: resources,
      peakRssBytes: Math.max(...resources.map((item) => item.rssBytes)),
      peakHeapUsedBytes: Math.max(...resources.map((item) => item.heapUsedBytes)),
      cpuUserMicros: cpu.user,
      cpuSystemMicros: cpu.system,
      eventLoopDelayP99Ms: eventLoop.percentile(99) / 1_000_000,
    },
    thresholds: { maxErrorRate: config.maxErrorRate, maxP99LatencyMs: config.maxP99LatencyMs },
    violations,
    evidence: { ledgerFile, reportFile, ledger: ledgerEvidence },
  };
  await writeFile(reportFile, `${JSON.stringify(report, null, 2)}\n`, { encoding: 'utf8', flag: 'wx' });
  return report;
}

function printablePlan(config) {
  return {
    profile: config.profile,
    baseUrl: config.baseUrl?.origin ?? null,
    endpoint: config.endpoint,
    durationSeconds: config.durationSeconds,
    concurrency: config.concurrency,
    requestsPerSecond: config.requestsPerSecond,
    maxRequests: Number.isFinite(config.maxRequests) ? config.maxRequests : null,
    budgetUsd: config.budgetUsd || null,
    ...safePlan(config),
  };
}

async function main() {
  const config = parseEdgeAcceptanceArguments(process.argv.slice(2));
  if (config.planOnly) {
    process.stdout.write(`${JSON.stringify(printablePlan(config), null, 2)}\n`);
    return;
  }
  const controller = new AbortController();
  for (const signal of ['SIGINT', 'SIGTERM']) {
    process.once(signal, () => controller.abort(new Error(signal)));
  }
  const report = await runEdgeAcceptance(config, { signal: controller.signal });
  process.stdout.write(`${JSON.stringify({
    result: report.result,
    runId: report.runId,
    reportFile: report.evidence.reportFile,
    ledgerFile: report.evidence.ledgerFile,
    completed: report.traffic.completed,
    errorRate: report.traffic.errorRate,
    p99Ms: report.latency.p99Ms,
    achievedRequestsPerSecond: report.traffic.achievedRequestsPerSecond,
    meteredEstimateUsd: report.cost.meteredEstimateUsd,
    violations: report.violations,
  }, null, 2)}\n`);
  if (report.result !== 'passed') process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}

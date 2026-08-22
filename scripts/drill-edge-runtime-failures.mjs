import { createHmac, randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const FAILURE_CODES = new Set([
  'EDGE_POLICY_UNAVAILABLE',
  'EDGE_RATE_LIMIT_UNAVAILABLE',
  'EDGE_BILLING_UNAVAILABLE',
  'EDGE_UPSTREAM_UNAVAILABLE',
]);

function argumentsMap(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 1) {
    const entry = argv[index];
    if (!entry?.startsWith('--')) throw new Error(`unexpected argument: ${entry}`);
    const [name, inlineValue] = entry.slice(2).split('=', 2);
    const value = inlineValue ?? argv[index + 1];
    if (!name || !value || value.startsWith('--')) throw new Error(`--${name} requires a value`);
    values.set(name, value);
    if (inlineValue === undefined) index += 1;
  }
  return values;
}

function required(values, name) {
  const value = values.get(name)?.trim();
  if (!value) throw new Error(`--${name} is required`);
  return value;
}

function boundedInteger(value, fallback, minimum, maximum, name) {
  const parsed = value === undefined ? fallback : Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`--${name} is invalid`);
  }
  return parsed;
}

function httpsOrigin(value, name) {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.pathname !== '/'
    || url.username || url.password || url.search || url.hash) {
    throw new Error(`--${name} must be an HTTPS origin without credentials, query, or fragment`);
  }
  return url;
}

function readSecret(path, name) {
  const value = readFileSync(resolve(path), 'utf8').trim();
  if (value.length < 32 || value.length > 8_192 || /\s/u.test(value)) {
    throw new Error(`${name} file is invalid`);
  }
  return value;
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value)
      .filter(([, item]) => item !== undefined)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => [key, canonicalize(item)]));
  }
  return value;
}

function signedRequest(token, timestamp, nonce, body) {
  const message = `${timestamp}\n${nonce}\n${JSON.stringify(canonicalize(body))}`;
  return `hmac-sha256:${createHmac('sha256', token).update(message, 'utf8').digest('base64url')}`;
}

async function responseBody(response) {
  const text = await response.text();
  try {
    return text ? JSON.parse(text) : {};
  } catch {
    return { raw: text.slice(0, 1_024) };
  }
}

function errorCode(body) {
  return typeof body?.error?.code === 'string' ? body.error.code : null;
}

export async function issueEdgeAcceptanceCredential(input, fetchImplementation = fetch) {
  const body = {
    ...input.identity,
    subjectId: input.subjectId,
    allowedModels: [input.model],
  };
  const timestamp = Date.now();
  const nonce = randomBytes(24).toString('base64url');
  const response = await fetchImplementation(
    new URL('/v1/edge-gateway/access-tokens', input.controlUrl),
    {
      method: 'POST',
      headers: {
        authorization: `Bearer ${input.leaseToken}`,
        'content-type': 'application/json',
        'x-otto-nonce': nonce,
        'x-otto-signature': signedRequest(input.leaseToken, timestamp, nonce, body),
        'x-otto-timestamp': String(timestamp),
      },
      body: JSON.stringify(body),
      redirect: 'error',
      signal: AbortSignal.timeout(input.requestTimeoutMs),
    },
  );
  const result = await responseBody(response);
  if (response.status !== 201 || typeof result.encodedToken !== 'string'
    || !Number.isSafeInteger(result.envelope?.token?.expiresAtMs)) {
    throw new Error(`Control could not issue an acceptance token (HTTP ${response.status})`);
  }
  return {
    encodedToken: result.encodedToken,
    expiresAtMs: result.envelope.token.expiresAtMs,
  };
}

export async function issueEdgeAcceptanceToken(input, fetchImplementation = fetch) {
  return (await issueEdgeAcceptanceCredential(input, fetchImplementation)).encodedToken;
}

export async function edgeReadiness(gatewayUrl, fetchImplementation = fetch, timeoutMs = 10_000) {
  try {
    const response = await fetchImplementation(new URL('/readyz', gatewayUrl), {
      redirect: 'error', signal: AbortSignal.timeout(timeoutMs),
    });
    await response.body?.cancel();
    return response.status;
  } catch {
    return 0;
  }
}

export async function runEdgeScenario(input, fetchImplementation = fetch) {
  const startedAt = Date.now();
  let response;
  try {
    response = await fetchImplementation(new URL('/v1/chat/completions', input.gatewayUrl), {
      method: 'POST',
      headers: {
        authorization: `Bearer ${input.accessToken}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        model: input.model,
        messages: [{ role: 'user', content: `OTTO_EDGE_ACCEPTANCE:${input.scenario}` }],
        stream: input.scenario === 'slow_stream',
      }),
      redirect: 'error',
      signal: AbortSignal.timeout(input.requestTimeoutMs),
    });
  } catch (error) {
    return {
      scenario: input.scenario,
      status: 0,
      code: null,
      durationMs: Date.now() - startedAt,
      bodyTerminated: error instanceof Error,
    };
  }
  let body;
  let bodyTerminated = false;
  try {
    body = await responseBody(response);
  } catch {
    bodyTerminated = true;
    body = {};
  }
  return {
    scenario: input.scenario,
    status: response.status,
    code: errorCode(body),
    durationMs: Date.now() - startedAt,
    bodyTerminated,
  };
}

export function assertEdgeScenario(result) {
  if (result.scenario === 'success' && (result.status < 200 || result.status >= 300)) {
    throw new Error(`provider baseline failed with HTTP ${result.status}`);
  }
  if (result.scenario === 'timeout'
    && !(result.status === 502 && result.code === 'EDGE_UPSTREAM_UNAVAILABLE')) {
    throw new Error(`provider timeout did not fail closed: HTTP ${result.status} ${result.code ?? ''}`);
  }
  if (result.scenario === 'slow_stream' && !result.bodyTerminated) {
    throw new Error('slow provider stream was not terminated by the gateway idle timeout');
  }
  if (result.scenario === '429' && result.status !== 429) {
    throw new Error(`provider 429 was not preserved: HTTP ${result.status}`);
  }
  if (result.scenario === '500' && result.status !== 500) {
    throw new Error(`provider 500 was not preserved: HTTP ${result.status}`);
  }
  if (result.scenario === '503' && ![502, 503].includes(result.status)) {
    throw new Error(`provider 503 did not produce an accepted fail-closed result: HTTP ${result.status}`);
  }
}

function dockerCompose(input, action, services) {
  const args = ['compose', '-f', input.composeFile, '--env-file', input.environmentFile];
  if (input.projectName) args.push('-p', input.projectName);
  args.push('--profile', 'edge', action, ...services);
  const result = spawnSync('docker', args, { cwd: input.workingDirectory, stdio: 'inherit' });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`docker compose ${action} failed`);
}

async function waitForReadiness(input, expectedReady, dependencies) {
  const deadline = dependencies.now() + input.timeoutMs;
  while (dependencies.now() <= deadline) {
    const status = await dependencies.readiness(input.gatewayUrl);
    if ((status >= 200 && status < 300) === expectedReady) return status;
    await dependencies.sleep(input.pollIntervalMs);
  }
  throw new Error(`gateway did not become ${expectedReady ? 'ready' : 'unavailable'} in time`);
}

export async function runEdgeRuntimeFailureAcceptance(input, injected = {}) {
  const dependencies = {
    now: injected.now ?? Date.now,
    sleep: injected.sleep ?? ((milliseconds) => new Promise((done) => setTimeout(done, milliseconds))),
    compose: injected.compose ?? ((action, services) => dockerCompose(input, action, services)),
    readiness: injected.readiness
      ?? ((gatewayUrl) => edgeReadiness(gatewayUrl, fetch, input.requestTimeoutMs)),
    issueToken: injected.issueToken ?? (() => issueEdgeAcceptanceToken(input)),
    scenario: injected.scenario ?? ((accessToken, scenario) => runEdgeScenario({
      gatewayUrl: input.gatewayUrl,
      accessToken,
      model: input.model,
      scenario,
      requestTimeoutMs: input.providerRequestTimeoutMs,
    })),
  };
  const startedAt = new Date(dependencies.now()).toISOString();
  const report = { version: 1, drill: 'edge_runtime_failures', startedAt, phases: [] };
  const stopped = new Set();
  const stop = async (services) => {
    await dependencies.compose('stop', services);
    for (const service of services) stopped.add(service);
  };
  const start = async (services) => {
    await dependencies.compose('start', services);
    for (const service of services) stopped.delete(service);
  };
  try {
    await waitForReadiness({ ...input, timeoutMs: input.recoveryTimeoutMs }, true, dependencies);
    let accessToken = await dependencies.issueToken();
    const baseline = await dependencies.scenario(accessToken, 'success');
    assertEdgeScenario(baseline);
    report.phases.push({ name: 'baseline', result: 'passed', evidence: baseline });

    await stop([input.redisService]);
    await waitForReadiness({ ...input, timeoutMs: input.failureDetectionTimeoutMs }, false, dependencies);
    const redisFailure = await dependencies.scenario(accessToken, 'success');
    if (redisFailure.status !== 503 || !FAILURE_CODES.has(redisFailure.code)) {
      throw new Error(`Redis loss did not fail closed: HTTP ${redisFailure.status}`);
    }
    await start([input.redisService]);
    await waitForReadiness({ ...input, timeoutMs: input.recoveryTimeoutMs }, true, dependencies);
    const redisRecovery = await dependencies.scenario(accessToken, 'success');
    assertEdgeScenario(redisRecovery);
    report.phases.push({
      name: 'redis_failure_and_recovery', result: 'passed',
      evidence: { failure: redisFailure, recovery: redisRecovery },
    });

    await dependencies.compose('restart', [input.gatewayService]);
    await waitForReadiness({ ...input, timeoutMs: input.recoveryTimeoutMs }, true, dependencies);
    await stop(input.controlServices);
    const cachedPolicyStatus = await dependencies.readiness(input.gatewayUrl);
    if (cachedPolicyStatus < 200 || cachedPolicyStatus >= 300) {
      throw new Error('gateway did not retain a freshly cached policy during the initial Control outage');
    }
    const expiryStartedAt = dependencies.now();
    await waitForReadiness({ ...input, timeoutMs: input.policyExpiryTimeoutMs }, false, dependencies);
    const policyExpiryDetectedMs = dependencies.now() - expiryStartedAt;
    await start(input.controlServices);
    await waitForReadiness({ ...input, timeoutMs: input.recoveryTimeoutMs }, true, dependencies);
    report.phases.push({
      name: 'control_outage_policy_expiry_and_recovery', result: 'passed',
      evidence: { cachedPolicyStatus, policyExpiryDetectedMs },
    });

    accessToken = await dependencies.issueToken();
    for (const scenario of ['429', '500', '503', 'slow_stream', 'timeout']) {
      const result = await dependencies.scenario(accessToken, scenario);
      assertEdgeScenario(result);
      report.phases.push({ name: `provider_${scenario}`, result: 'passed', evidence: result });
    }
    return {
      ...report,
      completedAt: new Date(dependencies.now()).toISOString(),
      result: 'passed',
    };
  } finally {
    const control = input.controlServices.filter((service) => stopped.has(service));
    if (control.length > 0) await start(control).catch(() => undefined);
    if (stopped.has(input.redisService)) await start([input.redisService]).catch(() => undefined);
  }
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

async function main() {
  const values = argumentsMap(process.argv.slice(2));
  if (required(values, 'confirm') !== 'RUN_OTTO_EDGE_RUNTIME_FAILURES') {
    throw new Error('--confirm=RUN_OTTO_EDGE_RUNTIME_FAILURES is required');
  }
  const workingDirectory = resolve(values.get('working-directory') ?? '.');
  const input = {
    gatewayUrl: httpsOrigin(required(values, 'gateway-url'), 'gateway-url'),
    controlUrl: httpsOrigin(required(values, 'control-url'), 'control-url'),
    identity: identityFile(required(values, 'identity-file')),
    leaseToken: readSecret(required(values, 'lease-token-file'), 'lease token'),
    subjectId: required(values, 'subject-id'),
    model: required(values, 'model'),
    workingDirectory,
    composeFile: resolve(workingDirectory, values.get('compose-file') ?? 'compose.production.yaml'),
    environmentFile: resolve(workingDirectory, values.get('env-file') ?? '.env.production'),
    projectName: values.get('project-name')?.trim() || null,
    redisService: values.get('redis-service')?.trim() || 'edge-redis',
    gatewayService: values.get('gateway-service')?.trim() || 'edge-gateway',
    controlServices: (values.get('control-services') ?? 'control-a,control-b,control-c')
      .split(',').map((value) => value.trim()).filter(Boolean),
    requestTimeoutMs: boundedInteger(values.get('request-timeout-ms'), 15_000, 500, 120_000, 'request-timeout-ms'),
    providerRequestTimeoutMs: boundedInteger(values.get('provider-timeout-ms'), 90_000, 1_000, 600_000, 'provider-timeout-ms'),
    failureDetectionTimeoutMs: boundedInteger(values.get('failure-detection-timeout-ms'), 60_000, 1_000, 600_000, 'failure-detection-timeout-ms'),
    recoveryTimeoutMs: boundedInteger(values.get('recovery-timeout-ms'), 300_000, 1_000, 1_800_000, 'recovery-timeout-ms'),
    policyExpiryTimeoutMs: boundedInteger(values.get('policy-expiry-timeout-ms'), 1_020_000, 60_000, 3_600_000, 'policy-expiry-timeout-ms'),
    pollIntervalMs: boundedInteger(values.get('poll-interval-ms'), 2_000, 100, 60_000, 'poll-interval-ms'),
  };
  if (input.controlServices.length === 0) throw new Error('--control-services is empty');
  const report = await runEdgeRuntimeFailureAcceptance(input);
  const output = resolve(required(values, 'output'));
  writeFileSync(output, `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  process.stdout.write(`Edge runtime failure drill passed; report written to ${output}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}

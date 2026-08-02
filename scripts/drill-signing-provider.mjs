import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

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

function httpsOrigin(value) {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.pathname !== '/'
    || url.username || url.password || url.search || url.hash) {
    throw new Error('--control-url must be an HTTPS URL without credentials, query, or fragment');
  }
  return url;
}

function readToken(path) {
  const token = readFileSync(resolve(path), 'utf8').trim();
  if (token.length < 32) throw new Error('administrator token file is empty or invalid');
  return token;
}

async function request(controlUrl, path, token, init = {}) {
  const response = await fetch(new URL(path, controlUrl), {
    ...init,
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      ...init.headers,
    },
    redirect: 'error',
    signal: AbortSignal.timeout(15_000),
  });
  const text = await response.text();
  let body;
  try {
    body = text ? JSON.parse(text) : {};
  } catch {
    throw new Error(`Control returned non-JSON HTTP ${response.status}`);
  }
  if (!response.ok) {
    throw new Error(`Control HTTP ${response.status}: ${body?.error?.message || 'request failed'}`);
  }
  return body;
}

function safeHealth(value) {
  return {
    state: value?.state ?? null,
    backend: value?.backend ?? null,
    activeLocation: value?.activeLocation ?? null,
    consecutiveFailures: Number(value?.consecutiveFailures ?? 0),
    failoversTotal: Number(value?.failoversTotal ?? 0),
    circuitOpenUntil: value?.circuitOpenUntil ?? null,
  };
}

export async function runSigningProviderDrill(input) {
  const startedAt = new Date().toISOString();
  const inventory = await request(input.controlUrl, '/v1/admin/signing-keys', input.token);
  const before = inventory.signingKeys?.find((key) => key.keyId === input.keyId);
  if (!before || !before.canSign || before.state === 'revoked') {
    throw new Error('target signing key is unavailable or revoked');
  }
  const result = await request(
    input.controlUrl,
    `/v1/admin/signing-keys/${encodeURIComponent(input.keyId)}/probe`,
    input.token,
    { method: 'POST', body: '{}' },
  );
  const probe = result.probe;
  if (probe?.verified !== true || probe.keyId !== input.keyId) {
    throw new Error('Control did not return a verified signing-key probe');
  }
  const health = safeHealth(probe.providerHealth);
  if (health.state !== 'available') throw new Error(`signing provider is ${health.state}`);
  if (input.expectedLocation && health.activeLocation !== input.expectedLocation) {
    throw new Error(`expected active location ${input.expectedLocation}, got ${health.activeLocation}`);
  }
  if (health.failoversTotal < input.minimumFailovers) {
    throw new Error(`expected at least ${input.minimumFailovers} provider failovers`);
  }
  return {
    version: 1,
    drill: 'signing_provider',
    keyId: input.keyId,
    startedAt,
    completedAt: new Date().toISOString(),
    result: 'passed',
    before: safeHealth(before.providerHealth),
    after: health,
  };
}

async function main() {
  const values = argumentsMap(process.argv.slice(2));
  if (required(values, 'confirm') !== 'PROBE_OTTO_SIGNING_PROVIDER') {
    throw new Error('--confirm=PROBE_OTTO_SIGNING_PROVIDER is required');
  }
  const minimumFailovers = Number(values.get('minimum-failovers') ?? '0');
  if (!Number.isSafeInteger(minimumFailovers) || minimumFailovers < 0) {
    throw new Error('--minimum-failovers must be a non-negative integer');
  }
  const report = await runSigningProviderDrill({
    controlUrl: httpsOrigin(required(values, 'control-url')),
    token: readToken(required(values, 'token-file')),
    keyId: required(values, 'key-id'),
    expectedLocation: values.get('expect-location')?.trim() || null,
    minimumFailovers,
  });
  const output = resolve(required(values, 'output'));
  writeFileSync(output, `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  process.stdout.write(`Signing provider drill passed; report written to ${output}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}

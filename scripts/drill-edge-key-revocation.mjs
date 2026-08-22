import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import {
  edgeReadiness,
  issueEdgeAcceptanceToken,
  runEdgeScenario,
} from './drill-edge-runtime-failures.mjs';
import { runSigningRevocationDrill } from './drill-signing-revocation.mjs';

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

function readSecret(path, name) {
  const value = readFileSync(resolve(path), 'utf8').trim();
  if (value.length < 32 || value.length > 8_192 || /\s/u.test(value)) {
    throw new Error(`${name} file is invalid`);
  }
  return value;
}

function httpsOrigin(value, name) {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.pathname !== '/'
    || url.username || url.password || url.search || url.hash) {
    throw new Error(`--${name} must be an HTTPS origin without credentials, query, or fragment`);
  }
  return url;
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

async function waitFor(input, predicate, description) {
  const deadline = input.now() + input.timeoutMs;
  while (input.now() <= deadline) {
    const result = await input.probe();
    if (predicate(result)) return result;
    await input.sleep(input.pollIntervalMs);
  }
  throw new Error(`${description} was not observed before timeout`);
}

function restartGateway(input) {
  const args = ['compose', '-f', input.composeFile, '--env-file', input.environmentFile];
  if (input.projectName) args.push('-p', input.projectName);
  args.push('--profile', 'edge', 'restart', input.gatewayService);
  const result = spawnSync('docker', args, { cwd: input.workingDirectory, stdio: 'inherit' });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error('docker compose restart edge gateway failed');
}

export async function runEdgeKeyRevocationAcceptance(input, injected = {}) {
  const dependencies = {
    now: injected.now ?? Date.now,
    sleep: injected.sleep ?? ((milliseconds) => new Promise((done) => setTimeout(done, milliseconds))),
    issueToken: injected.issueToken ?? (() => issueEdgeAcceptanceToken(input)),
    scenario: injected.scenario ?? ((accessToken) => runEdgeScenario({
      gatewayUrl: input.gatewayUrl,
      accessToken,
      model: input.model,
      scenario: 'success',
      requestTimeoutMs: input.requestTimeoutMs,
    })),
    readiness: injected.readiness
      ?? (() => edgeReadiness(input.gatewayUrl, fetch, input.requestTimeoutMs)),
    revoke: injected.revoke ?? (() => runSigningRevocationDrill(input)),
    restartGateway: injected.restartGateway ?? (() => restartGateway(input)),
  };
  const startedAt = new Date(dependencies.now()).toISOString();
  const oldToken = await dependencies.issueToken();
  const before = await dependencies.scenario(oldToken);
  if (before.status < 200 || before.status >= 300) {
    throw new Error(`pre-revocation gateway probe failed with HTTP ${before.status}`);
  }
  const revocation = await dependencies.revoke();
  await dependencies.restartGateway();
  await waitFor({
    ...dependencies,
    timeoutMs: input.refreshTimeoutMs,
    pollIntervalMs: input.pollIntervalMs,
    probe: dependencies.readiness,
  }, (status) => status >= 200 && status < 300, 'gateway reload with replacement policy');
  const oldTokenRejected = await waitFor({
    ...dependencies,
    timeoutMs: input.refreshTimeoutMs,
    pollIntervalMs: input.pollIntervalMs,
    probe: () => dependencies.scenario(oldToken),
  }, (result) => result.status === 401 && result.code === 'EDGE_UNAUTHORIZED',
  'revoked signing key rejection');
  const newToken = await dependencies.issueToken();
  const after = await dependencies.scenario(newToken);
  if (after.status < 200 || after.status >= 300) {
    throw new Error(`replacement-key gateway probe failed with HTTP ${after.status}`);
  }
  return {
    version: 1,
    drill: 'edge_signing_key_revocation',
    startedAt,
    completedAt: new Date(dependencies.now()).toISOString(),
    result: 'passed',
    revokedKeyId: revocation.revokedKeyId,
    activeKeyId: revocation.activeKeyId,
    approvalId: revocation.approvalId,
    publicKeyringVerified: revocation.publicKeyringVerified,
    oldTokenRejected,
    replacementTokenAccepted: after,
  };
}

async function main() {
  const values = argumentsMap(process.argv.slice(2));
  if (required(values, 'confirm') !== 'REVOKE_OTTO_EDGE_SIGNING_KEY') {
    throw new Error('--confirm=REVOKE_OTTO_EDGE_SIGNING_KEY is required');
  }
  const requestTimeoutMs = Number(values.get('request-timeout-ms') ?? '90000');
  const refreshTimeoutMs = Number(values.get('refresh-timeout-ms') ?? '300000');
  const pollIntervalMs = Number(values.get('poll-interval-ms') ?? '2000');
  if (![requestTimeoutMs, refreshTimeoutMs, pollIntervalMs].every((value) => (
    Number.isSafeInteger(value) && value >= 500 && value <= 600_000
  ))) throw new Error('timeout arguments are invalid');
  const input = {
    gatewayUrl: httpsOrigin(required(values, 'gateway-url'), 'gateway-url'),
    controlUrl: httpsOrigin(required(values, 'control-url'), 'control-url'),
    identity: identityFile(required(values, 'identity-file')),
    leaseToken: readSecret(required(values, 'lease-token-file'), 'lease token'),
    requesterToken: readSecret(required(values, 'requester-token-file'), 'requester token'),
    approverToken: readSecret(required(values, 'approver-token-file'), 'approver token'),
    auditorToken: readSecret(required(values, 'auditor-token-file'), 'auditor token'),
    subjectId: required(values, 'subject-id'),
    model: required(values, 'model'),
    keyId: required(values, 'key-id'),
    replacementKeyId: required(values, 'replacement-key-id'),
    reason: required(values, 'reason'),
    requestTimeoutMs,
    refreshTimeoutMs,
    pollIntervalMs,
    workingDirectory: resolve(values.get('working-directory') ?? '.'),
    projectName: values.get('project-name')?.trim() || null,
    gatewayService: values.get('gateway-service')?.trim() || 'edge-gateway',
  };
  input.composeFile = resolve(
    input.workingDirectory, values.get('compose-file') ?? 'compose.production.yaml',
  );
  input.environmentFile = resolve(
    input.workingDirectory, values.get('env-file') ?? '.env.production',
  );
  const report = await runEdgeKeyRevocationAcceptance(input);
  const output = resolve(required(values, 'output'));
  writeFileSync(output, `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  process.stdout.write(`Edge signing-key revocation drill passed; report written to ${output}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}

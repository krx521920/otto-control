import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
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

function preproductionOrigin(value, suffix, name) {
  const url = new URL(value);
  const hostname = url.hostname.toLowerCase();
  const normalizedSuffix = suffix.toLowerCase();
  if (url.protocol !== 'https:' || url.pathname !== '/'
    || url.username || url.password || url.search || url.hash
    || !hostname.endsWith(`.${normalizedSuffix}`)
    || hostname === normalizedSuffix
    || ['localhost', '127.0.0.1', '::1'].includes(hostname)) {
    throw new Error(`--${name} must be a preproduction HTTPS origin under .${normalizedSuffix}`);
  }
  return url;
}

function nodeEvidence(url) {
  return createHash('sha256').update(url.origin).digest('hex');
}

async function pollAll(input, probe, predicate, description, dependencies) {
  const deadline = dependencies.now() + input.refreshTimeoutMs;
  let latest = [];
  while (dependencies.now() <= deadline) {
    latest = await Promise.all(input.nodeUrls.map(probe));
    if (latest.every(predicate)) return latest;
    await dependencies.sleep(input.pollIntervalMs);
  }
  throw new Error(`${description} was not observed on every ESA preproduction node`);
}

export async function runEsaKeyringRevocationAcceptance(input, injected = {}) {
  if (input.nodeUrls.length < 2 || input.nodeUrls.length > 32) {
    throw new Error('between 2 and 32 distinct ESA preproduction nodes are required');
  }
  if (new Set(input.nodeUrls.map((value) => value.origin)).size !== input.nodeUrls.length) {
    throw new Error('ESA preproduction node URLs must be distinct');
  }
  const dependencies = {
    now: injected.now ?? Date.now,
    sleep: injected.sleep ?? ((milliseconds) => new Promise((done) => setTimeout(done, milliseconds))),
    issueToken: injected.issueToken ?? (() => issueEdgeAcceptanceToken(input)),
    scenario: injected.scenario ?? ((nodeUrl, accessToken) => runEdgeScenario({
      gatewayUrl: nodeUrl,
      accessToken,
      model: input.model,
      scenario: 'success',
      requestTimeoutMs: input.requestTimeoutMs,
    })),
    revoke: injected.revoke ?? (() => runSigningRevocationDrill(input)),
  };
  const startedAt = new Date(dependencies.now()).toISOString();
  const oldToken = await dependencies.issueToken();
  const before = await Promise.all(input.nodeUrls.map(
    (nodeUrl) => dependencies.scenario(nodeUrl, oldToken),
  ));
  if (before.some((result) => result.status < 200 || result.status >= 300)) {
    throw new Error('pre-revocation probe did not pass on every ESA preproduction node');
  }

  const revocation = await dependencies.revoke();
  const rejected = await pollAll(
    input,
    (nodeUrl) => dependencies.scenario(nodeUrl, oldToken),
    (result) => result.status === 401 && result.code === 'EDGE_UNAUTHORIZED',
    'revoked-key token rejection',
    dependencies,
  );
  const newToken = await dependencies.issueToken();
  const accepted = await pollAll(
    input,
    (nodeUrl) => dependencies.scenario(nodeUrl, newToken),
    (result) => result.status >= 200 && result.status < 300,
    'replacement-key token acceptance',
    dependencies,
  );

  return {
    version: 1,
    drill: 'esa_keyring_emergency_revocation',
    environment: 'preproduction',
    changeTicket: input.changeTicket,
    startedAt,
    completedAt: new Date(dependencies.now()).toISOString(),
    result: 'passed',
    revokedKeyId: revocation.revokedKeyId,
    activeKeyId: revocation.activeKeyId,
    approvalId: revocation.approvalId,
    publicKeyringVerified: revocation.publicKeyringVerified,
    nodeEvidence: input.nodeUrls.map((nodeUrl, index) => ({
      nodeId: nodeEvidence(nodeUrl),
      oldTokenStatus: rejected[index]?.status,
      replacementTokenStatus: accepted[index]?.status,
    })),
  };
}

async function main() {
  const values = argumentsMap(process.argv.slice(2));
  if (required(values, 'environment') !== 'preproduction') {
    throw new Error('--environment=preproduction is required');
  }
  if (required(values, 'confirm') !== 'REVOKE_OTTO_ESA_PREPRODUCTION_KEY') {
    throw new Error('--confirm=REVOKE_OTTO_ESA_PREPRODUCTION_KEY is required');
  }
  const suffix = required(values, 'allowed-host-suffix').replace(/^\.+/u, '');
  if (!/^[a-z0-9.-]+\.[a-z]{2,63}$/u.test(suffix)) {
    throw new Error('--allowed-host-suffix is invalid');
  }
  const requestTimeoutMs = Number(values.get('request-timeout-ms') ?? '90000');
  const refreshTimeoutMs = Number(values.get('refresh-timeout-ms') ?? '300000');
  const pollIntervalMs = Number(values.get('poll-interval-ms') ?? '2000');
  if (![requestTimeoutMs, refreshTimeoutMs, pollIntervalMs].every((value) => (
    Number.isSafeInteger(value) && value >= 500 && value <= 600_000
  ))) throw new Error('timeout arguments are invalid');
  const nodeUrls = required(values, 'node-urls').split(',')
    .map((value) => preproductionOrigin(value.trim(), suffix, 'node-urls'));
  const input = {
    controlUrl: preproductionOrigin(
      required(values, 'control-url'), suffix, 'control-url',
    ),
    nodeUrls,
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
    changeTicket: required(values, 'change-ticket'),
    requestTimeoutMs,
    refreshTimeoutMs,
    pollIntervalMs,
  };
  const report = await runEsaKeyringRevocationAcceptance(input);
  const output = resolve(required(values, 'output'));
  writeFileSync(output, `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  process.stdout.write(`ESA keyring emergency revocation passed; report written to ${output}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}

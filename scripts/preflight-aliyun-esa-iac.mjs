import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

function parseArguments(argv) {
  const values = new Map();
  for (const item of argv) {
    const match = /^--([a-z-]+)=(.+)$/u.exec(item);
    if (!match) throw new Error(`invalid argument: ${item}`);
    values.set(match[1], match[2]);
  }
  return values;
}

function required(values, name) {
  const value = values.get(name);
  if (!value) throw new Error(`--${name}=<path> is required`);
  return value;
}

function loadJson(path) {
  const raw = readFileSync(path, 'utf8');
  return { raw, value: JSON.parse(raw) };
}

function digest(raw) {
  return createHash('sha256').update(raw).digest('hex');
}

const SECRET_FIELDS = new Set([
  'value', 'secret', 'plaintext', 'apikey', 'api_key', 'token', 'credential', 'password',
]);

function rejectSecretMaterial(value, path = '$') {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => rejectSecretMaterial(entry, `${path}[${index}]`));
    return;
  }
  if (!value || typeof value !== 'object') return;
  for (const [key, child] of Object.entries(value)) {
    if (SECRET_FIELDS.has(key.toLowerCase())) {
      throw new Error(`secret material field is forbidden in manifest: ${path}.${key}`);
    }
    rejectSecretMaterial(child, `${path}.${key}`);
  }
}

function assertHex(value, field) {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/u.test(value)) {
    throw new Error(`${field} must be a lower-case SHA-256 digest`);
  }
}

function exactFields(value, allowed, name) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).some((field) => !allowed.has(field))) {
    throw new Error(`${name} contains unsupported fields`);
  }
}

export function validateAliyunEsaRelease({ worker, policy, keyring, secrets, canary, evidence }) {
  rejectSecretMaterial(secrets.value);
  exactFields(
    secrets.value,
    new Set(['schemaVersion', 'routineName', 'environment', 'bindings', 'forbiddenFields']),
    'Secret binding manifest',
  );
  if (secrets.value.schemaVersion !== 1 || secrets.value.environment !== 'production') {
    throw new Error('Secret binding manifest must use schemaVersion 1 and production environment');
  }
  if (!Array.isArray(secrets.value.bindings) || secrets.value.bindings.length === 0) {
    throw new Error('Secret binding manifest must contain at least one binding');
  }
  const names = new Set();
  for (const binding of secrets.value.bindings) {
    exactFields(
      binding,
      new Set(['binding', 'provider', 'secretRef', 'readback', 'terraformState']),
      'Secret binding',
    );
    if (!binding || typeof binding !== 'object'
      || !/^[A-Z][A-Z0-9_]{2,63}$/u.test(binding.binding ?? '')
      || binding.provider !== 'external-secret-provider'
      || !/^external-secret:\/\/[a-z0-9/_-]+\/versions\/[A-Za-z0-9._-]+$/u.test(binding.secretRef ?? '')
      || binding.readback !== 'prohibited'
      || binding.terraformState !== 'excluded') {
      throw new Error('Secret bindings require a write-only external version and must be excluded from Terraform state');
    }
    if (names.has(binding.binding)) throw new Error(`duplicate Secret binding: ${binding.binding}`);
    names.add(binding.binding);
  }

  exactFields(
    evidence.value,
    new Set([
      'schemaVersion', 'evidenceId', 'routineName', 'workerSha256', 'policySha256',
      'keyringSha256', 'secretBindingsSha256', 'secretBindingRevision',
      'productionDeploymentId', 'canaryReportSha256', 'approvedBy', 'approvedAt',
    ]),
    'Release evidence',
  );
  if (evidence.value.schemaVersion !== 1
    || !/^esa-release-[a-f0-9]{32,64}$/u.test(evidence.value.evidenceId ?? '')
    || !Array.isArray(evidence.value.approvedBy)
    || new Set(evidence.value.approvedBy).size < 2
    || typeof evidence.value.productionDeploymentId !== 'string'
    || evidence.value.productionDeploymentId.length < 8
    || typeof evidence.value.secretBindingRevision !== 'string'
    || evidence.value.secretBindingRevision.length < 8
    || !Number.isFinite(Date.parse(evidence.value.approvedAt ?? ''))) {
    throw new Error('Release evidence requires immutable IDs and two distinct approvers');
  }
  if (evidence.value.approvedBy.some((value) => (
    typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.:@-]{2,127}$/u.test(value)
  ))) throw new Error('Release evidence approver identity is invalid');
  for (const field of [
    'workerSha256', 'policySha256', 'keyringSha256', 'secretBindingsSha256',
    'canaryReportSha256',
  ]) {
    assertHex(evidence.value[field], field);
  }
  const actual = {
    workerSha256: digest(worker.raw),
    policySha256: digest(policy.raw),
    keyringSha256: digest(keyring.raw),
    secretBindingsSha256: digest(secrets.raw),
    canaryReportSha256: digest(canary.raw),
  };
  for (const [field, value] of Object.entries(actual)) {
    if (evidence.value[field] !== value) throw new Error(`${field} does not match release evidence`);
  }
  const policyBindings = new Set(
    (policy.value?.policy?.routes ?? []).map((route) => route?.authentication?.secretBinding),
  );
  if (policyBindings.size === 0 || [...policyBindings].some((name) => !names.has(name))) {
    throw new Error('Every signed policy Secret binding must exist in the external Secret manifest');
  }
  if (!keyring.value || typeof keyring.value !== 'object'
    || Array.isArray(keyring.value) || Object.keys(keyring.value).length === 0
    || Object.values(keyring.value).some((value) => typeof value !== 'string'
    || !value.includes('BEGIN PUBLIC KEY') || value.includes('PRIVATE KEY'))) {
    throw new Error('Control keyring may contain only public SPKI PEM values');
  }
  if (canary.value?.drill !== 'esa_canary_rollout'
    || canary.value?.result !== 'promoted'
    || !Number.isSafeInteger(canary.value?.startedPercent)
    || canary.value.startedPercent < 1 || canary.value.startedPercent > 10
    || canary.value?.completedPercent !== 100
    || canary.value?.billingReady !== true
    || canary.value?.rollbackDrill !== 'passed') {
    throw new Error('Canary report does not prove a healthy promotion and rollback drill');
  }
  return { evidenceId: evidence.value.evidenceId, ...actual };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    const args = parseArguments(process.argv.slice(2));
    const result = validateAliyunEsaRelease({
      worker: { raw: readFileSync(required(args, 'worker'), 'utf8') },
      policy: loadJson(required(args, 'policy')),
      keyring: loadJson(required(args, 'keyring')),
      secrets: loadJson(required(args, 'secret-bindings')),
      canary: loadJson(required(args, 'canary-report')),
      evidence: loadJson(required(args, 'release-evidence')),
    });
    process.stdout.write(`Aliyun ESA release preflight passed: ${result.evidenceId}\n`);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}

import { createPublicKey, verify } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { collectSigningAuditEvidence } from './signing-audit-evidence.mjs';

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

function verifyEnvelope(envelope, publicKeyPem) {
  if (!envelope?.license || typeof envelope.signature !== 'string'
    || !envelope.signature.startsWith('ed25519:')) {
    throw new Error('legacy License envelope is invalid');
  }
  const signature = Buffer.from(envelope.signature.slice('ed25519:'.length), 'base64url');
  if (signature.length !== 64 || !verify(
    null,
    Buffer.from(JSON.stringify(canonicalize(envelope.license))),
    createPublicKey(publicKeyPem),
    signature,
  )) {
    throw new Error('legacy License signature verification failed');
  }
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

export async function runSigningRotationDrill(input) {
  const startedAt = new Date().toISOString();
  const inventory = await request(input.controlUrl, '/v1/admin/signing-keys', input.requesterToken);
  const previous = inventory.signingKeys?.find((key) => key.state === 'active');
  const target = inventory.signingKeys?.find((key) => key.keyId === input.targetKeyId);
  if (!previous) throw new Error('Control has no active signing key');
  if (!target || !target.canSign || target.state === 'revoked') {
    throw new Error('target signing key is unavailable or revoked');
  }
  if (target.state === 'active') throw new Error('target signing key is already active');
  let legacyLicense = null;
  if (input.legacyLicenseId) {
    legacyLicense = await request(
      input.controlUrl,
      `/v1/admin/licenses/${encodeURIComponent(input.legacyLicenseId)}`,
      input.requesterToken,
    );
    if (legacyLicense.signingKeyId !== previous.keyId) {
      throw new Error('legacy License was not signed by the currently active key');
    }
    verifyEnvelope(legacyLicense, previous.publicKeyPem);
  }
  const probe = await request(
    input.controlUrl,
    `/v1/admin/signing-keys/${encodeURIComponent(target.keyId)}/probe`,
    input.requesterToken,
    { method: 'POST', body: '{}' },
  );
  if (probe.probe?.verified !== true) throw new Error('target signing key probe failed');

  const approvalResponse = await request(
    input.controlUrl,
    '/v1/admin/approvals',
    input.requesterToken,
    {
      method: 'POST',
      body: JSON.stringify({
        operation: 'signing_key.activate',
        targetType: 'signing_key',
        targetId: target.keyId,
        request: {},
      }),
    },
  );
  const approvalId = approvalResponse.approval?.id;
  if (!approvalId) throw new Error('Control did not create a rotation approval');
  const approved = await request(
    input.controlUrl,
    `/v1/admin/approvals/${encodeURIComponent(approvalId)}/decide`,
    input.approverToken,
    {
      method: 'POST',
      body: JSON.stringify({ decision: 'approve', reason: 'production signing-key rotation drill' }),
    },
  );
  if (approved.approval?.status !== 'approved') throw new Error('rotation approval was not approved');
  const activated = await request(
    input.controlUrl,
    `/v1/admin/signing-keys/${encodeURIComponent(target.keyId)}/activate`,
    input.requesterToken,
    { method: 'POST', headers: { 'x-otto-approval-id': approvalId }, body: '{}' },
  );
  const active = activated.signingKeys?.find((key) => key.state === 'active');
  const retired = activated.signingKeys?.find((key) => key.keyId === previous.keyId);
  if (active?.keyId !== target.keyId || retired?.state !== 'retired') {
    throw new Error('signing-key rotation state verification failed');
  }
  let legacyLicenseVerification = null;
  if (legacyLicense) {
    const afterRotation = await request(
      input.controlUrl,
      `/v1/admin/licenses/${encodeURIComponent(input.legacyLicenseId)}`,
      input.requesterToken,
    );
    if (afterRotation.signingKeyId !== retired.keyId
      || afterRotation.signature !== legacyLicense.signature) {
      throw new Error('legacy License changed during signing-key rotation');
    }
    verifyEnvelope(afterRotation, retired.publicKeyPem);
    legacyLicenseVerification = {
      licenseId: input.legacyLicenseId,
      signingKeyId: retired.keyId,
      keyState: retired.state,
      verifiedBeforeRotation: true,
      verifiedAfterRotation: true,
    };
  }
  const auditEvidence = input.auditorToken
    ? await collectSigningAuditEvidence({
      controlUrl: input.controlUrl,
      auditorToken: input.auditorToken,
      startedAt,
      expectedEvents: [
        { action: 'signing_key.probed', targetType: 'signing_key', targetId: target.keyId },
        { action: 'admin.approval.request', targetType: 'admin_approval', targetId: approvalId },
        { action: 'admin.approval.approve', targetType: 'admin_approval', targetId: approvalId },
        { action: 'admin.approval.consume', targetType: 'admin_approval', targetId: approvalId },
        { action: 'signing_key.activated', targetType: 'signing_key', targetId: target.keyId },
      ],
    })
    : null;
  return {
    version: 1,
    drill: 'signing_key_rotation',
    startedAt,
    completedAt: new Date().toISOString(),
    result: 'passed',
    previousKeyId: previous.keyId,
    activeKeyId: active.keyId,
    targetProvider: target.provider,
    targetBackend: probe.probe.providerHealth?.backend ?? null,
    targetLocation: probe.probe.providerHealth?.activeLocation ?? null,
    approvalId,
    legacyLicenseVerification,
    auditEvidence,
  };
}

async function main() {
  const values = argumentsMap(process.argv.slice(2));
  if (required(values, 'confirm') !== 'ROTATE_OTTO_SIGNING_KEY') {
    throw new Error('--confirm=ROTATE_OTTO_SIGNING_KEY is required');
  }
  const report = await runSigningRotationDrill({
    controlUrl: httpsOrigin(required(values, 'control-url')),
    requesterToken: readToken(required(values, 'requester-token-file')),
    approverToken: readToken(required(values, 'approver-token-file')),
    auditorToken: readToken(required(values, 'auditor-token-file')),
    targetKeyId: required(values, 'target-key-id'),
    legacyLicenseId: values.get('legacy-license-id')?.trim() || null,
  });
  const output = resolve(required(values, 'output'));
  writeFileSync(output, `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  process.stdout.write(`Signing-key rotation passed; report written to ${output}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}

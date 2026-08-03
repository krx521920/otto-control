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

function verifyKeyring(envelope, publicKeyPem) {
  if (!envelope?.keyring || typeof envelope.signature !== 'string'
    || !envelope.signature.startsWith('ed25519:')) {
    throw new Error('public signing keyring envelope is invalid');
  }
  const signature = Buffer.from(envelope.signature.slice('ed25519:'.length), 'base64url');
  if (signature.length !== 64 || !verify(
    null,
    Buffer.from(JSON.stringify(canonicalize(envelope.keyring))),
    createPublicKey(publicKeyPem),
    signature,
  )) {
    throw new Error('public signing keyring signature verification failed after revocation');
  }
}

export async function runSigningRevocationDrill(input) {
  if (input.keyId === input.replacementKeyId) {
    throw new Error('replacement signing key must differ from the revoked key');
  }
  const startedAt = new Date().toISOString();
  const inventory = await request(input.controlUrl, '/v1/admin/signing-keys', input.requesterToken);
  const target = inventory.signingKeys?.find((key) => key.keyId === input.keyId);
  const replacement = inventory.signingKeys?.find((key) => key.keyId === input.replacementKeyId);
  if (!target || target.state !== 'active') throw new Error('revocation target is not active');
  if (!replacement || replacement.state === 'revoked' || !replacement.canSign) {
    throw new Error('replacement signing key is unavailable or revoked');
  }
  const probe = await request(
    input.controlUrl,
    `/v1/admin/signing-keys/${encodeURIComponent(replacement.keyId)}/probe`,
    input.requesterToken,
    { method: 'POST', body: '{}' },
  );
  if (probe.probe?.verified !== true) throw new Error('replacement signing key probe failed');
  const revocationRequest = {
    replacementKeyId: replacement.keyId,
    reason: input.reason,
  };
  const requested = await request(input.controlUrl, '/v1/admin/approvals', input.requesterToken, {
    method: 'POST',
    body: JSON.stringify({
      operation: 'signing_key.revoke',
      targetType: 'signing_key',
      targetId: target.keyId,
      request: revocationRequest,
    }),
  });
  const approvalId = requested.approval?.id;
  if (!approvalId) throw new Error('Control did not create a revocation approval');
  const approved = await request(
    input.controlUrl,
    `/v1/admin/approvals/${encodeURIComponent(approvalId)}/decide`,
    input.approverToken,
    {
      method: 'POST',
      body: JSON.stringify({ decision: 'approve', reason: 'confirmed emergency revocation drill' }),
    },
  );
  if (approved.approval?.status !== 'approved') throw new Error('revocation approval was not approved');
  const revoked = await request(
    input.controlUrl,
    `/v1/admin/signing-keys/${encodeURIComponent(target.keyId)}/revoke`,
    input.requesterToken,
    {
      method: 'POST',
      headers: { 'x-otto-approval-id': approvalId },
      body: JSON.stringify(revocationRequest),
    },
  );
  const revokedKey = revoked.signingKeys?.find((key) => key.keyId === target.keyId);
  const activeKey = revoked.signingKeys?.find((key) => key.state === 'active');
  if (revokedKey?.state !== 'revoked' || activeKey?.keyId !== replacement.keyId) {
    throw new Error('signing-key emergency revocation state verification failed');
  }
  const keyring = await request(input.controlUrl, '/v1/signing-keyring', input.requesterToken);
  if (keyring.signingKeyId !== activeKey.keyId
    || keyring.keyring?.activeKeyId !== activeKey.keyId
    || keyring.keyring?.keys?.find((key) => key.keyId === target.keyId)?.state !== 'revoked') {
    throw new Error('public signing keyring did not publish the emergency revocation');
  }
  verifyKeyring(keyring, activeKey.publicKeyPem);
  const auditEvidence = input.auditorToken
    ? await collectSigningAuditEvidence({
      controlUrl: input.controlUrl,
      auditorToken: input.auditorToken,
      startedAt,
      expectedEvents: [
        {
          action: 'signing_key.probed',
          targetType: 'signing_key',
          targetId: replacement.keyId,
        },
        { action: 'admin.approval.request', targetType: 'admin_approval', targetId: approvalId },
        { action: 'admin.approval.approve', targetType: 'admin_approval', targetId: approvalId },
        { action: 'admin.approval.consume', targetType: 'admin_approval', targetId: approvalId },
        { action: 'signing_key.revoked', targetType: 'signing_key', targetId: target.keyId },
      ],
    })
    : null;
  return {
    version: 1,
    drill: 'signing_key_emergency_revocation',
    startedAt,
    completedAt: new Date().toISOString(),
    result: 'passed',
    revokedKeyId: target.keyId,
    activeKeyId: activeKey.keyId,
    approvalId,
    reason: input.reason,
    publicKeyringVerified: true,
    auditEvidence,
  };
}

async function main() {
  const values = argumentsMap(process.argv.slice(2));
  if (required(values, 'confirm') !== 'REVOKE_OTTO_SIGNING_KEY') {
    throw new Error('--confirm=REVOKE_OTTO_SIGNING_KEY is required');
  }
  const report = await runSigningRevocationDrill({
    controlUrl: httpsOrigin(required(values, 'control-url')),
    requesterToken: readToken(required(values, 'requester-token-file')),
    approverToken: readToken(required(values, 'approver-token-file')),
    auditorToken: readToken(required(values, 'auditor-token-file')),
    keyId: required(values, 'key-id'),
    replacementKeyId: required(values, 'replacement-key-id'),
    reason: required(values, 'reason'),
  });
  const output = resolve(required(values, 'output'));
  writeFileSync(output, `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  process.stdout.write(`Signing-key revocation passed; report written to ${output}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}

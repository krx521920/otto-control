import { createPublicKey, verify } from 'node:crypto';

import type {
  ExecutionReceiptKeyRecord,
  SignedExecutionReceiptV2,
} from '../../contracts/billing.js';
import { isOttoBillingModule } from '../../contracts/billing.js';
import {
  canonicalJson,
  ed25519PublicKeyId,
  ED25519_SIGNATURE_PREFIX,
} from '../../crypto/signed-envelope.js';
import { invalidRequest, unauthorized } from '../../errors.js';

const RECEIPT_ID = /^exec_[a-f0-9]{32}$/u;
const IDENTIFIER = /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,159}$/u;
const KEY_ID = /^[a-f0-9]{16}$/u;
const SIGNATURE = /^[a-zA-Z0-9_-]{86}$/u;
const MAX_UNITS = 9_000_000_000_000;
const MAX_OFFLINE_AGE_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_FUTURE_SKEW_MS = 5 * 60 * 1000;
const RECEIPT_FIELDS = new Set([
  'version', 'receiptId', 'deploymentId', 'organizationId', 'taskId', 'moduleId',
  'units', 'model', 'issuedAtMs', 'expiresAtMs', 'sequence', 'policyVersion',
]);
const ENVELOPE_FIELDS = new Set(['receipt', 'signingKeyId', 'signature']);

function objectValue(value: unknown, name: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw invalidRequest(`${name} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exactFields(body: Record<string, unknown>, expected: Set<string>, name: string): void {
  const unknown = Object.keys(body).filter((field) => !expected.has(field));
  if (unknown.length > 0) throw invalidRequest(`${name} contains unsupported fields`);
}

function identifier(body: Record<string, unknown>, field: string): string {
  const value = typeof body[field] === 'string' ? body[field].trim() : '';
  if (!IDENTIFIER.test(value)) throw invalidRequest(`receipt.${field} is invalid`);
  return value;
}

function safeInteger(value: unknown, field: string, maximum: number): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > maximum) {
    throw invalidRequest(`receipt.${field} is invalid`);
  }
  return parsed;
}

export function normalizeExecutionReceiptEnvelope(
  raw: unknown,
  now: number,
): SignedExecutionReceiptV2 {
  const envelope = objectValue(raw, 'execution receipt envelope');
  exactFields(envelope, ENVELOPE_FIELDS, 'execution receipt envelope');
  const body = objectValue(envelope.receipt, 'receipt');
  exactFields(body, RECEIPT_FIELDS, 'receipt');
  if (body.version !== 2) throw invalidRequest('receipt.version must be 2');
  const receiptId = typeof body.receiptId === 'string' ? body.receiptId.trim() : '';
  if (!RECEIPT_ID.test(receiptId)) throw invalidRequest('receipt.receiptId is invalid');
  const moduleId = typeof body.moduleId === 'string' ? body.moduleId.trim() : '';
  if (!isOttoBillingModule(moduleId)) throw invalidRequest('receipt.moduleId is invalid');
  const model = body.model === null
    ? null
    : typeof body.model === 'string' && body.model.trim().length <= 160
      ? body.model.trim() || null
      : (() => { throw invalidRequest('receipt.model is invalid'); })();
  const issuedAtMs = safeInteger(body.issuedAtMs, 'issuedAtMs', Number.MAX_SAFE_INTEGER);
  const expiresAtMs = safeInteger(body.expiresAtMs, 'expiresAtMs', Number.MAX_SAFE_INTEGER);
  if (issuedAtMs > now + MAX_FUTURE_SKEW_MS) throw invalidRequest('execution receipt is from the future');
  if (expiresAtMs <= issuedAtMs || expiresAtMs - issuedAtMs > MAX_OFFLINE_AGE_MS) {
    throw invalidRequest('execution receipt validity window is invalid');
  }
  if (now >= expiresAtMs) throw unauthorized('execution receipt has expired');
  const policyVersion = identifier(body, 'policyVersion');
  const signingKeyId = typeof envelope.signingKeyId === 'string'
    ? envelope.signingKeyId.trim().toLowerCase()
    : '';
  if (!KEY_ID.test(signingKeyId)) throw invalidRequest('signingKeyId is invalid');
  const signatureValue = typeof envelope.signature === 'string' ? envelope.signature.trim() : '';
  if (!signatureValue.startsWith(ED25519_SIGNATURE_PREFIX)
    || !SIGNATURE.test(signatureValue.slice(ED25519_SIGNATURE_PREFIX.length))) {
    throw invalidRequest('execution receipt signature is malformed');
  }
  return {
    receipt: {
      version: 2,
      receiptId,
      deploymentId: identifier(body, 'deploymentId'),
      organizationId: identifier(body, 'organizationId'),
      taskId: identifier(body, 'taskId'),
      moduleId,
      units: safeInteger(body.units, 'units', MAX_UNITS),
      model,
      issuedAtMs,
      expiresAtMs,
      sequence: safeInteger(body.sequence, 'sequence', Number.MAX_SAFE_INTEGER),
      policyVersion,
    },
    signingKeyId,
    signature: signatureValue,
  };
}

export function normalizeExecutionReceiptPublicKey(publicKeyPem: unknown): {
  keyId: string;
  publicKeyPem: string;
} {
  if (typeof publicKeyPem !== 'string' || publicKeyPem.length > 8_192) {
    throw invalidRequest('publicKeyPem is invalid');
  }
  try {
    const key = createPublicKey(publicKeyPem.trim().replace(/\\n/gu, '\n'));
    if (key.asymmetricKeyType !== 'ed25519') throw new Error('not Ed25519');
    return {
      keyId: ed25519PublicKeyId(key),
      publicKeyPem: key.export({ format: 'pem', type: 'spki' }).toString(),
    };
  } catch {
    throw invalidRequest('execution receipt public key must be Ed25519');
  }
}

export function verifyExecutionReceipt(
  envelope: SignedExecutionReceiptV2,
  key: ExecutionReceiptKeyRecord,
): void {
  if (key.deploymentId !== envelope.receipt.deploymentId
    || key.keyId !== envelope.signingKeyId
    || key.status !== 'active') {
    throw unauthorized('execution receipt signing key is not active');
  }
  const issuedAt = new Date(envelope.receipt.issuedAtMs);
  if (issuedAt < key.notBefore || (key.expiresAt && issuedAt >= key.expiresAt)) {
    throw unauthorized('execution receipt was issued outside the key validity window');
  }
  const signature = Buffer.from(
    envelope.signature.slice(ED25519_SIGNATURE_PREFIX.length),
    'base64url',
  );
  if (signature.length !== 64 || !verify(
    null,
    Buffer.from(canonicalJson(envelope.receipt), 'utf8'),
    createPublicKey(key.publicKeyPem),
    signature,
  )) throw unauthorized('execution receipt signature is invalid');
}

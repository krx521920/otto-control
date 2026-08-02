import { createHash, createPublicKey, verify } from 'node:crypto';

import { canonicalJson, ed25519PublicKeyId, ED25519_SIGNATURE_PREFIX } from '../../crypto/signed-envelope.js';
import { invalidRequest, unauthorized } from '../../errors.js';

export function normalizeFederationPublicKey(value: unknown): {
  keyId: string;
  publicKeyPem: string;
} {
  if (typeof value !== 'string' || value.length > 8_192) {
    throw invalidRequest('publicKeyPem must be an Ed25519 public key');
  }
  let key;
  try {
    key = createPublicKey(value.trim().replace(/\\n/gu, '\n'));
  } catch {
    throw invalidRequest('publicKeyPem must be a valid PEM public key');
  }
  if (key.asymmetricKeyType !== 'ed25519') {
    throw invalidRequest('federation signing key must be Ed25519');
  }
  return {
    keyId: ed25519PublicKeyId(key),
    publicKeyPem: key.export({ format: 'pem', type: 'spki' }).toString(),
  };
}

export function verifyFederationSignature(input: {
  payload: unknown;
  signature: string;
  publicKeyPem: string;
}): void {
  if (!input.signature.startsWith(ED25519_SIGNATURE_PREFIX)) {
    throw unauthorized('federation signature must use Ed25519');
  }
  let signature: Buffer;
  try {
    signature = Buffer.from(input.signature.slice(ED25519_SIGNATURE_PREFIX.length), 'base64url');
  } catch {
    throw unauthorized('federation signature is malformed');
  }
  if (signature.length !== 64 || !verify(
    null,
    Buffer.from(canonicalJson(input.payload)),
    createPublicKey(input.publicKeyPem),
    signature,
  )) {
    throw unauthorized('federation signature is invalid');
  }
}

export function ciphertextSha256(ciphertext: string): string {
  return createHash('sha256').update(ciphertext, 'utf8').digest('hex');
}

export function claimTokenHash(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

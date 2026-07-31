import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  type KeyObject,
} from 'node:crypto';

export const ED25519_SIGNATURE_PREFIX = 'ed25519:';

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([, item]) => item !== undefined)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, item]) => [key, canonicalize(item)]),
    );
  }
  return value;
}

/** Byte-for-byte compatible with Otto's signed-envelope contract. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function normalizePrivateKey(value: string): KeyObject {
  const trimmed = value.trim().replace(/\\n/gu, '\n');
  if (trimmed.includes('BEGIN PRIVATE KEY')) return createPrivateKey(trimmed);
  return createPrivateKey({
    key: Buffer.from(trimmed, 'base64'),
    format: 'der',
    type: 'pkcs8',
  });
}

function publicKeyId(key: KeyObject): string {
  const der = key.export({ format: 'der', type: 'spki' });
  return createHash('sha256').update(der).digest('hex').slice(0, 16);
}

export interface PayloadSigner {
  readonly keyId: string;
  readonly publicKeyPem: string;
  sign(payload: unknown): Promise<string>;
}

export interface SignedPayload {
  signingKeyId: string;
  signature: string;
}

export async function signPayload(
  signer: PayloadSigner,
  payload: unknown,
): Promise<SignedPayload> {
  if ('signWithKey' in signer && typeof signer.signWithKey === 'function') {
    return signer.signWithKey(payload) as Promise<SignedPayload>;
  }
  const signingKeyId = signer.keyId;
  return { signingKeyId, signature: await signer.sign(payload) };
}

export class LocalEd25519Signer implements PayloadSigner {
  readonly keyId: string;
  readonly publicKeyPem: string;
  readonly publicKey: KeyObject;
  readonly #privateKey: KeyObject;

  constructor(privateKey: string) {
    this.#privateKey = normalizePrivateKey(privateKey);
    this.publicKey = createPublicKey(this.#privateKey);
    this.keyId = publicKeyId(this.publicKey);
    this.publicKeyPem = this.publicKey.export({ format: 'pem', type: 'spki' }).toString();
  }

  async sign(payload: unknown): Promise<string> {
    const signature = sign(
      null,
      Buffer.from(canonicalJson(payload)),
      this.#privateKey,
    );
    return `${ED25519_SIGNATURE_PREFIX}${signature.toString('base64url')}`;
  }
}

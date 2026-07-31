import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  hkdfSync,
  randomBytes,
  scrypt,
  timingSafeEqual,
} from 'node:crypto';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const SCRYPT_COST = 32768;
const SCRYPT_BLOCK_SIZE = 8;
const SCRYPT_PARALLELIZATION = 1;
const SCRYPT_KEY_LENGTH = 32;

function deriveKey(secret: string, purpose: string): Buffer {
  return Buffer.from(hkdfSync(
    'sha256',
    Buffer.from(secret, 'utf8'),
    Buffer.from('otto-control-admin-identity-v1', 'utf8'),
    Buffer.from(purpose, 'utf8'),
    32,
  ));
}

function base32Encode(bytes: Buffer): string {
  let bits = 0;
  let value = 0;
  let result = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      result += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) result += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return result;
}

function base32Decode(value: string): Buffer {
  let bits = 0;
  let accumulator = 0;
  const bytes: number[] = [];
  for (const character of value.toUpperCase().replace(/=+$/u, '')) {
    const index = BASE32_ALPHABET.indexOf(character);
    if (index < 0) throw new Error('invalid base32 secret');
    accumulator = (accumulator << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((accumulator >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

function scryptKey(password: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(password, salt, SCRYPT_KEY_LENGTH, {
      N: SCRYPT_COST,
      r: SCRYPT_BLOCK_SIZE,
      p: SCRYPT_PARALLELIZATION,
      maxmem: 64 * 1024 * 1024,
    }, (error, key) => {
      if (error) reject(error);
      else resolve(key as Buffer);
    });
  });
}

export async function hashAdminPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const digest = await scryptKey(password, salt);
  return [
    'scrypt',
    String(SCRYPT_COST),
    String(SCRYPT_BLOCK_SIZE),
    String(SCRYPT_PARALLELIZATION),
    salt.toString('base64url'),
    digest.toString('base64url'),
  ].join('$');
}

export async function verifyAdminPassword(password: string, encoded: string): Promise<boolean> {
  const [algorithm, cost, blockSize, parallelization, saltText, digestText] = encoded.split('$');
  if (
    algorithm !== 'scrypt'
    || Number(cost) !== SCRYPT_COST
    || Number(blockSize) !== SCRYPT_BLOCK_SIZE
    || Number(parallelization) !== SCRYPT_PARALLELIZATION
    || !saltText
    || !digestText
  ) return false;
  const expected = Buffer.from(digestText, 'base64url');
  const actual = await scryptKey(password, Buffer.from(saltText, 'base64url'));
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

export function generateMfaSecret(): string {
  return base32Encode(randomBytes(20));
}

export function encryptMfaSecret(secret: string, controlSecret: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', deriveKey(controlSecret, 'mfa-encryption'), iv);
  const ciphertext = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);
  return [iv, cipher.getAuthTag(), ciphertext].map((part) => part.toString('base64url')).join('.');
}

export function decryptMfaSecret(ciphertext: string, controlSecret: string): string {
  const [ivText, tagText, encryptedText] = ciphertext.split('.');
  if (!ivText || !tagText || !encryptedText) throw new Error('invalid encrypted MFA secret');
  const decipher = createDecipheriv(
    'aes-256-gcm',
    deriveKey(controlSecret, 'mfa-encryption'),
    Buffer.from(ivText, 'base64url'),
  );
  decipher.setAuthTag(Buffer.from(tagText, 'base64url'));
  return Buffer.concat([
    decipher.update(Buffer.from(encryptedText, 'base64url')),
    decipher.final(),
  ]).toString('utf8');
}

export function generateTotpCode(secret: string, timestampMs = Date.now()): string {
  const counter = Math.floor(timestampMs / 30_000);
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac('sha1', base32Decode(secret)).update(message).digest();
  const offset = digest[digest.length - 1]! & 15;
  const code = (
    ((digest[offset]! & 127) << 24)
    | ((digest[offset + 1]! & 255) << 16)
    | ((digest[offset + 2]! & 255) << 8)
    | (digest[offset + 3]! & 255)
  ) % 1_000_000;
  return String(code).padStart(6, '0');
}

export function verifyTotpCode(secret: string, code: string, timestampMs = Date.now()): boolean {
  if (!/^\d{6}$/u.test(code)) return false;
  return [-1, 0, 1].some((offset) => {
    const expected = Buffer.from(generateTotpCode(secret, timestampMs + offset * 30_000));
    const actual = Buffer.from(code);
    return expected.length === actual.length && timingSafeEqual(expected, actual);
  });
}

export function randomOpaqueToken(): string {
  return randomBytes(32).toString('base64url');
}

export function hashOpaqueToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

export function createRecoveryCodes(): string[] {
  return Array.from({ length: 10 }, () => {
    const value = base32Encode(randomBytes(10));
    return `${value.slice(0, 5)}-${value.slice(5, 10)}-${value.slice(10, 15)}-${value.slice(15, 20)}`;
  });
}

export function hashRecoveryCode(code: string, controlSecret: string): string {
  return createHmac('sha256', deriveKey(controlSecret, 'recovery-code-pepper'))
    .update(code.trim().toUpperCase(), 'utf8')
    .digest('hex');
}

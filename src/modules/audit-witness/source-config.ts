import { createHash, createPublicKey, type KeyObject } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';

import { ed25519PublicKeyId } from '../../crypto/signed-envelope.js';

const MAX_CONFIG_BYTES = 64 * 1024;
const MAX_SECRET_BYTES = 4 * 1024;
const SOURCE_ID = /^[a-z][a-z0-9_-]{1,63}$/u;

export interface AuditWitnessSource {
  id: string;
  issuer: string;
  tokenHash: Buffer;
  publicKeys: ReadonlyMap<string, KeyObject>;
}

interface SourceDocument {
  id?: unknown;
  issuer?: unknown;
  tokenFile?: unknown;
  publicKeyFiles?: unknown;
  enabled?: unknown;
}

function regularFile(path: string, maximumBytes: number, label: string): void {
  let metadata: ReturnType<typeof statSync>;
  try {
    metadata = statSync(path);
  } catch {
    throw new Error(`${label} could not be read`);
  }
  if (!metadata.isFile() || metadata.size < 1 || metadata.size > maximumBytes) {
    throw new Error(`${label} must be a regular file no larger than ${maximumBytes} bytes`);
  }
}

function filePath(baseDirectory: string, value: unknown, label: string): string {
  if (typeof value !== 'string' || !value.trim()) throw new Error(`${label} is required`);
  const normalized = value.trim();
  return isAbsolute(normalized) ? normalized : resolve(baseDirectory, normalized);
}

function issuerUrl(value: unknown): string {
  if (typeof value !== 'string' || !value.trim()) throw new Error('audit witness issuer is required');
  let url: URL;
  try {
    url = new URL(value.trim());
  } catch {
    throw new Error('audit witness issuer must be an absolute HTTPS URL');
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) {
    throw new Error('audit witness issuer must use HTTPS without credentials, query, or fragment');
  }
  return url.toString().replace(/\/$/u, '');
}

function tokenHash(path: string): Buffer {
  regularFile(path, MAX_SECRET_BYTES, 'audit witness token file');
  const token = readFileSync(path, 'utf8').trim();
  if (Buffer.byteLength(token, 'utf8') < 32 || /\s/u.test(token)) {
    throw new Error('audit witness token must contain at least 32 bytes without whitespace');
  }
  return createHash('sha256').update(token, 'utf8').digest();
}

function publicKeys(baseDirectory: string, value: unknown): ReadonlyMap<string, KeyObject> {
  if (!Array.isArray(value) || value.length < 1 || value.length > 16) {
    throw new Error('audit witness publicKeyFiles must contain 1-16 paths');
  }
  const result = new Map<string, KeyObject>();
  for (const [index, item] of value.entries()) {
    const path = filePath(baseDirectory, item, `audit witness publicKeyFiles[${index}]`);
    regularFile(path, MAX_SECRET_BYTES, 'audit witness public key file');
    let key: KeyObject;
    try {
      key = createPublicKey(readFileSync(path, 'utf8'));
    } catch {
      throw new Error('audit witness public key file is not a valid public key');
    }
    if (key.asymmetricKeyType !== 'ed25519') {
      throw new Error('audit witness public keys must use Ed25519');
    }
    const keyId = ed25519PublicKeyId(key);
    if (result.has(keyId)) throw new Error('audit witness public keys must be unique');
    result.set(keyId, key);
  }
  return result;
}

export function loadAuditWitnessSources(path: string | null | undefined): AuditWitnessSource[] {
  if (!path) return [];
  regularFile(path, MAX_CONFIG_BYTES, 'audit witness sources file');
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, 'utf8')) as unknown;
  } catch {
    throw new Error('audit witness sources file must contain valid JSON');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('audit witness sources file must contain a JSON object');
  }
  const document = parsed as { version?: unknown; sources?: unknown };
  if (document.version !== 1 || !Array.isArray(document.sources)
    || document.sources.length > 100) {
    throw new Error('audit witness sources file must be version 1 with at most 100 sources');
  }
  const baseDirectory = dirname(path);
  const ids = new Set<string>();
  const issuers = new Set<string>();
  const tokenHashes = new Set<string>();
  const sources: AuditWitnessSource[] = [];
  for (const item of document.sources) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) {
      throw new Error('audit witness source entries must be objects');
    }
    const raw = item as SourceDocument;
    if (raw.enabled === false) continue;
    if (raw.enabled !== undefined && raw.enabled !== true) {
      throw new Error('audit witness source enabled must be a boolean');
    }
    if (typeof raw.id !== 'string' || !SOURCE_ID.test(raw.id)) {
      throw new Error('audit witness source id is invalid');
    }
    const issuer = issuerUrl(raw.issuer);
    const hash = tokenHash(filePath(baseDirectory, raw.tokenFile, 'audit witness tokenFile'));
    const hashHex = hash.toString('hex');
    if (ids.has(raw.id) || issuers.has(issuer) || tokenHashes.has(hashHex)) {
      throw new Error('audit witness source ids, issuers, and tokens must be unique');
    }
    ids.add(raw.id);
    issuers.add(issuer);
    tokenHashes.add(hashHex);
    sources.push({
      id: raw.id,
      issuer,
      tokenHash: hash,
      publicKeys: publicKeys(baseDirectory, raw.publicKeyFiles),
    });
  }
  return sources;
}

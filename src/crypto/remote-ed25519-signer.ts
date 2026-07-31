import {
  createPublicKey,
  randomUUID,
  verify,
  type KeyObject,
} from 'node:crypto';
import { request as httpsRequest, type RequestOptions } from 'node:https';
import type { IncomingMessage } from 'node:http';

import {
  canonicalJson,
  ED25519_SIGNATURE_PREFIX,
  ed25519PublicKeyId,
  type PayloadSigner,
  type SignerHealth,
} from './signed-envelope.js';

const MAX_RESPONSE_BYTES = 32 * 1024;
const MAX_SIGNING_PAYLOAD_BYTES = 1024 * 1024;
const CIRCUIT_FAILURE_THRESHOLD = 3;
const CIRCUIT_OPEN_MS = 30_000;
const KEY_REF_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9_.:/@-]{0,255}$/u;

export type RemoteSigningProvider = 'kms' | 'hsm';

export interface RemoteSigningRequest {
  version: 1;
  requestId: string;
  keyId: string;
  keyRef: string;
  algorithm: 'ed25519';
  encoding: 'base64';
  payload: string;
}

export interface RemoteSigningResponse {
  version: 1;
  requestId: string;
  keyId: string;
  algorithm: 'ed25519';
  signature: string;
}

export interface RemoteSigningTransport {
  sign(request: RemoteSigningRequest): Promise<unknown>;
}

export interface HttpsRemoteSigningTransportOptions {
  endpoint: string;
  timeoutMs?: number;
  bearerToken?: () => Promise<string>;
  certificate?: string | Buffer;
  privateKey?: string | Buffer;
  certificateAuthority?: string | Buffer;
}

function parseEndpoint(value: string): URL {
  let endpoint: URL;
  try {
    endpoint = new URL(value);
  } catch {
    throw new Error('remote signing endpoint must be a valid HTTPS URL');
  }
  if (endpoint.protocol !== 'https:' || endpoint.username || endpoint.password || endpoint.hash) {
    throw new Error('remote signing endpoint must be an HTTPS URL without credentials or fragments');
  }
  return endpoint;
}

function readJsonResponse(response: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let exceeded = false;
    response.on('data', (chunk: Buffer | string) => {
      if (exceeded) return;
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      size += bytes.length;
      if (size > MAX_RESPONSE_BYTES) {
        exceeded = true;
        reject(new Error('remote signing response exceeds 32 KiB'));
        response.destroy();
        return;
      }
      chunks.push(bytes);
    });
    response.on('end', () => {
      if (exceeded) return;
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(new Error('remote signing response is not valid JSON'));
      }
    });
    response.on('error', reject);
  });
}

export class HttpsRemoteSigningTransport implements RemoteSigningTransport {
  readonly #endpoint: URL;
  readonly #timeoutMs: number;
  readonly #bearerToken?: () => Promise<string>;
  readonly #tls: Pick<RequestOptions, 'ca' | 'cert' | 'key'>;

  constructor(options: HttpsRemoteSigningTransportOptions) {
    this.#endpoint = parseEndpoint(options.endpoint);
    this.#timeoutMs = options.timeoutMs ?? 5_000;
    if (!Number.isInteger(this.#timeoutMs) || this.#timeoutMs < 500 || this.#timeoutMs > 30_000) {
      throw new Error('remote signing timeout must be between 500 and 30000 milliseconds');
    }
    const hasCertificate = Boolean(options.certificate);
    const hasPrivateKey = Boolean(options.privateKey);
    if (hasCertificate !== hasPrivateKey) {
      throw new Error('remote signing mTLS certificate and private key must be configured together');
    }
    if (!options.bearerToken && !hasCertificate) {
      throw new Error('remote signing requires a bearer token or mTLS client identity');
    }
    this.#bearerToken = options.bearerToken;
    this.#tls = {
      ca: options.certificateAuthority,
      cert: options.certificate,
      key: options.privateKey,
    };
  }

  async sign(request: RemoteSigningRequest): Promise<unknown> {
    const body = Buffer.from(JSON.stringify(request), 'utf8');
    const token = (await this.#bearerToken?.())?.trim();
    if (this.#bearerToken && !token) throw new Error('remote signing bearer token is empty');
    return new Promise((resolve, reject) => {
      const call = httpsRequest(this.#endpoint, {
        method: 'POST',
        headers: {
          accept: 'application/json',
          'content-type': 'application/json',
          'content-length': String(body.length),
          ...(token ? { authorization: `Bearer ${token}` } : {}),
        },
        ...this.#tls,
      }, async (response) => {
        try {
          if (response.statusCode !== 200) {
            response.resume();
            reject(new Error(`remote signing service returned HTTP ${response.statusCode ?? 0}`));
            return;
          }
          const contentType = String(response.headers['content-type'] ?? '').toLowerCase();
          if (!contentType.startsWith('application/json')) {
            response.resume();
            reject(new Error('remote signing service returned an unexpected content type'));
            return;
          }
          resolve(await readJsonResponse(response));
        } catch (error) {
          reject(error);
        }
      });
      call.setTimeout(this.#timeoutMs, () => {
        call.destroy(new Error('remote signing request timed out'));
      });
      call.on('error', reject);
      call.end(body);
    });
  }
}

export interface RemoteEd25519SignerOptions {
  provider: RemoteSigningProvider;
  keyRef: string;
  publicKeyPem: string;
  transport: RemoteSigningTransport;
  now?: () => number;
}

export class RemoteEd25519Signer implements PayloadSigner {
  readonly keyId: string;
  readonly publicKeyPem: string;
  readonly provider: RemoteSigningProvider;
  readonly keyRef: string;
  readonly #publicKey: KeyObject;
  readonly #transport: RemoteSigningTransport;
  readonly #now: () => number;
  #consecutiveFailures = 0;
  #circuitOpenUntil = 0;
  #hasSucceeded = false;

  constructor(options: RemoteEd25519SignerOptions) {
    if (!KEY_REF_PATTERN.test(options.keyRef)) throw new Error('remote signing keyRef is invalid');
    this.#publicKey = createPublicKey(options.publicKeyPem.trim().replace(/\\n/gu, '\n'));
    if (this.#publicKey.asymmetricKeyType !== 'ed25519') {
      throw new Error('remote signing public key must be Ed25519');
    }
    this.keyId = ed25519PublicKeyId(this.#publicKey);
    this.publicKeyPem = this.#publicKey.export({ format: 'pem', type: 'spki' }).toString();
    this.provider = options.provider;
    this.keyRef = options.keyRef;
    this.#transport = options.transport;
    this.#now = options.now ?? Date.now;
  }

  health(): SignerHealth {
    const now = this.#now();
    return {
      state: this.#circuitOpenUntil > now
        ? 'circuit_open'
        : this.#consecutiveFailures > 0
          ? 'degraded'
          : this.#hasSucceeded ? 'available' : 'unchecked',
      consecutiveFailures: this.#consecutiveFailures,
      circuitOpenUntil: this.#circuitOpenUntil > now
        ? new Date(this.#circuitOpenUntil).toISOString()
        : null,
    };
  }

  async sign(payload: unknown): Promise<string> {
    const now = this.#now();
    if (this.#circuitOpenUntil > now) {
      throw new Error('remote signing circuit is open after repeated provider failures');
    }
    const message = Buffer.from(canonicalJson(payload), 'utf8');
    if (message.length > MAX_SIGNING_PAYLOAD_BYTES) {
      throw new Error('remote signing payload exceeds 1 MiB');
    }
    const request: RemoteSigningRequest = {
      version: 1,
      requestId: randomUUID(),
      keyId: this.keyId,
      keyRef: this.keyRef,
      algorithm: 'ed25519',
      encoding: 'base64',
      payload: message.toString('base64'),
    };
    try {
      const response = this.#parseResponse(await this.#transport.sign(request), request.requestId);
      const signature = Buffer.from(response.signature, 'base64url');
      if (signature.length !== 64 || !verify(null, message, this.#publicKey, signature)) {
        throw new Error('remote signing service returned a signature that failed local verification');
      }
      this.#consecutiveFailures = 0;
      this.#circuitOpenUntil = 0;
      this.#hasSucceeded = true;
      return `${ED25519_SIGNATURE_PREFIX}${signature.toString('base64url')}`;
    } catch (error) {
      this.#consecutiveFailures += 1;
      if (this.#consecutiveFailures >= CIRCUIT_FAILURE_THRESHOLD) {
        this.#circuitOpenUntil = now + CIRCUIT_OPEN_MS;
      }
      throw error;
    }
  }

  #parseResponse(value: unknown, requestId: string): RemoteSigningResponse {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new Error('remote signing response must be an object');
    }
    const response = value as Partial<RemoteSigningResponse>;
    if (
      response.version !== 1
      || response.requestId !== requestId
      || response.keyId !== this.keyId
      || response.algorithm !== 'ed25519'
      || typeof response.signature !== 'string'
      || !/^[a-zA-Z0-9_-]{86}$/u.test(response.signature)
    ) {
      throw new Error('remote signing response binding is invalid');
    }
    return response as RemoteSigningResponse;
  }
}

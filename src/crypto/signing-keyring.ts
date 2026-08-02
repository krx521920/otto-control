import { createPublicKey, randomBytes, verify } from 'node:crypto';

import {
  canonicalJson,
  ED25519_SIGNATURE_PREFIX,
  type PayloadSigner,
  type SignedPayload,
  type SignerHealth,
} from './signed-envelope.js';
import { conflict, notFound, unauthorized } from '../errors.js';
import type {
  ControlStore,
  SigningKeyProvider,
  SigningKeyRecord,
  SigningKeyTransition,
} from '../storage/control-store.js';

export interface SigningProviderHandle {
  signer: PayloadSigner;
  provider: SigningKeyProvider;
}

export interface PublicSigningKey extends SigningKeyRecord {
  canSign: boolean;
  providerHealth: SignerHealth | null;
}

export interface SigningKeyProbeResult {
  keyId: string;
  verified: true;
  probedAt: string;
  providerHealth: SignerHealth;
}

export interface SignedKeyringPayload {
  version: 1;
  activeKeyId: string;
  revisionMs: number;
  generatedAtMs: number;
  expiresAtMs: number;
  keys: Array<{
    keyId: string;
    algorithm: 'ed25519';
    publicKeyPem: string;
    provider: SigningKeyProvider;
    state: SigningKeyRecord['state'];
    activatedAt: string | null;
    retiredAt: string | null;
    revokedAt: string | null;
  }>;
}

export interface SignedKeyringEnvelope {
  keyring: SignedKeyringPayload;
  signingKeyId: string;
  signature: string;
}

export class ManagedSigningKeyring implements PayloadSigner {
  readonly #store: ControlStore;
  readonly #providers: ReadonlyMap<string, SigningProviderHandle>;
  #activeKeyId: string;

  private constructor(options: {
    store: ControlStore;
    providers: ReadonlyMap<string, SigningProviderHandle>;
    activeKeyId: string;
  }) {
    this.#store = options.store;
    this.#providers = options.providers;
    this.#activeKeyId = options.activeKeyId;
  }

  static async create(options: {
    store: ControlStore;
    providers: SigningProviderHandle[];
    preferredActiveKeyId?: string | null;
    now?: () => number;
  }): Promise<ManagedSigningKeyring> {
    if (options.providers.length === 0) throw new Error('at least one signing provider is required');
    const providers = new Map<string, SigningProviderHandle>();
    for (const handle of options.providers) {
      if (providers.has(handle.signer.keyId)) {
        throw new Error(`duplicate signing key: ${handle.signer.keyId}`);
      }
      providers.set(handle.signer.keyId, handle);
      await options.store.registerSigningKey({
        keyId: handle.signer.keyId,
        publicKeyPem: handle.signer.publicKeyPem,
        provider: handle.provider,
      });
    }

    const records = await options.store.listSigningKeys();
    let active = records.find((key) => key.state === 'active') ?? null;
    if (!active) {
      const preferred = options.preferredActiveKeyId || options.providers[0]!.signer.keyId;
      if (!providers.has(preferred)) {
        throw new Error(`preferred active signing key is unavailable: ${preferred}`);
      }
      const transition = await options.store.activateSigningKey(
        preferred,
        new Date((options.now ?? Date.now)()),
      );
      active = transition?.activeKey ?? null;
    }
    if (!active) throw new Error('signing keyring has no active key');
    if (!providers.has(active.keyId)) {
      throw new Error(`active signing key provider is unavailable: ${active.keyId}`);
    }
    return new ManagedSigningKeyring({
      store: options.store,
      providers,
      activeKeyId: active.keyId,
    });
  }

  get keyId(): string {
    return this.#activeKeyId;
  }

  get publicKeyPem(): string {
    return this.#requireProvider(this.#activeKeyId).signer.publicKeyPem;
  }

  async sign(payload: unknown): Promise<string> {
    return (await this.signWithKey(payload)).signature;
  }

  async signWithKey(payload: unknown): Promise<SignedPayload> {
    const signingKeyId = await this.#refreshActiveKeyId();
    const provider = this.#requireProvider(signingKeyId);
    return { signingKeyId, signature: await provider.signer.sign(payload) };
  }

  async list(): Promise<PublicSigningKey[]> {
    return (await this.#store.listSigningKeys()).map((key) => ({
      ...key,
      canSign: this.#providers.has(key.keyId),
      providerHealth: this.#providers.get(key.keyId)?.signer.health?.() ?? (
        this.#providers.has(key.keyId)
          ? { state: 'available', consecutiveFailures: 0, circuitOpenUntil: null }
          : null
      ),
    }));
  }

  async activate(keyId: string): Promise<SigningKeyTransition> {
    await this.probe(keyId);
    const transition = await this.#store.activateSigningKey(keyId, new Date());
    if (!transition) throw notFound('signing key not found');
    this.#activeKeyId = transition.activeKey!.keyId;
    return transition;
  }

  async probe(keyId: string): Promise<SigningKeyProbeResult> {
    const key = await this.#store.getSigningKey(keyId);
    if (!key) throw notFound('signing key not found');
    if (key.state === 'revoked') throw conflict('revoked signing key cannot be probed');
    const provider = this.#requireProvider(keyId);
    const configuredPublicKey = createPublicKey(provider.signer.publicKeyPem);
    const storedPublicKey = createPublicKey(key.publicKeyPem);
    if (!Buffer.from(configuredPublicKey.export({ format: 'der', type: 'spki' })).equals(
      Buffer.from(storedPublicKey.export({ format: 'der', type: 'spki' })),
    )) {
      throw conflict(`signing provider public key does not match registered key ${keyId}`);
    }
    const probedAt = new Date().toISOString();
    const payload = {
      version: 1,
      purpose: 'otto-control-signing-key-probe',
      keyId,
      challenge: randomBytes(32).toString('base64url'),
      probedAt,
    };
    const signature = await provider.signer.sign(payload);
    if (!signature.startsWith(ED25519_SIGNATURE_PREFIX)) {
      throw conflict(`signing provider returned an unsupported signature for key ${keyId}`);
    }
    const signatureBytes = Buffer.from(signature.slice(ED25519_SIGNATURE_PREFIX.length), 'base64url');
    if (signatureBytes.length !== 64 || !verify(
      null,
      Buffer.from(canonicalJson(payload)),
      configuredPublicKey,
      signatureBytes,
    )) {
      throw conflict(`signing provider probe verification failed for key ${keyId}`);
    }
    return {
      keyId,
      verified: true,
      probedAt,
      providerHealth: provider.signer.health?.() ?? {
        state: 'available',
        consecutiveFailures: 0,
        circuitOpenUntil: null,
      },
    };
  }

  async retire(keyId: string): Promise<SigningKeyTransition> {
    const transition = await this.#store.retireSigningKey(keyId, new Date());
    if (!transition) throw notFound('signing key not found');
    return transition;
  }

  async revoke(input: {
    keyId: string;
    replacementKeyId: string | null;
    reason: string;
  }): Promise<SigningKeyTransition> {
    const current = await this.#store.getSigningKey(input.keyId);
    if (!current) throw notFound('signing key not found');
    if (current.state === 'active') {
      if (!input.replacementKeyId) {
        throw conflict('revoking the active key requires a replacementKeyId');
      }
      this.#requireProvider(input.replacementKeyId);
    }
    const transition = await this.#store.revokeSigningKey({
      ...input,
      changedAt: new Date(),
    });
    if (!transition) throw notFound('signing key not found');
    if (transition.activeKey) this.#activeKeyId = transition.activeKey.keyId;
    return transition;
  }

  async assertLicenseSigningKeyUsable(keyId: string): Promise<void> {
    const key = await this.#store.getSigningKey(keyId);
    if (!key || key.state === 'revoked') {
      throw unauthorized('License signing key has been revoked or is unknown');
    }
  }

  async publicEnvelope(now = Date.now()): Promise<SignedKeyringEnvelope> {
    const keys = await this.list();
    const active = keys.find((key) => key.state === 'active');
    if (!active) throw new Error('signing keyring has no active key');
    const provider = this.#requireProvider(active.keyId);
    this.#activeKeyId = active.keyId;
    const keyring: SignedKeyringPayload = {
      version: 1,
      activeKeyId: active.keyId,
      revisionMs: Math.max(...keys.map((key) => key.updatedAt.getTime())),
      generatedAtMs: now,
      expiresAtMs: now + 10 * 60 * 1000,
      keys: keys.map((key) => ({
        keyId: key.keyId,
        algorithm: key.algorithm,
        publicKeyPem: key.publicKeyPem,
        provider: key.provider,
        state: key.state,
        activatedAt: key.activatedAt?.toISOString() ?? null,
        retiredAt: key.retiredAt?.toISOString() ?? null,
        revokedAt: key.revokedAt?.toISOString() ?? null,
      })),
    };
    return {
      keyring,
      signingKeyId: active.keyId,
      signature: await provider.signer.sign(keyring),
    };
  }

  async #refreshActiveKeyId(): Promise<string> {
    const active = (await this.#store.listSigningKeys()).find((key) => key.state === 'active');
    if (!active) throw new Error('signing keyring has no active key');
    this.#requireProvider(active.keyId);
    this.#activeKeyId = active.keyId;
    return active.keyId;
  }

  #requireProvider(keyId: string): SigningProviderHandle {
    const provider = this.#providers.get(keyId);
    if (!provider) throw conflict(`signing provider is unavailable for key ${keyId}`);
    return provider;
  }
}

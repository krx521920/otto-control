import { readFile } from 'node:fs/promises';
import { dirname, isAbsolute, resolve } from 'node:path';

import type { ControlConfig } from '../config.js';
import {
  HttpsRemoteSigningTransport,
  RemoteEd25519Signer,
} from './remote-ed25519-signer.js';
import { LocalEd25519Signer } from './signed-envelope.js';
import type { SigningProviderHandle } from './signing-keyring.js';

interface LocalKeyEntry {
  provider: 'local';
  privateKeyFile: string;
}

interface RemoteKeyEntry {
  provider: 'kms' | 'hsm';
  endpoint: string;
  keyRef: string;
  publicKeyFile: string;
  bearerTokenFile?: string;
  clientCertificateFile?: string;
  clientKeyFile?: string;
  caFile?: string;
  timeoutMs?: number;
}

interface KeyringManifest {
  version: 1;
  activeKeyId?: string;
  keys: Array<LocalKeyEntry | RemoteKeyEntry>;
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && Boolean(value.trim());
}

function validateRemoteEntry(entry: Record<string, unknown>): void {
  if (
    (entry.provider !== 'kms' && entry.provider !== 'hsm')
    || !nonEmptyString(entry.endpoint)
    || !nonEmptyString(entry.keyRef)
    || !nonEmptyString(entry.publicKeyFile)
  ) {
    throw new Error('signing keyring manifest contains an invalid KMS/HSM provider');
  }
  const optionalFiles = [
    entry.bearerTokenFile,
    entry.clientCertificateFile,
    entry.clientKeyFile,
    entry.caFile,
  ];
  if (optionalFiles.some((value) => value !== undefined && !nonEmptyString(value))) {
    throw new Error('signing keyring KMS/HSM credential paths must be non-empty strings');
  }
  const hasCertificate = nonEmptyString(entry.clientCertificateFile);
  const hasPrivateKey = nonEmptyString(entry.clientKeyFile);
  if (hasCertificate !== hasPrivateKey) {
    throw new Error('signing keyring KMS/HSM mTLS certificate and key must be configured together');
  }
  if (!nonEmptyString(entry.bearerTokenFile) && !hasCertificate) {
    throw new Error('signing keyring KMS/HSM provider requires bearerTokenFile or mTLS');
  }
  if (entry.timeoutMs !== undefined && (
    !Number.isInteger(entry.timeoutMs)
    || Number(entry.timeoutMs) < 500
    || Number(entry.timeoutMs) > 30_000
  )) {
    throw new Error('signing keyring KMS/HSM timeoutMs must be between 500 and 30000');
  }
}

function parseManifest(raw: string): KeyringManifest {
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    throw new Error('CONTROL_SIGNER_KEYRING_FILE must contain valid JSON');
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('signing keyring manifest must be an object');
  }
  const manifest = value as Partial<KeyringManifest>;
  if (manifest.version !== 1 || !Array.isArray(manifest.keys) || manifest.keys.length === 0) {
    throw new Error('signing keyring manifest must use version 1 and contain keys');
  }
  for (const key of manifest.keys) {
    if (!key || typeof key !== 'object' || Array.isArray(key)) {
      throw new Error('signing keyring manifest contains an invalid provider');
    }
    const entry = key as unknown as Record<string, unknown>;
    if (entry.provider === undefined || entry.provider === 'local') {
      if (!nonEmptyString(entry.privateKeyFile)) {
        throw new Error('signing keyring manifest contains an invalid local provider');
      }
    } else {
      validateRemoteEntry(entry);
    }
  }
  if (manifest.activeKeyId !== undefined && (
    typeof manifest.activeKeyId !== 'string' || !/^[a-f0-9]{16}$/u.test(manifest.activeKeyId)
  )) {
    throw new Error('signing keyring activeKeyId must be a 16-character hex key id');
  }
  return {
    ...manifest,
    keys: manifest.keys.map((key) => ({
      ...key,
      provider: key.provider ?? 'local',
    })),
  } as KeyringManifest;
}

function filePath(manifestPath: string, configuredPath: string): string {
  return isAbsolute(configuredPath)
    ? configuredPath
    : resolve(dirname(manifestPath), configuredPath);
}

async function optionalFile(
  manifestPath: string,
  configuredPath: string | undefined,
): Promise<Buffer | undefined> {
  return configuredPath
    ? readFile(filePath(manifestPath, configuredPath.trim()))
    : undefined;
}

export async function loadSigningProviders(config: Readonly<ControlConfig>): Promise<{
  providers: SigningProviderHandle[];
  preferredActiveKeyId: string | null;
}> {
  if (config.signerKeyringFile) {
    const manifestPath = resolve(config.signerKeyringFile);
    const manifest = parseManifest(await readFile(manifestPath, 'utf8'));
    const providers: SigningProviderHandle[] = [];
    for (const entry of manifest.keys) {
      if (entry.provider === 'local') {
        providers.push({
          provider: 'local',
          signer: new LocalEd25519Signer(await readFile(
            filePath(manifestPath, entry.privateKeyFile.trim()),
            'utf8',
          )),
        });
        continue;
      }
      const bearerTokenPath = entry.bearerTokenFile
        ? filePath(manifestPath, entry.bearerTokenFile.trim())
        : null;
      const transport = new HttpsRemoteSigningTransport({
        endpoint: entry.endpoint,
        timeoutMs: entry.timeoutMs,
        bearerToken: bearerTokenPath
          ? async () => readFile(bearerTokenPath, 'utf8')
          : undefined,
        certificate: await optionalFile(manifestPath, entry.clientCertificateFile),
        privateKey: await optionalFile(manifestPath, entry.clientKeyFile),
        certificateAuthority: await optionalFile(manifestPath, entry.caFile),
      });
      providers.push({
        provider: entry.provider,
        signer: new RemoteEd25519Signer({
          provider: entry.provider,
          keyRef: entry.keyRef,
          publicKeyPem: await readFile(
            filePath(manifestPath, entry.publicKeyFile.trim()),
            'utf8',
          ),
          transport,
        }),
      });
    }
    return {
      providers,
      preferredActiveKeyId: manifest.activeKeyId ?? null,
    };
  }

  if (!config.signerPrivateKeyFile) throw new Error('signing provider is not configured');
  return {
    providers: [{
      provider: 'local',
      signer: new LocalEd25519Signer(await readFile(config.signerPrivateKeyFile, 'utf8')),
    }],
    preferredActiveKeyId: null,
  };
}

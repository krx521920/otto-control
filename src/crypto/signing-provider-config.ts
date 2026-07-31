import { readFile } from 'node:fs/promises';
import { dirname, isAbsolute, resolve } from 'node:path';

import type { ControlConfig } from '../config.js';
import { LocalEd25519Signer } from './signed-envelope.js';
import type { SigningProviderHandle } from './signing-keyring.js';

interface KeyringManifest {
  version: 1;
  activeKeyId?: string;
  keys: Array<{
    provider?: 'local';
    privateKeyFile: string;
  }>;
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
    if (
      !key || typeof key !== 'object' ||
      (key.provider !== undefined && key.provider !== 'local') ||
      typeof key.privateKeyFile !== 'string' || !key.privateKeyFile.trim()
    ) {
      throw new Error('signing keyring manifest contains an invalid local provider');
    }
  }
  if (manifest.activeKeyId !== undefined && (
    typeof manifest.activeKeyId !== 'string' || !/^[a-f0-9]{16}$/u.test(manifest.activeKeyId)
  )) {
    throw new Error('signing keyring activeKeyId must be a 16-character hex key id');
  }
  return manifest as KeyringManifest;
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
      const configuredPath = entry.privateKeyFile.trim();
      const privateKeyPath = isAbsolute(configuredPath)
        ? configuredPath
        : resolve(dirname(manifestPath), configuredPath);
      providers.push({
        provider: 'local',
        signer: new LocalEd25519Signer(await readFile(privateKeyPath, 'utf8')),
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

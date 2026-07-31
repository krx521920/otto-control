import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { loadControlConfig } from '../src/config.js';
import { loadSigningProviders } from '../src/crypto/signing-provider-config.js';

describe('signing provider configuration', () => {
  it('loads multiple local providers from a versioned manifest', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'otto-signing-keyring-'));
    try {
      const keyFiles = ['current.pem', 'next.pem'];
      for (const keyFile of keyFiles) {
        const pair = generateKeyPairSync('ed25519');
        writeFileSync(
          join(directory, keyFile),
          pair.privateKey.export({ format: 'pem', type: 'pkcs8' }),
        );
      }
      const manifestPath = join(directory, 'keyring.json');
      writeFileSync(manifestPath, JSON.stringify({
        version: 1,
        keys: keyFiles.map((privateKeyFile) => ({ provider: 'local', privateKeyFile })),
      }));

      const loaded = await loadSigningProviders(loadControlConfig({
        CONTROL_SIGNER_KEYRING_FILE: manifestPath,
      }));
      expect(loaded.providers).toHaveLength(2);
      expect(new Set(loaded.providers.map((provider) => provider.signer.keyId)).size).toBe(2);
      expect(loaded.providers.every((provider) => provider.provider === 'local')).toBe(true);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});

import { generateKeyPairSync, sign as ed25519Sign, verify } from 'node:crypto';
import type { KeyObject } from 'node:crypto';

import {
  DescribeKeyCommand,
  GetPublicKeyCommand,
  SignCommand,
} from '@aws-sdk/client-kms';
import { describe, expect, it, vi } from 'vitest';

import {
  AwsKmsEd25519Signer,
  resolveAwsKmsWorkloadIdentitySource,
  type AwsKmsClientLike,
} from '../src/crypto/aws-kms-ed25519-signer.js';
import { canonicalJson } from '../src/crypto/signed-envelope.js';

const ACCOUNT_ID = '111122223333';
const MULTI_REGION_KEY_ID = `mrk-${'a'.repeat(32)}`;

function keyArn(region: string, keyId = MULTI_REGION_KEY_ID): string {
  return `arn:aws:kms:${region}:${ACCOUNT_ID}:key/${keyId}`;
}

function kmsClient(options: {
  region: string;
  privateKey: KeyObject;
  publicKey: KeyObject;
  failSigning?: boolean;
  permissionDenied?: boolean;
  keySpec?: string;
}): AwsKmsClientLike & { send: ReturnType<typeof vi.fn> } {
  const arn = keyArn(options.region);
  const send = vi.fn(async (command: unknown) => {
    if (command instanceof DescribeKeyCommand) {
      return {
        KeyMetadata: {
          Arn: arn,
          KeyId: MULTI_REGION_KEY_ID,
          AWSAccountId: ACCOUNT_ID,
          Enabled: true,
          KeyState: 'Enabled',
          KeyUsage: 'SIGN_VERIFY',
          KeySpec: options.keySpec ?? 'ECC_NIST_EDWARDS25519',
          Origin: 'AWS_KMS',
          KeyManager: 'CUSTOMER',
          MultiRegion: true,
          SigningAlgorithms: ['ED25519_SHA_512'],
        },
      };
    }
    if (command instanceof GetPublicKeyCommand) {
      return {
        KeyId: arn,
        KeyUsage: 'SIGN_VERIFY',
        KeySpec: options.keySpec ?? 'ECC_NIST_EDWARDS25519',
        SigningAlgorithms: ['ED25519_SHA_512'],
        PublicKey: options.publicKey.export({ format: 'der', type: 'spki' }),
      };
    }
    if (command instanceof SignCommand) {
      if (command.input.DryRun) {
        const error = new Error(options.permissionDenied ? 'denied' : 'dry run accepted');
        error.name = options.permissionDenied ? 'AccessDeniedException' : 'DryRunOperationException';
        throw error;
      }
      if (options.failSigning) throw new Error(`${options.region} unavailable`);
      const message = Buffer.from(command.input.Message!);
      return {
        KeyId: arn,
        SigningAlgorithm: 'ED25519_SHA_512',
        Signature: ed25519Sign(null, message, options.privateKey),
      };
    }
    throw new Error('unexpected AWS KMS command');
  });
  return { send };
}

describe('native AWS KMS Ed25519 signer', () => {
  it('accepts workload identities but rejects static AWS credentials', () => {
    expect(resolveAwsKmsWorkloadIdentitySource({
      AWS_WEB_IDENTITY_TOKEN_FILE: '/var/run/secrets/eks.amazonaws.com/token',
      AWS_ROLE_ARN: 'arn:aws:iam::111122223333:role/otto-control',
    })).toBe('web_identity');
    expect(resolveAwsKmsWorkloadIdentitySource({
      AWS_CONTAINER_CREDENTIALS_RELATIVE_URI: '/v2/credentials/task',
    })).toBe('container');
    expect(resolveAwsKmsWorkloadIdentitySource({
      AWS_ACCESS_KEY_ID: 'ASIAEXAMPLE',
      AWS_SECRET_ACCESS_KEY: 'ephemeral-secret',
      AWS_SESSION_TOKEN: 'oidc-derived-session-token',
    })).toBe('temporary_environment');
    expect(resolveAwsKmsWorkloadIdentitySource({})).toBe('instance_metadata');
    expect(() => resolveAwsKmsWorkloadIdentitySource({
      AWS_ACCESS_KEY_ID: 'AKIAEXAMPLE',
      AWS_SECRET_ACCESS_KEY: 'must-not-be-mounted',
    })).toThrow('forbids static credentials');
    expect(() => resolveAwsKmsWorkloadIdentitySource({
      AWS_ROLE_ARN: 'arn:aws:iam::111122223333:role/otto-control',
    })).toThrow('must be configured together');
  });

  it('validates the KMS key and permission before returning locally verified signatures', async () => {
    const pair = generateKeyPairSync('ed25519');
    const client = kmsClient({ region: 'us-east-1', ...pair });
    const signer = await AwsKmsEd25519Signer.create({
      keyArns: [keyArn('us-east-1')],
      clientFactory: () => client,
    });
    const payload = { licenseId: 'lic_aws_kms', modules: ['meeting_agent'] };
    const signature = await signer.sign(payload);

    expect(verify(
      null,
      Buffer.from(canonicalJson(payload)),
      pair.publicKey,
      Buffer.from(signature.slice('ed25519:'.length), 'base64url'),
    )).toBe(true);
    expect(signer.health()).toMatchObject({
      state: 'available',
      backend: 'aws_kms',
      activeLocation: 'us-east-1',
      failoversTotal: 0,
    });
    expect(client.send).toHaveBeenCalledTimes(4);
  });

  it('fails over only between explicit replicas of the same multi-Region key', async () => {
    const pair = generateKeyPairSync('ed25519');
    const primary = kmsClient({ region: 'us-east-1', ...pair, failSigning: true });
    const replica = kmsClient({ region: 'eu-west-1', ...pair });
    const signer = await AwsKmsEd25519Signer.create({
      keyArns: [keyArn('us-east-1'), keyArn('eu-west-1')],
      clientFactory: (region) => region === 'us-east-1' ? primary : replica,
    });

    await expect(signer.sign({ drill: 'regional-failover' })).resolves.toMatch(/^ed25519:/u);
    expect(signer.health()).toMatchObject({
      state: 'available',
      activeLocation: 'eu-west-1',
      failoversTotal: 1,
    });
    expect(primary.send).toHaveBeenCalledTimes(4);
    expect(replica.send).toHaveBeenCalledTimes(4);
  });

  it('rejects missing Sign permission and incompatible key metadata at startup', async () => {
    const pair = generateKeyPairSync('ed25519');
    await expect(AwsKmsEd25519Signer.create({
      keyArns: [keyArn('us-east-1')],
      clientFactory: () => kmsClient({ region: 'us-east-1', ...pair, permissionDenied: true }),
    })).rejects.toThrow('Sign permission validation failed');

    await expect(AwsKmsEd25519Signer.create({
      keyArns: [keyArn('us-east-1')],
      clientFactory: () => kmsClient({ region: 'us-east-1', ...pair, keySpec: 'ECC_NIST_P256' }),
    })).rejects.toThrow('not an enabled customer-managed Ed25519 signing key');
  });

  it('rejects unrelated disaster-recovery keys and oversized raw messages', async () => {
    const pair = generateKeyPairSync('ed25519');
    await expect(AwsKmsEd25519Signer.create({
      keyArns: [
        keyArn('us-east-1'),
        keyArn('eu-west-1', `mrk-${'b'.repeat(32)}`),
      ],
      clientFactory: () => kmsClient({ region: 'us-east-1', ...pair }),
    })).rejects.toThrow('replicas of one multi-Region key');

    const signer = await AwsKmsEd25519Signer.create({
      keyArns: [keyArn('us-east-1')],
      clientFactory: () => kmsClient({ region: 'us-east-1', ...pair }),
    });
    await expect(signer.sign({ content: 'x'.repeat(4_096) })).rejects.toThrow(
      'payload exceeds 4096 bytes',
    );
  });
});

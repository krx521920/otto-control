import {
  DescribeKeyCommand,
  GetPublicKeyCommand,
  KMSClient,
  SignCommand,
} from '@aws-sdk/client-kms';
import { fromHttp } from '@aws-sdk/credential-provider-http';
import { fromTokenFile } from '@aws-sdk/credential-provider-web-identity';
import { fromInstanceMetadata } from '@smithy/credential-provider-imds';
import {
  createPublicKey,
  verify,
  type KeyObject,
} from 'node:crypto';

import {
  canonicalJson,
  ED25519_SIGNATURE_PREFIX,
  ed25519PublicKeyId,
  type PayloadSigner,
  type SignerHealth,
} from './signed-envelope.js';

const MAX_RAW_MESSAGE_BYTES = 4_096;
const CIRCUIT_FAILURE_THRESHOLD = 3;
const CIRCUIT_OPEN_MS = 30_000;
const AWS_KMS_KEY_ARN_PATTERN = /^arn:(aws|aws-cn|aws-us-gov):kms:([a-z0-9-]{3,32}):(\d{12}):key\/(mrk-[a-f0-9]{32}|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$/u;

export interface AwsKmsClientLike {
  send(command: unknown, options?: { abortSignal?: AbortSignal }): Promise<unknown>;
}

interface AwsKmsTarget {
  keyArn: string;
  keyResourceId: string;
  region: string;
  client: AwsKmsClientLike;
}

export interface AwsKmsEd25519SignerOptions {
  keyArns: string[];
  timeoutMs?: number;
  validateSignPermission?: boolean;
  clientFactory?: (region: string) => AwsKmsClientLike;
  now?: () => number;
}

export type AwsKmsWorkloadIdentitySource =
  | 'temporary_environment'
  | 'web_identity'
  | 'container'
  | 'instance_metadata';

export function resolveAwsKmsWorkloadIdentitySource(
  env: Readonly<NodeJS.ProcessEnv>,
): AwsKmsWorkloadIdentitySource {
  const accessKeyId = env.AWS_ACCESS_KEY_ID?.trim();
  const secretAccessKey = env.AWS_SECRET_ACCESS_KEY?.trim();
  const sessionToken = env.AWS_SESSION_TOKEN?.trim();
  if (accessKeyId || secretAccessKey || sessionToken) {
    if (!accessKeyId || !secretAccessKey || !sessionToken) {
      throw new Error('AWS KMS signing forbids static credentials; use a workload IAM role');
    }
    return 'temporary_environment';
  }
  const hasWebIdentity = Boolean(env.AWS_WEB_IDENTITY_TOKEN_FILE?.trim());
  const hasRoleArn = Boolean(env.AWS_ROLE_ARN?.trim());
  if (hasWebIdentity !== hasRoleArn) {
    throw new Error('AWS_WEB_IDENTITY_TOKEN_FILE and AWS_ROLE_ARN must be configured together');
  }
  if (hasWebIdentity) return 'web_identity';
  if (env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI?.trim()
    || env.AWS_CONTAINER_CREDENTIALS_FULL_URI?.trim()) {
    return 'container';
  }
  return 'instance_metadata';
}

function workloadIdentityCredentials(
  region: string,
  env: Readonly<NodeJS.ProcessEnv> = process.env,
) {
  const source = resolveAwsKmsWorkloadIdentitySource(env);
  if (source === 'temporary_environment') {
    return async () => ({
      accessKeyId: env.AWS_ACCESS_KEY_ID!,
      secretAccessKey: env.AWS_SECRET_ACCESS_KEY!,
      sessionToken: env.AWS_SESSION_TOKEN!,
    });
  }
  if (source === 'web_identity') {
    return fromTokenFile({
      webIdentityTokenFile: env.AWS_WEB_IDENTITY_TOKEN_FILE,
      roleArn: env.AWS_ROLE_ARN,
      roleSessionName: env.AWS_ROLE_SESSION_NAME || 'otto-control-kms',
      clientConfig: { region },
    });
  }
  if (source === 'container') {
    return fromHttp({ timeout: 1_000, maxRetries: 2 });
  }
  return fromInstanceMetadata({ timeout: 1_000, maxRetries: 2 });
}

function parseKeyArn(value: string): {
  arn: string;
  partition: string;
  region: string;
  accountId: string;
  keyResourceId: string;
} {
  const normalized = value.trim();
  const match = AWS_KMS_KEY_ARN_PATTERN.exec(normalized);
  if (!match) {
    throw new Error('AWS KMS signing keys must use immutable key ARNs');
  }
  return {
    arn: normalized,
    partition: match[1]!,
    region: match[2]!,
    accountId: match[3]!,
    keyResourceId: match[4]!,
  };
}

function boundedTimeout(value: number | undefined): number {
  const timeoutMs = value ?? 5_000;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 500 || timeoutMs > 30_000) {
    throw new Error('AWS KMS signing timeout must be between 500 and 30000 milliseconds');
  }
  return timeoutMs;
}

async function sendWithTimeout(
  client: AwsKmsClientLike,
  command: unknown,
  timeoutMs: number,
): Promise<unknown> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  timer.unref?.();
  try {
    return await client.send(command, { abortSignal: controller.signal });
  } catch (error) {
    if (controller.signal.aborted) throw new Error('AWS KMS signing request timed out');
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

function assertKeyMetadata(value: unknown, expected: ReturnType<typeof parseKeyArn>, requireMultiRegion: boolean): {
  keyResourceId: string;
} {
  const metadata = (value as { KeyMetadata?: Record<string, unknown> }).KeyMetadata;
  if (!metadata
    || metadata.Arn !== expected.arn
    || metadata.KeyId !== expected.keyResourceId
    || metadata.AWSAccountId !== expected.accountId
    || metadata.Enabled !== true
    || metadata.KeyState !== 'Enabled'
    || metadata.KeyUsage !== 'SIGN_VERIFY'
    || metadata.KeySpec !== 'ECC_NIST_EDWARDS25519'
    || metadata.Origin !== 'AWS_KMS'
    || metadata.KeyManager !== 'CUSTOMER'
    || (requireMultiRegion && metadata.MultiRegion !== true)
    || !Array.isArray(metadata.SigningAlgorithms)
    || !metadata.SigningAlgorithms.includes('ED25519_SHA_512')) {
    throw new Error(`AWS KMS key ${expected.arn} is not an enabled customer-managed Ed25519 signing key`);
  }
  return { keyResourceId: expected.keyResourceId };
}

function publicKeyFromResponse(value: unknown, expected: ReturnType<typeof parseKeyArn>): KeyObject {
  const response = value as Record<string, unknown>;
  if (response.KeyId !== expected.arn
    || response.KeyUsage !== 'SIGN_VERIFY'
    || response.KeySpec !== 'ECC_NIST_EDWARDS25519'
    || !Array.isArray(response.SigningAlgorithms)
    || !response.SigningAlgorithms.includes('ED25519_SHA_512')
    || !(response.PublicKey instanceof Uint8Array)) {
    throw new Error(`AWS KMS public key response for ${expected.arn} is invalid`);
  }
  const key = createPublicKey({
    key: Buffer.from(response.PublicKey),
    format: 'der',
    type: 'spki',
  });
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new Error(`AWS KMS public key for ${expected.arn} is not Ed25519`);
  }
  return key;
}

async function assertSignPermission(
  target: AwsKmsTarget,
  timeoutMs: number,
): Promise<void> {
  try {
    await sendWithTimeout(target.client, new SignCommand({
      KeyId: target.keyArn,
      Message: Buffer.from('otto-control-kms-permission-probe', 'utf8'),
      MessageType: 'RAW',
      SigningAlgorithm: 'ED25519_SHA_512',
      DryRun: true,
    }), timeoutMs);
    throw new Error('AWS KMS DryRun unexpectedly returned a signature response');
  } catch (error) {
    if ((error as { name?: string }).name === 'DryRunOperationException') return;
    throw new Error(`AWS KMS Sign permission validation failed for ${target.keyArn}`, {
      cause: error,
    });
  }
}

export class AwsKmsEd25519Signer implements PayloadSigner {
  readonly keyId: string;
  readonly publicKeyPem: string;
  readonly #publicKey: KeyObject;
  readonly #targets: readonly AwsKmsTarget[];
  readonly #timeoutMs: number;
  readonly #now: () => number;
  #activeTargetIndex = 0;
  #consecutiveFailures = 0;
  #circuitOpenUntil = 0;
  #hasSucceeded: boolean;
  #failoversTotal = 0;

  private constructor(options: {
    publicKey: KeyObject;
    targets: AwsKmsTarget[];
    timeoutMs: number;
    now?: () => number;
  }) {
    this.#publicKey = options.publicKey;
    this.keyId = ed25519PublicKeyId(options.publicKey);
    this.publicKeyPem = options.publicKey.export({ format: 'pem', type: 'spki' }).toString();
    this.#targets = options.targets;
    this.#timeoutMs = options.timeoutMs;
    this.#hasSucceeded = false;
    this.#now = options.now ?? Date.now;
  }

  static async create(options: AwsKmsEd25519SignerOptions): Promise<AwsKmsEd25519Signer> {
    if (!Array.isArray(options.keyArns) || options.keyArns.length < 1 || options.keyArns.length > 3) {
      throw new Error('AWS KMS signing requires between one and three key ARNs');
    }
    const parsed = options.keyArns.map(parseKeyArn);
    if (new Set(parsed.map((key) => key.arn)).size !== parsed.length) {
      throw new Error('AWS KMS signing key ARNs must be unique');
    }
    if (parsed.length > 1 && (
      !parsed.every((key) => key.keyResourceId.startsWith('mrk-'))
      || new Set(parsed.map((key) => key.keyResourceId)).size !== 1
      || new Set(parsed.map((key) => key.accountId)).size !== 1
      || new Set(parsed.map((key) => key.partition)).size !== 1
      || new Set(parsed.map((key) => key.region)).size !== parsed.length
    )) {
      throw new Error('AWS KMS disaster recovery ARNs must be replicas of one multi-Region key');
    }
    const timeoutMs = boundedTimeout(options.timeoutMs);
    const targets: AwsKmsTarget[] = [];
    const publicKeys: KeyObject[] = [];
    for (const key of parsed) {
      const client = options.clientFactory?.(key.region) ?? new KMSClient({
        region: key.region,
        maxAttempts: 3,
        credentials: workloadIdentityCredentials(key.region),
      }) as unknown as AwsKmsClientLike;
      const metadata = await sendWithTimeout(
        client,
        new DescribeKeyCommand({ KeyId: key.arn }),
        timeoutMs,
      );
      assertKeyMetadata(metadata, key, parsed.length > 1);
      const publicKey = publicKeyFromResponse(await sendWithTimeout(
        client,
        new GetPublicKeyCommand({ KeyId: key.arn }),
        timeoutMs,
      ), key);
      targets.push({
        keyArn: key.arn,
        keyResourceId: key.keyResourceId,
        region: key.region,
        client,
      });
      publicKeys.push(publicKey);
    }
    const expectedPublicKey = publicKeys[0]!.export({ format: 'der', type: 'spki' });
    if (publicKeys.some((key) => !Buffer.from(
      key.export({ format: 'der', type: 'spki' }),
    ).equals(Buffer.from(expectedPublicKey)))) {
      throw new Error('AWS KMS disaster recovery keys do not share the same public key');
    }
    const validateSignPermission = options.validateSignPermission ?? true;
    if (validateSignPermission) {
      for (const target of targets) await assertSignPermission(target, timeoutMs);
    }
    return new AwsKmsEd25519Signer({
      publicKey: publicKeys[0]!,
      targets,
      timeoutMs,
      now: options.now,
    });
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
      backend: 'aws_kms',
      activeLocation: this.#targets[this.#activeTargetIndex]?.region ?? null,
      failoversTotal: this.#failoversTotal,
    };
  }

  async sign(payload: unknown): Promise<string> {
    const now = this.#now();
    if (this.#circuitOpenUntil > now) {
      throw new Error('AWS KMS signing circuit is open after repeated provider failures');
    }
    const message = Buffer.from(canonicalJson(payload), 'utf8');
    if (message.length > MAX_RAW_MESSAGE_BYTES) {
      throw new Error('AWS KMS Ed25519 raw signing payload exceeds 4096 bytes');
    }
    let finalError: unknown = null;
    for (let offset = 0; offset < this.#targets.length; offset += 1) {
      const targetIndex = (this.#activeTargetIndex + offset) % this.#targets.length;
      const target = this.#targets[targetIndex]!;
      try {
        const response = await sendWithTimeout(target.client, new SignCommand({
          KeyId: target.keyArn,
          Message: message,
          MessageType: 'RAW',
          SigningAlgorithm: 'ED25519_SHA_512',
        }), this.#timeoutMs) as Record<string, unknown>;
        if ((response.KeyId !== target.keyArn && response.KeyId !== target.keyResourceId)
          || response.SigningAlgorithm !== 'ED25519_SHA_512'
          || !(response.Signature instanceof Uint8Array)) {
          throw new Error('AWS KMS signing response binding is invalid');
        }
        const signature = Buffer.from(response.Signature);
        if (signature.length !== 64 || !verify(null, message, this.#publicKey, signature)) {
          throw new Error('AWS KMS returned a signature that failed local verification');
        }
        if (targetIndex !== this.#activeTargetIndex) this.#failoversTotal += 1;
        this.#activeTargetIndex = targetIndex;
        this.#consecutiveFailures = 0;
        this.#circuitOpenUntil = 0;
        this.#hasSucceeded = true;
        return `${ED25519_SIGNATURE_PREFIX}${signature.toString('base64url')}`;
      } catch (error) {
        finalError = error;
      }
    }
    this.#consecutiveFailures += 1;
    if (this.#consecutiveFailures >= CIRCUIT_FAILURE_THRESHOLD) {
      this.#circuitOpenUntil = now + CIRCUIT_OPEN_MS;
    }
    throw new Error('AWS KMS signing failed in every configured Region', { cause: finalError });
  }
}

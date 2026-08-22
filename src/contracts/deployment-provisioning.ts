import {
  createCipheriv,
  createDecipheriv,
  createHash,
  hkdfSync,
  randomBytes,
} from 'node:crypto';

import {
  canonicalJson,
  signPayload,
  type PayloadSigner,
} from '../crypto/signed-envelope.js';

export const ENTERPRISE_PROVISIONING_COMMAND_TYPE =
  'enterprise.initiate' as const;
export const ENTERPRISE_PROVISIONING_SCHEMA_VERSION = 1 as const;

export interface EnterpriseProvisioningPayload {
  organization: {
    id: string;
    name: string;
    slug?: string;
  };
  ceo: {
    username: string;
    name: string;
    phone: string;
  };
  defaultDepartmentName: string;
  modules: string[];
}

export interface EnterpriseProvisioningCommand {
  commandId: string;
  deploymentId: string;
  type: typeof ENTERPRISE_PROVISIONING_COMMAND_TYPE;
  schemaVersion: typeof ENTERPRISE_PROVISIONING_SCHEMA_VERSION;
  sequence: number;
  issuedAt: string;
  expiresAt: string;
  idempotencyKey: string;
  payloadDigest: string;
  payload: EnterpriseProvisioningPayload;
  signingKeyId: string;
  signature: string;
}

export type EnterpriseProvisioningSignedBody = Omit<
  EnterpriseProvisioningCommand,
  'signingKeyId' | 'signature'
>;

export interface EnterpriseProvisioningSecretContainer {
  version: 1;
  payload: EnterpriseProvisioningPayload;
  command: EnterpriseProvisioningCommand | null;
}

const PROVISIONING_CIPHER_VERSION = 'v1';
const PROVISIONING_KEY_INFO = 'otto-control:enterprise-provisioning:v1';

function provisioningKey(
  bootstrapSecret: string,
  enrollmentId: string,
): Buffer {
  return Buffer.from(
    hkdfSync(
      'sha256',
      Buffer.from(bootstrapSecret, 'utf8'),
      Buffer.from(enrollmentId, 'utf8'),
      Buffer.from(PROVISIONING_KEY_INFO, 'utf8'),
      32,
    ),
  );
}

function provisioningAad(enrollmentId: string): Buffer {
  return Buffer.from(
    canonicalJson({
      enrollmentId,
      purpose: ENTERPRISE_PROVISIONING_COMMAND_TYPE,
      version: 1,
    }),
    'utf8',
  );
}

export function encryptEnterpriseProvisioningContainer(
  bootstrapSecret: string,
  enrollmentId: string,
  container: EnterpriseProvisioningSecretContainer,
): string {
  const key = provisioningKey(bootstrapSecret, enrollmentId);
  const iv = randomBytes(12);
  try {
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(provisioningAad(enrollmentId));
    const ciphertext = Buffer.concat([
      cipher.update(canonicalJson(container), 'utf8'),
      cipher.final(),
    ]);
    return [
      PROVISIONING_CIPHER_VERSION,
      iv.toString('base64url'),
      cipher.getAuthTag().toString('base64url'),
      ciphertext.toString('base64url'),
    ].join('.');
  } finally {
    key.fill(0);
  }
}

export function decryptEnterpriseProvisioningContainer(
  bootstrapSecret: string,
  enrollmentId: string,
  encoded: string,
): EnterpriseProvisioningSecretContainer {
  const parts = encoded.split('.');
  if (parts.length !== 4 || parts[0] !== PROVISIONING_CIPHER_VERSION) {
    throw new Error('provisioning ciphertext is invalid');
  }
  const key = provisioningKey(bootstrapSecret, enrollmentId);
  try {
    const decipher = createDecipheriv(
      'aes-256-gcm',
      key,
      Buffer.from(parts[1]!, 'base64url'),
    );
    decipher.setAAD(provisioningAad(enrollmentId));
    decipher.setAuthTag(Buffer.from(parts[2]!, 'base64url'));
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(parts[3]!, 'base64url')),
      decipher.final(),
    ]).toString('utf8');
    const parsed = JSON.parse(
      plaintext,
    ) as EnterpriseProvisioningSecretContainer;
    if (
      parsed.version !== 1 ||
      !parsed.payload ||
      typeof parsed.payload !== 'object'
    ) {
      throw new Error('provisioning ciphertext is invalid');
    }
    return parsed;
  } catch {
    throw new Error('provisioning ciphertext is invalid');
  } finally {
    key.fill(0);
  }
}

export function enterpriseProvisioningPayloadDigest(payload: unknown): string {
  return createHash('sha256')
    .update(canonicalJson(payload), 'utf8')
    .digest('hex');
}

export async function signEnterpriseProvisioningCommand(
  signer: PayloadSigner,
  body: EnterpriseProvisioningSignedBody,
): Promise<EnterpriseProvisioningCommand> {
  const signed = await signPayload(signer, { envelope: body });
  return { ...body, ...signed };
}

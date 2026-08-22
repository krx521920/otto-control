import { generateKeyPairSync, verify } from 'node:crypto';

import { describe, expect, it, vi } from 'vitest';

import {
  decryptEnterpriseProvisioningContainer,
  encryptEnterpriseProvisioningContainer,
  enterpriseProvisioningPayloadDigest,
  signEnterpriseProvisioningCommand,
  type EnterpriseProvisioningPayload,
} from '../src/contracts/deployment-provisioning.js';
import {
  canonicalJson,
  LocalEd25519Signer,
} from '../src/crypto/signed-envelope.js';
import { PostgresControlStore } from '../src/storage/postgres-store.js';

const SECRET = 'test-bootstrap-secret-with-more-than-32-bytes';
const ENROLLMENT_ID = 'enroll_provisioningtest0001';
const payload: EnterpriseProvisioningPayload = {
  organization: { id: 'org_provisioning_test', name: 'Private Enterprise' },
  ceo: {
    username: 'private.ceo',
    name: 'Private Person',
    phone: '+8613800138000',
  },
  defaultDepartmentName: 'Executive Office',
  modules: ['enterprise_tree', 'direct_messages'],
};

describe('enterprise provisioning security contract', () => {
  it('encrypts provisioning PII with the bootstrap secret and authenticates metadata', () => {
    const ciphertext = encryptEnterpriseProvisioningContainer(
      SECRET,
      ENROLLMENT_ID,
      {
        version: 1,
        payload,
        command: null,
      },
    );
    expect(ciphertext).toMatch(/^v1\./u);
    expect(ciphertext).not.toContain(payload.organization.name);
    expect(ciphertext).not.toContain(payload.ceo.name);
    expect(ciphertext).not.toContain(payload.ceo.phone);
    expect(
      decryptEnterpriseProvisioningContainer(SECRET, ENROLLMENT_ID, ciphertext),
    ).toEqual({
      version: 1,
      payload,
      command: null,
    });
    expect(() =>
      decryptEnterpriseProvisioningContainer(
        'different-bootstrap-secret-with-more-than-32-bytes',
        ENROLLMENT_ID,
        ciphertext,
      ),
    ).toThrow('provisioning ciphertext is invalid');
    expect(() =>
      decryptEnterpriseProvisioningContainer(
        SECRET,
        'enroll_wrongcontext0001',
        ciphertext,
      ),
    ).toThrow('provisioning ciphertext is invalid');
  });

  it('signs exactly the Otto envelope body and preserves every command field in ciphertext', async () => {
    const keys = generateKeyPairSync('ed25519');
    const signer = new LocalEd25519Signer(
      keys.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    );
    const body = {
      commandId: 'cmd_provisioningtest0001',
      deploymentId: 'dep_provisioningtest0001',
      type: 'enterprise.initiate' as const,
      schemaVersion: 1 as const,
      sequence: 1,
      issuedAt: '2026-08-22T00:00:00.000Z',
      expiresAt: '2026-08-22T00:15:00.000Z',
      idempotencyKey: `bootstrap-enterprise:${ENROLLMENT_ID}`,
      payloadDigest: enterpriseProvisioningPayloadDigest(payload),
      payload,
    };
    const command = await signEnterpriseProvisioningCommand(signer, body);
    expect(
      verify(
        null,
        Buffer.from(canonicalJson({ envelope: body }), 'utf8'),
        signer.publicKey,
        Buffer.from(command.signature.slice('ed25519:'.length), 'base64url'),
      ),
    ).toBe(true);

    const ciphertext = encryptEnterpriseProvisioningContainer(
      SECRET,
      ENROLLMENT_ID,
      {
        version: 1,
        payload,
        command,
      },
    );
    const replay = decryptEnterpriseProvisioningContainer(
      SECRET,
      ENROLLMENT_ID,
      ciphertext,
    );
    expect(replay.command).toEqual(command);
    expect(replay.command?.commandId).toBe(command.commandId);
    expect(replay.command?.issuedAt).toBe(command.issuedAt);
    expect(replay.command?.signature).toBe(command.signature);
  });

  it('preserves activated history while retiring an expired PostgreSQL enrollment secret', async () => {
    const query = vi.fn(async (statement: string) => {
      if (statement.includes('SELECT * FROM control_deployment_enrollments')) {
        return {
          rowCount: 1,
          rows: [{
            id: ENROLLMENT_ID,
            status: 'activated',
            expires_at: new Date('2026-08-22T00:00:00.000Z'),
          }],
        };
      }
      return { rowCount: 0, rows: [] };
    });
    const release = vi.fn();
    const connect = vi.fn(async () => ({ query, release }));
    const StoreConstructor = PostgresControlStore as unknown as new (
      pool: never,
      poolState: { errorsTotal: number },
    ) => PostgresControlStore;
    const store = new StoreConstructor({ connect } as never, { errorsTotal: 0 });

    await expect(store.reserveDeploymentEnrollmentClaim({
      tokenHash: 'a'.repeat(64),
      requestHash: 'b'.repeat(64),
      deploymentId: 'dep_provisioningtest0001',
      machineFingerprint: 'c'.repeat(64),
      claimLeaseId: 'claim_provisioningtest0001',
      claimLeaseExpiresAt: new Date('2026-08-22T01:00:30.000Z'),
      appVersion: '1.10.2',
      buildCommit: 'test-build',
      publicOrigin: 'https://private.example.test',
      deploymentKind: 'private',
      now: new Date('2026-08-22T01:00:00.000Z'),
    })).resolves.toBeNull();

    const retirement = query.mock.calls.find(([statement]) =>
      statement.includes('token_hash = md5')
    );
    expect(retirement).toBeDefined();
    expect(retirement?.[0]).toContain(
      "status = CASE WHEN status = 'activated' THEN status ELSE 'revoked' END",
    );
    expect(retirement?.[0]).toContain('provisioning_ciphertext = NULL');
    expect(retirement?.[0]).toContain('deployment_id = NULL');
    expect(query).toHaveBeenCalledWith('COMMIT');
    expect(release).toHaveBeenCalledOnce();
  });

  it('overwrites the PostgreSQL input ciphertext with the completed command ciphertext', async () => {
    const query = vi.fn(
      async (statement: string, parameters?: readonly unknown[]) => {
        void statement;
        void parameters;
        return { rowCount: 0, rows: [] };
      },
    );
    const StoreConstructor = PostgresControlStore as unknown as new (
      pool: never,
      poolState: { errorsTotal: number },
    ) => PostgresControlStore;
    const store = new StoreConstructor({ query } as never, { errorsTotal: 0 });
    await store.completeDeploymentEnrollmentClaim({
      enrollmentId: ENROLLMENT_ID,
      claimLeaseId: 'claim_provisioningtest0001',
      activatedAt: new Date('2026-08-22T00:00:00.000Z'),
      replayExpiresAt: new Date('2026-08-22T00:15:00.000Z'),
      provisioningCiphertext: 'v1.completed-command-ciphertext',
    });
    const firstCall = query.mock.calls[0];
    expect(firstCall).toBeDefined();
    const [statement, parameters] = firstCall!;
    expect(statement).toContain('provisioning_ciphertext = $5');
    expect(statement).not.toContain('COALESCE(provisioning_ciphertext');
    expect(parameters?.[4]).toBe('v1.completed-command-ciphertext');
  });
});

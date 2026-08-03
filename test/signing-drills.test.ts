import { generateKeyPairSync } from 'node:crypto';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { LocalEd25519Signer } from '../src/crypto/signed-envelope.js';
import { runSigningProviderDrill } from '../scripts/drill-signing-provider.mjs';
import { runSigningRevocationDrill } from '../scripts/drill-signing-revocation.mjs';
import { runSigningRotationDrill } from '../scripts/drill-signing-rotation.mjs';

function response(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

describe('production signing drills', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('proves multi-Region provider failover without leaking the administrator token', async () => {
    const token = 'requester-session-token-that-must-not-enter-reports';
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(response({
        signingKeys: [{
          keyId: '0123456789abcdef',
          state: 'standby',
          canSign: true,
          providerHealth: {
            state: 'available', backend: 'aws_kms', activeLocation: 'ap-southeast-1',
            consecutiveFailures: 0, failoversTotal: 0, circuitOpenUntil: null,
          },
        }],
      }))
      .mockResolvedValueOnce(response({
        probe: {
          keyId: '0123456789abcdef',
          verified: true,
          providerHealth: {
            state: 'available', backend: 'aws_kms', activeLocation: 'ap-northeast-1',
            consecutiveFailures: 0, failoversTotal: 1, circuitOpenUntil: null,
          },
        },
      }));
    vi.stubGlobal('fetch', fetchMock);

    const report = await runSigningProviderDrill({
      controlUrl: new URL('https://control.example.test'),
      token,
      keyId: '0123456789abcdef',
      expectedLocation: 'ap-northeast-1',
      minimumFailovers: 1,
    });

    expect(report).toMatchObject({
      result: 'passed',
      after: { activeLocation: 'ap-northeast-1', failoversTotal: 1 },
    });
    expect(JSON.stringify(report)).not.toContain(token);
    expect(fetchMock.mock.calls[1]?.[0].toString()).toContain('/probe');
  });

  it('executes probe, dual approval, activation, and post-rotation verification in order', async () => {
    const requesterToken = 'requester-session-token-that-must-not-enter-reports';
    const approverToken = 'approver-session-token-that-must-not-enter-reports';
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(response({
        signingKeys: [
          { keyId: 'aaaaaaaaaaaaaaaa', state: 'active', canSign: true, provider: 'local' },
          { keyId: 'bbbbbbbbbbbbbbbb', state: 'standby', canSign: true, provider: 'kms' },
        ],
      }))
      .mockResolvedValueOnce(response({
        probe: {
          keyId: 'bbbbbbbbbbbbbbbb',
          verified: true,
          providerHealth: {
            state: 'available', backend: 'aws_kms', activeLocation: 'ap-southeast-1',
          },
        },
      }))
      .mockResolvedValueOnce(response({ approval: { id: 'approval-rotation-1' } }, 201))
      .mockResolvedValueOnce(response({ approval: { status: 'approved' } }))
      .mockResolvedValueOnce(response({
        signingKeys: [
          { keyId: 'aaaaaaaaaaaaaaaa', state: 'retired', canSign: true, provider: 'local' },
          { keyId: 'bbbbbbbbbbbbbbbb', state: 'active', canSign: true, provider: 'kms' },
        ],
      }));
    vi.stubGlobal('fetch', fetchMock);

    const report = await runSigningRotationDrill({
      controlUrl: new URL('https://control.example.test'),
      requesterToken,
      approverToken,
      targetKeyId: 'bbbbbbbbbbbbbbbb',
    });

    expect(report).toMatchObject({
      result: 'passed',
      previousKeyId: 'aaaaaaaaaaaaaaaa',
      activeKeyId: 'bbbbbbbbbbbbbbbb',
      approvalId: 'approval-rotation-1',
    });
    const calls = fetchMock.mock.calls;
    expect(calls.map((call) => new URL(call[0].toString()).pathname)).toEqual([
      '/v1/admin/signing-keys',
      '/v1/admin/signing-keys/bbbbbbbbbbbbbbbb/probe',
      '/v1/admin/approvals',
      '/v1/admin/approvals/approval-rotation-1/decide',
      '/v1/admin/signing-keys/bbbbbbbbbbbbbbbb/activate',
    ]);
    expect((calls[3]?.[1] as RequestInit).headers).toMatchObject({
      authorization: `Bearer ${approverToken}`,
    });
    expect((calls[4]?.[1] as RequestInit).headers).toMatchObject({
      authorization: `Bearer ${requesterToken}`,
      'x-otto-approval-id': 'approval-rotation-1',
    });
    expect(JSON.stringify(report)).not.toContain(requesterToken);
    expect(JSON.stringify(report)).not.toContain(approverToken);
  });

  it('verifies a legacy License before and after its signing key is retired', async () => {
    const previous = new LocalEd25519Signer(
      generateKeyPairSync('ed25519').privateKey
        .export({ format: 'pem', type: 'pkcs8' }).toString(),
    );
    const target = new LocalEd25519Signer(
      generateKeyPairSync('ed25519').privateKey
        .export({ format: 'pem', type: 'pkcs8' }).toString(),
    );
    const license = { id: 'lic_legacy', plan: 'enterprise', revision: 1 };
    const legacyEnvelope = {
      license,
      signingKeyId: previous.keyId,
      signature: await previous.sign(license),
    };
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(response({ signingKeys: [
        { keyId: previous.keyId, state: 'active', canSign: true, publicKeyPem: previous.publicKeyPem },
        { keyId: target.keyId, state: 'standby', canSign: true, publicKeyPem: target.publicKeyPem },
      ] }))
      .mockResolvedValueOnce(response(legacyEnvelope))
      .mockResolvedValueOnce(response({ probe: { verified: true, providerHealth: {} } }))
      .mockResolvedValueOnce(response({ approval: { id: 'approval-legacy-rotation' } }, 201))
      .mockResolvedValueOnce(response({ approval: { status: 'approved' } }))
      .mockResolvedValueOnce(response({ signingKeys: [
        { keyId: previous.keyId, state: 'retired', publicKeyPem: previous.publicKeyPem },
        { keyId: target.keyId, state: 'active', publicKeyPem: target.publicKeyPem },
      ] }))
      .mockResolvedValueOnce(response(legacyEnvelope));
    vi.stubGlobal('fetch', fetchMock);

    const report = await runSigningRotationDrill({
      controlUrl: new URL('https://control.example.test'),
      requesterToken: 'requester-session-token-that-is-long-enough',
      approverToken: 'approver-session-token-that-is-long-enough',
      targetKeyId: target.keyId,
      legacyLicenseId: license.id,
    });

    expect(report.legacyLicenseVerification).toEqual({
      licenseId: license.id,
      signingKeyId: previous.keyId,
      keyState: 'retired',
      verifiedBeforeRotation: true,
      verifiedAfterRotation: true,
    });
  });

  it('performs dual-approved emergency revocation and verifies the public keyring', async () => {
    const target = new LocalEd25519Signer(
      generateKeyPairSync('ed25519').privateKey
        .export({ format: 'pem', type: 'pkcs8' }).toString(),
    );
    const replacement = new LocalEd25519Signer(
      generateKeyPairSync('ed25519').privateKey
        .export({ format: 'pem', type: 'pkcs8' }).toString(),
    );
    const keyring = {
      version: 1,
      activeKeyId: replacement.keyId,
      keys: [
        { keyId: target.keyId, state: 'revoked' },
        { keyId: replacement.keyId, state: 'active' },
      ],
    };
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(response({ signingKeys: [
        { keyId: target.keyId, state: 'active', canSign: true, publicKeyPem: target.publicKeyPem },
        { keyId: replacement.keyId, state: 'standby', canSign: true, publicKeyPem: replacement.publicKeyPem },
      ] }))
      .mockResolvedValueOnce(response({ probe: { verified: true } }))
      .mockResolvedValueOnce(response({ approval: { id: 'approval-emergency-revoke' } }, 201))
      .mockResolvedValueOnce(response({ approval: { status: 'approved' } }))
      .mockResolvedValueOnce(response({ signingKeys: [
        { keyId: target.keyId, state: 'revoked', publicKeyPem: target.publicKeyPem },
        { keyId: replacement.keyId, state: 'active', publicKeyPem: replacement.publicKeyPem },
      ] }))
      .mockResolvedValueOnce(response({
        keyring,
        signingKeyId: replacement.keyId,
        signature: await replacement.sign(keyring),
      }));
    vi.stubGlobal('fetch', fetchMock);

    const report = await runSigningRevocationDrill({
      controlUrl: new URL('https://control.example.test'),
      requesterToken: 'requester-session-token-that-is-long-enough',
      approverToken: 'approver-session-token-that-is-long-enough',
      keyId: target.keyId,
      replacementKeyId: replacement.keyId,
      reason: 'simulated key compromise',
    });

    expect(report).toMatchObject({
      result: 'passed',
      revokedKeyId: target.keyId,
      activeKeyId: replacement.keyId,
      approvalId: 'approval-emergency-revoke',
      publicKeyringVerified: true,
    });
    expect(fetchMock.mock.calls.map((call) => new URL(call[0].toString()).pathname)).toEqual([
      '/v1/admin/signing-keys',
      `/v1/admin/signing-keys/${replacement.keyId}/probe`,
      '/v1/admin/approvals',
      '/v1/admin/approvals/approval-emergency-revoke/decide',
      `/v1/admin/signing-keys/${target.keyId}/revoke`,
      '/v1/signing-keyring',
    ]);
  });
});

import { generateKeyPairSync, verify, type KeyObject } from 'node:crypto';

import { beforeEach, describe, expect, it } from 'vitest';

import { canonicalJson, LocalEd25519Signer } from '../src/crypto/signed-envelope.js';
import { signTelemetryRequest } from '../src/crypto/telemetry-request.js';
import { CommercialControlService } from '../src/modules/commercial-control/service.js';
import { ControlTokenIssuer } from '../src/modules/commercial-control/token-issuer.js';
import {
  UpdatePolicyService,
  updateCohortPercent,
} from '../src/modules/update-policy/service.js';
import { MemoryControlStore } from './helpers/memory-store.js';

const ADMIN = 'admin@example.test';
const DEPLOYMENT_ID = 'dep_1234567890abcdef';
const FINGERPRINT = 'a'.repeat(64);
const TOKEN_SECRET = 'test-control-token-secret-that-is-long-enough';
const MANIFEST_SHA = 'b'.repeat(64);

function verifyEnvelope(publicKey: KeyObject, payload: unknown, signature: string): boolean {
  return verify(
    null,
    Buffer.from(canonicalJson(payload)),
    publicKey,
    Buffer.from(signature.slice('ed25519:'.length), 'base64url'),
  );
}

describe('signed update policy service', () => {
  let store: MemoryControlStore;
  let service: UpdatePolicyService;
  let commercial: CommercialControlService;
  let publicKey: KeyObject;
  let now: number;

  beforeEach(async () => {
    store = new MemoryControlStore();
    const keys = generateKeyPairSync('ed25519');
    publicKey = keys.publicKey;
    const signer = new LocalEd25519Signer(
      keys.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    );
    const tokenIssuer = new ControlTokenIssuer(TOKEN_SECRET);
    now = Date.parse('2026-07-31T08:00:00.000Z');
    commercial = new CommercialControlService({
      store,
      signer,
      tokenIssuer,
      publicBaseUrl: 'https://control.otto.test',
      now: () => now,
    });
    service = new UpdatePolicyService({
      store,
      signer,
      tokenIssuer,
      now: () => now,
    });
    const customer = await commercial.createCustomer({ name: 'Otto customer' }, ADMIN);
    await commercial.createDeployment({
      deploymentId: DEPLOYMENT_ID,
      customerId: customer.id,
      organizationId: 'org_update_test',
      machineFingerprint: FINGERPRINT,
      name: 'Update test server',
    }, ADMIN);
    await service.createDistribution({ id: 'otto', name: 'Otto desktop' }, ADMIN);
    await service.createDistribution({ id: 'otto-green', name: 'Otto Green' }, ADMIN);
    await service.assignDeployment(DEPLOYMENT_ID, { distributionId: 'otto' }, ADMIN);
  });

  it('validates immutable release artifacts and separates distributions', async () => {
    await expect(service.createRelease({
      distributionId: 'otto',
      version: '1.9.11',
      sourceCommit: 'abcdef1234567',
      channel: 'stable',
      rolloutPercent: 50,
      fullManifest: {
        url: 'http://updates.example.test/latest.json',
        sha256: MANIFEST_SHA,
      },
    }, ADMIN)).rejects.toThrow('100 percent rollout');

    await expect(service.createRelease({
      distributionId: 'otto-green',
      version: '1.9.11',
      sourceCommit: 'abcdef1234567',
      channel: 'canary',
      rolloutPercent: 10,
      fullManifest: {
        url: 'http://updates.example.test/latest.json',
        sha256: MANIFEST_SHA,
      },
    }, ADMIN)).rejects.toThrow('HTTPS URL');

    expect(updateCohortPercent('otto', 'rel_same', DEPLOYMENT_ID)).toBe(
      updateCohortPercent('otto', 'rel_same', DEPLOYMENT_ID),
    );
    expect(updateCohortPercent('otto', 'rel_same', DEPLOYMENT_ID)).toBeGreaterThanOrEqual(1);
    expect(updateCohortPercent('otto', 'rel_same', DEPLOYMENT_ID)).toBeLessThanOrEqual(100);
  });

  it('allows one private server to serve multiple isolated distributions', async () => {
    await service.assignDeployment(
      DEPLOYMENT_ID,
      { distributionId: 'otto-green' },
      ADMIN,
    );
    await service.assignDeployment(
      DEPLOYMENT_ID,
      { distributionId: 'otto-green' },
      ADMIN,
    );

    await expect(
      store.hasDeploymentUpdateAssignment(DEPLOYMENT_ID, 'otto'),
    ).resolves.toBe(true);
    await expect(
      store.hasDeploymentUpdateAssignment(DEPLOYMENT_ID, 'otto-green'),
    ).resolves.toBe(true);
  });

  it('returns a short-lived signed decision and rejects replay or cross-channel access', async () => {
    const release = await service.createRelease({
      distributionId: 'otto',
      version: '1.9.11',
      sourceCommit: 'abcdef1234567',
      channel: 'required',
      notes: 'Security update',
      fullManifest: {
        url: 'https://updates.example.test/otto/1.9.11/latest.json',
        sha256: MANIFEST_SHA,
      },
      incrementalManifest: {
        url: 'https://updates.example.test/otto/1.9.11/incremental.json',
        sha256: 'c'.repeat(64),
      },
    }, ADMIN);
    await service.activateRelease(release.id, ADMIN);
    const license = await commercial.issueLicense({
      deploymentId: DEPLOYMENT_ID,
      plan: 'enterprise',
      expiresAt: '2027-07-31T08:00:00.000Z',
      seatLimit: 50,
      modules: ['enterprise_tree'],
    }, ADMIN);
    const body = {
      version: 1,
      licenseId: license.license.id,
      deploymentId: DEPLOYMENT_ID,
      machineFingerprint: FINGERPRINT,
      distributionId: 'otto',
      currentVersion: '1.9.10',
    };
    const timestamp = now;
    const nonce = 'update_nonce_1234567890';
    const authentication = {
      authorization: `Bearer ${license.license.leaseToken!}`,
      timestamp: String(timestamp),
      nonce,
      signature: signTelemetryRequest({
        token: license.license.leaseToken!,
        timestamp,
        nonce,
        body,
      }),
    };
    const envelope = await service.resolve(body, authentication);
    expect(envelope.policy).toMatchObject({
      decision: 'update',
      reason: 'update_available',
      distributionId: 'otto',
      release: {
        id: release.id,
        mandatory: true,
        version: '1.9.11',
      },
    });
    expect(envelope.policy.expiresAtMs - envelope.policy.issuedAtMs).toBe(300_000);
    expect(verifyEnvelope(publicKey, envelope.policy, envelope.signature)).toBe(true);
    await expect(service.resolve(body, authentication)).rejects.toThrow('replay detected');

    const greenBody = { ...body, distributionId: 'otto-green' };
    await expect(service.resolve(greenBody, {
      ...authentication,
      nonce: 'update_nonce_green_12345',
      signature: signTelemetryRequest({
        token: license.license.leaseToken!,
        timestamp,
        nonce: 'update_nonce_green_12345',
        body: greenBody,
      }),
    })).rejects.toThrow('not assigned');
  });

  it('pauses the previous release and restores it during policy rollback', async () => {
    const first = await service.createRelease({
      distributionId: 'otto',
      version: '1.9.10',
      sourceCommit: 'aaaaaaa1234567',
      channel: 'stable',
      fullManifest: {
        url: 'https://updates.example.test/otto/1.9.10/latest.json',
        sha256: MANIFEST_SHA,
      },
    }, ADMIN);
    await service.activateRelease(first.id, ADMIN);
    now += 1000;
    const second = await service.createRelease({
      distributionId: 'otto',
      version: '1.9.11',
      sourceCommit: 'bbbbbbb1234567',
      channel: 'stable',
      fullManifest: {
        url: 'https://updates.example.test/otto/1.9.11/latest.json',
        sha256: 'c'.repeat(64),
      },
    }, ADMIN);
    const activated = await service.activateRelease(second.id, ADMIN);
    expect(activated.fallback?.id).toBe(first.id);
    expect(store.updateReleases.get(first.id)?.state).toBe('paused');

    now += 1000;
    const rollback = await service.rollbackRelease(second.id, ADMIN);
    expect(rollback.release.state).toBe('rolled_back');
    expect(rollback.fallback).toMatchObject({ id: first.id, state: 'active' });
    expect(await store.getActiveUpdateReleases('otto')).toHaveLength(1);
  });
});

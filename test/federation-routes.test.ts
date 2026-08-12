import { generateKeyPairSync } from 'node:crypto';

import type { FastifyInstance } from 'fastify';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import type {
  FederationEnvelope,
  FederationSignedRequest,
  SignedFederationEnvelope,
} from '../src/contracts/federation.js';
import { LocalEd25519Signer } from '../src/crypto/signed-envelope.js';
import { buildFederationApp } from '../src/federation-app.js';
import type { FederationConfig } from '../src/federation-config.js';
import { MemoryFederationStore } from '../src/modules/federation/memory-store.js';
import { FederationClient } from '../src/modules/federation/client.js';
import { FederationService } from '../src/modules/federation/service.js';
import type { FederationAttachmentObjectStore } from '../src/modules/federation/attachment-object-store.js';

const ADMIN_TOKEN = 'test-federation-admin-token-at-least-32-bytes';
const METRICS_TOKEN = 'test-federation-metrics-token-at-least-32-bytes';
const config: Readonly<FederationConfig> = {
  environment: 'test',
  host: '127.0.0.1',
  port: 7790,
  logLevel: 'silent',
  trustProxy: false,
  publicBaseUrl: 'https://federation.otto.test',
  databaseUrl: null,
  databaseSsl: false,
  adminToken: ADMIN_TOKEN,
  metricsToken: METRICS_TOKEN,
  maximumCiphertextBytes: 1024 * 1024,
  maximumClaimBytes: 4 * 1024 * 1024,
  maximumEnvelopeTtlMs: 7 * 24 * 60 * 60_000,
  maximumClockSkewMs: 5 * 60_000,
  claimTtlMs: 60_000,
  cleanupIntervalMs: 60_000,
  deliveredRetentionMs: 7 * 24 * 60 * 60_000,
  maximumAttachmentBytes: 1024 * 1024 * 1024,
  attachmentStorage: null,
};

function signer(): LocalEd25519Signer {
  const keys = generateKeyPairSync('ed25519');
  return new LocalEd25519Signer(
    keys.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
  );
}

class MemoryAttachmentObjectStore implements FederationAttachmentObjectStore {
  readonly objects = new Map<string, { sizeBytes: number; checksumSha256: string }>();
  readonly removed: string[] = [];

  objectKey(attachmentId: string): string {
    return `federation/${attachmentId}`;
  }

  async createUpload(input: { objectKey: string; expiresAt: Date }) {
    return {
      method: 'PUT' as const,
      url: `https://objects.otto.test/upload/${encodeURIComponent(input.objectKey)}`,
      headers: { 'content-type': 'application/otto-e2ee-attachment' },
      expiresAt: input.expiresAt.toISOString(),
    };
  }

  async inspect(objectKey: string) {
    const object = this.objects.get(objectKey);
    if (!object) throw new Error('object is missing');
    return { objectKey, ...object };
  }

  async createDownload(input: { objectKey: string; expiresAt: Date }) {
    return {
      method: 'GET' as const,
      url: `https://objects.otto.test/download/${encodeURIComponent(input.objectKey)}`,
      headers: {},
      expiresAt: input.expiresAt.toISOString(),
    };
  }

  async remove(objectKey: string): Promise<void> {
    this.objects.delete(objectKey);
    this.removed.push(objectKey);
  }
}

async function signedRequest(
  deploymentSigner: LocalEd25519Signer,
  deploymentId: string,
  now: number,
  body: Record<string, unknown>,
  nonce = `nonce_${crypto.randomUUID().replaceAll('-', '')}`,
): Promise<FederationSignedRequest<Record<string, unknown>>> {
  const request = {
    version: 1 as const,
    deploymentId,
    issuedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + 60_000).toISOString(),
    nonce,
    ...body,
  };
  return {
    request,
    signingKeyId: deploymentSigner.keyId,
    signature: await deploymentSigner.sign(request),
  };
}

async function signedEnvelope(input: {
  deploymentSigner: LocalEd25519Signer;
  senderDeploymentId: string;
  recipientDeploymentId: string;
  now: number;
  messageId?: string;
  nonce?: string;
  type?: FederationEnvelope['type'];
  routing?: Partial<FederationEnvelope['routing']>;
  ciphertext?: string;
}): Promise<SignedFederationEnvelope> {
  const messageId = input.messageId ?? `fmsg_${crypto.randomUUID().replaceAll('-', '')}`;
  const envelope: FederationEnvelope = {
    version: 1,
    messageId,
    type: input.type ?? 'chat.message',
    senderDeploymentId: input.senderDeploymentId,
    recipientDeploymentId: input.recipientDeploymentId,
    issuedAt: new Date(input.now).toISOString(),
    expiresAt: new Date(input.now + 24 * 60 * 60_000).toISOString(),
    nonce: input.nonce ?? `nonce_${crypto.randomUUID().replaceAll('-', '')}`,
    contentType: 'application/otto-e2ee+json',
    ciphertext: input.ciphertext ?? 'base64url-encrypted-payload',
    routing: {
      conversationId: 'conversation_2026',
      senderPrincipalId: 'account_alice',
      recipientPrincipalId: 'account_bob',
      ...input.routing,
    },
  };
  return {
    envelope,
    signingKeyId: input.deploymentSigner.keyId,
    signature: await input.deploymentSigner.sign(envelope),
  };
}

describe('Otto federation gateway', () => {
  let app: FastifyInstance;
  let service: FederationService;
  let store: MemoryFederationStore;
  let deploymentA: LocalEd25519Signer;
  let deploymentB: LocalEd25519Signer;
  let attachmentStore: MemoryAttachmentObjectStore;
  let now: number;

  beforeEach(async () => {
    now = Date.parse('2026-08-02T10:00:00.000Z');
    store = new MemoryFederationStore();
    deploymentA = signer();
    deploymentB = signer();
    attachmentStore = new MemoryAttachmentObjectStore();
    service = new FederationService({
      store,
      attachmentStore,
      now: () => now,
      maximumClaimBytes: 30,
    });
    app = await buildFederationApp({ config, service, logger: false });
    for (const [id, displayName, origin, key] of [
      ['deployment_a', 'Tenant A', 'https://a.private.test', deploymentA],
      ['deployment_b', 'Tenant B', 'https://b.private.test', deploymentB],
    ] as const) {
      const registered = await app.inject({
        method: 'POST',
        url: '/v1/admin/federation/deployments',
        headers: { authorization: `Bearer ${ADMIN_TOKEN}` },
        payload: {
          id,
          displayName,
          origin,
          capabilities: ['federation.v1', 'chat.e2ee', 'a2a.e2ee', 'attachment.e2ee'],
        },
      });
      expect(registered.statusCode).toBe(201);
      const registeredKey = await app.inject({
        method: 'POST',
        url: `/v1/admin/federation/deployments/${id}/keys`,
        headers: { authorization: `Bearer ${ADMIN_TOKEN}` },
        payload: { publicKeyPem: key.publicKeyPem },
      });
      expect(registeredKey.statusCode).toBe(201);
    }
  });

  afterEach(async () => {
    await app.close();
  });

  it('routes ciphertext between two deployments, leases once, and acknowledges delivery', async () => {
    const signed = await signedEnvelope({
      deploymentSigner: deploymentA,
      senderDeploymentId: 'deployment_a',
      recipientDeploymentId: 'deployment_b',
      now,
    });
    const sent = await app.inject({ method: 'POST', url: '/v1/federation/envelopes', payload: signed });
    expect(sent.statusCode).toBe(202);
    expect(sent.json()).toMatchObject({ accepted: true, duplicate: false, messageId: signed.envelope.messageId });

    const duplicate = await app.inject({ method: 'POST', url: '/v1/federation/envelopes', payload: signed });
    expect(duplicate.statusCode).toBe(202);
    expect(duplicate.json()).toMatchObject({ accepted: true, duplicate: true });

    const claim = await signedRequest(deploymentB, 'deployment_b', now, { limit: 20 });
    const inbox = await app.inject({ method: 'POST', url: '/v1/federation/inbox/claim', payload: claim });
    expect(inbox.statusCode).toBe(200);
    expect(inbox.json().messages).toHaveLength(1);
    expect(inbox.json().messages[0]).toMatchObject({
      envelope: {
        messageId: signed.envelope.messageId,
        senderDeploymentId: 'deployment_a',
        recipientDeploymentId: 'deployment_b',
        ciphertext: 'base64url-encrypted-payload',
      },
      signingKeyId: deploymentA.keyId,
    });

    const acknowledgement = await signedRequest(deploymentB, 'deployment_b', now, {
      messageId: signed.envelope.messageId,
      claimToken: inbox.json().messages[0].claimToken,
    });
    const acknowledged = await app.inject({
      method: 'POST', url: '/v1/federation/inbox/ack', payload: acknowledgement,
    });
    expect(acknowledged.statusCode).toBe(200);
    expect(acknowledged.json()).toEqual({ delivered: true });

    const emptyInbox = await app.inject({
      method: 'POST',
      url: '/v1/federation/inbox/claim',
      payload: await signedRequest(deploymentB, 'deployment_b', now, { limit: 20 }),
    });
    expect(emptyInbox.json()).toEqual({ messages: [] });
  });

  it('relays only verified ciphertext attachments to the signed recipient deployment', async () => {
    const attachmentId = 'fattachment_2026_secure_001';
    const ciphertextSha256 = 'a'.repeat(64);
    const uploadRequest = await signedRequest(deploymentA, 'deployment_a', now, {
      recipientDeploymentId: 'deployment_b',
      attachmentId,
      ciphertextBytes: 4096,
      ciphertextSha256,
      attachmentExpiresAt: new Date(now + 24 * 60 * 60_000).toISOString(),
    });
    const initialized = await app.inject({
      method: 'POST',
      url: '/v1/federation/attachments/uploads',
      payload: uploadRequest,
    });
    expect(initialized.statusCode).toBe(201);
    expect(initialized.json()).toMatchObject({
      duplicate: false,
      attachment: {
        id: attachmentId,
        senderDeploymentId: 'deployment_a',
        recipientDeploymentId: 'deployment_b',
        status: 'pending',
      },
      upload: { method: 'PUT' },
    });
    attachmentStore.objects.set(`federation/${attachmentId}`, {
      sizeBytes: 4096,
      checksumSha256: ciphertextSha256,
    });
    const completed = await app.inject({
      method: 'POST',
      url: '/v1/federation/attachments/complete',
      payload: await signedRequest(deploymentA, 'deployment_a', now, { attachmentId }),
    });
    expect(completed.statusCode).toBe(200);
    expect(completed.json()).toMatchObject({ attachment: { status: 'ready' } });

    const message = await signedEnvelope({
      deploymentSigner: deploymentA,
      senderDeploymentId: 'deployment_a',
      recipientDeploymentId: 'deployment_b',
      now,
      routing: { attachmentIds: [attachmentId] },
    });
    expect((await app.inject({
      method: 'POST',
      url: '/v1/federation/envelopes',
      payload: message,
    })).statusCode).toBe(202);

    const denied = await app.inject({
      method: 'POST',
      url: '/v1/federation/attachments/download',
      payload: await signedRequest(deploymentA, 'deployment_a', now, { attachmentId }),
    });
    expect(denied.statusCode).toBe(404);
    const allowed = await app.inject({
      method: 'POST',
      url: '/v1/federation/attachments/download',
      payload: await signedRequest(deploymentB, 'deployment_b', now, { attachmentId }),
    });
    expect(allowed.statusCode).toBe(200);
    expect(allowed.json()).toMatchObject({
      attachment: { id: attachmentId, ciphertextSha256 },
      download: { method: 'GET' },
    });

    now += 24 * 60 * 60_000 + 1;
    await service.expire();
    expect(attachmentStore.removed).toContain(`federation/${attachmentId}`);
  });

  it('fails closed for tampering, replay, wrong audience, and deployment blocks', async () => {
    const valid = await signedEnvelope({
      deploymentSigner: deploymentA,
      senderDeploymentId: 'deployment_a',
      recipientDeploymentId: 'deployment_b',
      now,
    });
    const tampered = structuredClone(valid);
    tampered.envelope.ciphertext = 'tampered-payload';
    expect((await app.inject({
      method: 'POST', url: '/v1/federation/envelopes', payload: tampered,
    })).statusCode).toBe(401);

    const extendedEnvelope = { ...valid.envelope, unsupportedExtension: 'poison' };
    expect((await app.inject({
      method: 'POST',
      url: '/v1/federation/envelopes',
      payload: {
        envelope: extendedEnvelope,
        signingKeyId: deploymentA.keyId,
        signature: await deploymentA.sign(extendedEnvelope),
      },
    })).statusCode).toBe(400);

    const nonCanonicalEnvelope = {
      ...valid.envelope,
      messageId: 'fmsg_noncanonical_timestamp',
      nonce: 'nonce_noncanonical_2026',
      issuedAt: valid.envelope.issuedAt.replace('.000Z', 'Z'),
    };
    expect((await app.inject({
      method: 'POST',
      url: '/v1/federation/envelopes',
      payload: {
        envelope: nonCanonicalEnvelope,
        signingKeyId: deploymentA.keyId,
        signature: await deploymentA.sign(nonCanonicalEnvelope),
      },
    })).statusCode).toBe(400);

    const replay = await signedRequest(
      deploymentB,
      'deployment_b',
      now,
      { limit: 1 },
      'nonce_replay_1234567890',
    );
    expect((await app.inject({
      method: 'POST', url: '/v1/federation/inbox/claim', payload: replay,
    })).statusCode).toBe(200);
    expect((await app.inject({
      method: 'POST', url: '/v1/federation/inbox/claim', payload: replay,
    })).statusCode).toBe(409);

    const wrongAudience = await signedRequest(deploymentA, 'deployment_b', now, { limit: 1 });
    expect((await app.inject({
      method: 'POST', url: '/v1/federation/inbox/claim', payload: wrongAudience,
    })).statusCode).toBe(401);

    const inFlight = await signedEnvelope({
      deploymentSigner: deploymentA,
      senderDeploymentId: 'deployment_a',
      recipientDeploymentId: 'deployment_b',
      now,
    });
    expect((await app.inject({
      method: 'POST', url: '/v1/federation/envelopes', payload: inFlight,
    })).statusCode).toBe(202);

    const blocked = await app.inject({
      method: 'POST',
      url: '/v1/admin/federation/deployments/deployment_b/blocks',
      headers: { authorization: `Bearer ${ADMIN_TOKEN}` },
      payload: { blockedDeploymentId: 'deployment_a', reason: 'security incident' },
    });
    expect(blocked.statusCode).toBe(201);
    expect((await store.getMessage(inFlight.envelope.messageId))?.status).toBe('expired');
    expect((await app.inject({
      method: 'POST',
      url: '/v1/federation/envelopes',
      payload: await signedEnvelope({
        deploymentSigner: deploymentA,
        senderDeploymentId: 'deployment_a',
        recipientDeploymentId: 'deployment_b',
        now,
      }),
    })).statusCode).toBe(403);
  });

  it('allows durable outbox retry within TTL and never reactivates a revoked key id', async () => {
    const delayed = await signedEnvelope({
      deploymentSigner: deploymentA,
      senderDeploymentId: 'deployment_a',
      recipientDeploymentId: 'deployment_b',
      now,
    });
    now += 10 * 60_000;
    expect((await app.inject({
      method: 'POST', url: '/v1/federation/envelopes', payload: delayed,
    })).statusCode).toBe(202);

    const revoked = await app.inject({
      method: 'POST',
      url: `/v1/admin/federation/deployments/deployment_a/keys/${deploymentA.keyId}/revoke`,
      headers: { authorization: `Bearer ${ADMIN_TOKEN}` },
    });
    expect(revoked.statusCode).toBe(200);
    expect((await store.getMessage(delayed.envelope.messageId))?.status).toBe('expired');
    const reused = await app.inject({
      method: 'POST',
      url: '/v1/admin/federation/deployments/deployment_a/keys',
      headers: { authorization: `Bearer ${ADMIN_TOKEN}` },
      payload: { publicKeyPem: deploymentA.publicKeyPem },
    });
    expect(reused.statusCode).toBe(409);
  });

  it('does not consume an envelope nonce when atomic enqueue validation fails', async () => {
    const retryable = await signedEnvelope({
      deploymentSigner: deploymentA,
      senderDeploymentId: 'deployment_a',
      recipientDeploymentId: 'deployment_b',
      now,
    });
    store.deployments.get('deployment_b')!.maxPendingMessages = 0;
    const exhausted = await app.inject({
      method: 'POST', url: '/v1/federation/envelopes', payload: retryable,
    });
    expect(exhausted.statusCode).toBe(429);
    expect(exhausted.json()).toMatchObject({ error: { code: 'CAPACITY_EXCEEDED' } });

    store.deployments.get('deployment_b')!.maxPendingMessages = 100;
    const retried = await app.inject({
      method: 'POST', url: '/v1/federation/envelopes', payload: retryable,
    });
    expect(retried.statusCode).toBe(202);
    expect(retried.json()).toMatchObject({ accepted: true, duplicate: false });
  });

  it('enforces a deployment-wide rate budget and exposes operator capacity without ciphertext', async () => {
    store.deployments.get('deployment_a')!.maxRequestsPerMinute = 1;
    expect((await app.inject({
      method: 'POST',
      url: '/v1/federation/envelopes',
      payload: await signedEnvelope({
        deploymentSigner: deploymentA,
        senderDeploymentId: 'deployment_a',
        recipientDeploymentId: 'deployment_b',
        now,
      }),
    })).statusCode).toBe(202);
    const limited = await app.inject({
      method: 'POST',
      url: '/v1/federation/envelopes',
      payload: await signedEnvelope({
        deploymentSigner: deploymentA,
        senderDeploymentId: 'deployment_a',
        recipientDeploymentId: 'deployment_b',
        now,
      }),
    });
    expect(limited.statusCode).toBe(429);
    expect(limited.json()).toMatchObject({ error: { code: 'RATE_LIMITED' } });

    const operations = await app.inject({
      method: 'GET',
      url: '/v1/admin/federation/deployments/deployment_b/operations',
      headers: { authorization: `Bearer ${ADMIN_TOKEN}` },
    });
    expect(operations.statusCode).toBe(200);
    expect(operations.body).not.toContain('base64url-encrypted-payload');
    expect(operations.json()).toMatchObject({
      deployment: {
        id: 'deployment_b',
        maxPendingMessages: 10_000,
        maxPendingBytes: 512 * 1024 * 1024,
        maxRequestsPerMinute: 1_200,
      },
      usage: { pendingMessages: 1, pendingBytes: 27 },
    });
    const audit = await app.inject({
      method: 'GET',
      url: '/v1/admin/federation/audit-events?limit=20',
      headers: { authorization: `Bearer ${ADMIN_TOKEN}` },
    });
    expect(audit.statusCode).toBe(200);
    expect(audit.body).not.toContain('base64url-encrypted-payload');
    expect(audit.json().events).toEqual(expect.arrayContaining([
      expect.objectContaining({
        action: 'federation.message.enqueue',
        targetId: expect.any(String),
      }),
    ]));
  });

  it('rejects new traffic immediately after a deployment is disabled', async () => {
    const disabled = await app.inject({
      method: 'PATCH',
      url: '/v1/admin/federation/deployments/deployment_a/status',
      headers: { authorization: `Bearer ${ADMIN_TOKEN}` },
      payload: { status: 'disabled' },
    });
    expect(disabled.statusCode).toBe(200);
    expect((await app.inject({
      method: 'POST',
      url: '/v1/federation/envelopes',
      payload: await signedEnvelope({
        deploymentSigner: deploymentA,
        senderDeploymentId: 'deployment_a',
        recipientDeploymentId: 'deployment_b',
        now,
      }),
    })).statusCode).toBe(403);
  });

  it('bounds each inbox claim by ciphertext bytes as well as message count', async () => {
    for (let index = 0; index < 2; index += 1) {
      expect((await app.inject({
        method: 'POST',
        url: '/v1/federation/envelopes',
        payload: await signedEnvelope({
          deploymentSigner: deploymentA,
          senderDeploymentId: 'deployment_a',
          recipientDeploymentId: 'deployment_b',
          now,
          ciphertext: 'base64url-encrypted-payload',
        }),
      })).statusCode).toBe(202);
    }
    const inbox = await app.inject({
      method: 'POST',
      url: '/v1/federation/inbox/claim',
      payload: await signedRequest(deploymentB, 'deployment_b', now, { limit: 20 }),
    });
    expect(inbox.statusCode).toBe(200);
    expect(inbox.json().messages).toHaveLength(1);
  });

  it('rejects an inbox when the encrypted byte budget is exhausted', async () => {
    store.deployments.get('deployment_b')!.maxPendingBytes = 20;
    const exhausted = await app.inject({
      method: 'POST',
      url: '/v1/federation/envelopes',
      payload: await signedEnvelope({
        deploymentSigner: deploymentA,
        senderDeploymentId: 'deployment_a',
        recipientDeploymentId: 'deployment_b',
        now,
      }),
    });
    expect(exhausted.statusCode).toBe(429);
    expect(exhausted.json()).toMatchObject({ error: { code: 'CAPACITY_EXCEEDED' } });
  });

  it('expires offline messages and purges retained ciphertext after the configured window', async () => {
    const pending = await signedEnvelope({
      deploymentSigner: deploymentA,
      senderDeploymentId: 'deployment_a',
      recipientDeploymentId: 'deployment_b',
      now,
    });
    expect((await app.inject({
      method: 'POST', url: '/v1/federation/envelopes', payload: pending,
    })).statusCode).toBe(202);

    now += 24 * 60 * 60_000 + 1;
    await expect(service.expire()).resolves.toEqual({ expired: 1, purged: 0 });
    expect((await store.getMessage(pending.envelope.messageId))?.status).toBe('expired');

    now += 7 * 24 * 60 * 60_000 + 1;
    await expect(service.expire()).resolves.toEqual({ expired: 0, purged: 1 });
    expect(await store.getMessage(pending.envelope.messageId)).toBeNull();
  });

  it('atomically consumes scoped A2A grants and only accepts a matching response', async () => {
    const grantRequest = await signedRequest(deploymentB, 'deployment_b', now, {
      grantId: 'fgrant_review_2026',
      requesterDeploymentId: 'deployment_a',
      ownerPrincipalId: 'account_bob',
      requesterPrincipalId: 'account_alice',
      scopes: ['worklog.read'],
      maxUses: 1,
      grantExpiresAt: new Date(now + 10 * 60_000).toISOString(),
    });
    const granted = await app.inject({
      method: 'POST', url: '/v1/federation/a2a/grants', payload: grantRequest,
    });
    expect(granted.statusCode).toBe(201);
    expect(granted.json()).toMatchObject({ id: 'fgrant_review_2026', usedCount: 0, maxUses: 1 });

    const request = await signedEnvelope({
      deploymentSigner: deploymentA,
      senderDeploymentId: 'deployment_a',
      recipientDeploymentId: 'deployment_b',
      now,
      type: 'a2a.request',
      routing: { a2aGrantId: 'fgrant_review_2026', a2aScope: 'worklog.read' },
    });
    expect((await app.inject({
      method: 'POST', url: '/v1/federation/envelopes', payload: request,
    })).statusCode).toBe(202);

    const secondRequest = await signedEnvelope({
      deploymentSigner: deploymentA,
      senderDeploymentId: 'deployment_a',
      recipientDeploymentId: 'deployment_b',
      now,
      type: 'a2a.request',
      routing: { a2aGrantId: 'fgrant_review_2026', a2aScope: 'worklog.read' },
    });
    expect((await app.inject({
      method: 'POST', url: '/v1/federation/envelopes', payload: secondRequest,
    })).statusCode).toBe(403);

    const response = await signedEnvelope({
      deploymentSigner: deploymentB,
      senderDeploymentId: 'deployment_b',
      recipientDeploymentId: 'deployment_a',
      now,
      type: 'a2a.response',
      routing: {
        senderPrincipalId: 'account_bob',
        recipientPrincipalId: 'account_alice',
        inReplyTo: request.envelope.messageId,
      },
    });
    expect((await app.inject({
      method: 'POST', url: '/v1/federation/envelopes', payload: response,
    })).statusCode).toBe(202);
  });

  it('never exposes ciphertext in status or metrics and protects operator endpoints', async () => {
    expect((await app.inject({
      method: 'GET', url: '/v1/admin/federation/deployments',
    })).statusCode).toBe(401);
    const status = await app.inject({ method: 'GET', url: '/v1/federation/status' });
    expect(status.statusCode).toBe(200);
    expect(status.body).not.toContain('ciphertext:');
    expect(status.json()).toMatchObject({
      protocolVersion: 1,
      privacy: { payloadStorage: 'ciphertext-only', gatewayCanDecrypt: false },
    });
    expect(status.json()).not.toHaveProperty('queue');
    const adminStatus = await app.inject({
      method: 'GET',
      url: '/v1/admin/federation/status',
      headers: { authorization: `Bearer ${ADMIN_TOKEN}` },
    });
    expect(adminStatus.statusCode).toBe(200);
    expect(adminStatus.json().queue).toEqual({ pending: 0, claimed: 0, delivered: 0, expired: 0 });
    expect(adminStatus.json().queueBytes).toEqual({ pending: 0, claimed: 0, delivered: 0, expired: 0 });
    expect((await app.inject({ method: 'GET', url: '/metrics' })).statusCode).toBe(404);
    const metrics = await app.inject({
      method: 'GET', url: '/metrics', headers: { authorization: `Bearer ${METRICS_TOKEN}` },
    });
    expect(metrics.statusCode).toBe(200);
    expect(metrics.body).toContain('otto_federation_http_requests_total');
    expect(metrics.body).toContain('otto_federation_queue_bytes');
    expect(metrics.body).toContain('otto_federation_rejections_total');
  });

  it('provides a private-server client that signs sends and verifies claimed envelopes', async () => {
    const injectedFetch = (async (input: string | URL | Request, init?: RequestInit) => {
      const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
      const response = await app.inject({
        method: (init?.method || 'GET') as 'GET' | 'POST',
        url: `${url.pathname}${url.search}`,
        headers: init?.headers as Record<string, string> | undefined,
        payload: typeof init?.body === 'string' ? init.body : undefined,
      });
      return new Response(response.body, {
        status: response.statusCode,
        headers: response.headers as Record<string, string>,
      });
    }) as typeof fetch;
    const sender = new FederationClient({
      baseUrl: 'http://127.0.0.1:7790',
      deploymentId: 'deployment_a',
      signer: deploymentA,
      fetch: injectedFetch,
      now: () => now,
      allowInsecureLoopback: true,
    });
    const recipient = new FederationClient({
      baseUrl: 'http://127.0.0.1:7790',
      deploymentId: 'deployment_b',
      signer: deploymentB,
      fetch: injectedFetch,
      now: () => now,
      allowInsecureLoopback: true,
    });
    expect(sender.capabilities).toEqual([
      'federation.v1',
      'chat.e2ee',
      'a2a.e2ee',
      'attachment.e2ee',
    ]);
    const prepared = await sender.createSignedEnvelope({
      recipientDeploymentId: 'deployment_b',
      type: 'chat.message',
      ciphertext: 'ZW5jcnlwdGVkLWNoYXQ',
      routing: {
        conversationId: 'conversation_client',
        senderPrincipalId: 'account_alice',
        recipientPrincipalId: 'account_bob',
      },
    });
    const sent = await sender.sendSignedEnvelope(prepared);
    expect(await sender.sendSignedEnvelope(prepared)).toMatchObject({
      accepted: true,
      duplicate: true,
      messageId: sent.messageId,
    });
    const claimed = await recipient.claim();
    expect(claimed).toHaveLength(1);
    expect(claimed[0]?.signed.envelope.messageId).toBe(sent.messageId);
    await recipient.acknowledge(sent.messageId, claimed[0]!.claimToken);
    expect((await store.getMessage(sent.messageId))?.status).toBe('delivered');
  });

  it('keeps expired non-revoked keys available only for messages signed during their validity', async () => {
    const expiresAt = new Date(now + 5 * 60_000).toISOString();
    expect((await app.inject({
      method: 'POST',
      url: '/v1/admin/federation/deployments/deployment_a/keys',
      headers: { authorization: `Bearer ${ADMIN_TOKEN}` },
      payload: { publicKeyPem: deploymentA.publicKeyPem, expiresAt },
    })).statusCode).toBe(201);

    const sender = new FederationClient({
      baseUrl: 'http://127.0.0.1:7790',
      deploymentId: 'deployment_a',
      signer: deploymentA,
      fetch: injectedFetch(app),
      now: () => now,
      allowInsecureLoopback: true,
    });
    const recipient = new FederationClient({
      baseUrl: 'http://127.0.0.1:7790',
      deploymentId: 'deployment_b',
      signer: deploymentB,
      fetch: injectedFetch(app),
      now: () => now,
      allowInsecureLoopback: true,
    });
    await sender.sendCiphertext({
      recipientDeploymentId: 'deployment_b',
      type: 'chat.message',
      ciphertext: 'ZW5jcnlwdGVkLWJlZm9yZS1rZXktZXhwaXJ5',
      routing: {
        conversationId: 'conversation_key_rotation',
        senderPrincipalId: 'account_alice',
        recipientPrincipalId: 'account_bob',
      },
    });

    now += 10 * 60_000;
    expect(await recipient.claim()).toHaveLength(1);
  });
});

function injectedFetch(app: FastifyInstance): typeof fetch {
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
    const response = await app.inject({
      method: (init?.method || 'GET') as 'GET' | 'POST',
      url: `${url.pathname}${url.search}`,
      headers: init?.headers as Record<string, string> | undefined,
      payload: typeof init?.body === 'string' ? init.body : undefined,
    });
    return new Response(response.body, {
      status: response.statusCode,
      headers: response.headers as Record<string, string>,
    });
  }) as typeof fetch;
}

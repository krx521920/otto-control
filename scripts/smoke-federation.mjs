import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';

import {
  LocalEd25519Signer,
  signPayload,
} from 'file:///app/dist/crypto/signed-envelope.js';
import { FederationClient } from 'file:///app/dist/modules/federation/client.js';
import { verifyFederationSignature } from 'file:///app/dist/modules/federation/crypto.js';

const relayUrl = process.env.FEDERATION_SMOKE_RELAY_URL || 'http://127.0.0.1:7790';
const claimUrl = process.env.FEDERATION_SMOKE_CLAIM_URL || 'http://federation-b:7790';
const acknowledgeUrl = process.env.FEDERATION_SMOKE_ACK_URL || 'http://federation-c:7790';
const tokenFile = process.env.FEDERATION_ADMIN_TOKEN_FILE || '/run/secrets/federation_admin_token';
const adminToken = readFileSync(tokenFile, 'utf8').trim();
if (adminToken.length < 32) throw new Error('federation smoke test requires an administrator token');

function localSigner() {
  const { privateKey } = generateKeyPairSync('ed25519');
  return new LocalEd25519Signer(
    privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  );
}

async function jsonRequest(url, init, expectedStatus) {
  const response = await fetch(url, { ...init, signal: AbortSignal.timeout(10_000) });
  const text = await response.text();
  if (response.status !== expectedStatus) {
    throw new Error(`federation smoke request failed (${response.status}): ${text.slice(0, 300)}`);
  }
  return text ? JSON.parse(text) : {};
}

async function admin(path, body, expectedStatus = 201) {
  return jsonRequest(`${relayUrl}${path}`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${adminToken}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify(body),
  }, expectedStatus);
}

async function signedRequest(signer, deploymentId, body) {
  const issuedAt = Date.now();
  const request = {
    version: 1,
    deploymentId,
    issuedAt: new Date(issuedAt).toISOString(),
    expiresAt: new Date(issuedAt + 60_000).toISOString(),
    nonce: `nonce_${randomBytes(24).toString('base64url')}`,
    ...body,
  };
  return { request, ...await signPayload(signer, request) };
}

const suffix = randomBytes(6).toString('hex');
const senderId = `smoke_sender_${suffix}`;
const recipientId = `smoke_recipient_${suffix}`;
const senderSigner = localSigner();
const recipientSigner = localSigner();
const capabilities = ['federation.v1', 'chat.e2ee', 'a2a.e2ee'];

for (const deployment of [
  { id: senderId, displayName: 'Federation smoke sender', signer: senderSigner },
  { id: recipientId, displayName: 'Federation smoke recipient', signer: recipientSigner },
]) {
  await admin('/v1/admin/federation/deployments', {
    id: deployment.id,
    displayName: deployment.displayName,
    origin: `https://${deployment.id}.example.test`,
    capabilities,
    maxPendingMessages: 100,
    maxPendingBytes: 10 * 1024 * 1024,
    maxRequestsPerMinute: 1_200,
  });
  await admin(`/v1/admin/federation/deployments/${deployment.id}/keys`, {
    keyId: deployment.signer.keyId,
    publicKeyPem: deployment.signer.publicKeyPem,
  });
}

const sender = new FederationClient({
  baseUrl: relayUrl,
  deploymentId: senderId,
  signer: senderSigner,
  allowInsecureLoopback: true,
});
const prepared = await Promise.all(Array.from({ length: 6 }, (_, index) => sender.createSignedEnvelope({
  recipientDeploymentId: recipientId,
  type: 'chat.message',
  ciphertext: Buffer.from(`otto-federation-smoke-ciphertext-${index}`).toString('base64url'),
  routing: {
    conversationId: `smoke_conversation_${suffix}`,
    senderPrincipalId: 'smoke_sender_account',
    recipientPrincipalId: 'smoke_recipient_account',
  },
  expiresInMs: 5 * 60_000,
})));
const sent = await Promise.all(prepared.map((envelope) => sender.sendSignedEnvelope(envelope)));
const duplicate = await sender.sendSignedEnvelope(prepared[0]);
if (sent.some((result) => !result.accepted || result.duplicate) || !duplicate.duplicate) {
  throw new Error('federation relay did not preserve idempotent delivery');
}

const claimUrls = [relayUrl, claimUrl, acknowledgeUrl];
const claims = await Promise.all(claimUrls.map(async (url) => jsonRequest(
  `${url}/v1/federation/inbox/claim`,
  {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(await signedRequest(recipientSigner, recipientId, { limit: 10 })),
  },
  200,
)));
const expectedIds = new Set(sent.map((result) => result.messageId));
const claimed = claims.flatMap((claim) => claim.messages || [])
  .filter((item) => expectedIds.has(item.envelope?.messageId));
if (claimed.length !== expectedIds.size || new Set(claimed.map((item) => item.envelope.messageId)).size !== expectedIds.size) {
  throw new Error('concurrent federation replicas duplicated or lost an inbox lease');
}
for (const item of claimed) {
  if (!item.claimToken) throw new Error('federation recipient did not receive a claim token');
  verifyFederationSignature({
    payload: item.envelope,
    signature: item.signature,
    publicKeyPem: senderSigner.publicKeyPem,
  });
}
await Promise.all(claimed.map(async (item, index) => jsonRequest(
  `${claimUrls[(index + 1) % claimUrls.length]}/v1/federation/inbox/ack`,
  {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(await signedRequest(recipientSigner, recipientId, {
      messageId: item.envelope.messageId,
      claimToken: item.claimToken,
    })),
  },
  200,
)));
const status = await jsonRequest(`${acknowledgeUrl}/v1/admin/federation/status`, {
  method: 'GET',
  headers: { authorization: `Bearer ${adminToken}` },
}, 200);
if ((status.queue?.delivered || 0) < expectedIds.size) {
  throw new Error('federation acknowledgements were not committed across replicas');
}

process.stdout.write(`Federation three-replica smoke test passed for ${senderId} -> ${recipientId}.\n`);

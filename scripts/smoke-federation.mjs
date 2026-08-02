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
const prepared = await sender.createSignedEnvelope({
  recipientDeploymentId: recipientId,
  type: 'chat.message',
  ciphertext: 'b3R0by1mZWRlcmF0aW9uLXNtb2tlLWNpcGhlcnRleHQ',
  routing: {
    conversationId: `smoke_conversation_${suffix}`,
    senderPrincipalId: 'smoke_sender_account',
    recipientPrincipalId: 'smoke_recipient_account',
  },
  expiresInMs: 5 * 60_000,
});
const sent = await sender.sendSignedEnvelope(prepared);
const duplicate = await sender.sendSignedEnvelope(prepared);
if (!sent.accepted || sent.duplicate || !duplicate.duplicate) {
  throw new Error('federation relay did not preserve idempotent delivery');
}

const claim = await jsonRequest(`${claimUrl}/v1/federation/inbox/claim`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify(await signedRequest(recipientSigner, recipientId, { limit: 10 })),
}, 200);
const claimed = claim.messages?.find((item) => item.envelope?.messageId === sent.messageId);
if (!claimed?.claimToken) throw new Error('federation recipient did not claim the sent envelope');
verifyFederationSignature({
  payload: claimed.envelope,
  signature: claimed.signature,
  publicKeyPem: senderSigner.publicKeyPem,
});

await jsonRequest(`${acknowledgeUrl}/v1/federation/inbox/ack`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify(await signedRequest(recipientSigner, recipientId, {
    messageId: sent.messageId,
    claimToken: claimed.claimToken,
  })),
}, 200);
const status = await jsonRequest(`${acknowledgeUrl}/v1/federation/status`, { method: 'GET' }, 200);
if ((status.queue?.delivered || 0) < 1) throw new Error('federation acknowledgement was not committed');

process.stdout.write(`Federation smoke test passed for ${senderId} -> ${recipientId}.\n`);

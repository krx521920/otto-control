import { createHash } from 'node:crypto';

const HASH_PATTERN = /^[a-f0-9]{64}$/u;

async function request(controlUrl, path, token, init = {}) {
  const response = await fetch(new URL(path, controlUrl), {
    ...init,
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      ...init.headers,
    },
    redirect: 'error',
    signal: AbortSignal.timeout(15_000),
  });
  const text = await response.text();
  let body;
  try {
    body = text ? JSON.parse(text) : {};
  } catch {
    throw new Error(`Control returned non-JSON HTTP ${response.status}`);
  }
  if (!response.ok) {
    throw new Error(`Control HTTP ${response.status}: ${body?.error?.message || 'request failed'}`);
  }
  return body;
}

function eventEvidence(event, expected) {
  if (event?.action !== expected.action
    || event.targetType !== expected.targetType
    || event.targetId !== expected.targetId
    || !Number.isSafeInteger(event.id)
    || !Number.isSafeInteger(event.chainSequence)
    || event.chainSequence < 1
    || !HASH_PATTERN.test(event.eventHash ?? '')
    || !HASH_PATTERN.test(event.previousHash ?? '')) {
    throw new Error(`audit evidence is incomplete for ${expected.action}`);
  }
  return {
    id: event.id,
    action: event.action,
    targetType: event.targetType,
    targetId: event.targetId,
    chainSequence: event.chainSequence,
    eventHash: event.eventHash,
    createdAt: event.createdAt,
  };
}

export async function collectSigningAuditEvidence(input) {
  if (!Array.isArray(input.expectedEvents) || input.expectedEvents.length === 0) {
    throw new Error('at least one signing drill audit event is required');
  }
  const startedAtMs = Date.parse(input.startedAt);
  if (!Number.isFinite(startedAtMs)) throw new Error('signing drill startedAt is invalid');
  const queryFrom = new Date(startedAtMs - 5 * 60_000).toISOString();
  const events = [];
  for (const expected of input.expectedEvents) {
    const query = new URLSearchParams({
      action: expected.action,
      targetType: expected.targetType,
      targetId: expected.targetId,
      from: queryFrom,
      limit: '10',
    });
    const result = await request(
      input.controlUrl,
      `/v1/admin/audit/events?${query.toString()}`,
      input.auditorToken,
    );
    const matching = result.events?.find((event) => (
      event.action === expected.action
      && event.targetType === expected.targetType
      && event.targetId === expected.targetId
    ));
    events.push(eventEvidence(matching, expected));
  }

  const integrity = await request(
    input.controlUrl,
    '/v1/admin/audit/verify',
    input.auditorToken,
    { method: 'POST', body: '{}' },
  );
  const highestSequence = Math.max(...events.map((event) => event.chainSequence));
  if (integrity.receipt?.valid !== true
    || integrity.receipt.brokenAtSequence !== null
    || !Number.isSafeInteger(integrity.receipt.checkedEvents)
    || integrity.receipt.checkedEvents < highestSequence
    || !Number.isSafeInteger(integrity.receipt.lastSequence)
    || integrity.receipt.lastSequence < highestSequence
    || !HASH_PATTERN.test(integrity.receipt.headHash ?? '')
    || typeof integrity.signingKeyId !== 'string'
    || !integrity.signingKeyId
    || typeof integrity.signature !== 'string'
    || !integrity.signature.startsWith('ed25519:')) {
    throw new Error('audit integrity receipt does not cover the signing drill events');
  }

  return {
    verified: true,
    events,
    integrity: {
      checkedEvents: integrity.receipt.checkedEvents,
      lastSequence: integrity.receipt.lastSequence,
      headHash: integrity.receipt.headHash,
      signingKeyId: integrity.signingKeyId,
      signatureSha256: createHash('sha256').update(integrity.signature).digest('hex'),
      generatedAt: integrity.receipt.generatedAt,
    },
  };
}

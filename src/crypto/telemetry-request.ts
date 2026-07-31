import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

import { canonicalJson } from './signed-envelope.js';

export const TELEMETRY_REQUEST_SIGNATURE_PREFIX = 'hmac-sha256:';

export function telemetryIntegrityHash(payload: unknown): string {
  return `sha256:${createHash('sha256')
    .update(canonicalJson(payload))
    .digest('base64url')}`;
}

export function signTelemetryRequest(input: {
  token: string;
  timestamp: number;
  nonce: string;
  body: unknown;
}): string {
  const message = `${input.timestamp}\n${input.nonce}\n${canonicalJson(input.body)}`;
  return TELEMETRY_REQUEST_SIGNATURE_PREFIX + createHmac('sha256', input.token)
    .update(message, 'utf8')
    .digest('base64url');
}

export function secureTextMatches(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left, 'utf8');
  const rightBytes = Buffer.from(right, 'utf8');
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}

import { timingSafeEqual } from 'node:crypto';

import type { FastifyRequest } from 'fastify';

export function bearerToken(request: FastifyRequest): string {
  const authorization = request.headers.authorization?.trim() || '';
  return /^Bearer\s+(.+)$/iu.exec(authorization)?.[1] || '';
}

export function secretMatches(candidate: string, expected: string): boolean {
  const left = Buffer.from(candidate, 'utf8');
  const right = Buffer.from(expected, 'utf8');
  return left.length === right.length && timingSafeEqual(left, right);
}

export function actorId(request: FastifyRequest): string {
  const value = request.headers['x-otto-actor-id'];
  return typeof value === 'string' && /^[a-zA-Z0-9_.:@-]{2,128}$/u.test(value)
    ? value
    : 'control-admin';
}


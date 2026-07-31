import { timingSafeEqual } from 'node:crypto';

import type { FastifyRequest } from 'fastify';

import type { AdminPermission, AdminPrincipal } from '../contracts/admin-identity.js';
import { forbidden } from '../errors.js';
import type { AdminIdentityService } from '../modules/admin-identity/service.js';

export function bearerToken(request: FastifyRequest): string {
  const authorization = request.headers.authorization?.trim() || '';
  return /^Bearer\s+(.+)$/iu.exec(authorization)?.[1] || '';
}

export function secretMatches(candidate: string, expected: string): boolean {
  const left = Buffer.from(candidate, 'utf8');
  const right = Buffer.from(expected, 'utf8');
  return left.length === right.length && timingSafeEqual(left, right);
}

export interface AdminRouteAuthentication {
  identity: AdminIdentityService;
}

export interface AuthenticatedAdmin {
  actorId: string;
  principal: AdminPrincipal;
}

export async function authenticateAdmin(
  request: FastifyRequest,
  options: AdminRouteAuthentication,
  permission: AdminPermission,
): Promise<AuthenticatedAdmin> {
  const principal = await options.identity.authenticate(bearerToken(request));
  if (!principal.permissions.includes(permission)) {
    throw forbidden(`Missing permission: ${permission}`);
  }
  return { actorId: principal.accountId, principal };
}

export async function consumeRouteApproval(
  request: FastifyRequest,
  identity: AdminIdentityService,
  principal: AdminPrincipal,
  input: { operation: string; targetType: string; targetId: string; request: unknown },
): Promise<void> {
  const header = request.headers['x-otto-approval-id'];
  const approvalId = typeof header === 'string' ? header.trim() : '';
  await identity.consumeApproval(principal, approvalId, input);
}

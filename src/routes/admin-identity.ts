import type { FastifyInstance } from 'fastify';

import { invalidRequest, unauthorized } from '../errors.js';
import type { AdminIdentityService } from '../modules/admin-identity/service.js';
import { authenticateAdmin, bearerToken, secretMatches } from './route-auth.js';

export interface AdminIdentityRouteOptions {
  identity: AdminIdentityService;
  adminToken: string;
}

function bodyObject(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw invalidRequest('request body must be an object');
  }
  return value as Record<string, unknown>;
}

function text(body: Record<string, unknown>, key: string): string {
  return typeof body[key] === 'string' ? body[key] : '';
}

function textArray(body: Record<string, unknown>, key: string): string[] {
  return Array.isArray(body[key])
    ? body[key].filter((value): value is string => typeof value === 'string')
    : [];
}

export async function registerAdminIdentityRoutes(
  app: FastifyInstance,
  options: AdminIdentityRouteOptions,
): Promise<void> {
  app.post('/v1/admin-auth/bootstrap', {
    config: { rateLimit: { max: 5, timeWindow: '15 minutes' } },
  }, async (request, reply) => {
    if (!secretMatches(bearerToken(request), options.adminToken)) {
      throw unauthorized('Bootstrap administrator token is invalid');
    }
    const body = bodyObject(request.body);
    const enrollment = await options.identity.bootstrap({
      username: text(body, 'username'),
      displayName: text(body, 'displayName'),
      password: text(body, 'password'),
    });
    return reply.code(201).send({ enrollment });
  });

  app.post('/v1/admin-auth/enroll/confirm', {
    config: { rateLimit: { max: 10, timeWindow: '15 minutes' } },
  }, async (request) => {
    const body = bodyObject(request.body);
    return options.identity.confirmEnrollment({
      accountId: text(body, 'accountId'),
      enrollmentToken: text(body, 'enrollmentToken'),
      totpCode: text(body, 'totpCode'),
    });
  });

  app.post('/v1/admin-auth/login', {
    config: { rateLimit: { max: 10, timeWindow: '15 minutes' } },
  }, async (request) => {
    const body = bodyObject(request.body);
    return options.identity.login({
      username: text(body, 'username'),
      password: text(body, 'password'),
      totpCode: text(body, 'totpCode') || undefined,
      recoveryCode: text(body, 'recoveryCode') || undefined,
    });
  });

  app.post('/v1/admin-auth/logout', async (request, reply) => {
    const principal = await options.identity.authenticate(bearerToken(request));
    await options.identity.logout(principal);
    return reply.code(204).send();
  });

  app.get('/v1/admin-auth/me', async (request) => ({
    principal: await options.identity.authenticate(bearerToken(request)),
  }));

  app.get('/v1/admin/roles', async (request) => {
    const { principal } = await authenticateAdmin(request, options, 'identity.read');
    return { roles: await options.identity.listRoles(principal!) };
  });

  app.get('/v1/admin/accounts', async (request) => {
    const { principal } = await authenticateAdmin(request, options, 'identity.read');
    return { accounts: await options.identity.listAccounts(principal!) };
  });

  app.post('/v1/admin/accounts', async (request, reply) => {
    const { principal } = await authenticateAdmin(request, options, 'identity.manage');
    const body = bodyObject(request.body);
    const enrollment = await options.identity.createAccount(principal!, {
      username: text(body, 'username'),
      displayName: text(body, 'displayName'),
      password: text(body, 'password'),
      roleIds: textArray(body, 'roleIds'),
    });
    return reply.code(201).send({ enrollment });
  });

  app.put<{ Params: { accountId: string } }>(
    '/v1/admin/accounts/:accountId/roles',
    async (request) => {
      const { principal } = await authenticateAdmin(request, options, 'identity.manage');
      const body = bodyObject(request.body);
      return {
        roleIds: await options.identity.replaceRoles(
          principal!,
          request.params.accountId,
          textArray(body, 'roleIds'),
        ),
      };
    },
  );

  app.put<{ Params: { accountId: string } }>(
    '/v1/admin/accounts/:accountId/status',
    async (request) => {
      const { principal } = await authenticateAdmin(request, options, 'identity.manage');
      const body = bodyObject(request.body);
      const status = text(body, 'status');
      if (status !== 'active' && status !== 'disabled') throw invalidRequest('status is invalid');
      return {
        account: await options.identity.setAccountStatus(
          principal!,
          request.params.accountId,
          status,
        ),
      };
    },
  );

  app.post('/v1/admin/approvals', async (request, reply) => {
    const { principal } = await authenticateAdmin(request, options, 'approval.request');
    const body = bodyObject(request.body);
    const approval = await options.identity.requestApproval(principal!, {
      operation: text(body, 'operation'),
      targetType: text(body, 'targetType'),
      targetId: text(body, 'targetId'),
      request: body.request ?? {},
    });
    return reply.code(201).send({ approval });
  });

  app.get<{ Querystring: { limit?: string } }>('/v1/admin/approvals', async (request) => {
    const { principal } = await authenticateAdmin(request, options, 'approval.read');
    return {
      approvals: await options.identity.listApprovals(
        principal!,
        request.query.limit === undefined ? 100 : Number(request.query.limit),
      ),
    };
  });

  app.post<{ Params: { approvalId: string } }>(
    '/v1/admin/approvals/:approvalId/decide',
    async (request) => {
      const { principal } = await authenticateAdmin(request, options, 'approval.decide');
      const body = bodyObject(request.body);
      const decision = text(body, 'decision');
      if (decision !== 'approve' && decision !== 'reject') {
        throw invalidRequest('decision must be approve or reject');
      }
      return {
        approval: await options.identity.decideApproval(
          principal!,
          request.params.approvalId,
          decision,
          text(body, 'reason') || null,
        ),
      };
    },
  );
}

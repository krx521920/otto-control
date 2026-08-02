import type { FastifyInstance } from 'fastify';

import type { AdminIdentityService } from '../modules/admin-identity/service.js';
import type { CommercialControlService } from '../modules/commercial-control/service.js';
import { authenticateAdmin, bearerToken, consumeRouteApproval } from './route-auth.js';

export interface CommercialControlRouteOptions {
  service: CommercialControlService;
  identity: AdminIdentityService;
}

export async function registerCommercialControlRoutes(
  app: FastifyInstance,
  options: CommercialControlRouteOptions,
): Promise<void> {
  app.register(async (admin) => {
    admin.get<{ Querystring: { limit?: string } }>('/overview', async (request) => {
      await authenticateAdmin(request, options, 'commercial.read');
      return options.service.operatorOverview(
        request.query.limit === undefined ? 12 : Number(request.query.limit),
      );
    });

    admin.post('/customers', async (request, reply) => {
      const auth = await authenticateAdmin(request, options, 'customer.create');
      const customer = await options.service.createCustomer(request.body, auth.actorId);
      return reply.code(201).send({ customer });
    });

    admin.post('/deployments', async (request, reply) => {
      const auth = await authenticateAdmin(request, options, 'deployment.create');
      const deployment = await options.service.createDeployment(request.body, auth.actorId);
      return reply.code(201).send({ deployment });
    });

    admin.post('/licenses', async (request, reply) => {
      const auth = await authenticateAdmin(request, options, 'license.issue');
      const envelope = await options.service.issueLicense(request.body, auth.actorId);
      return reply.code(201).send(envelope);
    });

    admin.get('/signing-key', async (request) => {
      await authenticateAdmin(request, options, 'signing_key.read');
      return { signingKey: await options.service.signingKey() };
    });

    admin.get('/signing-keys', async (request) => {
      await authenticateAdmin(request, options, 'signing_key.read');
      return { signingKeys: await options.service.signingKeys() };
    });

    admin.post<{ Params: { keyId: string } }>(
      '/signing-keys/:keyId/probe',
      { config: { rateLimit: { max: 10, timeWindow: '1 minute' } } },
      async (request) => {
        const auth = await authenticateAdmin(request, options, 'signing_key.manage');
        return { probe: await options.service.probeSigningKey(
          request.params.keyId,
          auth.actorId,
        ) };
      },
    );

    admin.post<{ Params: { keyId: string } }>(
      '/signing-keys/:keyId/activate',
      async (request) => {
        const auth = await authenticateAdmin(request, options, 'signing_key.manage');
        await consumeRouteApproval(request, options.identity, auth.principal, {
          operation: 'signing_key.activate',
          targetType: 'signing_key',
          targetId: request.params.keyId,
          request: {},
        });
        return { signingKeys: await options.service.activateSigningKey(
          request.params.keyId,
          auth.actorId,
        ) };
      },
    );

    admin.post<{ Params: { keyId: string } }>(
      '/signing-keys/:keyId/retire',
      async (request) => {
        const auth = await authenticateAdmin(request, options, 'signing_key.manage');
        await consumeRouteApproval(request, options.identity, auth.principal, {
          operation: 'signing_key.retire',
          targetType: 'signing_key',
          targetId: request.params.keyId,
          request: {},
        });
        return { signingKeys: await options.service.retireSigningKey(
          request.params.keyId,
          auth.actorId,
        ) };
      },
    );

    admin.post<{ Params: { keyId: string } }>(
      '/signing-keys/:keyId/revoke',
      async (request) => {
        const auth = await authenticateAdmin(request, options, 'signing_key.manage');
        await consumeRouteApproval(request, options.identity, auth.principal, {
          operation: 'signing_key.revoke',
          targetType: 'signing_key',
          targetId: request.params.keyId,
          request: request.body ?? {},
        });
        return { signingKeys: await options.service.revokeSigningKey(
          request.params.keyId,
          request.body,
          auth.actorId,
        ) };
      },
    );

    admin.get<{ Params: { licenseId: string } }>('/licenses/:licenseId', async (request) => {
      await authenticateAdmin(request, options, 'license.export');
      return options.service.getLicenseEnvelope(request.params.licenseId);
    });

    admin.get<{ Params: { licenseId: string } }>(
      '/licenses/:licenseId/summary',
      async (request) => {
        await authenticateAdmin(request, options, 'license.read');
        return { license: await options.service.operatorLicenseDetail(request.params.licenseId) };
      },
    );

    admin.post<{ Params: { licenseId: string } }>(
      '/licenses/:licenseId/renew',
      async (request) => {
        const auth = await authenticateAdmin(request, options, 'license.manage');
        return options.service.renewLicense(request.params.licenseId, request.body, auth.actorId);
      },
    );

    admin.post<{ Params: { licenseId: string } }>(
      '/licenses/:licenseId/resize',
      async (request) => {
        const auth = await authenticateAdmin(request, options, 'license.manage');
        return options.service.resizeLicense(request.params.licenseId, request.body, auth.actorId);
      },
    );

    admin.post<{ Params: { licenseId: string } }>(
      '/licenses/:licenseId/transfer-machine',
      async (request) => {
        const auth = await authenticateAdmin(request, options, 'license.transfer');
        await consumeRouteApproval(request, options.identity, auth.principal, {
          operation: 'license.transfer_machine',
          targetType: 'license',
          targetId: request.params.licenseId,
          request: request.body ?? {},
        });
        return options.service.transferLicenseMachine(
          request.params.licenseId,
          request.body,
          auth.actorId,
        );
      },
    );

    admin.post<{ Params: { licenseId: string } }>(
      '/licenses/:licenseId/rebind-deployment',
      async (request) => {
        const auth = await authenticateAdmin(request, options, 'license.transfer');
        await consumeRouteApproval(request, options.identity, auth.principal, {
          operation: 'license.rebind_deployment',
          targetType: 'license',
          targetId: request.params.licenseId,
          request: request.body ?? {},
        });
        return options.service.rebindLicenseDeployment(
          request.params.licenseId,
          request.body,
          auth.actorId,
        );
      },
    );

    admin.get<{
      Params: { licenseId: string };
      Querystring: { limit?: string };
    }>('/licenses/:licenseId/lifecycle', async (request) => {
      await authenticateAdmin(request, options, 'license.usage.read');
      return {
        events: await options.service.licenseLifecycle(
          request.params.licenseId,
          request.query.limit === undefined ? 50 : Number(request.query.limit),
        ),
      };
    });

    admin.get<{ Params: { licenseId: string } }>(
      '/licenses/:licenseId/seats',
      async (request) => {
        await authenticateAdmin(request, options, 'license.usage.read');
        return { usage: await options.service.licenseSeatUsage(request.params.licenseId) };
      },
    );

    admin.post<{ Params: { licenseId: string } }>(
      '/licenses/:licenseId/revoke',
      async (request) => {
        const auth = await authenticateAdmin(request, options, 'license.revoke');
        await consumeRouteApproval(request, options.identity, auth.principal, {
          operation: 'license.revoke',
          targetType: 'license',
          targetId: request.params.licenseId,
          request: {},
        });
        return { license: await options.service.revokeLicense(
          request.params.licenseId,
          auth.actorId,
        ) };
      },
    );

    admin.get<{
      Params: { deploymentId: string };
      Querystring: { hours?: string };
    }>('/deployments/:deploymentId/health', async (request) => {
      await authenticateAdmin(request, options, 'telemetry.read');
      return { health: await options.service.deploymentHealth(
        request.params.deploymentId,
        request.query.hours === undefined ? 24 : Number(request.query.hours),
      ) };
    });
  }, { prefix: '/v1/admin' });

  app.get('/v1/signing-keyring', {
    config: { rateLimit: { max: 60, timeWindow: '1 minute' } },
  }, async () => options.service.publicSigningKeyring());

  app.post<{ Params: { licenseId: string } }>(
    '/v1/licenses/:licenseId/lease',
    async (request) => options.service.issueLease(
      request.params.licenseId,
      request.body,
      bearerToken(request),
    ),
  );

  app.post('/v1/telemetry/ingest', {
    config: {
      rateLimit: {
        max: 300,
        timeWindow: '1 minute',
        ban: 20,
      },
    },
  }, async (request, reply) => {
    const receipt = await options.service.ingestTelemetry(request.body, {
      authorization: request.headers.authorization,
      timestamp: typeof request.headers['x-otto-timestamp'] === 'string'
        ? request.headers['x-otto-timestamp']
        : undefined,
      nonce: typeof request.headers['x-otto-nonce'] === 'string'
        ? request.headers['x-otto-nonce']
        : undefined,
      signature: typeof request.headers['x-otto-signature'] === 'string'
        ? request.headers['x-otto-signature']
        : undefined,
    });
    return reply.code(202).send(receipt);
  });
}

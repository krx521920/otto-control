import { randomUUID } from 'node:crypto';

import type {
  EdgeGatewayLimitsV1,
  EdgeGatewayPolicyV1,
  EdgeModelRouteV1,
  SignedEdgeAccessTokenV1,
  SignedEdgeGatewayPolicyV1,
} from '../../contracts/edge-gateway.js';
import { secureTextMatches, signTelemetryRequest } from '../../crypto/telemetry-request.js';
import { signPayload, type PayloadSigner } from '../../crypto/signed-envelope.js';
import {
  EdgeGatewayProtocolError,
  encodeEdgeAccessTokenEnvelope,
  normalizeSignedEdgeAccessToken,
  normalizeSignedEdgeGatewayPolicy,
} from '../../edge-gateway/protocol.js';
import { conflict, forbidden, invalidRequest, notFound, unauthorized } from '../../errors.js';
import type { ControlStore, EdgeGatewayPolicyRecord } from '../../storage/control-store.js';
import { authenticateOnlineDeployment } from '../commercial-control/deployment-authentication.js';
import type { ControlTokenIssuer } from '../commercial-control/token-issuer.js';

const IDENTIFIER_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,159}$/u;
const NONCE_PATTERN = /^[a-zA-Z0-9_-]{16,128}$/u;
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
const POLICY_REQUEST_FIELDS = new Set([
  'organizationId', 'policyVersion', 'routes', 'limits', 'status',
]);
const RESOLVE_REQUEST_FIELDS = new Set([
  'licenseId', 'deploymentId', 'organizationId', 'machineFingerprint',
]);
const TOKEN_REQUEST_FIELDS = new Set([
  ...RESOLVE_REQUEST_FIELDS, 'subjectId', 'allowedModels',
]);

export interface EdgeGatewayControlServiceOptions {
  signer: PayloadSigner;
  store?: ControlStore;
  tokenIssuer?: ControlTokenIssuer;
  now?: () => number;
  id?: () => string;
}

export interface IssueEdgeGatewayPolicyInput {
  policyVersion: string;
  deploymentId: string;
  organizationId: string;
  routes: EdgeModelRouteV1[];
  limits: EdgeGatewayLimitsV1;
  durationMs?: number;
}

export interface IssueEdgeAccessTokenInput {
  deploymentId: string;
  organizationId: string;
  subjectId: string;
  policyVersion: string;
  allowedModels: string[];
  durationMs?: number;
}

export interface EdgeGatewayRequestAuthentication {
  authorization?: string;
  timestamp?: string;
  nonce?: string;
  signature?: string;
}

function objectValue(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw invalidRequest('request body must be an object');
  }
  return value as Record<string, unknown>;
}

function exactFields(body: Record<string, unknown>, fields: Set<string>, name: string): void {
  if (Object.keys(body).some((field) => !fields.has(field))) {
    throw invalidRequest(`${name} contains unsupported fields`);
  }
}

function requiredString(body: Record<string, unknown>, field: string, maximum = 160): string {
  const value = typeof body[field] === 'string' ? body[field].trim() : '';
  if (!value || value.length > maximum || !IDENTIFIER_PATTERN.test(value)) {
    throw invalidRequest(`${field} is invalid`);
  }
  return value;
}

function bearerToken(value: string | undefined): string {
  return /^Bearer\s+(.+)$/iu.exec(value?.trim() || '')?.[1] || '';
}

function protocolInputError(error: unknown): never {
  if (error instanceof EdgeGatewayProtocolError) throw invalidRequest(error.message);
  throw error;
}

/**
 * Control-plane issuer for edge artifacts. This class signs only metadata; model
 * prompts, responses, provider secrets, and conversation context are never
 * accepted by this boundary.
 */
export class EdgeGatewayControlService {
  readonly #signer: PayloadSigner;
  readonly #store?: ControlStore;
  readonly #tokens?: ControlTokenIssuer;
  readonly #now: () => number;
  readonly #id: () => string;

  constructor(options: EdgeGatewayControlServiceOptions) {
    this.#signer = options.signer;
    this.#store = options.store;
    this.#tokens = options.tokenIssuer;
    this.#now = options.now ?? Date.now;
    this.#id = options.id ?? randomUUID;
  }

  async issuePolicy(input: IssueEdgeGatewayPolicyInput): Promise<SignedEdgeGatewayPolicyV1> {
    const issuedAtMs = this.#now();
    const policy: EdgeGatewayPolicyV1 = {
      version: 1,
      policyId: `edge_policy_${this.#id()}`,
      policyVersion: input.policyVersion,
      deploymentId: input.deploymentId,
      organizationId: input.organizationId,
      routes: input.routes,
      limits: input.limits,
      issuedAtMs,
      expiresAtMs: issuedAtMs + (input.durationMs ?? 15 * 60 * 1000),
    };
    const envelope = { policy, ...await signPayload(this.#signer, policy) };
    return normalizeSignedEdgeGatewayPolicy(envelope, issuedAtMs);
  }

  async issueAccessToken(
    input: IssueEdgeAccessTokenInput,
  ): Promise<SignedEdgeAccessTokenV1> {
    const issuedAtMs = this.#now();
    const token = {
      version: 1 as const,
      tokenId: `edge_token_${this.#id()}`,
      deploymentId: input.deploymentId,
      organizationId: input.organizationId,
      subjectId: input.subjectId,
      scope: 'model_gateway' as const,
      policyVersion: input.policyVersion,
      allowedModels: input.allowedModels,
      issuedAtMs,
      expiresAtMs: issuedAtMs + (input.durationMs ?? 5 * 60 * 1000),
    };
    const envelope = { token, ...await signPayload(this.#signer, token) };
    return normalizeSignedEdgeAccessToken(envelope, issuedAtMs);
  }

  async configurePolicy(
    deploymentId: string,
    raw: unknown,
    actorId: string,
  ): Promise<EdgeGatewayPolicyRecord> {
    const store = this.#requireStore();
    const body = objectValue(raw);
    exactFields(body, POLICY_REQUEST_FIELDS, 'edge gateway policy');
    if (!IDENTIFIER_PATTERN.test(deploymentId)) throw invalidRequest('deploymentId is invalid');
    const deployment = await store.getDeployment(deploymentId);
    if (!deployment) throw notFound('deployment not found');
    if (deployment.status !== 'active') throw conflict('deployment is inactive');
    const organizationId = requiredString(body, 'organizationId');
    if (organizationId !== deployment.organizationId) {
      throw forbidden('edge gateway policy organization does not match deployment');
    }
    const status = body.status === undefined ? 'active' : body.status;
    if (status !== 'active' && status !== 'suspended') {
      throw invalidRequest('status is invalid');
    }
    let normalized: SignedEdgeGatewayPolicyV1;
    try {
      normalized = await this.issuePolicy({
        deploymentId,
        organizationId,
        policyVersion: requiredString(body, 'policyVersion'),
        routes: body.routes as EdgeModelRouteV1[],
        limits: body.limits as EdgeGatewayLimitsV1,
      });
    } catch (error) {
      protocolInputError(error);
    }
    const changedAt = new Date(this.#now());
    const record = await store.upsertEdgeGatewayPolicy({
      deploymentId,
      organizationId,
      policyVersion: normalized.policy.policyVersion,
      routes: normalized.policy.routes,
      limits: normalized.policy.limits,
      status,
      updatedBy: actorId,
      changedAt,
    });
    await store.appendAuditEvent({
      actorId,
      action: 'edge_gateway.policy.configured',
      targetType: 'deployment',
      targetId: deploymentId,
      detail: {
        organizationId,
        policyVersion: record.policyVersion,
        status,
        routeCount: record.routes.length,
        publicModels: [...new Set(record.routes.map((route) => route.publicModel))].sort(),
      },
    });
    return record;
  }

  async policy(deploymentId: string): Promise<EdgeGatewayPolicyRecord> {
    const policy = await this.#requireStore().getEdgeGatewayPolicy(deploymentId);
    if (!policy) throw notFound('edge gateway policy not found');
    return policy;
  }

  async resolvePolicy(
    raw: unknown,
    authentication: EdgeGatewayRequestAuthentication,
  ): Promise<SignedEdgeGatewayPolicyV1> {
    const body = objectValue(raw);
    exactFields(body, RESOLVE_REQUEST_FIELDS, 'edge gateway policy request');
    const authenticated = await this.#authenticate(body, authentication);
    const policy = await this.#activePolicy(
      authenticated.deploymentId,
      authenticated.organizationId,
    );
    await this.#assertBillingAdmission(
      authenticated.customerId,
      authenticated.organizationId,
      authenticated.license.billingEnforcement ?? 'disabled',
    );
    return this.issuePolicy(policy);
  }

  async issueDeploymentAccessToken(
    raw: unknown,
    authentication: EdgeGatewayRequestAuthentication,
  ): Promise<{ envelope: SignedEdgeAccessTokenV1; encodedToken: string }> {
    const body = objectValue(raw);
    exactFields(body, TOKEN_REQUEST_FIELDS, 'edge access token request');
    const authenticated = await this.#authenticate(body, authentication);
    const policy = await this.#activePolicy(
      authenticated.deploymentId,
      authenticated.organizationId,
    );
    await this.#assertBillingAdmission(
      authenticated.customerId,
      authenticated.organizationId,
      authenticated.license.billingEnforcement ?? 'disabled',
    );
    const subjectId = requiredString(body, 'subjectId');
    if (!Array.isArray(body.allowedModels) || body.allowedModels.length < 1
      || body.allowedModels.length > 64) {
      throw invalidRequest('allowedModels is invalid');
    }
    const allowedModels = body.allowedModels.map((model) => {
      if (typeof model !== 'string' || !model.trim() || model.trim().length > 160) {
        throw invalidRequest('allowedModels is invalid');
      }
      return model.trim();
    });
    if (new Set(allowedModels).size !== allowedModels.length) {
      throw invalidRequest('allowedModels must be unique');
    }
    const configuredModels = new Set(policy.routes.map((route) => route.publicModel));
    if (allowedModels.some((model) => !configuredModels.has(model))) {
      throw forbidden('requested model is not allowed by the active edge policy');
    }
    const envelope = await this.issueAccessToken({
      deploymentId: policy.deploymentId,
      organizationId: policy.organizationId,
      subjectId,
      policyVersion: policy.policyVersion,
      allowedModels,
    });
    await this.#requireStore().appendAuditEvent({
      actorId: `deployment:${policy.deploymentId}`,
      action: 'edge_gateway.access_token.issued',
      targetType: 'edge_access_token',
      targetId: envelope.token.tokenId,
      detail: {
        deploymentId: policy.deploymentId,
        organizationId: policy.organizationId,
        subjectId,
        policyVersion: policy.policyVersion,
        allowedModels,
        expiresAtMs: envelope.token.expiresAtMs,
      },
    });
    return { envelope, encodedToken: encodeEdgeAccessTokenEnvelope(envelope) };
  }

  #requireStore(): ControlStore {
    if (!this.#store) throw new Error('edge gateway Control store is not configured');
    return this.#store;
  }

  #requireTokens(): ControlTokenIssuer {
    if (!this.#tokens) throw new Error('edge gateway token issuer is not configured');
    return this.#tokens;
  }

  async #authenticate(
    body: Record<string, unknown>,
    authentication: EdgeGatewayRequestAuthentication,
  ) {
    const store = this.#requireStore();
    const tokens = this.#requireTokens();
    const binding = {
      licenseId: requiredString(body, 'licenseId'),
      deploymentId: requiredString(body, 'deploymentId'),
      organizationId: requiredString(body, 'organizationId'),
      machineFingerprint: typeof body.machineFingerprint === 'string'
        ? body.machineFingerprint.trim().toLowerCase()
        : '',
    };
    const now = this.#now();
    const authenticated = await authenticateOnlineDeployment({
      store,
      tokens,
      binding,
      bearerToken: bearerToken(authentication.authorization),
      nowMs: now,
      purpose: 'edge gateway',
    });
    const timestamp = Number(authentication.timestamp);
    const nonce = authentication.nonce?.trim() || '';
    const signature = authentication.signature?.trim() || '';
    if (!Number.isFinite(timestamp) || Math.abs(now - timestamp) > MAX_CLOCK_SKEW_MS) {
      throw unauthorized('edge gateway request timestamp is invalid');
    }
    if (!NONCE_PATTERN.test(nonce)) throw invalidRequest('edge gateway nonce is invalid');
    const leaseToken = tokens.issue({
      purpose: 'lease',
      licenseId: binding.licenseId,
      deploymentId: binding.deploymentId,
      version: authenticated.license.tokenVersion,
    });
    const expectedSignature = signTelemetryRequest({ token: leaseToken, timestamp, nonce, body });
    if (!secureTextMatches(signature, expectedSignature)) {
      throw unauthorized('edge gateway request signature is invalid');
    }
    const accepted = await store.consumeEdgeGatewayNonce({
      deploymentId: binding.deploymentId,
      nonce,
      nowMs: now,
      expiresAtMs: now + MAX_CLOCK_SKEW_MS * 2,
    });
    if (!accepted) throw conflict('edge gateway request replay detected');
    return authenticated;
  }

  async #activePolicy(
    deploymentId: string,
    organizationId: string,
  ): Promise<EdgeGatewayPolicyRecord> {
    const policy = await this.policy(deploymentId);
    if (policy.status !== 'active') throw forbidden('edge gateway policy is suspended');
    if (policy.organizationId !== organizationId) {
      throw forbidden('edge gateway policy organization does not match request');
    }
    return policy;
  }

  async #assertBillingAdmission(
    customerId: string,
    organizationId: string,
    enforcement: 'disabled' | 'enforce',
  ): Promise<void> {
    if (enforcement !== 'enforce') return;
    const account = await this.#requireStore().getCreditAccount(customerId, organizationId);
    if (!account || account.availableBalance < 1) {
      throw forbidden('model gateway credit balance is exhausted');
    }
  }
}

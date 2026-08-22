import type { EdgeGatewayOutcomeV2 } from '../contracts/edge-gateway.js';
import type { EdgeBillingCoordinator } from './billing-coordinator.js';
import type { EdgeConcurrencyLimiter } from './concurrency-limit.js';
import type { EdgeRouteCircuitBreaker } from './circuit-breaker.js';
import {
  createOttoEdgeGateway,
  type EdgeGatewayBackgroundContext,
  type EdgeGatewayOutcomeSink,
} from './gateway.js';
import { createEdgeSignatureVerifier } from './protocol.js';
import type { EdgeRateLimiter } from './rate-limit.js';
import type { EdgeRequestLimits } from './request-limits.js';
import type { EdgeRequestLedger } from './request-ledger.js';
import type { EdgeUpstreamResponseLimits } from './upstream-response-limits.js';
import type { EdgeUpstreamOriginPolicy } from './upstream-origin-policy.js';

export interface AliyunEsaEdgeKv {
  get(key: string, options: { type: 'text' }): Promise<string | undefined>;
}

export interface AliyunEsaGatewayOptions {
  policyKv: AliyunEsaEdgeKv;
  policyKey: string;
  controlPublicKeys: Readonly<Record<string, string>>;
  providerSecret(binding: string): Promise<string | null> | string | null;
  rateLimiter: EdgeRateLimiter;
  concurrencyLimiter: EdgeConcurrencyLimiter;
  circuitBreaker?: EdgeRouteCircuitBreaker;
  billingCoordinator?: EdgeBillingCoordinator;
  requestLedger: EdgeRequestLedger;
  recordOutcome?(outcome: EdgeGatewayOutcomeV2): Promise<void>;
  fetch?: typeof fetch;
  now?: () => number;
  requestId?: () => string;
  requestLimits?: EdgeRequestLimits;
  responseLimits?: EdgeUpstreamResponseLimits;
  upstreamOriginPolicy: EdgeUpstreamOriginPolicy;
}

/**
 * Standard Web Service Worker adapter for Alibaba Cloud ESA. The deployment
 * bootstrap owns EdgeKV construction and secret lookup so neither provider
 * credentials nor Alibaba-specific globals enter the portable gateway core.
 */
export function createAliyunEsaGateway(options: AliyunEsaGatewayOptions): {
  fetch(request: Request, context?: EdgeGatewayBackgroundContext): Promise<Response>;
} {
  const outcomeSink: EdgeGatewayOutcomeSink | undefined = options.recordOutcome
    ? { record: options.recordOutcome }
    : undefined;
  const gateway = createOttoEdgeGateway({
    policySource: {
      async load() {
        const value = await options.policyKv.get(options.policyKey, { type: 'text' });
        // JSON.parse fails closed for both a missing value and malformed JSON;
        // the portable gateway translates either failure into policy-unavailable.
        return JSON.parse(value as string) as unknown;
      },
    },
    verifier: createEdgeSignatureVerifier(options.controlPublicKeys),
    // The portable core owns provider-secret normalization and byte validation,
    // so every runtime has one authoritative security boundary.
    secretResolver: {
      async get(binding) {
        return options.providerSecret(binding);
      },
    },
    rateLimiter: options.rateLimiter,
    concurrencyLimiter: options.concurrencyLimiter,
    circuitBreaker: options.circuitBreaker,
    billingCoordinator: options.billingCoordinator,
    requestLedger: options.requestLedger,
    outcomeSink,
    fetch: options.fetch,
    now: options.now,
    requestId: options.requestId,
    requestLimits: options.requestLimits,
    responseLimits: options.responseLimits,
    upstreamOriginPolicy: options.upstreamOriginPolicy,
  });
  return {
    fetch(request, context) {
      return gateway.fetch(request, context);
    },
  };
}

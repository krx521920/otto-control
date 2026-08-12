import type { EdgeGatewayOutcomeV2 } from '../contracts/edge-gateway.js';
import { createOttoEdgeGateway, type EdgeGatewayOutcomeSink } from './gateway.js';
import { createEdgeSignatureVerifier } from './protocol.js';
import type { EdgeRateLimiter } from './rate-limit.js';

export interface AliyunEsaEdgeKv {
  get(key: string, options: { type: 'text' }): Promise<string | undefined>;
}

export interface AliyunEsaGatewayOptions {
  policyKv: AliyunEsaEdgeKv;
  policyKey: string;
  controlPublicKeys: Readonly<Record<string, string>>;
  providerSecret(binding: string): Promise<string | null> | string | null;
  rateLimiter: EdgeRateLimiter;
  recordOutcome?(outcome: EdgeGatewayOutcomeV2): Promise<void>;
  fetch?: typeof fetch;
  now?: () => number;
  requestId?: () => string;
}

/**
 * Standard Web Service Worker adapter for Alibaba Cloud ESA. The deployment
 * bootstrap owns EdgeKV construction and secret lookup so neither provider
 * credentials nor Alibaba-specific globals enter the portable gateway core.
 */
export function createAliyunEsaGateway(options: AliyunEsaGatewayOptions): {
  fetch(request: Request): Promise<Response>;
} {
  const outcomeSink: EdgeGatewayOutcomeSink | undefined = options.recordOutcome
    ? { record: options.recordOutcome }
    : undefined;
  const gateway = createOttoEdgeGateway({
    policySource: {
      async load() {
        const value = await options.policyKv.get(options.policyKey, { type: 'text' });
        if (!value) throw new Error('gateway policy is missing from EdgeKV');
        return JSON.parse(value) as unknown;
      },
    },
    verifier: createEdgeSignatureVerifier(options.controlPublicKeys),
    secretResolver: {
      async get(binding) {
        const value = await options.providerSecret(binding);
        return typeof value === 'string' && value.trim() ? value.trim() : null;
      },
    },
    rateLimiter: options.rateLimiter,
    outcomeSink,
    fetch: options.fetch,
    now: options.now,
    requestId: options.requestId,
  });
  return {
    fetch(request) {
      return gateway.fetch(request);
    },
  };
}

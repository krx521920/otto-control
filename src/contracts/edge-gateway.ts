export type EdgeGatewayEndpoint = 'chat_completions' | 'responses';

export type EdgeProviderAuthentication =
  | {
      type: 'bearer';
      secretBinding: string;
    }
  | {
      type: 'header';
      headerName: string;
      secretBinding: string;
    };

export interface EdgeRouteMeteringV1 {
  type: 'openai_tokens';
  reserveUnits: number;
}

/**
 * A route is selected exclusively from a Control-signed policy. Client input can
 * select publicModel, but can never supply an upstream URL or secret binding.
 */
export interface EdgeModelRouteV1 {
  id: string;
  providerAdapter?: string;
  endpoint: EdgeGatewayEndpoint;
  publicModel: string;
  upstreamModel: string;
  upstreamUrl: string;
  priority: number;
  authentication: EdgeProviderAuthentication;
  metering?: EdgeRouteMeteringV1;
}

export interface EdgeGatewayLimitsV1 {
  maxRequestBytes: number;
  requestsPerMinute: number;
  upstreamConnectTimeoutMs: number;
  upstreamIdleTimeoutMs: number;
  maxRouteAttempts: number;
}

export interface EdgeGatewayPolicyV1 {
  version: 1;
  policyId: string;
  policyVersion: string;
  deploymentId: string;
  organizationId: string;
  routes: EdgeModelRouteV1[];
  limits: EdgeGatewayLimitsV1;
  issuedAtMs: number;
  expiresAtMs: number;
}

export interface SignedEdgeGatewayPolicyV1 {
  policy: EdgeGatewayPolicyV1;
  signingKeyId: string;
  signature: string;
}

export interface EdgeAccessTokenV1 {
  version: 1;
  tokenId: string;
  deploymentId: string;
  organizationId: string;
  subjectId: string;
  scope: 'model_gateway';
  policyVersion: string;
  allowedModels: string[];
  issuedAtMs: number;
  expiresAtMs: number;
}

export interface SignedEdgeAccessTokenV1 {
  token: EdgeAccessTokenV1;
  signingKeyId: string;
  signature: string;
}

/**
 * Content-free operational evidence. It is deliberately insufficient for
 * billing until a trusted usage aggregator has added provider token counts and
 * produced an ExecutionReceiptV2.
 */
export interface EdgeModelUsageV1 {
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
}

export interface EdgeGatewayOutcomeV2 {
  version: 2;
  requestId: string;
  tokenId: string;
  deploymentId: string;
  organizationId: string;
  subjectId: string;
  endpoint: EdgeGatewayEndpoint;
  publicModel: string;
  routeId: string | null;
  upstreamStatus: number | null;
  outcome:
    | 'succeeded'
    | 'rejected'
    | 'upstream_failed'
    | 'client_cancelled'
    | 'response_limit_exceeded'
    | 'stream_timed_out';
  durationMs: number;
  occurredAtMs: number;
  usage: EdgeModelUsageV1 | null;
}

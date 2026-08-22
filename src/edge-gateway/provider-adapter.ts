import type {
  EdgeGatewayEndpoint,
  EdgeModelRouteV1,
  EdgeModelUsageV1,
  EdgeRouteMeteringV1,
} from '../contracts/edge-gateway.js';
import { OpenAiUsageMeter } from './usage-meter.js';

/**
 * A streaming usage meter may observe provider response bytes, but its output is
 * deliberately limited to normalized token counts. Implementations are trusted
 * gateway code and must retain only bounded usage metadata, never model content.
 */
export interface EdgeTokenUsageMeter {
  push(bytes: Uint8Array): void;
  finish(): EdgeModelUsageV1 | null;
}

/**
 * Declaring this extension contract does not make an arbitrary provider
 * supported. Every implementation must be explicitly registered, reviewed, and
 * shipped with the gateway.
 */
export interface EdgeTokenUsageAdapter {
  readonly meteringType: string;
  createMeter(context: Readonly<{ endpoint: EdgeGatewayEndpoint }>): EdgeTokenUsageMeter;
}

export type EdgeProviderErrorCategory =
  | 'invalid_request'
  | 'authentication'
  | 'permission'
  | 'not_found'
  | 'conflict'
  | 'rate_limit'
  | 'provider_unavailable'
  | 'unknown';

export interface EdgeProviderErrorClassification {
  readonly category: EdgeProviderErrorCategory;
  readonly retryable: boolean;
}

export interface EdgeProviderRequestContext {
  readonly endpoint: EdgeGatewayEndpoint;
  readonly upstreamModel: string;
  readonly body: Readonly<Record<string, unknown>>;
  readonly metering: EdgeRouteMeteringV1 | null;
}

export interface EdgePreparedProviderRequest {
  /** JSON request body only. URL, headers, and credentials remain gateway-owned. */
  readonly body: Record<string, unknown>;
  readonly usageMeter: EdgeTokenUsageMeter | null;
  /** Classification uses status metadata only and never retains an error body. */
  classifyError(status: number): EdgeProviderErrorClassification | null;
}

export interface EdgeProviderAdapter {
  readonly id: string;
  readonly supportedEndpoints: readonly EdgeGatewayEndpoint[];
  readonly tokenUsageAdapters: readonly EdgeTokenUsageAdapter[];
  prepareRequest(context: EdgeProviderRequestContext): EdgePreparedProviderRequest;
}

export const OPENAI_PROVIDER_ADAPTER_ID = 'openai';
export const VOLCENGINE_ARK_PROVIDER_ADAPTER_ID = 'volcengine-ark';
export const ZHIPU_BIGMODEL_PROVIDER_ADAPTER_ID = 'zhipu-bigmodel';

export class UnsupportedEdgeProviderAdapterError extends Error {
  readonly adapterId: string;

  constructor(adapterId: string) {
    super(`unsupported edge provider adapter: ${adapterId}`);
    this.name = 'UnsupportedEdgeProviderAdapterError';
    this.adapterId = adapterId;
  }
}

export class UnsupportedEdgeProviderEndpointError extends Error {
  readonly adapterId: string;
  readonly endpoint: EdgeGatewayEndpoint;

  constructor(adapterId: string, endpoint: EdgeGatewayEndpoint) {
    super(`provider adapter ${adapterId} does not support endpoint: ${endpoint}`);
    this.name = 'UnsupportedEdgeProviderEndpointError';
    this.adapterId = adapterId;
    this.endpoint = endpoint;
  }
}

function createOpenAiTokenUsageAdapter(): EdgeTokenUsageAdapter {
  return Object.freeze({
    meteringType: 'openai_tokens',
    createMeter: ({ endpoint }: Readonly<{ endpoint: EdgeGatewayEndpoint }>) => new OpenAiUsageMeter({
      allowResponseEnvelope: endpoint === 'responses',
    }),
  });
}

function tokenUsageMeter(
  adapters: readonly EdgeTokenUsageAdapter[],
  context: EdgeProviderRequestContext,
): EdgeTokenUsageMeter | null {
  if (!context.metering) return null;
  const matches = adapters.filter(
    (adapter) => adapter.meteringType === context.metering?.type,
  );
  if (matches.length !== 1) {
    throw new Error(`unsupported or ambiguous token metering type: ${context.metering.type}`);
  }
  return matches[0]!.createMeter({ endpoint: context.endpoint });
}

function classifyOpenAiCompatibleError(status: number): EdgeProviderErrorClassification | null {
  if (!Number.isInteger(status) || status < 100 || status > 599) {
    return { category: 'unknown', retryable: false };
  }
  if (status < 400) return null;
  if (status === 400 || status === 408 || status === 413 || status === 422) {
    return { category: 'invalid_request', retryable: false };
  }
  if (status === 401) return { category: 'authentication', retryable: false };
  if (status === 403) return { category: 'permission', retryable: false };
  if (status === 404) return { category: 'not_found', retryable: false };
  if (status === 409) return { category: 'conflict', retryable: false };
  if (status === 429) return { category: 'rate_limit', retryable: true };
  if (status === 502 || status === 503 || status === 504) {
    return { category: 'provider_unavailable', retryable: true };
  }
  return { category: status >= 500 ? 'provider_unavailable' : 'unknown', retryable: false };
}

function createOpenAiCompatibleAdapter(
  id: string,
  supportedEndpoints: readonly EdgeGatewayEndpoint[],
  options: Readonly<{ includeChatStreamingUsageOption: boolean }>,
): EdgeProviderAdapter {
  const endpoints = Object.freeze([...supportedEndpoints]);
  const tokenUsageAdapters = Object.freeze([createOpenAiTokenUsageAdapter()]);
  return Object.freeze({
    id,
    supportedEndpoints: endpoints,
    tokenUsageAdapters,
    prepareRequest(context: EdgeProviderRequestContext): EdgePreparedProviderRequest {
      if (!endpoints.includes(context.endpoint)) {
        throw new UnsupportedEdgeProviderEndpointError(id, context.endpoint);
      }
      const body: Record<string, unknown> = {
        ...context.body,
        model: context.upstreamModel,
      };
      if (options.includeChatStreamingUsageOption
        && context.endpoint === 'chat_completions'
        && context.metering
        && body.stream === true) {
        const existing = body.stream_options;
        body.stream_options = {
          ...(existing && typeof existing === 'object' && !Array.isArray(existing)
            ? existing as Record<string, unknown>
            : {}),
          include_usage: true,
        };
      }
      return {
        body,
        usageMeter: tokenUsageMeter(tokenUsageAdapters, context),
        classifyError: classifyOpenAiCompatibleError,
      };
    },
  });
}

const builtInProviderAdapters = new Map<string, EdgeProviderAdapter>([
  [OPENAI_PROVIDER_ADAPTER_ID, createOpenAiCompatibleAdapter(
    OPENAI_PROVIDER_ADAPTER_ID,
    ['chat_completions', 'responses'],
    { includeChatStreamingUsageOption: true },
  )],
  [VOLCENGINE_ARK_PROVIDER_ADAPTER_ID, createOpenAiCompatibleAdapter(
    VOLCENGINE_ARK_PROVIDER_ADAPTER_ID,
    ['chat_completions', 'responses'],
    { includeChatStreamingUsageOption: true },
  )],
  [ZHIPU_BIGMODEL_PROVIDER_ADAPTER_ID, createOpenAiCompatibleAdapter(
    ZHIPU_BIGMODEL_PROVIDER_ADAPTER_ID,
    ['chat_completions'],
    { includeChatStreamingUsageOption: false },
  )],
]);

/**
 * Resolves only adapters compiled into this gateway. Runtime module loading and
 * user-supplied adapter code are intentionally excluded from this trust boundary.
 */
export function resolveEdgeProviderAdapter(id: string): EdgeProviderAdapter | null {
  return builtInProviderAdapters.get(id) ?? null;
}

export function prepareEdgeProviderRequest(
  route: EdgeModelRouteV1,
  body: Readonly<Record<string, unknown>>,
): EdgePreparedProviderRequest {
  const adapterId = route.providerAdapter ?? OPENAI_PROVIDER_ADAPTER_ID;
  const adapter = resolveEdgeProviderAdapter(adapterId);
  if (!adapter) throw new UnsupportedEdgeProviderAdapterError(adapterId);
  return adapter.prepareRequest({
    endpoint: route.endpoint,
    upstreamModel: route.upstreamModel,
    body,
    metering: route.metering ?? null,
  });
}

export function supportedEdgeProviderAdapterIds(): readonly string[] {
  return Object.freeze([...builtInProviderAdapters.keys()]);
}
import { describe, expect, it } from 'vitest';

import {
  OPENAI_PROVIDER_ADAPTER_ID,
  prepareEdgeProviderRequest,
  resolveEdgeProviderAdapter,
  supportedEdgeProviderAdapterIds,
  VOLCENGINE_ARK_PROVIDER_ADAPTER_ID,
  ZHIPU_BIGMODEL_PROVIDER_ADAPTER_ID,
  type EdgeProviderRequestContext,
} from '../src/edge-gateway/provider-adapter.js';

const encoder = new TextEncoder();
const adapterIds = [
  OPENAI_PROVIDER_ADAPTER_ID,
  VOLCENGINE_ARK_PROVIDER_ADAPTER_ID,
  ZHIPU_BIGMODEL_PROVIDER_ADAPTER_ID,
] as const;

function request(
  overrides: Partial<EdgeProviderRequestContext> = {},
): EdgeProviderRequestContext {
  return {
    endpoint: 'chat_completions',
    upstreamModel: 'configured-upstream-model',
    body: { model: 'public-model', messages: [{ role: 'user', content: 'private' }] },
    metering: { type: 'openai_tokens', reserveUnits: 100 },
    ...overrides,
  };
}

describe('edge provider adapters', () => {
  it('registers only the three explicitly supported providers', () => {
    expect(supportedEdgeProviderAdapterIds()).toEqual(adapterIds);
    const adapters = adapterIds.map((id) => resolveEdgeProviderAdapter(id));
    expect(adapters.map((adapter) => adapter?.id)).toEqual(adapterIds);
    expect(new Set(adapters).size).toBe(3);
    expect(new Set(adapters.map((adapter) => adapter?.tokenUsageAdapters[0])).size).toBe(3);
    expect(resolveEdgeProviderAdapter('openai-compatible')).toBeNull();
    expect(resolveEdgeProviderAdapter('arbitrary-provider')).toBeNull();
  });

  it.each([
    OPENAI_PROVIDER_ADAPTER_ID,
    VOLCENGINE_ARK_PROVIDER_ADAPTER_ID,
  ])('%s maps the signed model and requests Chat streaming usage', (adapterId) => {
    const adapter = resolveEdgeProviderAdapter(adapterId)!;
    const body = {
      model: 'public-model',
      stream: true,
      stream_options: { custom_option: true, include_usage: false },
      messages: [{ role: 'user', content: 'private' }],
    };

    const prepared = adapter.prepareRequest(request({ body }));

    expect(prepared.body).toEqual({
      ...body,
      model: 'configured-upstream-model',
      stream_options: { custom_option: true, include_usage: true },
    });
    expect(body.stream_options).toEqual({ custom_option: true, include_usage: false });
    expect(prepared.body).not.toBe(body);
    expect(prepared.body.stream_options).not.toBe(body.stream_options);
  });

  it('does not send an undocumented stream_options field to BigModel', () => {
    const adapter = resolveEdgeProviderAdapter(ZHIPU_BIGMODEL_PROVIDER_ADAPTER_ID)!;
    const body = { model: 'public-model', stream: true, messages: [] };

    const prepared = adapter.prepareRequest(request({ body }));

    expect(prepared.body).toEqual({
      ...body,
      model: 'configured-upstream-model',
    });
    expect(prepared.body).not.toHaveProperty('stream_options');
  });

  it.each([
    OPENAI_PROVIDER_ADAPTER_ID,
    VOLCENGINE_ARK_PROVIDER_ADAPTER_ID,
  ])('%s does not send Chat stream_options to the Responses endpoint', (adapterId) => {
    const adapter = resolveEdgeProviderAdapter(adapterId)!;

    const prepared = adapter.prepareRequest(request({
      endpoint: 'responses',
      body: { model: 'public-model', stream: true, input: 'private' },
    }));

    expect(prepared.body).not.toHaveProperty('stream_options');
  });

  it.each(adapterIds)('%s normalizes OpenAI-compatible JSON usage', (adapterId) => {
    const meter = resolveEdgeProviderAdapter(adapterId)!
      .prepareRequest(request()).usageMeter!;
    meter.push(encoder.encode(JSON.stringify({
      choices: [{ message: { content: 'private provider response' } }],
      usage: { prompt_tokens: 11, completion_tokens: 4, total_tokens: 15 },
    })));

    expect(meter.finish()).toEqual({ inputTokens: 11, outputTokens: 4, totalTokens: 15 });
  });

  it.each(adapterIds)('%s normalizes final SSE usage across chunks', (adapterId) => {
    const meter = resolveEdgeProviderAdapter(adapterId)!
      .prepareRequest(request({ body: { model: 'public-model', stream: true } })).usageMeter!;
    meter.push(encoder.encode('data: {"choices":[{"delta":{"content":"private"}}],"usage":null}\n\n'));
    meter.push(encoder.encode('data: {"choices":[],"usage":{"prompt_tokens":7,'));
    meter.push(encoder.encode('"completion_tokens":2,"total_tokens":9}}\n\n'));
    meter.push(encoder.encode('data: [DONE]\n\n'));

    expect(meter.finish()).toEqual({ inputTokens: 7, outputTokens: 2, totalTokens: 9 });
  });

  it.each([
    OPENAI_PROVIDER_ADAPTER_ID,
    VOLCENGINE_ARK_PROVIDER_ADAPTER_ID,
  ])('%s supports Responses API nested SSE usage', (adapterId) => {
    const meter = resolveEdgeProviderAdapter(adapterId)!
      .prepareRequest(request({ endpoint: 'responses' })).usageMeter!;
    meter.push(encoder.encode('data: {"type":"response.output_text.delta","delta":"private"}\n\n'));
    meter.push(encoder.encode('data: {"response":{"usage":{"input_tokens":7,'));
    meter.push(encoder.encode('"output_tokens":2,"total_tokens":9}}}\n\n'));

    expect(meter.finish()).toEqual({ inputTokens: 7, outputTokens: 2, totalTokens: 9 });
  });

  it('limits BigModel to its explicitly registered chat endpoint', () => {
    const adapter = resolveEdgeProviderAdapter(ZHIPU_BIGMODEL_PROVIDER_ADAPTER_ID)!;
    expect(adapter.supportedEndpoints).toEqual(['chat_completions']);
    expect(() => adapter.prepareRequest(request({ endpoint: 'responses' })))
      .toThrow('does not support endpoint');
  });

  it.each(adapterIds)('%s classifies compatible HTTP errors without reading bodies', (adapterId) => {
    const prepared = resolveEdgeProviderAdapter(adapterId)!.prepareRequest(request());
    expect(prepared.classifyError(200)).toBeNull();
    expect(prepared.classifyError(400)).toEqual({
      category: 'invalid_request', retryable: false,
    });
    expect(prepared.classifyError(401)).toEqual({
      category: 'authentication', retryable: false,
    });
    expect(prepared.classifyError(429)).toEqual({
      category: 'rate_limit', retryable: true,
    });
    expect(prepared.classifyError(503)).toEqual({
      category: 'provider_unavailable', retryable: true,
    });
    expect(prepared.classifyError(500)).toEqual({
      category: 'provider_unavailable', retryable: false,
    });
  });

  it.each(adapterIds)('%s does not meter an unmetered route', (adapterId) => {
    const prepared = resolveEdgeProviderAdapter(adapterId)!.prepareRequest(request({
      body: { model: 'public-model', stream: true },
      metering: null,
    }));
    expect(prepared.body).toEqual({ model: 'configured-upstream-model', stream: true });
    expect(prepared.usageMeter).toBeNull();
  });

  it('defaults legacy routes to OpenAI and rejects an unknown signed adapter', () => {
    const route = {
      id: 'route-adapter-test',
      endpoint: 'chat_completions' as const,
      publicModel: 'public-model',
      upstreamModel: 'configured-upstream-model',
      upstreamUrl: 'https://provider.test/v1/chat/completions',
      priority: 1,
      authentication: { type: 'bearer' as const, secretBinding: 'PROVIDER_API_KEY' },
    };
    expect(prepareEdgeProviderRequest(route, { model: 'public-model' }).body.model)
      .toBe('configured-upstream-model');
    expect(() => prepareEdgeProviderRequest({
      ...route,
      providerAdapter: 'unknown-provider',
    }, { model: 'public-model' })).toThrow('unsupported edge provider adapter');
  });

  it('fails closed when provider usage is missing or inconsistent', () => {
    const adapter = resolveEdgeProviderAdapter(OPENAI_PROVIDER_ADAPTER_ID)!;
    const missing = adapter.prepareRequest(request()).usageMeter!;
    missing.push(encoder.encode(JSON.stringify({ choices: [] })));
    expect(missing.finish()).toBeNull();

    const inconsistent = adapter.prepareRequest(request()).usageMeter!;
    inconsistent.push(encoder.encode(JSON.stringify({
      usage: { prompt_tokens: 3, completion_tokens: 2, total_tokens: 99 },
    })));
    expect(inconsistent.finish()).toBeNull();
  });
});
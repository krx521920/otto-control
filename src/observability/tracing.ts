import { isSpanContextValid, trace } from '@opentelemetry/api';
import fastifyOtel from '@fastify/otel';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { HttpInstrumentation } from '@opentelemetry/instrumentation-http';
import { PgInstrumentation } from '@opentelemetry/instrumentation-pg';
import { registerInstrumentations } from '@opentelemetry/instrumentation';
import { resourceFromAttributes } from '@opentelemetry/resources';
import {
  BatchSpanProcessor,
  NodeTracerProvider,
  ParentBasedSampler,
  TraceIdRatioBasedSampler,
} from '@opentelemetry/sdk-trace-node';
import { readFileSync } from 'node:fs';

const REDACTED_QUERY_PARAMETERS = [
  'access_token',
  'AWSAccessKeyId',
  'api_key',
  'authorization',
  'code',
  'key',
  'password',
  'secret',
  'sig',
  'signature',
  'token',
  'X-Goog-Signature',
];
const { FastifyOtelInstrumentation } = fastifyOtel;

export interface TracingConfiguration {
  endpoint: string;
  headers: Readonly<Record<string, string>>;
  sampleRatio: number;
  serviceVersion: string;
  environment: string;
  instanceId: string;
}

export interface TracingRuntime {
  shutdown(): Promise<void>;
}

function parseSampleRatio(value: string | undefined, production: boolean): number {
  const normalized = value?.trim() || (production ? '0.1' : '1');
  if (!/^(?:0(?:\.\d+)?|1(?:\.0+)?)$/u.test(normalized)) {
    throw new Error('CONTROL_TRACE_SAMPLE_RATIO must be between 0 and 1');
  }
  return Number(normalized);
}

function loadHeaders(path: string | undefined): Readonly<Record<string, string>> {
  const normalized = path?.trim();
  if (!normalized) return Object.freeze({});
  let raw: string;
  try {
    raw = readFileSync(normalized, 'utf8');
  } catch {
    throw new Error('CONTROL_OTLP_HEADERS_FILE could not be read');
  }
  if (Buffer.byteLength(raw, 'utf8') > 16_384) {
    throw new Error('CONTROL_OTLP_HEADERS_FILE exceeds 16384 bytes');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error('CONTROL_OTLP_HEADERS_FILE must contain a JSON object');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('CONTROL_OTLP_HEADERS_FILE must contain a JSON object');
  }
  const headers: Record<string, string> = {};
  const entries = Object.entries(parsed);
  if (entries.length > 32) throw new Error('CONTROL_OTLP_HEADERS_FILE contains too many headers');
  for (const [name, value] of entries) {
    if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/u.test(name) || typeof value !== 'string') {
      throw new Error('CONTROL_OTLP_HEADERS_FILE contains an invalid header');
    }
    if (/[\r\n]/u.test(value) || Buffer.byteLength(value, 'utf8') > 4_096) {
      throw new Error('CONTROL_OTLP_HEADERS_FILE contains an invalid header value');
    }
    headers[name] = value;
  }
  return Object.freeze(headers);
}

export function loadTracingConfiguration(
  env: NodeJS.ProcessEnv = process.env,
): Readonly<TracingConfiguration> | null {
  const endpointValue = env.CONTROL_OTLP_TRACE_ENDPOINT?.trim();
  const headersFile = env.CONTROL_OTLP_HEADERS_FILE?.trim();
  if (!endpointValue) {
    if (headersFile) {
      throw new Error('CONTROL_OTLP_TRACE_ENDPOINT is required with CONTROL_OTLP_HEADERS_FILE');
    }
    return null;
  }

  let endpoint: URL;
  try {
    endpoint = new URL(endpointValue);
  } catch {
    throw new Error('CONTROL_OTLP_TRACE_ENDPOINT must be an absolute URL');
  }
  const production = env.NODE_ENV === 'production';
  if ((production && endpoint.protocol !== 'https:')
    || (!production && endpoint.protocol !== 'https:' && endpoint.protocol !== 'http:')
    || endpoint.username
    || endpoint.password
    || endpoint.search
    || endpoint.hash) {
    throw new Error(
      'CONTROL_OTLP_TRACE_ENDPOINT must use HTTPS in production without credentials, query, or fragment',
    );
  }
  if (!endpoint.pathname.endsWith('/v1/traces')) {
    throw new Error('CONTROL_OTLP_TRACE_ENDPOINT must end with /v1/traces');
  }

  return Object.freeze({
    endpoint: endpoint.toString(),
    headers: loadHeaders(headersFile),
    sampleRatio: parseSampleRatio(env.CONTROL_TRACE_SAMPLE_RATIO, production),
    serviceVersion: env.OTTO_CONTROL_VERSION?.trim() || '0.24.0',
    environment: env.NODE_ENV?.trim() || 'development',
    instanceId: env.HOSTNAME?.trim() || `pid-${process.pid}`,
  });
}

function requestPath(url: string | undefined): string {
  try {
    return new URL(url || '/', 'http://localhost').pathname;
  } catch {
    return '/';
  }
}

export function startTracingFromEnvironment(
  env: NodeJS.ProcessEnv = process.env,
): TracingRuntime | null {
  const config = loadTracingConfiguration(env);
  if (!config) return null;

  const exporter = new OTLPTraceExporter({
    url: config.endpoint,
    headers: { ...config.headers },
    timeoutMillis: 10_000,
  });
  const provider = new NodeTracerProvider({
    resource: resourceFromAttributes({
      'service.name': 'otto-control',
      'service.version': config.serviceVersion,
      'service.instance.id': config.instanceId,
      'deployment.environment.name': config.environment,
    }),
    sampler: new ParentBasedSampler({
      root: new TraceIdRatioBasedSampler(config.sampleRatio),
    }),
    spanProcessors: [new BatchSpanProcessor(exporter)],
  });
  provider.register();
  const disableInstrumentations = registerInstrumentations({
    instrumentations: [
      new HttpInstrumentation({
        ignoreIncomingRequestHook: (request) => {
          const path = requestPath(request.url);
          return path === '/metrics' || path === '/health/live';
        },
        redactedQueryParams: REDACTED_QUERY_PARAMETERS,
      }),
      new FastifyOtelInstrumentation({
        registerOnInitialization: true,
        ignorePaths: ({ url }) => url === '/metrics' || url === '/health/live',
        recordExceptions: true,
        instrumentHooks: false,
      }),
      new PgInstrumentation({
        enhancedDatabaseReporting: false,
        requireParentSpan: true,
        addSqlCommenterCommentToQueries: false,
        enableTraceContextPropagation: false,
      }),
    ],
  });
  return {
    shutdown: async () => {
      disableInstrumentations();
      await provider.shutdown();
    },
  };
}

export function traceLogContext(): Record<string, string> {
  const spanContext = trace.getActiveSpan()?.spanContext();
  if (!spanContext || !isSpanContextValid(spanContext)) return {};
  return {
    traceId: spanContext.traceId,
    spanId: spanContext.spanId,
  };
}

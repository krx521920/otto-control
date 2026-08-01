import type { FastifyInstance, FastifyRequest } from 'fastify';
import {
  Counter,
  Gauge,
  Histogram,
  Registry,
  collectDefaultMetrics,
} from 'prom-client';

import type { ControlConfig } from '../config.js';
import { secureTextMatches } from '../crypto/telemetry-request.js';
import type {
  DatabaseCapacitySnapshot,
  DatabaseObservabilitySource,
} from './contracts.js';

const HTTP_DURATION_BUCKETS_SECONDS = [
  0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30,
];

function routeLabel(request: FastifyRequest): string {
  return request.routeOptions.url || '__unmatched__';
}

function workloadLabel(route: string): string {
  if (route.startsWith('/health/')) return 'platform_health';
  if (route === '/v1/licenses/:licenseId/lease') return 'license_lease';
  if (route === '/v1/telemetry/ingest') return 'telemetry_ingest';
  if (route.startsWith('/v1/billing/')) return 'billing';
  if (route === '/v1/update-policy/resolve') return 'update_delivery';
  if (route.startsWith('/v1/admin') || route.startsWith('/admin')) return 'administration';
  return 'control_api';
}

function bearerToken(authorization: string | undefined): string {
  if (!authorization?.startsWith('Bearer ')) return '';
  return authorization.slice('Bearer '.length).trim();
}

function isMetricsRequest(request: FastifyRequest): boolean {
  return request.url.split('?', 1)[0] === '/metrics';
}

export class ControlMetrics {
  readonly #registry = new Registry();
  readonly #requestStartedAt = new WeakMap<FastifyRequest, bigint>();
  readonly #database?: DatabaseObservabilitySource;
  readonly #slowRequestThresholdMs: number;
  readonly #sloLatencyTargetMs: number;
  readonly #metricsToken: string | null;
  readonly #capacitySampleIntervalMs: number;
  readonly #requests: Counter<'method' | 'route' | 'status_code'>;
  readonly #requestDuration: Histogram<'method' | 'route'>;
  readonly #requestsInFlight: Gauge<'method'>;
  readonly #slowRequests: Counter<'method' | 'route'>;
  readonly #sloEvents: Counter<'objective' | 'result' | 'workload'>;
  readonly #capacityDatabaseBytes: Gauge;
  readonly #capacityRelationBytes: Gauge<'relation'>;
  readonly #capacityRelationRows: Gauge<'relation'>;
  readonly #capacitySampleTimestamp: Gauge;
  readonly #capacitySampleFailures: Counter;
  #capacityTimer: NodeJS.Timeout | null = null;
  #capacitySampling = false;

  constructor(
    config: Readonly<ControlConfig>,
    database?: DatabaseObservabilitySource,
  ) {
    this.#database = database;
    this.#slowRequestThresholdMs = config.slowRequestThresholdMs;
    this.#sloLatencyTargetMs = config.sloLatencyTargetMs;
    this.#metricsToken = config.metricsToken;
    this.#capacitySampleIntervalMs = config.capacitySampleIntervalMs;
    this.#registry.setDefaultLabels({
      service: 'otto-control',
      version: config.version,
      instance: process.env.HOSTNAME?.trim() || 'local',
    });
    collectDefaultMetrics({
      register: this.#registry,
      prefix: 'otto_control_process_',
      eventLoopMonitoringPrecision: 20,
    });

    this.#requests = new Counter({
      name: 'otto_control_http_requests_total',
      help: 'Completed Otto Control HTTP requests.',
      labelNames: ['method', 'route', 'status_code'],
      registers: [this.#registry],
    });
    this.#requestDuration = new Histogram({
      name: 'otto_control_http_request_duration_seconds',
      help: 'Otto Control HTTP request duration in seconds.',
      labelNames: ['method', 'route'],
      buckets: HTTP_DURATION_BUCKETS_SECONDS,
      registers: [this.#registry],
    });
    this.#requestsInFlight = new Gauge({
      name: 'otto_control_http_requests_in_flight',
      help: 'Current in-flight Otto Control HTTP requests.',
      labelNames: ['method'],
      registers: [this.#registry],
    });
    this.#slowRequests = new Counter({
      name: 'otto_control_http_slow_requests_total',
      help: 'Requests exceeding the configured slow-request threshold.',
      labelNames: ['method', 'route'],
      registers: [this.#registry],
    });
    this.#sloEvents = new Counter({
      name: 'otto_control_http_slo_events_total',
      help: 'Good and bad events used to calculate availability and latency SLOs.',
      labelNames: ['objective', 'result', 'workload'],
      registers: [this.#registry],
    });

    const availabilityTarget = new Gauge({
      name: 'otto_control_slo_availability_target_ratio',
      help: 'Configured HTTP availability SLO target.',
      registers: [this.#registry],
    });
    availabilityTarget.set(config.sloAvailabilityTarget);
    const latencyTarget = new Gauge({
      name: 'otto_control_slo_latency_target_seconds',
      help: 'Configured HTTP latency SLO threshold in seconds.',
      registers: [this.#registry],
    });
    latencyTarget.set(config.sloLatencyTargetMs / 1_000);

    this.#capacityDatabaseBytes = new Gauge({
      name: 'otto_control_database_size_bytes',
      help: 'Last sampled PostgreSQL database size.',
      registers: [this.#registry],
    });
    this.#capacityRelationBytes = new Gauge({
      name: 'otto_control_database_relation_size_bytes',
      help: 'Last sampled PostgreSQL relation size.',
      labelNames: ['relation'],
      registers: [this.#registry],
    });
    this.#capacityRelationRows = new Gauge({
      name: 'otto_control_database_relation_estimated_rows',
      help: 'Last PostgreSQL estimated live row count.',
      labelNames: ['relation'],
      registers: [this.#registry],
    });
    this.#capacitySampleTimestamp = new Gauge({
      name: 'otto_control_capacity_sample_timestamp_seconds',
      help: 'Unix timestamp of the last successful capacity sample.',
      registers: [this.#registry],
    });
    this.#capacitySampleFailures = new Counter({
      name: 'otto_control_capacity_sample_failures_total',
      help: 'Failed PostgreSQL capacity samples.',
      registers: [this.#registry],
    });

    const poolTotal = new Gauge({
      name: 'otto_control_postgres_pool_connections',
      help: 'PostgreSQL pool connections by state.',
      labelNames: ['state'] as const,
      registers: [this.#registry],
      collect: () => {
        const snapshot = this.#database?.poolSnapshot();
        if (!snapshot) return;
        poolTotal.set({ state: 'total' }, snapshot.totalConnections);
        poolTotal.set({ state: 'idle' }, snapshot.idleConnections);
        poolTotal.set({ state: 'busy' }, Math.max(
          snapshot.totalConnections - snapshot.idleConnections,
          0,
        ));
        poolTotal.set({ state: 'maximum' }, snapshot.maximumConnections);
      },
    });
    const poolWaiting: Gauge = new Gauge({
      name: 'otto_control_postgres_pool_waiting_requests',
      help: 'Requests waiting for a PostgreSQL pool connection.',
      registers: [this.#registry],
      collect: (): void => {
        poolWaiting.set(this.#database?.poolSnapshot().waitingRequests ?? 0);
      },
    });
    const poolErrors: Gauge = new Gauge({
      name: 'otto_control_postgres_pool_errors_total',
      help: 'Cumulative PostgreSQL idle-client pool errors since process start.',
      registers: [this.#registry],
      collect: (): void => {
        poolErrors.set(this.#database?.poolSnapshot().errorsTotal ?? 0);
      },
    });
    const poolUtilization: Gauge = new Gauge({
      name: 'otto_control_postgres_pool_utilization_ratio',
      help: 'Busy PostgreSQL pool connections divided by configured maximum.',
      registers: [this.#registry],
      collect: (): void => {
        const snapshot = this.#database?.poolSnapshot();
        if (!snapshot) {
          poolUtilization.set(0);
          return;
        }
        const busy = Math.max(snapshot.totalConnections - snapshot.idleConnections, 0);
        poolUtilization.set(busy / snapshot.maximumConnections);
      },
    });
  }

  async register(app: FastifyInstance): Promise<void> {
    app.addHook('onRequest', async (request) => {
      if (isMetricsRequest(request)) return;
      this.#requestStartedAt.set(request, process.hrtime.bigint());
      this.#requestsInFlight.inc({ method: request.method });
    });
    app.addHook('onResponse', async (request, reply) => {
      const startedAt = this.#requestStartedAt.get(request);
      if (startedAt === undefined) return;
      this.#requestStartedAt.delete(request);
      this.#requestsInFlight.dec({ method: request.method });
      const durationMs = Number(process.hrtime.bigint() - startedAt) / 1_000_000;
      const route = routeLabel(request);
      const workload = workloadLabel(route);
      this.#requests.inc({
        method: request.method,
        route,
        status_code: String(reply.statusCode),
      });
      this.#requestDuration.observe(
        { method: request.method, route },
        durationMs / 1_000,
      );
      this.#sloEvents.inc({
        objective: 'availability',
        result: reply.statusCode >= 500 ? 'bad' : 'good',
        workload,
      });
      this.#sloEvents.inc({
        objective: 'latency',
        result: durationMs > this.#sloLatencyTargetMs ? 'bad' : 'good',
        workload,
      });
      if (durationMs >= this.#slowRequestThresholdMs) {
        this.#slowRequests.inc({ method: request.method, route });
        request.log.warn({
          event: 'slow_request',
          durationMs: Math.round(durationMs),
          method: request.method,
          route,
          statusCode: reply.statusCode,
        }, 'slow request observed');
      }
    });

    app.get('/metrics', {
      config: { otel: false },
    }, async (request, reply) => {
      if (this.#metricsToken && !secureTextMatches(
        bearerToken(request.headers.authorization),
        this.#metricsToken,
      )) {
        return reply
          .header('www-authenticate', 'Bearer realm="otto-control-metrics"')
          .code(401)
          .send({
            error: {
              code: 'UNAUTHORIZED',
              message: 'Metrics token is required',
              requestId: request.id,
            },
          });
      }
      return reply
        .type(this.#registry.contentType)
        .send(await this.#registry.metrics());
    });

    app.addHook('onReady', async () => {
      await this.#sampleCapacity(app);
      this.#capacityTimer = setInterval(() => {
        void this.#sampleCapacity(app);
      }, this.#capacitySampleIntervalMs);
      this.#capacityTimer.unref();
    });
    app.addHook('onClose', async () => this.close());
  }

  close(): void {
    if (this.#capacityTimer) clearInterval(this.#capacityTimer);
    this.#capacityTimer = null;
  }

  async #sampleCapacity(app: FastifyInstance): Promise<void> {
    if (!this.#database || this.#capacitySampling) return;
    this.#capacitySampling = true;
    try {
      this.#applyCapacity(await this.#database.sampleCapacity());
    } catch (error) {
      this.#capacitySampleFailures.inc();
      app.log.warn({ err: error, event: 'capacity_sample_failed' }, 'capacity sample failed');
    } finally {
      this.#capacitySampling = false;
    }
  }

  #applyCapacity(snapshot: DatabaseCapacitySnapshot): void {
    this.#capacityDatabaseBytes.set(snapshot.databaseBytes);
    this.#capacityRelationBytes.reset();
    this.#capacityRelationRows.reset();
    for (const [relation, capacity] of Object.entries(snapshot.relations)) {
      this.#capacityRelationBytes.set({ relation }, capacity.bytes);
      this.#capacityRelationRows.set({ relation }, capacity.estimatedRows);
    }
    this.#capacitySampleTimestamp.set(snapshot.sampledAtMs / 1_000);
  }
}

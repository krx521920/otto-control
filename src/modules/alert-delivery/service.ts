import { createHash, createHmac, randomUUID } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';

import type {
  AlertDeliveryPayload,
  AlertDeliveryRecord,
  AlertDeliveryView,
  AlertPollResult,
  AlertSeverity,
} from '../../contracts/alert-delivery.js';
import { conflict, invalidRequest, notFound } from '../../errors.js';
import type { ControlStore } from '../../storage/control-store.js';
import type { BackupStatusService } from '../backup-status/service.js';
import {
  alertChannelSummary,
  loadAlertChannelDefinitions,
  type AlertChannelDefinition,
  type AlertChannelSummary,
} from './channel-config.js';

const MAX_BATCH_SIZE = 20;
const DELIVERY_LEASE_MS = 2 * 60_000;
const MAX_SECRET_BYTES = 4 * 1024;

type AlertFetch = typeof fetch;

export interface AlertDeliveryServiceOptions {
  store: ControlStore;
  backupStatus: BackupStatusService;
  channelsFile?: string | null;
  channels?: readonly AlertChannelDefinition[];
  webhookUrl?: string | null;
  webhookSecretFile?: string | null;
  pollIntervalMs?: number;
  timeoutMs?: number;
  maxAttempts?: number;
  retentionDays?: number;
  now?: () => number;
  fetcher?: AlertFetch;
}

interface RuntimeAlertChannel {
  definition: AlertChannelDefinition;
  url: URL;
  secret: Buffer | null;
}

function loadSecret(path: string): Buffer {
  let metadata: ReturnType<typeof statSync>;
  let value: string;
  try {
    metadata = statSync(path);
    value = readFileSync(path, 'utf8').trim();
  } catch {
    throw new Error('alert webhook secret file could not be read');
  }
  if (!metadata.isFile() || metadata.size < 32 || metadata.size > MAX_SECRET_BYTES) {
    throw new Error('alert webhook secret file must be a regular file containing 32-4096 bytes');
  }
  if (Buffer.byteLength(value, 'utf8') < 32) {
    throw new Error('alert webhook secret must contain at least 32 bytes');
  }
  return Buffer.from(value, 'utf8');
}

function parseWebhookUrl(value: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error('alert webhook URL must be an absolute HTTPS URL');
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) {
    throw new Error('alert webhook URL must use HTTPS without credentials or fragments');
  }
  return url;
}

function safeDeliveryError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return message
    .replace(/https:\/\/[^\s/]+[^\s]*/giu, '[WEBHOOK]')
    .replace(/(authorization|secret|token|credential)\s*[:=]\s*[^\s]+/giu, '$1=[REDACTED]')
    .replace(/[A-Za-z]:\\[^\s]+|\/(?:[^\s/]+\/){2,}[^\s]*/gu, '[LOCAL_PATH]')
    .replace(/\s+/gu, ' ')
    .trim()
    .slice(0, 500) || 'alert delivery failed';
}

function deliveryView(record: AlertDeliveryRecord): AlertDeliveryView {
  return {
    ...record,
    nextAttemptAt: record.nextAttemptAt.toISOString(),
    leaseUntil: record.leaseUntil?.toISOString() ?? null,
    deliveredAt: record.deliveredAt?.toISOString() ?? null,
    createdAt: record.createdAt.toISOString(),
    updatedAt: record.updatedAt.toISOString(),
  };
}

function retryDelayMs(attempt: number): number {
  return Math.min(60 * 60_000, 30_000 * (2 ** Math.max(0, attempt - 1)));
}

export class AlertDeliveryService {
  readonly #store: ControlStore;
  readonly #backupStatus: BackupStatusService;
  readonly #channels: ReadonlyMap<string, RuntimeAlertChannel>;
  readonly #pollIntervalMs: number;
  readonly #timeoutMs: number;
  readonly #maxAttempts: number;
  readonly #retentionMs: number;
  readonly #now: () => number;
  readonly #fetcher: AlertFetch;
  #timer: NodeJS.Timeout | null = null;
  #active: Promise<AlertPollResult> | null = null;

  constructor(options: AlertDeliveryServiceOptions) {
    this.#store = options.store;
    this.#backupStatus = options.backupStatus;
    this.#pollIntervalMs = options.pollIntervalMs ?? 60_000;
    this.#timeoutMs = options.timeoutMs ?? 10_000;
    this.#maxAttempts = options.maxAttempts ?? 8;
    const retentionDays = options.retentionDays ?? 365;
    this.#now = options.now ?? Date.now;
    this.#fetcher = options.fetcher ?? fetch;
    if (!Number.isInteger(this.#pollIntervalMs)
      || this.#pollIntervalMs < 5_000 || this.#pollIntervalMs > 3_600_000) {
      throw new Error('alert poll interval must be between 5000 and 3600000 milliseconds');
    }
    if (!Number.isInteger(this.#timeoutMs)
      || this.#timeoutMs < 500 || this.#timeoutMs > 30_000) {
      throw new Error('alert webhook timeout must be between 500 and 30000 milliseconds');
    }
    if (!Number.isInteger(this.#maxAttempts)
      || this.#maxAttempts < 1 || this.#maxAttempts > 20) {
      throw new Error('alert maximum attempts must be between 1 and 20');
    }
    if (!Number.isInteger(retentionDays) || retentionDays < 30 || retentionDays > 3_650) {
      throw new Error('alert retention must be between 30 and 3650 days');
    }
    this.#retentionMs = retentionDays * 24 * 60 * 60 * 1000;
    const hasLegacy = Boolean(options.webhookUrl || options.webhookSecretFile);
    const configurationSources = [Boolean(options.channelsFile), Boolean(options.channels), hasLegacy]
      .filter(Boolean).length;
    if (configurationSources > 1) {
      throw new Error('configure alert channels using exactly one configuration source');
    }
    if (hasLegacy && (!options.webhookUrl || !options.webhookSecretFile)) {
      throw new Error('alert webhook URL and secret file must be configured together');
    }
    const definitions = options.channels
      ? [...options.channels]
      : options.channelsFile
        ? loadAlertChannelDefinitions(options.channelsFile)
        : options.webhookUrl && options.webhookSecretFile
          ? [{
              id: 'legacy-webhook',
              name: 'Legacy webhook',
              url: options.webhookUrl,
              secretFile: options.webhookSecretFile,
              enabled: true,
              minimumSeverity: 'warning' as const,
            }]
          : [];
    const channels = new Map<string, RuntimeAlertChannel>();
    for (const definition of definitions) {
      if (channels.has(definition.id)) throw new Error(`duplicate alert channel id: ${definition.id}`);
      channels.set(definition.id, {
        definition: { ...definition },
        url: parseWebhookUrl(definition.url),
        secret: definition.enabled ? loadSecret(definition.secretFile) : null,
      });
    }
    this.#channels = channels;
  }

  get enabled(): boolean {
    return [...this.#channels.values()].some((channel) => channel.definition.enabled);
  }

  start(onError: (error: unknown) => void = () => {}): void {
    if (!this.enabled || this.#timer) return;
    const tick = (): void => {
      void this.pollOnce().catch(onError);
    };
    tick();
    this.#timer = setInterval(tick, this.#pollIntervalMs);
    this.#timer.unref();
  }

  async close(): Promise<void> {
    if (this.#timer) clearInterval(this.#timer);
    this.#timer = null;
    await this.#active;
  }

  async pollOnce(actorId = 'system:alert-worker'): Promise<AlertPollResult> {
    if (!this.enabled) {
      return {
        enabled: false,
        observedStatus: null,
        enqueued: false,
        enqueuedCount: 0,
        processed: 0,
        delivered: 0,
        retrying: 0,
        failed: 0,
      };
    }
    if (this.#active) return this.#active;
    const active = this.#poll(actorId).finally(() => {
      if (this.#active === active) this.#active = null;
    });
    this.#active = active;
    return active;
  }

  async list(limit = 50): Promise<{
    enabled: boolean;
    channels: AlertChannelSummary[];
    deliveries: AlertDeliveryView[];
  }> {
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
      throw invalidRequest('alert delivery limit must be between 1 and 100');
    }
    return {
      enabled: this.enabled,
      channels: [...this.#channels.values()]
        .map((channel) => alertChannelSummary(channel.definition)),
      deliveries: (await this.#store.listAlertDeliveries(limit)).map(deliveryView),
    };
  }

  async retry(id: string, actorId: string): Promise<AlertDeliveryView> {
    if (!/^alert_[a-f0-9]{32}$/u.test(id)) throw invalidRequest('alert delivery id is invalid');
    const current = await this.#store.getAlertDelivery(id);
    if (!current) throw notFound('alert delivery not found');
    if (current.status !== 'failed') throw conflict('only failed alert deliveries can be retried');
    const channel = this.#channels.get(current.channelId);
    if (!channel?.definition.enabled || !channel.secret) {
      throw conflict('alert channel is unavailable or disabled');
    }
    const retriedAt = new Date(this.#now());
    const retried = await this.#store.retryAlertDelivery({
      id,
      retriedAt,
      audit: {
        actorId,
        action: 'alert.delivery.retried',
        targetType: 'alert_delivery',
        targetId: id,
        detail: {
          channelId: current.channelId,
          previousAttempts: current.attempts,
          eventType: current.eventType,
        },
      },
    });
    if (!retried) throw conflict('alert delivery changed concurrently; reload and retry');
    return deliveryView(retried);
  }

  async #poll(actorId: string): Promise<AlertPollResult> {
    const pollStartedAt = this.#now();
    await this.#store.pruneAlertDeliveries(new Date(pollStartedAt - this.#retentionMs));
    const status = await this.#backupStatus.status();
    let enqueuedCount = 0;
    if (status.alerts.length > 0) {
      const severity: AlertSeverity = status.alerts.some((alert) => alert.severity === 'critical')
        ? 'critical'
        : 'warning';
      const fingerprint = createHash('sha256').update(JSON.stringify({
        source: 'backup_status',
        reason: status.reason,
        backupRecordedAt: status.latest?.recordedAt ?? null,
        alertCodes: status.alerts.map((alert) => alert.code).sort(),
      })).digest('hex');
      const eventId = `alert_${randomUUID().replaceAll('-', '')}`;
      const payload: AlertDeliveryPayload = {
        version: 1,
        eventId,
        eventType: 'backup.recovery.alert',
        source: 'backup_status',
        severity,
        fingerprint,
        observedAt: new Date(this.#now()).toISOString(),
        condition: {
          status: status.status,
          reason: status.reason,
          ageHours: status.ageHours,
          backupName: status.latest?.backup.name ?? null,
          backupRecordedAt: status.latest?.recordedAt ?? null,
          alerts: status.alerts,
        },
      };
      for (const channel of this.#channels.values()) {
        if (!channel.definition.enabled) continue;
        if (channel.definition.minimumSeverity === 'critical' && severity !== 'critical') continue;
        const deliveryId = `alert_${randomUUID().replaceAll('-', '')}`;
        const queued = await this.#store.enqueueAlertDelivery({
          id: deliveryId,
          channelId: channel.definition.id,
          source: payload.source,
          eventType: payload.eventType,
          fingerprint,
          severity,
          payload,
          createdAt: new Date(this.#now()),
          audit: {
            actorId,
            action: 'alert.delivery.enqueued',
            targetType: 'alert_delivery',
            targetId: deliveryId,
            detail: {
              channelId: channel.definition.id,
              source: payload.source,
              severity,
              reason: status.reason,
              fingerprint,
            },
          },
        });
        if (queued.created) enqueuedCount += 1;
      }
    }

    const result: AlertPollResult = {
      enabled: true,
      observedStatus: status.status,
      enqueued: enqueuedCount > 0,
      enqueuedCount,
      processed: 0,
      delivered: 0,
      retrying: 0,
      failed: 0,
    };
    const activeChannelIds = [...this.#channels.values()]
      .filter((channel) => channel.definition.enabled)
      .map((channel) => channel.definition.id);
    while (result.processed < MAX_BATCH_SIZE) {
      const now = new Date(this.#now());
      const delivery = await this.#store.claimAlertDelivery({
        now,
        leaseUntil: new Date(now.getTime() + DELIVERY_LEASE_MS),
        channelIds: activeChannelIds,
      });
      if (!delivery) break;
      result.processed += 1;
      try {
        await this.#deliver(delivery);
        const deliveredAt = new Date(this.#now());
        const finished = await this.#store.finishAlertDelivery({
          id: delivery.id,
          expectedLeaseUntil: delivery.leaseUntil!,
          status: 'delivered',
          nextAttemptAt: deliveredAt,
          lastError: null,
          deliveredAt,
          updatedAt: deliveredAt,
          audit: {
            actorId: 'system:alert-worker',
            action: 'alert.delivery.delivered',
            targetType: 'alert_delivery',
            targetId: delivery.id,
            detail: {
              channelId: delivery.channelId,
              attempts: delivery.attempts,
              eventType: delivery.eventType,
            },
          },
        });
        if (!finished) throw new Error('alert delivery lease was lost before completion');
        result.delivered += 1;
      } catch (error) {
        const failedAt = new Date(this.#now());
        const terminal = delivery.attempts >= this.#maxAttempts;
        const lastError = safeDeliveryError(error);
        const finished = await this.#store.finishAlertDelivery({
          id: delivery.id,
          expectedLeaseUntil: delivery.leaseUntil!,
          status: terminal ? 'failed' : 'retrying',
          nextAttemptAt: terminal
            ? failedAt
            : new Date(failedAt.getTime() + retryDelayMs(delivery.attempts)),
          lastError,
          deliveredAt: null,
          updatedAt: failedAt,
          audit: terminal ? {
            actorId: 'system:alert-worker',
            action: 'alert.delivery.failed',
            targetType: 'alert_delivery',
            targetId: delivery.id,
            detail: {
              channelId: delivery.channelId,
              attempts: delivery.attempts,
              eventType: delivery.eventType,
            },
          } : null,
        });
        if (!finished) throw new Error('alert delivery lease was lost before retry scheduling');
        if (terminal) {
          result.failed += 1;
        } else {
          result.retrying += 1;
        }
      }
    }
    return result;
  }

  async #deliver(record: AlertDeliveryRecord): Promise<void> {
    const channel = this.#channels.get(record.channelId);
    if (!channel?.definition.enabled || !channel.secret) {
      throw new Error('alert channel is unavailable or disabled');
    }
    const body = JSON.stringify(record.payload);
    const timestamp = String(this.#now());
    const signature = createHmac('sha256', channel.secret)
      .update(`${timestamp}\n${body}`)
      .digest('hex');
    const response = await this.#fetcher(channel.url, {
      method: 'POST',
      redirect: 'manual',
      signal: AbortSignal.timeout(this.#timeoutMs),
      headers: {
        'content-type': 'application/json',
        'user-agent': 'otto-control-alerts/1',
        'x-otto-alert-id': record.id,
        'x-otto-alert-channel': record.channelId,
        'x-otto-alert-timestamp': timestamp,
        'x-otto-alert-signature': `v1=${signature}`,
      },
      body,
    });
    await response.body?.cancel();
    if (response.status < 200 || response.status >= 300) {
      throw new Error(`webhook returned HTTP ${response.status}`);
    }
  }
}

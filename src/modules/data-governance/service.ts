import { createHash, randomBytes, randomUUID } from 'node:crypto';

import type {
  CustomerDataExportSnapshot,
  DataGovernanceConfig,
  DataGovernanceRequestRecord,
  DataGovernanceStateRecord,
  LegalHoldRecord,
} from '../../contracts/data-governance.js';
import { canonicalJson, signPayload, type PayloadSigner } from '../../crypto/signed-envelope.js';
import { conflict, invalidRequest, notFound } from '../../errors.js';
import type { AuditService } from '../audit/service.js';
import type { AuditEventInput } from '../../storage/control-store.js';
import type { DataGovernanceStore } from './store.js';

const CUSTOMER_ID_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._:-]{2,127}$/u;
const SENSITIVE_KEY = /(password|secret|token|credential|signature|ciphertext|private.?key)/iu;
const DAY_MS = 24 * 60 * 60 * 1_000;
const LEGAL_HOLD_SCOPES = new Set([
  'all',
  'data_governance',
  'customer_identity',
  'deployment_identity',
  'health_telemetry',
  'billing_ledger',
  'security_audit',
]);

export const DATA_CLASSIFICATION_CATALOG = [
  {
    id: 'customer_identity',
    purpose: '合同客户识别、服务交付和客户支持',
    location: 'Otto Control PostgreSQL / control_customers',
    content: ['客户 ID', '企业名称', '数据驻留区域'],
    defaultDisposition: '注销后企业名称去标识化，保留不可逆客户标识用于账务与审计关联',
  },
  {
    id: 'deployment_identity',
    purpose: '私有化部署识别、授权绑定和安全风控',
    location: 'Otto Control PostgreSQL / control_deployments, control_licenses',
    content: ['部署 ID', '组织 ID', '机器指纹', '部署名称'],
    defaultDisposition: '注销后去标识化；令牌、Nonce 和在线席位状态删除',
  },
  {
    id: 'health_telemetry',
    purpose: '运行健康、错误率、调用量和容量诊断',
    location: 'Otto Control PostgreSQL / control_telemetry_events',
    content: ['版本', '粗粒度 CPU/内存', '错误码', '调用成功率和耗时'],
    defaultDisposition: '按配置保留期删除；默认不接收聊天、文件、会议或提示词正文',
  },
  {
    id: 'billing_ledger',
    purpose: '积分、消费、退款、对账和争议处理',
    location: 'Otto Control PostgreSQL / control_credit_*',
    content: ['积分变动', '模块', '金额', '时间', '幂等参考'],
    defaultDisposition: '注销后去除业务描述与部署标识，仅限制处理并保留最小账务凭证',
  },
  {
    id: 'security_audit',
    purpose: '越权调查、安全事件响应和责任追溯',
    location: '哈希链审计表、外部锚和可选 WORM 对象存储',
    content: ['操作者', '操作类型', '目标 ID', '最小化操作详情', '证据哈希'],
    defaultDisposition: '不可静默修改；按策略到期后处置，禁止写入聊天原文或文件内容',
  },
] as const;

type GovernanceStore = DataGovernanceStore & {
  appendAuditEvent(input: AuditEventInput): Promise<void>;
};

function requiredText(value: unknown, name: string, maximum = 500): string {
  if (typeof value !== 'string' || !value.trim() || value.trim().length > maximum) {
    throw invalidRequest(`${name} must be a non-empty string up to ${maximum} characters`);
  }
  return value.trim();
}

function customerId(value: unknown): string {
  const normalized = requiredText(value, 'customerId', 128);
  if (!CUSTOMER_ID_PATTERN.test(normalized)) throw invalidRequest('customerId is invalid');
  return normalized;
}

function optionalDate(value: unknown, name: string): Date | null {
  if (value === undefined || value === null || value === '') return null;
  const parsed = new Date(requiredText(value, name, 64));
  if (!Number.isFinite(parsed.getTime())) throw invalidRequest(`${name} must be an ISO timestamp`);
  return parsed;
}

function sha256(value: unknown): string {
  return createHash('sha256').update(canonicalJson(value)).digest('hex');
}

function sanitize(value: unknown, depth = 0): unknown {
  if (depth > 8) return '[MAX_DEPTH]';
  if (Array.isArray(value)) return value.slice(0, 10_000).map((item) => sanitize(item, depth + 1));
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>)
      .slice(0, 1_000)
      .map(([key, item]) => [key, SENSITIVE_KEY.test(key) ? '[REDACTED]' : sanitize(item, depth + 1)]));
  }
  if (typeof value === 'string' && value.length > 4_000) return `${value.slice(0, 4_000)}...`;
  return value;
}

function requestView(record: DataGovernanceRequestRecord, nowMs = Date.now()): Record<string, unknown> {
  const completedWithinSla = record.completedAt
    ? record.completedAt.getTime() <= record.dueAt.getTime()
    : null;
  const slaStatus = completedWithinSla === true
    ? 'met'
    : completedWithinSla === false
      ? 'breached_completed'
      : nowMs > record.dueAt.getTime() ? 'overdue' : 'open';
  return {
    ...record,
    earliestExecutionAt: record.earliestExecutionAt?.toISOString() ?? null,
    dueAt: record.dueAt.toISOString(),
    completedAt: record.completedAt?.toISOString() ?? null,
    createdAt: record.createdAt.toISOString(),
    updatedAt: record.updatedAt.toISOString(),
    sla: {
      status: slaStatus,
      deadline: record.dueAt.toISOString(),
      completedWithinSla,
    },
    evidence: record.manifestSha256 ? {
      manifestSha256: record.manifestSha256,
      completedAt: record.completedAt?.toISOString() ?? null,
    } : null,
  };
}

function holdView(record: LegalHoldRecord): Record<string, unknown> {
  return {
    ...record,
    expiresAt: record.expiresAt?.toISOString() ?? null,
    releasedAt: record.releasedAt?.toISOString() ?? null,
    createdAt: record.createdAt.toISOString(),
    updatedAt: record.updatedAt.toISOString(),
  };
}

export class DataGovernanceService {
  readonly #store: GovernanceStore;
  readonly #signer: PayloadSigner;
  readonly #audit: AuditService;
  readonly #config: DataGovernanceConfig;
  readonly #now: () => number;
  readonly #policySha256: string;
  readonly #telemetryRetentionDays: number;
  #retentionTimer: ReturnType<typeof setInterval> | null = null;

  constructor(options: {
    store: GovernanceStore;
    signer: PayloadSigner;
    audit: AuditService;
    config: DataGovernanceConfig;
    telemetryRetentionDays: number;
    now?: () => number;
  }) {
    this.#store = options.store;
    this.#signer = options.signer;
    this.#audit = options.audit;
    this.#config = options.config;
    this.#telemetryRetentionDays = options.telemetryRetentionDays;
    this.#now = options.now ?? Date.now;
    this.#policySha256 = sha256({
      version: options.config.policyVersion,
      effectiveAt: options.config.policyEffectiveAt,
      dataRegion: options.config.dataRegion,
      allowedRegions: options.config.allowedRegions,
      crossBorderEnabled: options.config.crossBorderEnabled,
      catalog: DATA_CLASSIFICATION_CATALOG,
      retention: {
        billingDays: options.config.billingRetentionDays,
        auditDays: options.config.auditRetentionDays,
        exportRecordDays: options.config.exportRecordRetentionDays,
      },
      requestSlaDays: options.config.privacyRequestSlaDays,
    });
  }

  async initialize(): Promise<DataGovernanceStateRecord> {
    return this.#store.initializeDataGovernanceState({
      dataRegion: this.#config.dataRegion,
      allowedRegions: this.#config.allowedRegions,
      crossBorderEnabled: this.#config.crossBorderEnabled,
      crossBorderAssessmentId: this.#config.crossBorderAssessmentId,
      policyVersion: this.#config.policyVersion,
      policySha256: this.#policySha256,
      policyEffectiveAt: new Date(this.#config.policyEffectiveAt),
      controllerName: this.#config.controllerName,
      privacyContact: this.#config.privacyContact,
    });
  }

  start(onError?: (error: unknown) => void): void {
    if (this.#retentionTimer) return;
    const run = () => {
      void this.runRetention('system:data-retention', this.#telemetryRetentionDays).catch(onError);
    };
    run();
    this.#retentionTimer = setInterval(run, this.#config.retentionPollIntervalMs);
    this.#retentionTimer.unref?.();
  }

  close(): void {
    if (this.#retentionTimer) clearInterval(this.#retentionTimer);
    this.#retentionTimer = null;
  }

  privacyNotice(): Record<string, unknown> {
    return {
      version: this.#config.policyVersion,
      sha256: this.#policySha256,
      effectiveAt: this.#config.policyEffectiveAt,
      controller: this.#config.controllerName,
      contact: this.#config.privacyContact,
      processingPrinciples: ['目的明确', '最小必要', '默认本地驻留', '分级授权', '可导出', '可注销', '可审计'],
      userContentBoundary: '控制面默认不接收聊天正文、文件内容、会议内容或提示词正文',
      rights: ['查阅', '复制与导出', '更正', '删除或匿名化', '限制处理', '注销', '投诉与解释说明'],
      dataMapUrl: '/v1/privacy/data-map',
      legalReviewRequired: true,
      requestSlaDays: this.#config.privacyRequestSlaDays,
    };
  }

  dataMap(): Record<string, unknown> {
    return {
      policyVersion: this.#config.policyVersion,
      policySha256: this.#policySha256,
      primaryRegion: this.#config.dataRegion,
      allowedRegions: this.#config.allowedRegions,
      crossBorderEnabled: this.#config.crossBorderEnabled,
      crossBorderAssessmentId: this.#config.crossBorderAssessmentId,
      classifications: DATA_CLASSIFICATION_CATALOG,
      retention: {
        billingDays: this.#config.billingRetentionDays,
        auditDays: this.#config.auditRetentionDays,
        exportRecordDays: this.#config.exportRecordRetentionDays,
      },
      privacyRequestSlaDays: this.#config.privacyRequestSlaDays,
    };
  }

  async status(): Promise<Record<string, unknown>> {
    const state = await this.#store.getDataGovernanceState();
    if (!state) throw conflict('data governance has not been initialized');
    return {
      policy: this.privacyNotice(),
      residency: {
        primaryRegion: state.dataRegion,
        allowedRegions: state.allowedRegions,
        crossBorderEnabled: state.crossBorderEnabled,
        assessmentId: state.crossBorderAssessmentId,
      },
      initializedAt: state.initializedAt.toISOString(),
      updatedAt: state.updatedAt.toISOString(),
      classifications: DATA_CLASSIFICATION_CATALOG,
    };
  }

  async acceptPrivacyPolicy(actorId: string, raw: Record<string, unknown>): Promise<Record<string, unknown>> {
    const acceptedVersion = requiredText(raw.policyVersion, 'policyVersion', 64);
    if (acceptedVersion !== this.#config.policyVersion) {
      throw conflict('only the current privacy policy version can be accepted');
    }
    const acceptedAt = new Date(this.#now());
    const record = await this.#store.recordPrivacyAcceptance({
      id: `privacy_${randomUUID().replaceAll('-', '')}`,
      customerId: customerId(raw.customerId),
      policyVersion: this.#config.policyVersion,
      policySha256: this.#policySha256,
      acceptedBy: requiredText(raw.acceptedBy, 'acceptedBy', 160),
      acceptedAt,
    });
    await this.#auditEvent(actorId, 'privacy_policy.accept', 'customer', record.customerId, {
      policyVersion: record.policyVersion,
      policySha256: record.policySha256,
    });
    return { ...record, acceptedAt: record.acceptedAt.toISOString() };
  }

  async exportCustomer(actorId: string, rawCustomerId: unknown, rawReason: unknown): Promise<Record<string, unknown>> {
    const id = customerId(rawCustomerId);
    const reason = requiredText(rawReason, 'reason');
    const snapshot = await this.#store.exportCustomerGovernanceData(id);
    if (!snapshot) throw notFound('customer not found');
    const createdAt = new Date(this.#now());
    const request = await this.#store.createDataGovernanceRequest({
      id: `dgr_${randomUUID().replaceAll('-', '')}`,
      customerId: id,
      type: 'customer_export',
      reason,
      requestedBy: actorId,
      earliestExecutionAt: null,
      dueAt: new Date(createdAt.getTime() + this.#config.privacyRequestSlaDays * DAY_MS),
      createdAt,
    });
    const data = sanitize(snapshot) as CustomerDataExportSnapshot;
    const bundle = {
      version: 1,
      requestId: request.id,
      customerId: id,
      generatedAt: createdAt.toISOString(),
      policyVersion: this.#config.policyVersion,
      policySha256: this.#policySha256,
      dataRegion: this.#config.dataRegion,
      data,
    };
    const manifestSha256 = sha256(bundle);
    const signed = { bundle, manifestSha256, ...await signPayload(this.#signer, bundle) };
    await this.#store.completeDataGovernanceRequest({
      id: request.id,
      status: 'completed',
      manifestSha256,
      result: { delivered: true, classifications: DATA_CLASSIFICATION_CATALOG.map((item) => item.id) },
      completedAt: createdAt,
    });
    await this.#auditEvent(actorId, 'customer_data.export', 'customer', id, {
      requestId: request.id,
      manifestSha256,
    });
    return signed;
  }

  async requestCustomerErasure(
    actorId: string,
    rawCustomerId: unknown,
    rawReason: unknown,
  ): Promise<Record<string, unknown>> {
    const id = customerId(rawCustomerId);
    const snapshot = await this.#store.exportCustomerGovernanceData(id);
    if (!snapshot) throw notFound('customer not found');
    if (snapshot.customer.erasedAt) throw conflict('customer data has already been erased');
    const createdAt = new Date(this.#now());
    const earliestExecutionAt = new Date(
      createdAt.getTime() + this.#config.customerErasureGraceDays * DAY_MS,
    );
    const record = await this.#store.createDataGovernanceRequest({
      id: `dgr_${randomUUID().replaceAll('-', '')}`,
      customerId: id,
      type: 'customer_erasure',
      reason: requiredText(rawReason, 'reason'),
      requestedBy: actorId,
      earliestExecutionAt,
      dueAt: new Date(Math.max(
        earliestExecutionAt.getTime(),
        createdAt.getTime() + this.#config.privacyRequestSlaDays * DAY_MS,
      )),
      createdAt,
    });
    await this.#auditEvent(actorId, 'customer_erasure.request', 'customer', id, {
      requestId: record.id,
      earliestExecutionAt: record.earliestExecutionAt?.toISOString(),
    });
    return requestView(record, this.#now());
  }

  async executeCustomerErasure(actorId: string, requestId: string): Promise<Record<string, unknown>> {
    const request = await this.#store.getDataGovernanceRequest(requiredText(requestId, 'requestId', 128));
    if (!request || request.type !== 'customer_erasure') throw notFound('erasure request not found');
    if (request.status !== 'pending') throw conflict('erasure request is not pending');
    const now = new Date(this.#now());
    if (request.earliestExecutionAt && request.earliestExecutionAt > now) {
      throw conflict('customer erasure grace period has not elapsed');
    }
    const holds = await this.#store.listActiveLegalHolds(request.customerId, now);
    if (holds.length > 0) throw conflict('customer erasure is blocked by an active legal hold');
    const result = await this.#store.executeCustomerErasure({
      requestId: request.id,
      pseudonymSeed: randomBytes(32).toString('hex'),
      billingRetainUntil: new Date(now.getTime() + this.#config.billingRetentionDays * DAY_MS),
      auditRetainUntil: new Date(now.getTime() + this.#config.auditRetentionDays * DAY_MS),
      completedAt: now,
    });
    if (!result) throw conflict('customer erasure could not be executed');
    const manifestSha256 = sha256(result);
    await this.#store.completeDataGovernanceRequest({
      id: request.id,
      status: 'completed',
      manifestSha256,
      result: result as unknown as Record<string, unknown>,
      completedAt: now,
    });
    await this.#auditEvent(actorId, 'customer_erasure.execute', 'customer', request.customerId, {
      requestId: request.id,
      manifestSha256,
      dispositions: result.dispositions.map(({ dataClass, disposition, records }) => ({
        dataClass,
        disposition,
        records,
      })),
    });
    return { result, manifestSha256, ...await signPayload(this.#signer, result) };
  }

  async createLegalHold(actorId: string, raw: Record<string, unknown>): Promise<Record<string, unknown>> {
    if (!Array.isArray(raw.scope) || raw.scope.length < 1 || raw.scope.length > 20) {
      throw invalidRequest('scope must contain between 1 and 20 data class identifiers');
    }
    const scope = [...new Set(raw.scope.map((item) => requiredText(item, 'scope item', 64)))];
    if (scope.some((item) => !LEGAL_HOLD_SCOPES.has(item))) {
      throw invalidRequest('scope contains an unknown data class identifier');
    }
    const expiresAt = optionalDate(raw.expiresAt, 'expiresAt');
    const now = new Date(this.#now());
    if (expiresAt && expiresAt <= now) throw invalidRequest('expiresAt must be in the future');
    const record = await this.#store.createLegalHold({
      id: `hold_${randomUUID().replaceAll('-', '')}`,
      customerId: customerId(raw.customerId),
      scope,
      reason: requiredText(raw.reason, 'reason', 1_000),
      createdBy: actorId,
      expiresAt,
      createdAt: now,
    });
    await this.#auditEvent(actorId, 'legal_hold.create', 'legal_hold', record.id, {
      customerId: record.customerId,
      scope: record.scope,
      expiresAt: record.expiresAt?.toISOString() ?? null,
    });
    return holdView(record);
  }

  async releaseLegalHold(actorId: string, id: string, rawReason: unknown): Promise<Record<string, unknown>> {
    const released = await this.#store.releaseLegalHold({
      id: requiredText(id, 'legalHoldId', 128),
      releasedBy: actorId,
      releaseReason: requiredText(rawReason, 'reason', 1_000),
      releasedAt: new Date(this.#now()),
    });
    if (!released) throw notFound('active legal hold not found');
    await this.#auditEvent(actorId, 'legal_hold.release', 'legal_hold', released.id, {
      customerId: released.customerId,
    });
    return holdView(released);
  }

  async forensicExport(actorId: string, raw: Record<string, unknown>): Promise<Record<string, unknown>> {
    const id = customerId(raw.customerId);
    const snapshot = await this.#store.exportCustomerGovernanceData(id);
    if (!snapshot) throw notFound('customer not found');
    const generatedAt = new Date(this.#now());
    const request = await this.#store.createDataGovernanceRequest({
      id: `dgr_${randomUUID().replaceAll('-', '')}`,
      customerId: id,
      type: 'forensic_export',
      reason: requiredText(raw.reason, 'reason', 1_000),
      requestedBy: actorId,
      earliestExecutionAt: null,
      dueAt: new Date(generatedAt.getTime() + this.#config.privacyRequestSlaDays * DAY_MS),
      createdAt: generatedAt,
    });
    const auditReceipt = await this.#audit.verify();
    const manifest = {
      version: 1,
      requestId: request.id,
      customerId: id,
      generatedAt: generatedAt.toISOString(),
      dataRegion: this.#config.dataRegion,
      customerSnapshotSha256: sha256(sanitize(snapshot)),
      auditReceipt,
      chainOfCustody: [{
        sequence: 1,
        action: 'manifest_generated',
        actorId,
        at: generatedAt.toISOString(),
      }],
      limitations: [
        '该清单证明控制面快照与审计链状态，不包含 Otto 私有服务器上的聊天、文件或会议原文。',
        '向外部机构交付前必须按案件范围复核、最小化并记录接收方。',
      ],
    };
    const manifestSha256 = sha256(manifest);
    await this.#store.completeDataGovernanceRequest({
      id: request.id,
      status: 'completed',
      manifestSha256,
      result: { delivered: true, auditHeadHash: auditReceipt.receipt.headHash },
      completedAt: generatedAt,
    });
    await this.#auditEvent(actorId, 'forensic_export.create', 'customer', id, {
      requestId: request.id,
      manifestSha256,
      auditHeadHash: auditReceipt.receipt.headHash,
    });
    return { manifest, manifestSha256, ...await signPayload(this.#signer, manifest) };
  }

  async request(id: string): Promise<Record<string, unknown>> {
    const record = await this.#store.getDataGovernanceRequest(requiredText(id, 'requestId', 128));
    if (!record) throw notFound('data governance request not found');
    return requestView(record, this.#now());
  }

  async runRetention(actorId: string, telemetryRetentionDays: number): Promise<Record<string, unknown>> {
    const now = new Date(this.#now());
    const result = await this.#store.runDataRetention({
      telemetryBefore: new Date(now.getTime() - telemetryRetentionDays * DAY_MS),
      exportPayloadBefore: new Date(now.getTime() - this.#config.exportRecordRetentionDays * DAY_MS),
      now,
    });
    await this.#auditEvent(
      actorId,
      'data_retention.run',
      'data_governance',
      this.#config.policyVersion,
      { ...result },
    );
    return { ...result, completedAt: now.toISOString() };
  }

  async #auditEvent(
    actorId: string,
    action: string,
    targetType: string,
    targetId: string,
    detail: Record<string, unknown>,
  ): Promise<void> {
    await this.#store.appendAuditEvent({ actorId, action, targetType, targetId, detail });
  }
}

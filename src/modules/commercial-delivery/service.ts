import { createHash } from 'node:crypto';

import type { OttoLicenseCapability } from '../../contracts/license.js';
import type { CreditStatement, ExecutionReceiptRecord } from '../../contracts/billing.js';
import type {
  CommercialDeliveryRoiLine,
  CommercialDeliveryRoiReport,
} from '../../contracts/commercial-delivery.js';
import {
  commercialPlan,
  OTTO_COMMERCIAL_PLAN_CATALOG,
  validatePlanModules,
} from '../../contracts/commercial-package.js';
import type { DataGovernanceConfig } from '../../contracts/data-governance.js';
import { canonicalJson, signPayload, type PayloadSigner } from '../../crypto/signed-envelope.js';
import { invalidRequest, notFound } from '../../errors.js';
import type { AuditEventInput } from '../../storage/control-store.js';
import type { BillingService } from '../billing/service.js';
import type { DataGovernanceService } from '../data-governance/service.js';
import type { DataGovernanceStore } from '../data-governance/store.js';

const CUSTOMER_ID_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._:-]{2,127}$/u;
const DAY_MS = 24 * 60 * 60 * 1_000;

type DeliveryStore = DataGovernanceStore & {
  appendAuditEvent(input: AuditEventInput): Promise<void>;
};

function customerId(value: unknown): string {
  const normalized = typeof value === 'string' ? value.trim() : '';
  if (!CUSTOMER_ID_PATTERN.test(normalized)) throw invalidRequest('customerId is invalid');
  return normalized;
}

function optionalPositiveNumber(
  value: unknown,
  name: string,
  maximum: number,
): number | null {
  if (value === undefined || value === null || value === '') return null;
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0 || parsed > maximum) {
    throw invalidRequest(`${name} must be greater than zero and no more than ${maximum}`);
  }
  return parsed;
}

function sha256(value: unknown): string {
  return createHash('sha256').update(canonicalJson(value)).digest('hex');
}

function reportRange(
  raw: Record<string, unknown>,
  nowMs: number,
): Record<string, unknown> {
  const to = raw.to === undefined ? new Date(nowMs + 1) : new Date(String(raw.to));
  const from = raw.from === undefined
    ? new Date(to.getTime() - 30 * DAY_MS)
    : new Date(String(raw.from));
  if (!Number.isFinite(from.getTime()) || !Number.isFinite(to.getTime()) || from >= to) {
    throw invalidRequest('from and to must define a valid increasing date range');
  }
  if (to.getTime() - from.getTime() > 366 * DAY_MS) {
    throw invalidRequest('commercial delivery range cannot exceed 366 days');
  }
  return { ...raw, from: from.toISOString(), to: to.toISOString() };
}

function csvCell(value: unknown): string {
  const text = value === null || value === undefined ? '' : String(value);
  return `"${text.replaceAll('"', '""')}"`;
}

export class CommercialDeliveryService {
  readonly #store: DeliveryStore;
  readonly #billing: BillingService;
  readonly #governance: DataGovernanceService;
  readonly #signer: PayloadSigner;
  readonly #config: DataGovernanceConfig;
  readonly #now: () => number;

  constructor(options: {
    store: DeliveryStore;
    billing: BillingService;
    governance: DataGovernanceService;
    signer: PayloadSigner;
    config: DataGovernanceConfig;
    now?: () => number;
  }) {
    this.#store = options.store;
    this.#billing = options.billing;
    this.#governance = options.governance;
    this.#signer = options.signer;
    this.#config = options.config;
    this.#now = options.now ?? Date.now;
  }

  async package(
    actorId: string,
    rawCustomerId: unknown,
    raw: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const id = customerId(rawCustomerId);
    const snapshot = await this.#store.exportCustomerGovernanceData(id);
    if (!snapshot) throw notFound('customer not found');
    const range = reportRange(raw, this.#now());
    const [statement, receipts] = await Promise.all([
      this.#billing.statement(id, range),
      this.#billing.executionReceipts(id, { ...range, limit: 10_000 }),
    ]);
    const roi = this.#roi(statement, receipts, raw);
    const generatedAt = new Date(this.#now()).toISOString();
    const licenses = snapshot.licenses.map((license) => {
      const definition = commercialPlan(license.plan);
      const policy = definition
        ? validatePlanModules(definition, license.modules as OttoLicenseCapability[])
        : null;
      return {
        id: license.id,
        deploymentId: license.deploymentId,
        plan: license.plan,
        planCatalogVersion: OTTO_COMMERCIAL_PLAN_CATALOG.version,
        planCompliant: Boolean(definition && policy?.missing.length === 0
          && policy.unsupported.length === 0),
        policyIssues: definition ? [
          ...policy!.missing.map((module) => `missing:${module}`),
          ...policy!.unsupported.map((module) => `unsupported:${module}`),
        ] : ['unknown_plan'],
        issuedAt: new Date(license.issuedAtMs).toISOString(),
        expiresAt: new Date(license.expiresAtMs).toISOString(),
        revokedAt: license.revokedAtMs === null
          ? null
          : new Date(license.revokedAtMs).toISOString(),
        seatLimit: license.seatLimit,
        modules: license.modules,
        offline: license.offline,
        telemetryAllowed: license.telemetryAllowed,
      };
    });
    const bundle = {
      version: 1,
      generatedAt,
      customer: {
        id: snapshot.customer.id,
        name: snapshot.customer.name,
        status: snapshot.customer.status,
        dataRegion: snapshot.customer.dataRegion,
      },
      authorization: {
        planCatalog: OTTO_COMMERCIAL_PLAN_CATALOG,
        licenses,
      },
      reportingBoundary: {
        enabledByLicense: licenses.some((license) => license.telemetryAllowed),
        defaultUploads: [
          '部署与组织标识',
          'License、席位和模块状态',
          '签名执行收据中的模块、单位、模型标识、时间和序列号',
          '粗粒度健康、错误码、成功率和耗时',
        ],
        prohibitedByDefault: [
          '聊天正文',
          '文件和附件内容',
          '会议正文与录音',
          '提示词和模型回复正文',
          '企业知识原文',
          '本地个人记忆',
        ],
        privacyNotice: this.#governance.privacyNotice(),
        dataMap: this.#governance.dataMap(),
      },
      commercialTerms: {
        version: OTTO_COMMERCIAL_PLAN_CATALOG.version,
        refund: {
          automatic: false,
          decisionBasis: '合同约定、已消费收据、服务故障证据和人工复核',
          reviewSlaBusinessDays: 10,
        },
        overage: '按签名套餐策略执行：在线版宽限期后阻断，政企版进入合同复核',
      },
      billing: {
        statement,
        rates: snapshot.billing.rates,
        ledgerRetentionDays: this.#config.billingRetentionDays,
      },
      roi,
      privacyOperations: {
        requestSlaDays: this.#config.privacyRequestSlaDays,
        erasureGraceDays: this.#config.customerErasureGraceDays,
        exportRecordRetentionDays: this.#config.exportRecordRetentionDays,
        controller: this.#config.controllerName,
        contact: this.#config.privacyContact,
      },
    };
    const manifestSha256 = sha256(bundle);
    const signed = { bundle, manifestSha256, ...await signPayload(this.#signer, bundle) };
    await this.#store.appendAuditEvent({
      actorId,
      action: 'customer_delivery.export',
      targetType: 'customer',
      targetId: id,
      detail: {
        manifestSha256,
        from: statement.from.toISOString(),
        to: statement.to.toISOString(),
        verifiedReceiptCount: roi.totals.verifiedTasks,
      },
    });
    return signed;
  }

  async roiCsv(
    actorId: string,
    rawCustomerId: unknown,
    raw: Record<string, unknown>,
  ): Promise<string> {
    const id = customerId(rawCustomerId);
    const range = reportRange(raw, this.#now());
    const [statement, receipts] = await Promise.all([
      this.#billing.statement(id, range),
      this.#billing.executionReceipts(id, { ...range, limit: 10_000 }),
    ]);
    const report = this.#roi(statement, receipts, raw);
    const header = ['module', 'verifiedTasks', 'verifiedUnits', 'consumedCredits'];
    const rows = report.lines.map((line) => [
      line.module,
      line.verifiedTasks,
      line.verifiedUnits,
      line.consumedCredits,
    ]);
    const summary = [
      ['assumptionSource', report.assumptions.source],
      ['minutesSavedPerTask', report.assumptions.minutesSavedPerTask],
      ['laborCostCentsPerHour', report.assumptions.laborCostCentsPerHour],
      ['estimatedHoursSaved', report.totals.estimatedHoursSaved],
      ['estimatedLaborValueCents', report.totals.estimatedLaborValueCents],
    ];
    const csv = `\uFEFF${[header, ...rows, [], ...summary]
      .map((row) => row.map(csvCell).join(','))
      .join('\r\n')}\r\n`;
    await this.#store.appendAuditEvent({
      actorId,
      action: 'customer_delivery.roi_export',
      targetType: 'customer',
      targetId: id,
      detail: {
        contentSha256: createHash('sha256').update(csv).digest('hex'),
        from: statement.from.toISOString(),
        to: statement.to.toISOString(),
        verifiedReceiptCount: report.totals.verifiedTasks,
      },
    });
    return csv;
  }

  #roi(
    statement: CreditStatement,
    receipts: ExecutionReceiptRecord[],
    raw: Record<string, unknown>,
  ): CommercialDeliveryRoiReport {
    const minutesSavedPerTask = optionalPositiveNumber(
      raw.minutesSavedPerTask,
      'minutesSavedPerTask',
      1_440,
    );
    const laborCostCentsPerHour = optionalPositiveNumber(
      raw.laborCostCentsPerHour,
      'laborCostCentsPerHour',
      100_000_000,
    );
    const modules = new Map<string, CommercialDeliveryRoiLine>();
    for (const receipt of receipts) {
      const current = modules.get(receipt.moduleId) ?? {
        module: receipt.moduleId,
        verifiedTasks: 0,
        verifiedUnits: 0,
        consumedCredits: 0,
      };
      current.verifiedTasks += 1;
      current.verifiedUnits += receipt.units;
      modules.set(receipt.moduleId, current);
    }
    for (const line of statement.lines) {
      const current = modules.get(line.module) ?? {
        module: line.module,
        verifiedTasks: 0,
        verifiedUnits: 0,
        consumedCredits: 0,
      };
      current.consumedCredits += line.netCredits;
      modules.set(line.module, current);
    }
    const lines = [...modules.values()].sort((left, right) => left.module.localeCompare(right.module));
    const verifiedTasks = lines.reduce((sum, line) => sum + line.verifiedTasks, 0);
    const verifiedUnits = lines.reduce((sum, line) => sum + line.verifiedUnits, 0);
    const consumedCredits = lines.reduce((sum, line) => sum + line.consumedCredits, 0);
    const estimatedHoursSaved = minutesSavedPerTask === null
      ? null
      : Math.round((verifiedTasks * minutesSavedPerTask / 60) * 100) / 100;
    const estimatedLaborValueCents = estimatedHoursSaved === null || laborCostCentsPerHour === null
      ? null
      : Math.round(estimatedHoursSaved * laborCostCentsPerHour);
    return {
      evidenceTrust: 'deployment_signed_receipt_v2',
      assumptions: {
        minutesSavedPerTask,
        laborCostCentsPerHour,
        source: minutesSavedPerTask !== null && laborCostCentsPerHour !== null
          ? 'customer_supplied'
          : 'not_configured',
      },
      lines,
      totals: {
        verifiedTasks,
        verifiedUnits,
        consumedCredits,
        estimatedHoursSaved,
        estimatedLaborValueCents,
      },
      limitations: [
        '任务次数与单位只采用通过 Ed25519 验签的执行收据。',
        '时间节省和人工价值仅在客户明确提供假设时计算，不代表财务承诺。',
        '积分不是法定货币，净收益需结合客户合同价格和实际业务结果另行核算。',
      ],
    };
  }
}

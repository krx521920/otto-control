import { generateKeyPairSync } from 'node:crypto';

import { describe, expect, it, vi } from 'vitest';

import type { CreditStatement, ExecutionReceiptRecord } from '../src/contracts/billing.js';
import type { CustomerDataExportSnapshot, DataGovernanceConfig } from '../src/contracts/data-governance.js';
import { LocalEd25519Signer } from '../src/crypto/signed-envelope.js';
import type { BillingService } from '../src/modules/billing/service.js';
import { CommercialDeliveryService } from '../src/modules/commercial-delivery/service.js';
import type { DataGovernanceService } from '../src/modules/data-governance/service.js';
import type { DataGovernanceStore } from '../src/modules/data-governance/store.js';

const CUSTOMER_ID = 'customer_001';
const NOW = Date.parse('2026-08-03T08:00:00.000Z');

function fixture() {
  const keys = generateKeyPairSync('ed25519');
  const signer = new LocalEd25519Signer(
    keys.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
  );
  const snapshot: CustomerDataExportSnapshot = {
    customer: {
      id: CUSTOMER_ID,
      name: 'Acme',
      status: 'active',
      dataRegion: 'CN-BJ',
      erasedAt: null,
      createdAt: '2026-01-01T00:00:00.000Z',
      updatedAt: '2026-08-01T00:00:00.000Z',
    },
    deployments: [{
      id: 'dep_1234567890abcdef',
      organizationId: 'org_acme',
      machineFingerprint: 'a'.repeat(64),
      name: 'Acme server',
      status: 'active',
      createdAt: '2026-01-01T00:00:00.000Z',
      updatedAt: '2026-08-01T00:00:00.000Z',
    }],
    licenses: [{
      id: 'lic_001',
      deploymentId: 'dep_1234567890abcdef',
      plan: 'enterprise',
      issuedAtMs: Date.parse('2026-01-01T00:00:00.000Z'),
      expiresAtMs: Date.parse('2027-01-01T00:00:00.000Z'),
      seatLimit: 50,
      modules: ['enterprise_tree', 'direct_messages'],
      offline: false,
      telemetryAllowed: true,
      seatEnforcement: 'enforce',
      billingEnforcement: 'enforce',
      revokedAtMs: null,
      createdAt: '2026-01-01T00:00:00.000Z',
      updatedAt: '2026-01-01T00:00:00.000Z',
    }],
    billing: { account: {}, rates: [], transactions: [] },
    telemetry: {
      totalEvents: 0,
      byType: {},
      firstReceivedAt: null,
      lastReceivedAt: null,
    },
    privacyAcceptances: [],
  };
  const statement: CreditStatement = {
    customerId: CUSTOMER_ID,
    from: new Date('2026-07-01T00:00:00.000Z'),
    to: new Date('2026-08-01T00:00:00.000Z'),
    openingBalance: 10_000,
    closingBalance: 9_800,
    totalToppedUp: 0,
    totalConsumed: 200,
    totalRefunded: 0,
    lines: [{
      organizationId: 'org_acme',
      module: 'meeting_agent',
      consumedCredits: 200,
      refundedCredits: 0,
      netCredits: 200,
      transactionCount: 2,
    }],
  };
  const receipts = [1, 2].map((sequence): ExecutionReceiptRecord => ({
    version: 2,
    receiptId: `exec_${String(sequence).padStart(32, '0')}`,
    customerId: CUSTOMER_ID,
    deploymentId: 'dep_1234567890abcdef',
    organizationId: 'org_acme',
    taskId: `task_${sequence}`,
    moduleId: 'meeting_agent',
    units: 1,
    model: 'test-model',
    issuedAtMs: NOW - 1_000,
    expiresAtMs: NOW + 60_000,
    sequence,
    policyVersion: '2026-08-03',
    signingKeyId: '0123456789abcdef',
    signature: 'ed25519:test',
    transactionId: `ctx_${sequence}`,
    verificationStatus: 'verified',
    receivedAt: new Date(NOW),
  }));
  const appendAuditEvent = vi.fn(async () => undefined);
  const store = {
    exportCustomerGovernanceData: vi.fn(async () => snapshot),
    appendAuditEvent,
  } as unknown as DataGovernanceStore & { appendAuditEvent: typeof appendAuditEvent };
  const billing = {
    statement: vi.fn(async () => statement),
    executionReceipts: vi.fn(async () => receipts),
  } as unknown as BillingService;
  const governance = {
    privacyNotice: () => ({ version: '2026-08-01' }),
    dataMap: () => ({ primaryRegion: 'CN-BJ' }),
  } as unknown as DataGovernanceService;
  const config: DataGovernanceConfig = {
    dataRegion: 'CN-BJ',
    allowedRegions: ['CN-BJ'],
    crossBorderEnabled: false,
    crossBorderAssessmentId: null,
    policyVersion: '2026-08-01',
    policyEffectiveAt: '2026-08-01T00:00:00.000Z',
    controllerName: 'Otto Test Operator',
    privacyContact: 'privacy@example.test',
    customerErasureGraceDays: 14,
    privacyRequestSlaDays: 15,
    billingRetentionDays: 1_095,
    auditRetentionDays: 2_555,
    exportRecordRetentionDays: 30,
    retentionPollIntervalMs: 86_400_000,
  };
  return {
    appendAuditEvent,
    service: new CommercialDeliveryService({
      store,
      billing,
      governance,
      signer,
      config,
      now: () => NOW,
    }),
  };
}

describe('commercial customer delivery', () => {
  it('signs authorization, privacy boundary, statement, and evidence-based ROI together', async () => {
    const { service, appendAuditEvent } = fixture();
    const result = await service.package('admin_001', CUSTOMER_ID, {
      minutesSavedPerTask: '30',
      laborCostCentsPerHour: '10000',
    });
    expect(result).toHaveProperty('manifestSha256');
    expect(result).toHaveProperty('signature');
    expect(result.bundle).toMatchObject({
      customer: { id: CUSTOMER_ID, dataRegion: 'CN-BJ' },
      authorization: { licenses: [{ plan: 'enterprise', planCompliant: true }] },
      reportingBoundary: { enabledByLicense: true },
      roi: {
        evidenceTrust: 'deployment_signed_receipt_v2',
        totals: {
          verifiedTasks: 2,
          verifiedUnits: 2,
          consumedCredits: 200,
          estimatedHoursSaved: 1,
          estimatedLaborValueCents: 10_000,
        },
      },
    });
    expect(JSON.stringify(result)).not.toContain('a'.repeat(64));
    expect(appendAuditEvent).toHaveBeenCalledWith(expect.objectContaining({
      action: 'customer_delivery.export',
      targetId: CUSTOMER_ID,
    }));
  });

  it('does not invent ROI value when the customer supplied no assumptions', async () => {
    const { service } = fixture();
    const csv = await service.roiCsv('admin_001', CUSTOMER_ID, {});
    expect(csv).toContain('not_configured');
    expect(csv).not.toContain('NaN');
  });
});

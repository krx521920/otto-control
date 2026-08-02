import { generateKeyPairSync } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import type {
  CustomerDataExportSnapshot,
  CustomerErasureResult,
  DataGovernanceRequestRecord,
  DataGovernanceStateRecord,
  LegalHoldRecord,
  PrivacyAcceptanceRecord,
} from '../src/contracts/data-governance.js';
import { AUDIT_GENESIS_HASH } from '../src/audit-chain.js';
import { LocalEd25519Signer } from '../src/crypto/signed-envelope.js';
import type { AuditService } from '../src/modules/audit/service.js';
import { DataGovernanceService } from '../src/modules/data-governance/service.js';
import type { DataGovernanceStore } from '../src/modules/data-governance/store.js';
import type { AuditEventInput } from '../src/storage/control-store.js';

const snapshot: CustomerDataExportSnapshot = {
  customer: {
    id: 'customer_001',
    name: 'Example customer',
    status: 'active',
    dataRegion: 'CN-BJ',
    erasedAt: null,
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
  },
  deployments: [{
    id: 'deployment_001',
    organizationId: 'org_001',
    machineFingerprint: 'machine-fingerprint',
    name: 'Production',
    status: 'active',
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
  }],
  licenses: [],
  billing: {
    account: null,
    rates: [],
    transactions: [{ id: 'tx_001', metadata: { apiToken: 'must-not-leak', purpose: 'invoice' } }],
  },
  telemetry: { totalEvents: 0, byType: {}, firstReceivedAt: null, lastReceivedAt: null },
  privacyAcceptances: [],
};

class GovernanceMemoryStore implements DataGovernanceStore {
  state: DataGovernanceStateRecord | null = null;
  requests = new Map<string, DataGovernanceRequestRecord>();
  holds = new Map<string, LegalHoldRecord>();
  audits: AuditEventInput[] = [];

  async initializeDataGovernanceState(
    input: Omit<DataGovernanceStateRecord, 'initializedAt' | 'updatedAt'>,
  ): Promise<DataGovernanceStateRecord> {
    const now = new Date('2026-08-02T00:00:00.000Z');
    this.state = { ...input, initializedAt: this.state?.initializedAt ?? now, updatedAt: now };
    return this.state;
  }

  async getDataGovernanceState(): Promise<DataGovernanceStateRecord | null> {
    return this.state;
  }

  async createDataGovernanceRequest(
    input: Omit<DataGovernanceRequestRecord, 'status' | 'manifestSha256' | 'result' | 'completedAt' | 'updatedAt'>,
  ): Promise<DataGovernanceRequestRecord> {
    const record: DataGovernanceRequestRecord = {
      ...input,
      status: 'pending',
      manifestSha256: null,
      result: null,
      completedAt: null,
      updatedAt: input.createdAt,
    };
    this.requests.set(record.id, record);
    return record;
  }

  async getDataGovernanceRequest(id: string): Promise<DataGovernanceRequestRecord | null> {
    return this.requests.get(id) ?? null;
  }

  async completeDataGovernanceRequest(input: {
    id: string; status: 'completed' | 'blocked' | 'failed'; manifestSha256: string | null;
    result: Record<string, unknown>; completedAt: Date;
  }): Promise<DataGovernanceRequestRecord | null> {
    const current = this.requests.get(input.id);
    if (!current) return null;
    const record = {
      ...current,
      status: input.status,
      manifestSha256: input.manifestSha256,
      result: input.result,
      completedAt: input.completedAt,
      updatedAt: input.completedAt,
    };
    this.requests.set(input.id, record);
    return record;
  }

  async exportCustomerGovernanceData(customerId: string): Promise<CustomerDataExportSnapshot | null> {
    return customerId === snapshot.customer.id ? structuredClone(snapshot) : null;
  }

  async createLegalHold(input: {
    id: string; customerId: string; scope: string[]; reason: string; createdBy: string;
    expiresAt: Date | null; createdAt: Date;
  }): Promise<LegalHoldRecord> {
    const record: LegalHoldRecord = {
      ...input,
      releasedAt: null,
      releasedBy: null,
      releaseReason: null,
      updatedAt: input.createdAt,
    };
    this.holds.set(record.id, record);
    return record;
  }

  async getLegalHold(id: string): Promise<LegalHoldRecord | null> {
    return this.holds.get(id) ?? null;
  }

  async listActiveLegalHolds(customerId: string, at: Date): Promise<LegalHoldRecord[]> {
    return [...this.holds.values()].filter((hold) => hold.customerId === customerId
      && !hold.releasedAt && (!hold.expiresAt || hold.expiresAt > at));
  }

  async releaseLegalHold(input: {
    id: string; releasedBy: string; releaseReason: string; releasedAt: Date;
  }): Promise<LegalHoldRecord | null> {
    const current = this.holds.get(input.id);
    if (!current || current.releasedAt) return null;
    const record = { ...current, ...input, updatedAt: input.releasedAt };
    this.holds.set(input.id, record);
    return record;
  }

  async recordPrivacyAcceptance(input: PrivacyAcceptanceRecord): Promise<PrivacyAcceptanceRecord> {
    return input;
  }

  async executeCustomerErasure(input: {
    requestId: string; billingRetainUntil: Date; auditRetainUntil: Date; completedAt: Date;
  }): Promise<CustomerErasureResult | null> {
    const request = this.requests.get(input.requestId);
    if (!request) return null;
    return {
      requestId: request.id,
      customerId: request.customerId,
      completedAt: input.completedAt.toISOString(),
      dispositions: [{
        dataClass: 'customer_identity',
        disposition: 'anonymized',
        records: 1,
        reason: 'test',
        retainUntil: null,
      }],
    };
  }

  async runDataRetention(): Promise<{
    telemetryEventsDeleted: number; expiredNoncesDeleted: number;
    expiredExportPayloadsRestricted: number;
  }> {
    return { telemetryEventsDeleted: 2, expiredNoncesDeleted: 3, expiredExportPayloadsRestricted: 1 };
  }

  async appendAuditEvent(input: AuditEventInput): Promise<void> {
    this.audits.push(input);
  }
}

function fixture(now = Date.parse('2026-08-20T00:00:00.000Z')): {
  service: DataGovernanceService;
  store: GovernanceMemoryStore;
} {
  const keys = generateKeyPairSync('ed25519');
  const signer = new LocalEd25519Signer(
    keys.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
  );
  const store = new GovernanceMemoryStore();
  const audit = {
    verify: async () => ({
      receipt: {
        version: 1 as const,
        issuer: 'test',
        generatedAt: new Date(now).toISOString(),
        valid: true,
        checkedEvents: 0,
        firstSequence: null,
        lastSequence: 0,
        headHash: AUDIT_GENESIS_HASH,
        brokenAtSequence: null,
        legacyEventCount: 0,
      },
      signingKeyId: signer.keyId,
      signature: 'ed25519:test',
    }),
  } as unknown as AuditService;
  return {
    store,
    service: new DataGovernanceService({
      store,
      signer,
      audit,
      now: () => now,
      config: {
        dataRegion: 'CN-BJ',
        allowedRegions: ['CN-BJ'],
        crossBorderEnabled: false,
        crossBorderAssessmentId: null,
        policyVersion: '2026-08-01',
        policyEffectiveAt: '2026-08-01T00:00:00.000Z',
        controllerName: 'Otto Test',
        privacyContact: 'privacy@example.test',
        customerErasureGraceDays: 14,
        billingRetentionDays: 1_095,
        auditRetentionDays: 2_555,
        exportRecordRetentionDays: 30,
        retentionPollIntervalMs: 24 * 60 * 60 * 1_000,
      },
      telemetryRetentionDays: 90,
    }),
  };
}

describe('data governance service', () => {
  it('publishes a versioned privacy notice and persistent residency state', async () => {
    const { service } = fixture();
    await service.initialize();
    expect(await service.status()).toMatchObject({
      policy: { version: '2026-08-01', legalReviewRequired: true },
      residency: { primaryRegion: 'CN-BJ', crossBorderEnabled: false },
    });
    expect(service.dataMap()).toMatchObject({ primaryRegion: 'CN-BJ' });
  });

  it('exports only the allowlisted snapshot and redacts secret-shaped metadata', async () => {
    const { service, store } = fixture();
    await service.initialize();
    const exported = await service.exportCustomer('admin_001', 'customer_001', 'customer request');
    expect(exported).toHaveProperty('manifestSha256');
    expect(exported).toHaveProperty('signature');
    expect(JSON.stringify(exported)).not.toContain('must-not-leak');
    expect(JSON.stringify(exported)).toContain('[REDACTED]');
    expect(store.audits.at(-1)).toMatchObject({ action: 'customer_data.export' });
  });

  it('enforces the erasure grace period and active legal holds before execution', async () => {
    const early = fixture(Date.parse('2026-08-02T00:00:00.000Z'));
    await early.service.initialize();
    const request = await early.service.requestCustomerErasure(
      'admin_001',
      'customer_001',
      'contract ended',
    );
    await expect(early.service.executeCustomerErasure('admin_001', String(request.id)))
      .rejects.toThrow('grace period');

    const ready = fixture();
    await ready.service.initialize();
    const readyRequest = await ready.service.requestCustomerErasure(
      'admin_001',
      'customer_001',
      'contract ended',
    );
    await ready.service.createLegalHold('admin_002', {
      customerId: 'customer_001',
      scope: ['billing_ledger'],
      reason: 'open dispute',
    });
    const stored = ready.store.requests.get(String(readyRequest.id))!;
    stored.earliestExecutionAt = new Date('2026-08-03T00:00:00.000Z');
    await expect(ready.service.executeCustomerErasure('admin_001', stored.id))
      .rejects.toThrow('active legal hold');
  });
});

import { describe, expect, it } from 'vitest';

import { reconcileEdgeBilling } from '../scripts/reconcile-edge-billing.mjs';

const period = {
  from: '2026-08-01T00:00:00.000Z',
  to: '2026-09-01T00:00:00.000Z',
};

function otto() {
  return {
    schemaVersion: 1,
    period,
    currency: 'CNY',
    reservations: [
      {
        requestId: 'request-1',
        reservationId: 'hold-1',
        providerBillingKey: 'provider-usage-1',
        provider: 'provider-cn',
        model: 'model-a',
        reservedUnits: 2_000,
        actualUnits: 1_250,
        chargedMicros: 35_000,
        status: 'settled',
        occurredAt: '2026-08-02T00:00:00.000Z',
      },
      {
        requestId: 'request-2',
        reservationId: 'hold-2',
        providerBillingKey: null,
        provider: 'provider-cn',
        model: 'model-a',
        reservedUnits: 500,
        actualUnits: 0,
        chargedMicros: 0,
        status: 'released',
        occurredAt: '2026-08-02T00:01:00.000Z',
      },
    ],
  };
}

function provider() {
  return {
    schemaVersion: 1,
    period,
    currency: 'CNY',
    entries: [{
      providerBillingKey: 'provider-usage-1',
      provider: 'provider-cn',
      model: 'model-a',
      actualUnits: 1_250,
      chargedMicros: 35_000,
      occurredAt: '2026-08-02T00:00:02.000Z',
    }],
  };
}

describe('Edge Gateway billing reconciliation', () => {
  it('proves reservation, settlement, release, and provider charge equality', () => {
    expect(reconcileEdgeBilling(otto(), provider(), {
      now: () => Date.parse('2026-09-02T00:00:00.000Z'),
    })).toMatchObject({
      result: 'passed',
      reservations: { total: 2, settled: 1, released: 1, active: 0, uncertain: 0, overrun: 0 },
      otto: { billableEntries: 1, actualUnits: 1_250, chargedMicros: 35_000 },
      provider: { billableEntries: 1, actualUnits: 1_250, chargedMicros: 35_000 },
      issues: [],
    });
  });

  it('fails closed for unfinalized holds, overruns, mismatches, and unmatched entries', () => {
    const local = otto();
    local.reservations[0] = {
      ...local.reservations[0]!,
      reservedUnits: 1_000,
      actualUnits: 1_300,
      chargedMicros: 40_000,
      provider: 'wrong-provider',
    };
    local.reservations.push({
      ...local.reservations[1]!,
      requestId: 'request-3',
      reservationId: 'hold-3',
      status: 'uncertain',
    });
    const external = provider();
    external.entries.push({
      ...external.entries[0]!,
      providerBillingKey: 'provider-usage-orphan',
    });
    const report = reconcileEdgeBilling(local, external);
    expect(report.result).toBe('failed');
    expect(new Set(report.issues.map((entry) => entry.type))).toEqual(new Set([
      'reservation_overrun',
      'unfinalized_reservation',
      'routing_mismatch',
      'unit_mismatch',
      'amount_mismatch',
      'missing_otto_charge',
    ]));
  });

  it('uses explicit tolerances without hiding reservation or inventory exceptions', () => {
    const local = otto();
    local.reservations[0] = {
      ...local.reservations[0]!,
      actualUnits: 1_251,
      chargedMicros: 35_005,
    };
    expect(reconcileEdgeBilling(local, provider(), {
      unitTolerance: 1,
      amountToleranceMicros: 5,
    }).result).toBe('passed');
  });

  it('rejects duplicate keys, inconsistent release evidence, and incompatible statements', () => {
    const duplicate = provider();
    duplicate.entries.push({ ...duplicate.entries[0]! });
    expect(() => reconcileEdgeBilling(otto(), duplicate)).toThrow('duplicate');

    const invalidRelease = otto();
    invalidRelease.reservations[1] = {
      ...invalidRelease.reservations[1]!,
      chargedMicros: 1,
    };
    expect(() => reconcileEdgeBilling(invalidRelease, provider())).toThrow(
      'released evidence is inconsistent',
    );

    expect(() => reconcileEdgeBilling(
      otto(),
      { ...provider(), currency: 'USD' },
    )).toThrow('currencies do not match');
    expect(() => reconcileEdgeBilling(
      otto(),
      { ...provider(), period: { ...period, to: '2026-10-01T00:00:00.000Z' } },
    )).toThrow('periods do not match');
  });
});

export interface EdgeBillingReservationEvidence {
  requestId: string;
  reservationId: string;
  providerBillingKey: string | null;
  provider: string;
  model: string;
  reservedUnits: number;
  actualUnits: number;
  chargedMicros: number;
  status: 'settled' | 'released' | 'active' | 'uncertain';
  occurredAt: string;
}

export interface EdgeBillingReconciliationReport {
  schemaVersion: 1;
  result: 'passed' | 'failed';
  generatedAt: string;
  issues: Array<{
    type: string;
    providerBillingKey: string | null;
    detail: string;
  }>;
  reservations: {
    total: number;
    settled: number;
    released: number;
    active: number;
    uncertain: number;
    overrun: number;
  };
}

export function reconcileEdgeBilling(
  otto: unknown,
  provider: unknown,
  options?: {
    amountToleranceMicros?: number;
    unitTolerance?: number;
    now?: () => number;
  },
): EdgeBillingReconciliationReport;

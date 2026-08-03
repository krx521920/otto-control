import type { OttoBillingModule } from './billing.js';

export interface CommercialDeliveryRoiAssumptions {
  minutesSavedPerTask: number | null;
  laborCostCentsPerHour: number | null;
  source: 'customer_supplied' | 'not_configured';
}

export interface CommercialDeliveryRoiLine {
  module: OttoBillingModule;
  verifiedTasks: number;
  verifiedUnits: number;
  consumedCredits: number;
}

export interface CommercialDeliveryRoiReport {
  evidenceTrust: 'deployment_signed_receipt_v2';
  assumptions: CommercialDeliveryRoiAssumptions;
  lines: CommercialDeliveryRoiLine[];
  totals: {
    verifiedTasks: number;
    verifiedUnits: number;
    consumedCredits: number;
    estimatedHoursSaved: number | null;
    estimatedLaborValueCents: number | null;
  };
  limitations: string[];
}

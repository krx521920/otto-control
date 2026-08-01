export type OperatorLicenseState = 'active' | 'expiring' | 'grace' | 'expired' | 'revoked';
export type OperatorRecordStatus = 'active' | 'suspended';

export interface OperatorCustomerView {
  id: string;
  name: string;
  status: OperatorRecordStatus;
  updatedAt: string;
}

export interface OperatorDeploymentView {
  id: string;
  name: string;
  customerId: string;
  customerName: string;
  organizationId: string;
  status: OperatorRecordStatus;
  updatedAt: string;
}

export interface OperatorLicenseView {
  id: string;
  deploymentId: string;
  customerName: string;
  organizationId: string;
  plan: string;
  seatLimit: number;
  moduleCount: number;
  offline: boolean;
  state: OperatorLicenseState;
  expiresAt: string;
  updatedAt: string;
}

export interface OperatorLicenseDetail extends OperatorLicenseView {
  revision: number;
  issuedAt: string;
  gracePeriodDays: number;
  seatEnforcement: 'monitor' | 'enforce';
  modules: string[];
  telemetryAllowed: boolean;
}

export interface OperatorOverview {
  generatedAt: string;
  counts: {
    customers: { total: number; active: number; suspended: number };
    deployments: { total: number; active: number; suspended: number };
    licenses: {
      total: number;
      active: number;
      expiringSoon: number;
      grace: number;
      expired: number;
      revoked: number;
    };
  };
  recent: {
    customers: OperatorCustomerView[];
    deployments: OperatorDeploymentView[];
    licenses: OperatorLicenseView[];
  };
}

import type {
  OttoBillingEnforcement,
  OttoLicenseCapability,
  OttoSeatEnforcement,
} from './license.js';

export const OTTO_COMMERCIAL_PLAN_IDS = [
  'basic',
  'enterprise',
  'park',
  'government',
] as const;

export type OttoCommercialPlanId = (typeof OTTO_COMMERCIAL_PLAN_IDS)[number];

export interface OttoCommercialPlanDefinition {
  id: OttoCommercialPlanId;
  name: string;
  audience: string;
  requiredModules: OttoLicenseCapability[];
  defaultModules: OttoLicenseCapability[];
  allowedModules: OttoLicenseCapability[];
  offlineAllowed: boolean;
  defaultTelemetryAllowed: boolean;
  defaultSeatEnforcement: OttoSeatEnforcement;
  defaultBillingEnforcement: OttoBillingEnforcement;
  overagePolicy: 'block_after_grace' | 'contract_review';
}

const COMMON_MODULES: OttoLicenseCapability[] = [
  'enterprise_tree',
  'direct_messages',
  'knowledge',
];

const ALL_ENTERPRISE_MODULES: OttoLicenseCapability[] = [
  ...COMMON_MODULES,
  'feishu_auto_reply',
  'atoa',
  'skill_market',
  'park_service',
];

export const OTTO_COMMERCIAL_PLAN_CATALOG = Object.freeze({
  version: '2026-08-03',
  pricingAuthority: 'customer_rate_card' as const,
  creditUnit: 'OTTO_CREDIT' as const,
  plans: [
    {
      id: 'basic',
      name: '基础版',
      audience: '小型团队与基础企业协作',
      requiredModules: ['enterprise_tree'],
      defaultModules: COMMON_MODULES,
      allowedModules: COMMON_MODULES,
      offlineAllowed: false,
      defaultTelemetryAllowed: true,
      defaultSeatEnforcement: 'monitor',
      defaultBillingEnforcement: 'disabled',
      overagePolicy: 'block_after_grace',
    },
    {
      id: 'enterprise',
      name: '企业版',
      audience: '需要企业协作、知识与集成能力的组织',
      requiredModules: ['enterprise_tree'],
      defaultModules: [
        ...COMMON_MODULES,
        'feishu_auto_reply',
        'atoa',
        'skill_market',
      ],
      allowedModules: ALL_ENTERPRISE_MODULES,
      offlineAllowed: false,
      defaultTelemetryAllowed: true,
      defaultSeatEnforcement: 'monitor',
      defaultBillingEnforcement: 'disabled',
      overagePolicy: 'block_after_grace',
    },
    {
      id: 'park',
      name: '产业园版',
      audience: '产业园运营方及园区企业服务场景',
      requiredModules: ['enterprise_tree', 'park_service'],
      defaultModules: ALL_ENTERPRISE_MODULES,
      allowedModules: ALL_ENTERPRISE_MODULES,
      offlineAllowed: false,
      defaultTelemetryAllowed: true,
      defaultSeatEnforcement: 'monitor',
      defaultBillingEnforcement: 'disabled',
      overagePolicy: 'block_after_grace',
    },
    {
      id: 'government',
      name: '政企版',
      audience: '需要离线授权、数据驻留和合同化额度的政企客户',
      requiredModules: ['enterprise_tree'],
      defaultModules: ALL_ENTERPRISE_MODULES,
      allowedModules: ALL_ENTERPRISE_MODULES,
      offlineAllowed: true,
      defaultTelemetryAllowed: false,
      defaultSeatEnforcement: 'monitor',
      defaultBillingEnforcement: 'disabled',
      overagePolicy: 'contract_review',
    },
  ] satisfies OttoCommercialPlanDefinition[],
});

export function commercialPlan(
  value: string,
): OttoCommercialPlanDefinition | null {
  return OTTO_COMMERCIAL_PLAN_CATALOG.plans.find((plan) => plan.id === value) ?? null;
}

export function validatePlanModules(
  plan: OttoCommercialPlanDefinition,
  modules: readonly OttoLicenseCapability[],
): { missing: OttoLicenseCapability[]; unsupported: OttoLicenseCapability[] } {
  const selected = new Set(modules);
  return {
    missing: plan.requiredModules.filter((module) => !selected.has(module)),
    unsupported: modules.filter((module) => !plan.allowedModules.includes(module)),
  };
}

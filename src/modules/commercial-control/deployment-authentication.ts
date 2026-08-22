import { invalidRequest, unauthorized } from '../../errors.js';
import type { ControlStore, LicenseRecord } from '../../storage/control-store.js';
import type { ControlTokenIssuer } from './token-issuer.js';

const IDENTIFIER_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,159}$/u;
const FINGERPRINT_PATTERN = /^[a-f0-9]{64}$/u;

export interface OnlineDeploymentBinding {
  licenseId: string;
  deploymentId: string;
  organizationId: string;
  machineFingerprint: string;
}

export interface AuthenticatedOnlineDeployment {
  customerId: string;
  license: LicenseRecord;
  organizationId: string;
  deploymentId: string;
}

export async function authenticateOnlineDeployment(input: {
  store: ControlStore;
  tokens: ControlTokenIssuer;
  binding: OnlineDeploymentBinding;
  bearerToken: string;
  nowMs: number;
  purpose: string;
  allowDeploymentOrganization?: boolean;
}): Promise<AuthenticatedOnlineDeployment> {
  const binding = {
    licenseId: input.binding.licenseId.trim(),
    deploymentId: input.binding.deploymentId.trim(),
    organizationId: input.binding.organizationId.trim(),
    machineFingerprint: input.binding.machineFingerprint.trim().toLowerCase(),
  };
  if (!IDENTIFIER_PATTERN.test(binding.licenseId)) throw invalidRequest('licenseId is invalid');
  if (!IDENTIFIER_PATTERN.test(binding.deploymentId)) {
    throw invalidRequest('deploymentId is invalid');
  }
  if (!IDENTIFIER_PATTERN.test(binding.organizationId)) {
    throw invalidRequest('organizationId is invalid');
  }
  if (!FINGERPRINT_PATTERN.test(binding.machineFingerprint)) {
    throw invalidRequest('machineFingerprint is invalid');
  }

  const license = await input.store.getLicense(binding.licenseId);
  if (!license) throw unauthorized('License is invalid');
  if (license.offline) throw unauthorized(`offline License cannot use online ${input.purpose}`);
  if (
    license.revokedAtMs !== null
    || input.nowMs >= license.expiresAtMs + license.gracePeriodMs
  ) {
    throw unauthorized('License is revoked or expired');
  }
  if (
    license.deploymentId !== binding.deploymentId
    || (!input.allowDeploymentOrganization
      && license.organizationId !== binding.organizationId)
    || license.machineFingerprint !== binding.machineFingerprint
  ) {
    throw unauthorized(`${input.purpose} request binding is invalid`);
  }
  const expected = input.tokens.issue({
    purpose: 'lease',
    licenseId: binding.licenseId,
    deploymentId: binding.deploymentId,
    version: license.tokenVersion,
  });
  if (!input.tokens.matches(input.bearerToken, expected)) {
    throw unauthorized(`${input.purpose} token is invalid`);
  }
  const deployment = await input.store.getDeployment(binding.deploymentId);
  if (!deployment || deployment.status !== 'active') {
    throw unauthorized('deployment is inactive');
  }
  if (
    deployment.organizationId !== binding.organizationId
    && !input.allowDeploymentOrganization
  ) {
    throw unauthorized(`${input.purpose} deployment organization is invalid`);
  }
  return {
    customerId: deployment.customerId,
    license,
    organizationId: binding.organizationId,
    deploymentId: binding.deploymentId,
  };
}

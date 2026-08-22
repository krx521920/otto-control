export type EdgeRuntimeScenario = 'success' | 'timeout' | 'slow_stream' | '429' | '500' | '503';

export interface EdgeScenarioResult {
  scenario: EdgeRuntimeScenario;
  status: number;
  code: string | null;
  durationMs: number;
  bodyTerminated: boolean;
}

export interface EdgeAcceptanceIdentity {
  licenseId: string;
  deploymentId: string;
  organizationId: string;
  machineFingerprint: string;
}

export interface EdgeRuntimeFailureInput {
  gatewayUrl: URL;
  controlUrl: URL;
  identity: EdgeAcceptanceIdentity;
  leaseToken: string;
  subjectId: string;
  model: string;
  workingDirectory: string;
  composeFile: string;
  environmentFile: string;
  projectName: string | null;
  redisService: string;
  gatewayService: string;
  controlServices: string[];
  requestTimeoutMs: number;
  providerRequestTimeoutMs: number;
  failureDetectionTimeoutMs: number;
  recoveryTimeoutMs: number;
  policyExpiryTimeoutMs: number;
  pollIntervalMs: number;
}

export interface EdgeRuntimeFailureDependencies {
  now?(): number;
  sleep?(milliseconds: number): Promise<void>;
  compose?(action: string, services: string[]): void | Promise<void>;
  readiness?(gatewayUrl: URL): Promise<number>;
  issueToken?(): Promise<string>;
  scenario?(accessToken: string, scenario: EdgeRuntimeScenario): Promise<EdgeScenarioResult>;
}

export function assertEdgeScenario(result: EdgeScenarioResult): void;
export function edgeReadiness(
  gatewayUrl: URL,
  fetchImplementation?: typeof fetch,
  timeoutMs?: number,
): Promise<number>;
export function runEdgeScenario(input: {
  gatewayUrl: URL;
  accessToken: string;
  model: string;
  scenario: EdgeRuntimeScenario;
  requestTimeoutMs: number;
}, fetchImplementation?: typeof fetch): Promise<EdgeScenarioResult>;
export function issueEdgeAcceptanceToken(input: {
  controlUrl: URL;
  identity: EdgeAcceptanceIdentity;
  leaseToken: string;
  subjectId: string;
  model: string;
  requestTimeoutMs: number;
}, fetchImplementation?: typeof fetch): Promise<string>;
export function issueEdgeAcceptanceCredential(input: {
  controlUrl: URL;
  identity: EdgeAcceptanceIdentity;
  leaseToken: string;
  subjectId: string;
  model: string;
  requestTimeoutMs: number;
}, fetchImplementation?: typeof fetch): Promise<{ encodedToken: string; expiresAtMs: number }>;
export function runEdgeRuntimeFailureAcceptance(
  input: EdgeRuntimeFailureInput,
  injected?: EdgeRuntimeFailureDependencies,
): Promise<Record<string, unknown>>;

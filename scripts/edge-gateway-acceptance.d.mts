export interface EdgeAcceptanceConfiguration {
  profile: 'ci-smoke' | 'soak-24h' | 'cost-load';
  baseUrl: URL | null;
  endpoint: '/v1/chat/completions' | '/v1/responses';
  model: string;
  prompt: string;
  durationSeconds: number;
  concurrency: number;
  requestsPerSecond: number;
  maxRequests: number;
  requestTimeoutMs: number;
  sampleIntervalMs: number;
  maxErrorRate: number;
  maxP99LatencyMs: number;
  maxOutputTokens: number;
  estimatedInputTokens: number;
  inputPricePerMillionUsd: number;
  outputPricePerMillionUsd: number;
  budgetUsd: number;
  accessToken: string | null;
  accessTokenFile: string | null;
  controlUrl: URL | null;
  identityFile: string | null;
  leaseTokenFile: string | null;
  subjectId: string;
  tokenRefreshBeforeMs: number;
  operationsToken: string | null;
  operationsTokenFile: string | null;
  outputDirectory: string;
  repositoryRoot: string;
  releaseCandidate: string | null;
  releaseArtifact: string | null;
  confirmation: string;
  planOnly: boolean;
}

export const EDGE_ACCEPTANCE_CONFIRMATION: 'RUN_REAL_EDGE_ACCEPTANCE';
export const EDGE_ACCEPTANCE_PROFILES: Readonly<Record<string, Readonly<Record<string, number>>>>;
export interface EdgeAcceptanceReport {
  result: 'passed' | 'failed';
  runId: string;
  traffic: {
    launched: number;
    completed: number;
    succeeded: number;
    failed: number;
    errorRate: number;
    achievedRequestsPerSecond: number;
  };
  latency: { p99Ms: number | null };
  tokens: { input: number; output: number; total: number };
  cost: { meteredEstimateUsd: number; reservedWorstCaseUsd: number };
  capacity: {
    recommendedCeilingWithThirtyPercentHeadroom: number;
    operationsStart: { status: number } | null;
  };
  resources: { peakRssBytes: number };
  violations: string[];
  evidence: {
    ledgerFile: string;
    reportFile: string;
    ledger: { path: string; sha256: string; bytes: number } | null;
  };
  provenance: {
    schemaVersion: number;
    evidenceClass: 'production-live' | 'simulation';
    generator: string;
    releaseCandidate: string | null;
    releaseArtifact: { path: string; sha256: string; bytes: number } | null;
    runner: Record<string, string>;
  };
}
export function parseEdgeAcceptanceArguments(
  argv: string[],
  environment?: NodeJS.ProcessEnv,
): EdgeAcceptanceConfiguration;
export function runEdgeAcceptance(
  configuration: EdgeAcceptanceConfiguration,
  options?: {
    signal?: AbortSignal;
    now?: () => number;
    environment?: NodeJS.ProcessEnv;
    issueCredential?: (input: unknown) => Promise<{ encodedToken: string; expiresAtMs: number }>;
  },
): Promise<EdgeAcceptanceReport>;

import type {
  EdgeAcceptanceIdentity,
  EdgeScenarioResult,
} from './drill-edge-runtime-failures.mjs';
import type { SigningRevocationDrillReport } from './drill-signing-revocation.mjs';

export interface EdgeKeyRevocationInput {
  gatewayUrl: URL;
  controlUrl: URL;
  identity: EdgeAcceptanceIdentity;
  leaseToken: string;
  requesterToken: string;
  approverToken: string;
  auditorToken: string;
  subjectId: string;
  model: string;
  keyId: string;
  replacementKeyId: string;
  reason: string;
  requestTimeoutMs: number;
  refreshTimeoutMs: number;
  pollIntervalMs: number;
  workingDirectory: string;
  composeFile: string;
  environmentFile: string;
  projectName: string | null;
  gatewayService: string;
}

export interface EdgeKeyRevocationDependencies {
  now?(): number;
  sleep?(milliseconds: number): Promise<void>;
  issueToken?(): Promise<string>;
  scenario?(accessToken: string): Promise<EdgeScenarioResult>;
  readiness?(): Promise<number>;
  revoke?(): Promise<SigningRevocationDrillReport>;
  restartGateway?(): void | Promise<void>;
}

export function runEdgeKeyRevocationAcceptance(
  input: EdgeKeyRevocationInput,
  injected?: EdgeKeyRevocationDependencies,
): Promise<Record<string, unknown>>;

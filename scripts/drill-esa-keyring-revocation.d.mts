import type {
  EdgeAcceptanceIdentity,
  EdgeScenarioResult,
} from './drill-edge-runtime-failures.mjs';
import type { SigningRevocationDrillReport } from './drill-signing-revocation.mjs';

export interface EsaKeyringRevocationInput {
  controlUrl: URL;
  nodeUrls: URL[];
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
  changeTicket: string;
  requestTimeoutMs: number;
  refreshTimeoutMs: number;
  pollIntervalMs: number;
}

export interface EsaKeyringRevocationDependencies {
  now?(): number;
  sleep?(milliseconds: number): Promise<void>;
  issueToken?(): Promise<string>;
  scenario?(nodeUrl: URL, accessToken: string): Promise<EdgeScenarioResult>;
  revoke?(): Promise<SigningRevocationDrillReport>;
}

export function runEsaKeyringRevocationAcceptance(
  input: EsaKeyringRevocationInput,
  injected?: EsaKeyringRevocationDependencies,
): Promise<Record<string, unknown>>;

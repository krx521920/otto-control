export interface FileEvidence {
  path: string;
  sha256: string;
  bytes: number;
}

export interface ReleaseEvidence {
  gitCommit: string;
  artifact: FileEvidence;
}

export interface EvidenceEnvironment {
  evidenceClass: 'production-live' | 'simulation';
  runner: Record<string, string>;
}

export const SHA256_PATTERN: RegExp;
export const GIT_COMMIT_PATTERN: RegExp;
export function sha256Bytes(bytes: string | NodeJS.ArrayBufferView): string;
export function sha256File(path: string): string;
export function immutableReleaseEvidence(input: {
  root: string;
  releaseCandidate: string;
  artifactPath: string;
}): ReleaseEvidence;
export function classifyEvidenceEnvironment(environment?: NodeJS.ProcessEnv): EvidenceEnvironment;
export function productionProvenance(input: {
  environment?: NodeJS.ProcessEnv;
  generator: string;
  release: ReleaseEvidence;
}): {
  schemaVersion: 1;
  evidenceClass: 'production-live' | 'simulation';
  generator: string;
  releaseCandidate: string;
  releaseArtifact: FileEvidence;
  runner: Record<string, string>;
};
export function elapsedEvidence(
  startedAtMs: number,
  completedAtMs: number,
  monotonicDurationMs: number,
): {
  startedAt: string;
  completedAt: string;
  wallClockDurationSeconds: number;
  monotonicDurationSeconds: number;
};
export function fileEvidence(root: string, path: string, name?: string): FileEvidence;

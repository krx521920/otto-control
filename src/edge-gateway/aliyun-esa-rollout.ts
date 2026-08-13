const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const KEY_ID_PATTERN = /^[a-f0-9]{16}$/u;
const IDENTIFIER_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._/-]{2,127}$/u;

export interface AliyunEsaImmutableReleaseBinding {
  releaseId: string;
  workerDigest: string;
  policyDigest: string;
  keyring: {
    revision: number;
    digest: string;
    activeKeyId: string;
  };
  /** Secret values never enter rollout state. Values are provider version digests. */
  secretVersionDigests: Readonly<Record<string, string>>;
}

export interface AliyunEsaDeployment {
  deploymentId: string;
  binding: AliyunEsaImmutableReleaseBinding;
}

export interface AliyunEsaHealthSample {
  requestCount: number;
  errorRate: number;
  p95LatencyMs: number;
  ready: boolean;
  billingReady: boolean;
  observedBinding: AliyunEsaImmutableReleaseBinding;
}

export interface AliyunEsaHealthGate {
  minimumRequests: number;
  maximumErrorRate: number;
  maximumP95LatencyMs: number;
}

export type AliyunEsaRolloutPhase =
  | 'preparing'
  | 'canary'
  | 'promoting'
  | 'stable'
  | 'rollback_pending'
  | 'rolled_back'
  | 'manual_intervention';

export interface AliyunEsaRolloutCheckpoint {
  version: 1;
  rolloutId: string;
  sequence: number;
  phase: AliyunEsaRolloutPhase;
  candidateDeploymentId: string | null;
  baselineDeploymentId: string;
  candidatePercent: number;
  candidate: AliyunEsaImmutableReleaseBinding;
  baseline: AliyunEsaImmutableReleaseBinding;
  recordedAt: string;
  reason: string | null;
  health: AliyunEsaHealthSample | null;
}

export interface AliyunEsaRolloutPlan {
  rolloutId: string;
  candidate: AliyunEsaImmutableReleaseBinding;
  baseline: AliyunEsaDeployment;
  percentages: readonly number[];
  healthGate: AliyunEsaHealthGate;
}

export interface AliyunEsaRolloutDriver {
  stage(binding: AliyunEsaImmutableReleaseBinding): Promise<AliyunEsaDeployment>;
  switchTraffic(input: {
    rolloutId: string;
    candidateDeploymentId: string;
    baselineDeploymentId: string;
    candidatePercent: number;
    idempotencyKey: string;
  }): Promise<void>;
  measure(deploymentId: string, candidatePercent: number): Promise<AliyunEsaHealthSample>;
  checkpoint(value: AliyunEsaRolloutCheckpoint): Promise<void>;
  deactivate(deploymentId: string): Promise<void>;
  now?(): number;
}

export interface AliyunEsaRolloutResult {
  result: 'promoted' | 'rolled_back';
  checkpoints: readonly AliyunEsaRolloutCheckpoint[];
}

export class AliyunEsaRolloutError extends Error {
  readonly code: string;
  readonly checkpoints: readonly AliyunEsaRolloutCheckpoint[];

  constructor(code: string, message: string, checkpoints: readonly AliyunEsaRolloutCheckpoint[]) {
    super(message);
    this.name = 'AliyunEsaRolloutError';
    this.code = code;
    this.checkpoints = checkpoints;
  }
}

function configurationError(message: string): never {
  throw new AliyunEsaRolloutError('ESA_ROLLOUT_CONFIGURATION_INVALID', message, []);
}

function assertDigest(value: string, field: string): void {
  if (!DIGEST_PATTERN.test(value)) configurationError(`${field} must be an immutable SHA-256 digest`);
}

function assertBinding(binding: AliyunEsaImmutableReleaseBinding, field: string): void {
  if (!IDENTIFIER_PATTERN.test(binding.releaseId)) configurationError(`${field} releaseId is invalid`);
  assertDigest(binding.workerDigest, `${field} workerDigest`);
  assertDigest(binding.policyDigest, `${field} policyDigest`);
  assertDigest(binding.keyring.digest, `${field} keyring digest`);
  if (!Number.isSafeInteger(binding.keyring.revision) || binding.keyring.revision < 1
    || !KEY_ID_PATTERN.test(binding.keyring.activeKeyId)) {
    configurationError(`${field} keyring identity is invalid`);
  }
  const secretEntries = Object.entries(binding.secretVersionDigests);
  if (secretEntries.length < 1 || secretEntries.length > 64) {
    configurationError(`${field} must bind between 1 and 64 versioned secrets`);
  }
  for (const [name, digest] of secretEntries) {
    if (!/^[A-Z][A-Z0-9_]{2,63}$/u.test(name)) {
      configurationError(`${field} secret binding name is invalid`);
    }
    assertDigest(digest, `${field} secret version`);
  }
}

function stableBinding(binding: AliyunEsaImmutableReleaseBinding): string {
  return JSON.stringify({
    releaseId: binding.releaseId,
    workerDigest: binding.workerDigest,
    policyDigest: binding.policyDigest,
    keyring: binding.keyring,
    secretVersionDigests: Object.fromEntries(
      Object.entries(binding.secretVersionDigests).sort(([left], [right]) => left.localeCompare(right)),
    ),
  });
}

function assertPlan(plan: AliyunEsaRolloutPlan): void {
  if (!IDENTIFIER_PATTERN.test(plan.rolloutId)
    || !IDENTIFIER_PATTERN.test(plan.baseline.deploymentId)) {
    configurationError('rollout or baseline deployment identity is invalid');
  }
  assertBinding(plan.candidate, 'candidate');
  assertBinding(plan.baseline.binding, 'baseline');
  if (stableBinding(plan.candidate) === stableBinding(plan.baseline.binding)) {
    configurationError('candidate must differ from the pinned baseline');
  }
  if (plan.percentages.length < 2 || plan.percentages.length > 10
    || plan.percentages[plan.percentages.length - 1] !== 100
    || (plan.percentages[0] ?? 100) > 10
    || plan.percentages.some((value, index) => !Number.isSafeInteger(value)
      || value < 1 || value > 100 || (index > 0 && value <= plan.percentages[index - 1]!))) {
    configurationError('rollout percentages must increase from a canary of at most 10 to 100');
  }
  if (!Number.isSafeInteger(plan.healthGate.minimumRequests)
    || plan.healthGate.minimumRequests < 1 || plan.healthGate.minimumRequests > 10_000_000
    || !Number.isFinite(plan.healthGate.maximumErrorRate)
    || plan.healthGate.maximumErrorRate < 0 || plan.healthGate.maximumErrorRate > 1
    || !Number.isSafeInteger(plan.healthGate.maximumP95LatencyMs)
    || plan.healthGate.maximumP95LatencyMs < 1
    || plan.healthGate.maximumP95LatencyMs > 600_000) {
    configurationError('health gate is invalid');
  }
}

function healthFailure(
  sample: AliyunEsaHealthSample,
  expected: AliyunEsaImmutableReleaseBinding,
  gate: AliyunEsaHealthGate,
): string | null {
  if (stableBinding(sample.observedBinding) !== stableBinding(expected)) {
    return 'health probe observed a release binding different from the immutable candidate';
  }
  if (!sample.ready) return 'candidate readiness failed';
  if (!sample.billingReady) return 'candidate billing aggregation is not ready';
  if (!Number.isSafeInteger(sample.requestCount) || sample.requestCount < gate.minimumRequests) {
    return 'candidate health sample is below the minimum request count';
  }
  if (!Number.isFinite(sample.errorRate) || sample.errorRate < 0
    || sample.errorRate > gate.maximumErrorRate) {
    return 'candidate error rate exceeded the health gate';
  }
  if (!Number.isFinite(sample.p95LatencyMs) || sample.p95LatencyMs < 0
    || sample.p95LatencyMs > gate.maximumP95LatencyMs) {
    return 'candidate P95 latency exceeded the health gate';
  }
  return null;
}

export async function runAliyunEsaCanaryRollout(
  plan: AliyunEsaRolloutPlan,
  driver: AliyunEsaRolloutDriver,
): Promise<AliyunEsaRolloutResult> {
  assertPlan(plan);
  const checkpoints: AliyunEsaRolloutCheckpoint[] = [];
  const now = driver.now ?? Date.now;
  let sequence = 0;
  let candidate: AliyunEsaDeployment | null = null;
  let candidatePercent = 0;

  const record = async (
    phase: AliyunEsaRolloutPhase,
    reason: string | null = null,
    health: AliyunEsaHealthSample | null = null,
  ): Promise<void> => {
    const checkpoint: AliyunEsaRolloutCheckpoint = {
      version: 1,
      rolloutId: plan.rolloutId,
      sequence: ++sequence,
      phase,
      candidateDeploymentId: candidate?.deploymentId ?? null,
      baselineDeploymentId: plan.baseline.deploymentId,
      candidatePercent,
      candidate: plan.candidate,
      baseline: plan.baseline.binding,
      recordedAt: new Date(now()).toISOString(),
      reason,
      health,
    };
    await driver.checkpoint(checkpoint);
    checkpoints.push(checkpoint);
  };

  await record('preparing');
  try {
    candidate = await driver.stage(plan.candidate);
    if (!IDENTIFIER_PATTERN.test(candidate.deploymentId)
      || stableBinding(candidate.binding) !== stableBinding(plan.candidate)) {
      await driver.deactivate(candidate.deploymentId);
      candidate = null;
      throw new Error('staged deployment does not match the immutable candidate binding');
    }
    for (const percentage of plan.percentages) {
      candidatePercent = percentage;
      await driver.switchTraffic({
        rolloutId: plan.rolloutId,
        candidateDeploymentId: candidate.deploymentId,
        baselineDeploymentId: plan.baseline.deploymentId,
        candidatePercent,
        idempotencyKey: `${plan.rolloutId}:${sequence + 1}:${candidatePercent}`,
      });
      const sample = await driver.measure(candidate.deploymentId, candidatePercent);
      const reason = healthFailure(sample, plan.candidate, plan.healthGate);
      await record(candidatePercent === 100 ? 'promoting' : 'canary', reason, sample);
      if (reason) throw new Error(reason);
    }
    await driver.deactivate(plan.baseline.deploymentId);
    await record('stable');
    return { result: 'promoted', checkpoints };
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    if (!candidate || candidatePercent === 0) {
      throw new AliyunEsaRolloutError('ESA_ROLLOUT_PREPARATION_FAILED', reason, checkpoints);
    }
    await record('rollback_pending', reason);
    try {
      await driver.switchTraffic({
        rolloutId: plan.rolloutId,
        candidateDeploymentId: candidate.deploymentId,
        baselineDeploymentId: plan.baseline.deploymentId,
        candidatePercent: 0,
        idempotencyKey: `${plan.rolloutId}:${sequence + 1}:rollback`,
      });
      const baselineHealth = await driver.measure(plan.baseline.deploymentId, 100);
      const rollbackFailure = healthFailure(baselineHealth, plan.baseline.binding, plan.healthGate);
      if (rollbackFailure) throw new Error(`rollback verification failed: ${rollbackFailure}`);
      await driver.deactivate(candidate.deploymentId);
      candidatePercent = 0;
      await record('rolled_back', reason, baselineHealth);
      return { result: 'rolled_back', checkpoints };
    } catch (rollbackError) {
      const rollbackReason = rollbackError instanceof Error
        ? rollbackError.message
        : String(rollbackError);
      await record('manual_intervention', `${reason}; ${rollbackReason}`);
      throw new AliyunEsaRolloutError(
        'ESA_ROLLOUT_ROLLBACK_FAILED',
        `automatic rollback failed: ${rollbackReason}`,
        checkpoints,
      );
    }
  }
}

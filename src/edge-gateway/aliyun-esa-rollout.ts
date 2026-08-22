const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const KEY_ID_PATTERN = /^[a-f0-9]{16}$/u;
const IDENTIFIER_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._/-]{2,127}$/u;
const DEPLOYMENT_ID_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{2,127}$/u;
const ROLLOUT_PHASES = new Set<AliyunEsaRolloutPhase>([
  'preparing', 'staged', 'canary', 'promoting', 'stable',
  'rollback_pending', 'rolled_back', 'manual_intervention',
]);

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
  | 'staged'
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
  stage(input: {
    rolloutId: string;
    binding: AliyunEsaImmutableReleaseBinding;
    idempotencyKey: string;
  }): Promise<AliyunEsaDeployment>;
  switchTraffic(input: {
    rolloutId: string;
    candidateDeploymentId: string;
    baselineDeploymentId: string;
    candidatePercent: number;
    idempotencyKey: string;
  }): Promise<void>;
  measure(deploymentId: string, candidatePercent: number): Promise<AliyunEsaHealthSample>;
  /**
   * Reconcile a durable checkpoint with the provider's signed deployment
   * binding and live traffic state before any resumed action is allowed.
   */
  verifyCheckpoint(value: AliyunEsaRolloutCheckpoint): Promise<boolean>;
  checkpoint(value: AliyunEsaRolloutCheckpoint): Promise<void>;
  deactivate(deploymentId: string): Promise<void>;
  now?(): number;
}

export interface AliyunEsaRolloutResult {
  result: 'promoted' | 'rolled_back';
  checkpoints: readonly AliyunEsaRolloutCheckpoint[];
}

export interface AliyunEsaRolloutExecutionOptions {
  /**
   * Latest durable checkpoint for this rollout. The driver must enforce
   * compare-and-set checkpoint sequencing outside this pure state machine.
   */
  resumeFrom?: AliyunEsaRolloutCheckpoint;
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

/**
 * Drivers must throw this when a rollout lease, fencing token, or checkpoint
 * compare-and-set is lost. The state machine must stop without rollback,
 * because another executor now owns the rollout.
 */
export class AliyunEsaRolloutExecutionLostError extends Error {
  readonly code = 'ESA_ROLLOUT_EXECUTION_LOST';

  constructor(message = 'rollout execution lease or checkpoint ownership was lost') {
    super(message);
    this.name = 'AliyunEsaRolloutExecutionLostError';
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

function assertResumeCheckpoint(
  plan: AliyunEsaRolloutPlan,
  checkpoint: AliyunEsaRolloutCheckpoint,
): void {
  let immutablePlanMatches = false;
  try {
    immutablePlanMatches = stableBinding(checkpoint.candidate) === stableBinding(plan.candidate)
      && stableBinding(checkpoint.baseline) === stableBinding(plan.baseline.binding);
  } catch {
    configurationError('resume checkpoint immutable binding is invalid');
  }
  if (checkpoint.version !== 1 || checkpoint.rolloutId !== plan.rolloutId
    || !Number.isSafeInteger(checkpoint.sequence) || checkpoint.sequence < 1
    || checkpoint.baselineDeploymentId !== plan.baseline.deploymentId
    || !immutablePlanMatches
    || typeof checkpoint.recordedAt !== 'string'
    || !Number.isFinite(Date.parse(checkpoint.recordedAt))
    || new Date(checkpoint.recordedAt).toISOString() !== checkpoint.recordedAt
    || !Number.isSafeInteger(checkpoint.candidatePercent)
    || checkpoint.candidatePercent < 0 || checkpoint.candidatePercent > 100
    || !ROLLOUT_PHASES.has(checkpoint.phase)
    || (checkpoint.reason !== null
      && (typeof checkpoint.reason !== 'string'
        || !checkpoint.reason.trim() || checkpoint.reason.length > 2_048))) {
    configurationError('resume checkpoint does not match the immutable rollout plan');
  }
  if (checkpoint.phase === 'preparing') {
    if (checkpoint.candidateDeploymentId !== null || checkpoint.candidatePercent !== 0
      || checkpoint.reason !== null || checkpoint.health !== null) {
      configurationError('preparing checkpoint is invalid');
    }
    return;
  }
  if (typeof checkpoint.candidateDeploymentId !== 'string'
    || !DEPLOYMENT_ID_PATTERN.test(checkpoint.candidateDeploymentId)) {
    configurationError('resume checkpoint candidate deployment identity is invalid');
  }
  if (checkpoint.phase === 'staged') {
    if (checkpoint.candidatePercent !== 0 || checkpoint.reason !== null
      || checkpoint.health !== null) {
      configurationError('staged checkpoint is invalid');
    }
    return;
  }

  const validatedHealthFailure = (
    expected: AliyunEsaImmutableReleaseBinding,
  ): string | null => {
    const sample = checkpoint.health as unknown;
    if (!sample || typeof sample !== 'object' || Array.isArray(sample)) {
      configurationError(`${checkpoint.phase} checkpoint health is invalid`);
    }
    const body = sample as Record<string, unknown>;
    if (typeof body.requestCount !== 'number' || typeof body.errorRate !== 'number'
      || typeof body.p95LatencyMs !== 'number' || typeof body.ready !== 'boolean'
      || typeof body.billingReady !== 'boolean' || !body.observedBinding
      || typeof body.observedBinding !== 'object' || Array.isArray(body.observedBinding)) {
      configurationError(`${checkpoint.phase} checkpoint health is invalid`);
    }
    try {
      return healthFailure(sample as AliyunEsaHealthSample, expected, plan.healthGate);
    } catch {
      configurationError(`${checkpoint.phase} checkpoint health is invalid`);
    }
  };

  if (checkpoint.phase === 'stable') {
    if (checkpoint.candidatePercent !== 100 || checkpoint.reason !== null
      || checkpoint.health !== null) {
      configurationError('stable checkpoint is invalid');
    }
    return;
  }
  if (checkpoint.phase === 'promoting') {
    if (checkpoint.candidatePercent !== 100 || checkpoint.reason !== null
      || validatedHealthFailure(plan.candidate) !== null) {
      configurationError('promoting checkpoint is invalid');
    }
    return;
  }
  if (checkpoint.phase === 'canary') {
    const failure = validatedHealthFailure(plan.candidate);
    if (checkpoint.candidatePercent === 100
      || !plan.percentages.includes(checkpoint.candidatePercent)
      || checkpoint.reason !== failure) {
      configurationError('canary checkpoint is inconsistent with its health evidence');
    }
    return;
  }
  if (checkpoint.phase === 'rolled_back') {
    if (checkpoint.candidatePercent !== 0 || checkpoint.reason === null
      || validatedHealthFailure(plan.baseline.binding) !== null) {
      configurationError('rolled_back checkpoint is invalid');
    }
    return;
  }
  if (!plan.percentages.includes(checkpoint.candidatePercent)
    || checkpoint.reason === null || checkpoint.health !== null) {
    configurationError(`${checkpoint.phase} checkpoint is invalid`);
  }
}

function assertPlan(plan: AliyunEsaRolloutPlan): void {
  if (!IDENTIFIER_PATTERN.test(plan.rolloutId)
    || !DEPLOYMENT_ID_PATTERN.test(plan.baseline.deploymentId)) {
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
  options: AliyunEsaRolloutExecutionOptions = {},
): Promise<AliyunEsaRolloutResult> {
  assertPlan(plan);
  if (options.resumeFrom) {
    assertResumeCheckpoint(plan, options.resumeFrom);
    let verified = false;
    try {
      verified = await driver.verifyCheckpoint(options.resumeFrom);
    } catch (error) {
      if (error instanceof AliyunEsaRolloutExecutionLostError) throw error;
      throw new AliyunEsaRolloutError(
        'ESA_ROLLOUT_RESUME_VERIFICATION_FAILED',
        `failed to reconcile rollout checkpoint with ESA: ${
          error instanceof Error ? error.message : String(error)}`,
        [options.resumeFrom],
      );
    }
    if (!verified) {
      throw new AliyunEsaRolloutError(
        'ESA_ROLLOUT_STATE_DIVERGED',
        'durable checkpoint does not match the signed ESA deployment and live traffic state',
        [options.resumeFrom],
      );
    }
  }
  const checkpoints: AliyunEsaRolloutCheckpoint[] = options.resumeFrom
    ? [options.resumeFrom]
    : [];
  const now = driver.now ?? Date.now;
  let sequence = options.resumeFrom?.sequence ?? 0;
  let candidate: AliyunEsaDeployment | null = options.resumeFrom?.candidateDeploymentId
    ? { deploymentId: options.resumeFrom.candidateDeploymentId, binding: plan.candidate }
    : null;
  let candidatePercent = options.resumeFrom?.candidatePercent ?? 0;

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

  if (options.resumeFrom?.phase === 'stable') {
    return { result: 'promoted', checkpoints };
  }
  if (options.resumeFrom?.phase === 'rolled_back') {
    return { result: 'rolled_back', checkpoints };
  }
  if (options.resumeFrom?.phase === 'manual_intervention') {
    throw new AliyunEsaRolloutError(
      'ESA_ROLLOUT_MANUAL_INTERVENTION_REQUIRED',
      'rollout cannot resume after entering manual intervention',
      checkpoints,
    );
  }

  if (!options.resumeFrom) await record('preparing');

  const rollback = async (reason: string): Promise<AliyunEsaRolloutResult> => {
    if (!candidate || candidatePercent === 0) {
      if (candidate) await driver.deactivate(candidate.deploymentId);
      throw new AliyunEsaRolloutError('ESA_ROLLOUT_PREPARATION_FAILED', reason, checkpoints);
    }
    if (options.resumeFrom?.phase !== 'rollback_pending') {
      await record('rollback_pending', reason);
    }
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
      if (rollbackError instanceof AliyunEsaRolloutExecutionLostError) throw rollbackError;
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
  };

  if (options.resumeFrom?.phase === 'rollback_pending'
    || (options.resumeFrom?.phase === 'canary' && options.resumeFrom.reason)) {
    return rollback(options.resumeFrom.reason ?? 'resuming a pending rollback');
  }

  try {
    if (!candidate) {
      candidate = await driver.stage({
        rolloutId: plan.rolloutId,
        binding: plan.candidate,
        idempotencyKey: `${plan.rolloutId}:stage`,
      });
      if (typeof candidate.deploymentId !== 'string'
        || !DEPLOYMENT_ID_PATTERN.test(candidate.deploymentId)) {
        candidate = null;
        throw new Error('staged deployment returned an invalid identity');
      }
      if (stableBinding(candidate.binding) !== stableBinding(plan.candidate)) {
        await driver.deactivate(candidate.deploymentId);
        candidate = null;
        throw new Error('staged deployment does not match the immutable candidate binding');
      }
      await record('staged');
    }

    const completedIndex = candidatePercent === 0
      ? -1
      : plan.percentages.indexOf(candidatePercent);
    for (const percentage of plan.percentages.slice(completedIndex + 1)) {
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
    await record('stable');
    return { result: 'promoted', checkpoints };
  } catch (error) {
    if (error instanceof AliyunEsaRolloutExecutionLostError) throw error;
    const reason = error instanceof Error ? error.message : String(error);
    return rollback(reason);
  }
}

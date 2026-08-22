import { describe, expect, it, vi } from 'vitest';

import {
  AliyunEsaRolloutError,
  AliyunEsaRolloutExecutionLostError,
  runAliyunEsaCanaryRollout,
  type AliyunEsaHealthSample,
  type AliyunEsaImmutableReleaseBinding,
  type AliyunEsaRolloutCheckpoint,
  type AliyunEsaRolloutDriver,
  type AliyunEsaRolloutPlan,
} from '../src/edge-gateway/aliyun-esa-rollout.js';

const digest = (value: string) => `sha256:${value.repeat(64)}`;

function binding(releaseId: string, value: string): AliyunEsaImmutableReleaseBinding {
  return {
    releaseId,
    workerDigest: digest(value),
    policyDigest: digest(value === 'a' ? 'b' : 'a'),
    keyring: {
      revision: value === 'a' ? 1 : 2,
      digest: digest(value === 'a' ? 'c' : 'd'),
      activeKeyId: value.repeat(16),
    },
    secretVersionDigests: { MODEL_PROVIDER_TOKEN: digest(value === 'a' ? 'd' : 'c') },
  };
}

function plan(): AliyunEsaRolloutPlan {
  return {
    rolloutId: 'rollout-2026-08-13',
    candidate: binding('release-2', 'b'),
    baseline: { deploymentId: 'deployment-1', binding: binding('release-1', 'a') },
    percentages: [5, 25, 100],
    healthGate: {
      minimumRequests: 1_000,
      maximumErrorRate: 0.01,
      maximumP95LatencyMs: 1_000,
    },
  };
}

function healthy(observedBinding: AliyunEsaImmutableReleaseBinding): AliyunEsaHealthSample {
  return {
    requestCount: 2_000,
    errorRate: 0.001,
    p95LatencyMs: 250,
    ready: true,
    billingReady: true,
    observedBinding,
  };
}

function resumeCheckpoint(
  input: AliyunEsaRolloutPlan,
  overrides: Partial<AliyunEsaRolloutCheckpoint> = {},
): AliyunEsaRolloutCheckpoint {
  return {
    version: 1,
    rolloutId: input.rolloutId,
    sequence: 2,
    phase: 'staged',
    candidateDeploymentId: 'deployment-2',
    baselineDeploymentId: input.baseline.deploymentId,
    candidatePercent: 0,
    candidate: input.candidate,
    baseline: input.baseline.binding,
    recordedAt: '2026-08-13T00:00:00.000Z',
    reason: null,
    health: null,
    ...overrides,
  };
}

function driver(
  input: AliyunEsaRolloutPlan,
  samples: AliyunEsaHealthSample[],
): AliyunEsaRolloutDriver & {
  traffic: ReturnType<typeof vi.fn>;
  checkpoints: AliyunEsaRolloutCheckpoint[];
  deactivated: string[];
} {
  const checkpoints: AliyunEsaRolloutCheckpoint[] = [];
  const deactivated: string[] = [];
  return {
    stage: vi.fn(async () => ({ deploymentId: 'deployment-2', binding: input.candidate })),
    traffic: vi.fn(async () => undefined),
    async switchTraffic(value) { await this.traffic(value); },
    measure: vi.fn(async () => samples.shift() ?? healthy(input.candidate)),
    verifyCheckpoint: vi.fn(async () => true),
    checkpoint: vi.fn(async (value) => { checkpoints.push(value); }),
    deactivate: vi.fn(async (deploymentId) => { deactivated.push(deploymentId); }),
    now: () => 1_786_633_200_000,
    checkpoints,
    deactivated,
  };
}

describe('Aliyun ESA immutable canary rollout', () => {
  it('promotes an immutable binding through every gated traffic stage', async () => {
    const input = plan();
    const implementation = driver(input, [
      healthy(input.candidate), healthy(input.candidate), healthy(input.candidate),
    ]);
    const result = await runAliyunEsaCanaryRollout(input, implementation);

    expect(result.result).toBe('promoted');
    expect(implementation.traffic.mock.calls.map(([value]) => value.candidatePercent))
      .toEqual([5, 25, 100]);
    expect(implementation.traffic.mock.calls.map(([value]) => value.idempotencyKey))
      .toEqual([
        'rollout-2026-08-13:3:5',
        'rollout-2026-08-13:4:25',
        'rollout-2026-08-13:5:100',
      ]);
    expect(implementation.checkpoints.map((value) => value.phase))
      .toEqual(['preparing', 'staged', 'canary', 'canary', 'promoting', 'stable']);
    expect(implementation.stage).toHaveBeenCalledWith({
      rolloutId: input.rolloutId,
      binding: input.candidate,
      idempotencyKey: `${input.rolloutId}:stage`,
    });
    expect(implementation.deactivated).toEqual([]);
  });

  it('restores the still-active baseline when the final stable checkpoint fails', async () => {
    const input = plan();
    const implementation = driver(input, [
      healthy(input.candidate),
      healthy(input.candidate),
      healthy(input.candidate),
      healthy(input.baseline.binding),
    ]);
    implementation.checkpoint = vi.fn(async (value) => {
      if (value.phase === 'stable') throw new Error('stable checkpoint unavailable');
      implementation.checkpoints.push(value);
    });

    const result = await runAliyunEsaCanaryRollout(input, implementation);

    expect(result.result).toBe('rolled_back');
    expect(implementation.traffic.mock.calls.map(([value]) => value.candidatePercent))
      .toEqual([5, 25, 100, 0]);
    expect(implementation.checkpoints.map((value) => value.phase))
      .toEqual(['preparing', 'staged', 'canary', 'canary', 'promoting',
        'rollback_pending', 'rolled_back']);
    expect(implementation.deactivated).toEqual(['deployment-2']);
  });

  it('automatically restores the pinned baseline when a canary health gate fails', async () => {
    const input = plan();
    const failed = { ...healthy(input.candidate), errorRate: 0.02 };
    const implementation = driver(input, [failed, healthy(input.baseline.binding)]);
    const result = await runAliyunEsaCanaryRollout(input, implementation);

    expect(result.result).toBe('rolled_back');
    expect(implementation.traffic.mock.calls.map(([value]) => value.candidatePercent))
      .toEqual([5, 0]);
    expect(implementation.checkpoints.map((value) => value.phase))
      .toEqual(['preparing', 'staged', 'canary', 'rollback_pending', 'rolled_back']);
    expect(implementation.deactivated).toEqual(['deployment-2']);
  });

  it('fails closed if the staged deployment is not the requested immutable version', async () => {
    const input = plan();
    const implementation = driver(input, []);
    implementation.stage = vi.fn(async () => ({
      deploymentId: 'deployment-2',
      binding: { ...input.candidate, workerDigest: digest('f') },
    }));
    await expect(runAliyunEsaCanaryRollout(input, implementation)).rejects.toMatchObject({
      code: 'ESA_ROLLOUT_PREPARATION_FAILED',
    });
    expect(implementation.traffic).not.toHaveBeenCalled();
    expect(implementation.deactivated).toEqual(['deployment-2']);
  });

  it('does not pass an untrusted staged deployment identity to the deactivation driver', async () => {
    const input = plan();
    const implementation = driver(input, []);
    implementation.stage = vi.fn(async () => ({
      deploymentId: 'deployment/../../baseline',
      binding: input.candidate,
    }));

    await expect(runAliyunEsaCanaryRollout(input, implementation)).rejects.toMatchObject({
      code: 'ESA_ROLLOUT_PREPARATION_FAILED',
    });
    expect(implementation.traffic).not.toHaveBeenCalled();
    expect(implementation.deactivated).toEqual([]);
  });

  it('deactivates a zero-traffic candidate if its durable staged checkpoint fails', async () => {
    const input = plan();
    const implementation = driver(input, []);
    implementation.checkpoint = vi.fn(async (value) => {
      if (value.phase === 'staged') throw new Error('checkpoint unavailable');
    });

    await expect(runAliyunEsaCanaryRollout(input, implementation)).rejects.toMatchObject({
      code: 'ESA_ROLLOUT_PREPARATION_FAILED',
    });
    expect(implementation.traffic).not.toHaveBeenCalled();
    expect(implementation.deactivated).toEqual(['deployment-2']);
  });

  it('stops without rollback when checkpoint fencing ownership is lost', async () => {
    const input = plan();
    const implementation = driver(input, [healthy(input.candidate)]);
    implementation.checkpoint = vi.fn(async (value) => {
      if (value.phase === 'canary') {
        throw new AliyunEsaRolloutExecutionLostError('checkpoint CAS rejected');
      }
      implementation.checkpoints.push(value);
    });

    await expect(runAliyunEsaCanaryRollout(input, implementation)).rejects.toMatchObject({
      code: 'ESA_ROLLOUT_EXECUTION_LOST',
    });
    expect(implementation.traffic.mock.calls.map(([value]) => value.candidatePercent))
      .toEqual([5]);
    expect(implementation.deactivated).toEqual([]);
  });

  it('rejects a resumed checkpoint when provider state cannot be reconciled', async () => {
    const input = plan();
    const implementation = driver(input, []);
    implementation.verifyCheckpoint = vi.fn(async () => false);
    const staged = resumeCheckpoint(input);

    await expect(runAliyunEsaCanaryRollout(input, implementation, {
      resumeFrom: staged,
    })).rejects.toMatchObject({ code: 'ESA_ROLLOUT_STATE_DIVERGED' });
    expect(implementation.stage).not.toHaveBeenCalled();
    expect(implementation.traffic).not.toHaveBeenCalled();
    expect(implementation.deactivated).toEqual([]);
  });

  it('raises an operator incident instead of claiming success when rollback is unhealthy', async () => {
    const input = plan();
    const implementation = driver(input, [
      { ...healthy(input.candidate), ready: false },
      { ...healthy(input.baseline.binding), billingReady: false },
    ]);
    const error = await runAliyunEsaCanaryRollout(input, implementation)
      .then(() => null, (caught: unknown) => caught);
    expect(error).toBeInstanceOf(AliyunEsaRolloutError);
    expect(error).toMatchObject({ code: 'ESA_ROLLOUT_ROLLBACK_FAILED' });
    expect((error as AliyunEsaRolloutError).checkpoints.at(-1)?.phase)
      .toBe('manual_intervention');
  });

  it('rejects mutable tags, skipped canaries, and unversioned secret bindings', async () => {
    const mutable = plan();
    mutable.candidate = { ...mutable.candidate, workerDigest: 'latest' };
    await expect(runAliyunEsaCanaryRollout(mutable, driver(mutable, []))).rejects.toMatchObject({
      code: 'ESA_ROLLOUT_CONFIGURATION_INVALID',
    });

    const skipped = plan();
    skipped.percentages = [25, 100];
    await expect(runAliyunEsaCanaryRollout(skipped, driver(skipped, []))).rejects.toThrow(
      'canary of at most 10',
    );

    const unversioned = plan();
    unversioned.candidate = { ...unversioned.candidate, secretVersionDigests: {} };
    await expect(runAliyunEsaCanaryRollout(unversioned, driver(unversioned, []))).rejects.toThrow(
      'versioned secrets',
    );
  });

  it('resumes after staging without creating a duplicate deployment', async () => {
    const input = plan();
    const implementation = driver(input, []);
    const staged = {
      version: 1 as const,
      rolloutId: input.rolloutId,
      sequence: 2,
      phase: 'staged' as const,
      candidateDeploymentId: 'deployment-2',
      baselineDeploymentId: input.baseline.deploymentId,
      candidatePercent: 0,
      candidate: input.candidate,
      baseline: input.baseline.binding,
      recordedAt: '2026-08-13T00:00:00.000Z',
      reason: null,
      health: null,
    };
    const result = await runAliyunEsaCanaryRollout(input, implementation, {
      resumeFrom: staged,
    });

    expect(result.result).toBe('promoted');
    expect(implementation.stage).not.toHaveBeenCalled();
    expect(implementation.traffic.mock.calls.map(([value]) => value.candidatePercent))
      .toEqual([5, 25, 100]);
    expect(implementation.checkpoints.map((value) => value.sequence)).toEqual([3, 4, 5, 6]);
  });

  it('replays the next idempotent traffic step after a crash', async () => {
    const input = plan();
    const implementation = driver(input, []);
    const canary = {
      version: 1 as const,
      rolloutId: input.rolloutId,
      sequence: 3,
      phase: 'canary' as const,
      candidateDeploymentId: 'deployment-2',
      baselineDeploymentId: input.baseline.deploymentId,
      candidatePercent: 5,
      candidate: input.candidate,
      baseline: input.baseline.binding,
      recordedAt: '2026-08-13T00:00:00.000Z',
      reason: null,
      health: healthy(input.candidate),
    };
    await runAliyunEsaCanaryRollout(input, implementation, { resumeFrom: canary });

    expect(implementation.traffic.mock.calls.map(([value]) => [
      value.candidatePercent, value.idempotencyKey,
    ])).toEqual([
      [25, `${input.rolloutId}:4:25`],
      [100, `${input.rolloutId}:5:100`],
    ]);
  });

  it('resumes a failed canary by rolling back instead of promoting it', async () => {
    const input = plan();
    const implementation = driver(input, [healthy(input.baseline.binding)]);
    const failedCanary = {
      version: 1 as const,
      rolloutId: input.rolloutId,
      sequence: 3,
      phase: 'canary' as const,
      candidateDeploymentId: 'deployment-2',
      baselineDeploymentId: input.baseline.deploymentId,
      candidatePercent: 5,
      candidate: input.candidate,
      baseline: input.baseline.binding,
      recordedAt: '2026-08-13T00:00:00.000Z',
      reason: 'candidate readiness failed',
      health: { ...healthy(input.candidate), ready: false },
    };
    const result = await runAliyunEsaCanaryRollout(input, implementation, {
      resumeFrom: failedCanary,
    });

    expect(result.result).toBe('rolled_back');
    expect(implementation.traffic).toHaveBeenCalledTimes(1);
    expect(implementation.traffic).toHaveBeenCalledWith(expect.objectContaining({
      candidatePercent: 0,
      idempotencyKey: `${input.rolloutId}:5:rollback`,
    }));
  });

  it('returns terminal checkpoints idempotently and rejects manual intervention resumes', async () => {
    const input = plan();
    const implementation = driver(input, []);
    const terminal = {
      version: 1 as const,
      rolloutId: input.rolloutId,
      sequence: 6,
      phase: 'stable' as const,
      candidateDeploymentId: 'deployment-2',
      baselineDeploymentId: input.baseline.deploymentId,
      candidatePercent: 100,
      candidate: input.candidate,
      baseline: input.baseline.binding,
      recordedAt: '2026-08-13T00:00:00.000Z',
      reason: null,
      health: null,
    };
    await expect(runAliyunEsaCanaryRollout(input, implementation, {
      resumeFrom: terminal,
    })).resolves.toMatchObject({ result: 'promoted' });
    expect(implementation.stage).not.toHaveBeenCalled();

    await expect(runAliyunEsaCanaryRollout(input, implementation, {
      resumeFrom: {
        ...terminal,
        phase: 'manual_intervention',
        candidatePercent: 25,
        reason: 'automatic rollback failed',
      },
    })).rejects.toMatchObject({ code: 'ESA_ROLLOUT_MANUAL_INTERVENTION_REQUIRED' });
  });

  it('rejects checkpoints from a different immutable rollout', async () => {
    const input = plan();
    const implementation = driver(input, []);
    const wrong = {
      version: 1 as const,
      rolloutId: input.rolloutId,
      sequence: 2,
      phase: 'staged' as const,
      candidateDeploymentId: 'deployment-2',
      baselineDeploymentId: input.baseline.deploymentId,
      candidatePercent: 0,
      candidate: binding('release-tampered', 'f'),
      baseline: input.baseline.binding,
      recordedAt: '2026-08-13T00:00:00.000Z',
      reason: null,
      health: null,
    };
    await expect(runAliyunEsaCanaryRollout(input, implementation, {
      resumeFrom: wrong,
    })).rejects.toMatchObject({ code: 'ESA_ROLLOUT_CONFIGURATION_INVALID' });

    await expect(runAliyunEsaCanaryRollout(input, implementation, {
      resumeFrom: { ...wrong, candidate: input.candidate, phase: 'canary', candidatePercent: 0 },
    })).rejects.toMatchObject({ code: 'ESA_ROLLOUT_CONFIGURATION_INVALID' });
  });

  it('rejects every unsafe immutable plan boundary', async () => {
    const invalidPlans: Array<(value: AliyunEsaRolloutPlan) => void> = [
      (value) => { value.rolloutId = 'ab'; },
      (value) => { value.baseline.deploymentId = '/invalid'; },
      (value) => { value.candidate = { ...value.candidate, releaseId: 'x' }; },
      (value) => { value.candidate = { ...value.candidate, policyDigest: 'sha256:bad' }; },
      (value) => { value.candidate = { ...value.candidate, keyring: { ...value.candidate.keyring, digest: 'bad' } }; },
      (value) => { value.candidate = { ...value.candidate, keyring: { ...value.candidate.keyring, revision: 0 } }; },
      (value) => { value.candidate = { ...value.candidate, keyring: { ...value.candidate.keyring, revision: 1.5 } }; },
      (value) => { value.candidate = { ...value.candidate, keyring: { ...value.candidate.keyring, activeKeyId: 'g'.repeat(16) } }; },
      (value) => { value.candidate = { ...value.candidate, secretVersionDigests: { bad: digest('a') } }; },
      (value) => { value.candidate = { ...value.candidate, secretVersionDigests: { MODEL_PROVIDER_TOKEN: 'bad' } }; },
      (value) => {
        value.candidate = {
          ...value.candidate,
          secretVersionDigests: Object.fromEntries(
            Array.from({ length: 65 }, (_, index) => [`SECRET_${index}`, digest('a')]),
          ),
        };
      },
      (value) => { value.candidate = value.baseline.binding; },
      (value) => { value.percentages = [5]; },
      (value) => { value.percentages = Array.from({ length: 11 }, (_, index) => (index + 1) * 5); },
      (value) => { value.percentages = [5, 99]; },
      (value) => { value.percentages = [11, 100]; },
      (value) => { value.percentages = [1.5, 100]; },
      (value) => { value.percentages = [0, 100]; },
      (value) => { value.percentages = [5, 101, 100]; },
      (value) => { value.percentages = [5, 5, 100]; },
      (value) => { value.healthGate = { ...value.healthGate, minimumRequests: 0 }; },
      (value) => { value.healthGate = { ...value.healthGate, minimumRequests: 10_000_001 }; },
      (value) => { value.healthGate = { ...value.healthGate, minimumRequests: 1.5 }; },
      (value) => { value.healthGate = { ...value.healthGate, maximumErrorRate: Number.NaN }; },
      (value) => { value.healthGate = { ...value.healthGate, maximumErrorRate: -0.1 }; },
      (value) => { value.healthGate = { ...value.healthGate, maximumErrorRate: 1.1 }; },
      (value) => { value.healthGate = { ...value.healthGate, maximumP95LatencyMs: 0 }; },
      (value) => { value.healthGate = { ...value.healthGate, maximumP95LatencyMs: 600_001 }; },
      (value) => { value.healthGate = { ...value.healthGate, maximumP95LatencyMs: 1.5 }; },
    ];

    for (const mutate of invalidPlans) {
      const input = plan();
      mutate(input);
      await expect(runAliyunEsaCanaryRollout(input, driver(input, []))).rejects.toMatchObject({
        code: 'ESA_ROLLOUT_CONFIGURATION_INVALID',
      });
    }
  });

  it('rejects malformed durable checkpoint state combinations', async () => {
    const input = plan();
    const invalid: AliyunEsaRolloutCheckpoint[] = [
      resumeCheckpoint(input, { version: 2 as 1 }),
      resumeCheckpoint(input, { rolloutId: 'rollout-other' }),
      resumeCheckpoint(input, { sequence: 0 }),
      resumeCheckpoint(input, { sequence: 1.5 }),
      resumeCheckpoint(input, { phase: 'unknown' as AliyunEsaRolloutCheckpoint['phase'] }),
      resumeCheckpoint(input, { baselineDeploymentId: 'deployment-other' }),
      resumeCheckpoint(input, { candidate: binding('release-other', 'f') }),
      resumeCheckpoint(input, { baseline: binding('release-other', 'f') }),
      resumeCheckpoint(input, { recordedAt: 'not-a-date' }),
      resumeCheckpoint(input, { recordedAt: '2026-08-13T00:00:00Z' }),
      resumeCheckpoint(input, { candidatePercent: 1.5 }),
      resumeCheckpoint(input, { reason: '' }),
      resumeCheckpoint(input, { phase: 'preparing', candidateDeploymentId: 'deployment-2' }),
      resumeCheckpoint(input, { phase: 'preparing', candidateDeploymentId: null, candidatePercent: 5 }),
      resumeCheckpoint(input, { candidateDeploymentId: null }),
      resumeCheckpoint(input, { candidateDeploymentId: '/bad' }),
      resumeCheckpoint(input, { phase: 'staged', candidatePercent: 5 }),
      resumeCheckpoint(input, { phase: 'rolled_back', candidatePercent: 5 }),
      resumeCheckpoint(input, { phase: 'stable', candidatePercent: 25 }),
      resumeCheckpoint(input, { phase: 'promoting', candidatePercent: 25 }),
      resumeCheckpoint(input, { phase: 'canary', candidatePercent: 100 }),
      resumeCheckpoint(input, { phase: 'canary', candidatePercent: 10 }),
      resumeCheckpoint(input, { phase: 'rollback_pending', candidatePercent: 10 }),
      resumeCheckpoint(input, { phase: 'manual_intervention', candidatePercent: 10 }),
      resumeCheckpoint(input, {
        phase: 'canary',
        candidatePercent: 5,
        reason: null,
        health: { ...healthy(input.candidate), ready: false },
      }),
      resumeCheckpoint(input, {
        phase: 'canary',
        candidatePercent: 5,
        reason: 'candidate readiness failed',
        health: healthy(input.candidate),
      }),
      resumeCheckpoint(input, {
        phase: 'canary',
        candidatePercent: 5,
        reason: null,
        health: { ...healthy(input.candidate), ready: 'yes' as unknown as boolean },
      }),
    ];

    for (const checkpoint of invalid) {
      await expect(runAliyunEsaCanaryRollout(input, driver(input, []), {
        resumeFrom: checkpoint,
      })).rejects.toMatchObject({ code: 'ESA_ROLLOUT_CONFIGURATION_INVALID' });
    }
  });

  it('fails every health dimension closed and accepts exact gate boundaries', async () => {
    const input = plan();
    const failures: AliyunEsaHealthSample[] = [
      healthy(input.baseline.binding),
      { ...healthy(input.candidate), ready: false },
      { ...healthy(input.candidate), billingReady: false },
      { ...healthy(input.candidate), requestCount: 999 },
      { ...healthy(input.candidate), requestCount: 1.5 },
      { ...healthy(input.candidate), errorRate: -0.1 },
      { ...healthy(input.candidate), errorRate: Number.NaN },
      { ...healthy(input.candidate), errorRate: 0.02 },
      { ...healthy(input.candidate), p95LatencyMs: -1 },
      { ...healthy(input.candidate), p95LatencyMs: Number.POSITIVE_INFINITY },
      { ...healthy(input.candidate), p95LatencyMs: 1_001 },
    ];
    for (const failed of failures) {
      const result = await runAliyunEsaCanaryRollout(
        input,
        driver(input, [failed, healthy(input.baseline.binding)]),
      );
      expect(result.result).toBe('rolled_back');
    }

    const exact = {
      ...healthy(input.candidate),
      requestCount: input.healthGate.minimumRequests,
      errorRate: input.healthGate.maximumErrorRate,
      p95LatencyMs: input.healthGate.maximumP95LatencyMs,
    };
    await expect(runAliyunEsaCanaryRollout(
      input,
      driver(input, [exact, exact, exact]),
    )).resolves.toMatchObject({ result: 'promoted' });
  });

  it('resumes preparing and rolled-back checkpoints without unsafe side effects', async () => {
    const input = plan();
    const preparingDriver = driver(input, []);
    await expect(runAliyunEsaCanaryRollout(input, preparingDriver, {
      resumeFrom: resumeCheckpoint(input, {
        phase: 'preparing',
        sequence: 1,
        candidateDeploymentId: null,
      }),
    })).resolves.toMatchObject({ result: 'promoted' });
    expect(preparingDriver.stage).toHaveBeenCalledOnce();

    const terminalDriver = driver(input, []);
    await expect(runAliyunEsaCanaryRollout(input, terminalDriver, {
      resumeFrom: resumeCheckpoint(input, {
        phase: 'rolled_back',
        reason: 'candidate readiness failed',
        health: healthy(input.baseline.binding),
      }),
    })).resolves.toMatchObject({ result: 'rolled_back' });
    expect(terminalDriver.stage).not.toHaveBeenCalled();
  });
});

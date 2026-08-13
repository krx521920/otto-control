import { describe, expect, it, vi } from 'vitest';

import {
  AliyunEsaRolloutError,
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
        'rollout-2026-08-13:2:5',
        'rollout-2026-08-13:3:25',
        'rollout-2026-08-13:4:100',
      ]);
    expect(implementation.checkpoints.map((value) => value.phase))
      .toEqual(['preparing', 'canary', 'canary', 'promoting', 'stable']);
    expect(implementation.deactivated).toEqual(['deployment-1']);
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
      .toEqual(['preparing', 'canary', 'rollback_pending', 'rolled_back']);
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
});

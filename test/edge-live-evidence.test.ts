import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  classifyEvidenceEnvironment,
  elapsedEvidence,
  fileEvidence,
  immutableReleaseEvidence,
} from '../scripts/edge-live-evidence.mjs';
import {
  parseEdgeAcceptanceArguments,
  runEdgeAcceptance,
} from '../scripts/edge-gateway-acceptance.mjs';

const ROOT = resolve(import.meta.dirname, '..');

function productionRunnerEnvironment(): NodeJS.ProcessEnv {
  return {
    GITHUB_ACTIONS: 'true',
    RUNNER_ENVIRONMENT: 'self-hosted',
    GITHUB_EVENT_NAME: 'workflow_dispatch',
    GITHUB_REPOSITORY: 'krx521920/otto-control',
    GITHUB_WORKFLOW: 'Edge production acceptance',
    GITHUB_RUN_ID: '123456',
    GITHUB_RUN_ATTEMPT: '1',
    GITHUB_JOB: 'soak',
    RUNNER_NAME: 'otto-edge-production-runner',
  };
}

describe('Edge live evidence', () => {
  it('never labels a local or incomplete runner as production evidence', () => {
    expect(classifyEvidenceEnvironment({}).evidenceClass).toBe('simulation');
    expect(classifyEvidenceEnvironment({
      ...productionRunnerEnvironment(),
      GITHUB_EVENT_NAME: 'push',
    }).evidenceClass).toBe('simulation');
    expect(classifyEvidenceEnvironment({
      ...productionRunnerEnvironment(),
      RUNNER_ENVIRONMENT: 'github-hosted',
    }).evidenceClass).toBe('simulation');
    expect(classifyEvidenceEnvironment(productionRunnerEnvironment()).evidenceClass)
      .toBe('production-live');
  });

  it('binds an evidence artifact to the exact checked-out commit and SHA-256', () => {
    const head = execFileSync('git', ['rev-parse', 'HEAD'], {
      cwd: ROOT,
      encoding: 'utf8',
      windowsHide: true,
    }).trim();
    const release = immutableReleaseEvidence({
      root: ROOT,
      releaseCandidate: head,
      artifactPath: 'package.json',
    });

    expect(release.gitCommit).toBe(head);
    expect(release.artifact.path).toBe('package.json');
    expect(release.artifact.bytes).toBeGreaterThan(0);
    expect(release.artifact.sha256).toMatch(/^[a-f0-9]{64}$/u);
    expect(() => immutableReleaseEvidence({
      root: ROOT,
      releaseCandidate: '0'.repeat(40),
      artifactPath: 'package.json',
    })).toThrow(/resolve|match/u);
    expect(() => immutableReleaseEvidence({
      root: ROOT,
      releaseCandidate: 'not-a-commit',
      artifactPath: 'package.json',
    })).toThrow('full lowercase 40-character');
  });

  it('does not let generated evidence escape its declared root', () => {
    const temporary = mkdtempSync(join(tmpdir(), 'otto-edge-evidence-'));
    const outside = join(temporary, 'outside.json');
    writeFileSync(outside, '{}\n');
    try {
      expect(() => fileEvidence(ROOT, outside, 'acceptance ledger'))
        .toThrow('inside the repository');
    } finally {
      rmSync(temporary, { recursive: true, force: true });
    }
  });

  it('requires positive wall-clock and monotonic timing', () => {
    expect(elapsedEvidence(1_000, 2_000, 999)).toMatchObject({
      wallClockDurationSeconds: 1,
      monotonicDurationSeconds: 0.999,
    });
    expect(() => elapsedEvidence(2_000, 1_000, 999)).toThrow('timing is invalid');
    expect(() => elapsedEvidence(1_000, 2_000, 0)).toThrow('timing is invalid');
  });

  it('rejects shortened formal profiles before any traffic is sent', () => {
    expect(() => parseEdgeAcceptanceArguments([
      '--profile=soak-24h',
      '--duration-seconds=1',
      '--plan-only=true',
    ])).toThrow('duration is fixed');
  });

  it('refuses to generate formal evidence from a local simulation', async () => {
    const head = execFileSync('git', ['rev-parse', 'HEAD'], {
      cwd: ROOT,
      encoding: 'utf8',
      windowsHide: true,
    }).trim();
    const config = parseEdgeAcceptanceArguments([
      '--profile=cost-load',
      '--base-url=https://edge.example.test',
      '--control-url=https://control.example.test',
      '--identity-file=secure/identity.json',
      '--lease-token-file=secure/lease.token',
      '--budget-usd=1',
      '--input-price-per-million-usd=1',
      '--output-price-per-million-usd=1',
      `--release-candidate=${head}`,
      '--release-artifact=package.json',
      '--plan-only=true',
    ]);

    await expect(runEdgeAcceptance(config, { environment: {} }))
      .rejects.toThrow('formal evidence must run');
  });
});

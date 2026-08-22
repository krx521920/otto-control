import { createHash } from 'node:crypto';
import { existsSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { isAbsolute, relative, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';

export const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
export const GIT_COMMIT_PATTERN = /^[a-f0-9]{40}$/u;

export function sha256Bytes(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export function sha256File(path) {
  return sha256Bytes(readFileSync(path));
}

function repositoryPath(root, path, name) {
  const rootReal = realpathSync(root);
  const candidate = resolve(rootReal, path);
  if (!existsSync(candidate)) throw new Error(`${name} does not exist`);
  const candidateReal = realpathSync(candidate);
  const result = relative(rootReal, candidateReal).replaceAll('\\', '/');
  if (!result || isAbsolute(result) || result.startsWith('../') || result === '..') {
    throw new Error(`${name} must be a file inside the repository`);
  }
  return { absolute: candidateReal, relative: result };
}

export function immutableReleaseEvidence({ root, releaseCandidate, artifactPath }) {
  if (!GIT_COMMIT_PATTERN.test(releaseCandidate ?? '')) {
    throw new Error('--release-candidate must be a full lowercase 40-character Git commit SHA');
  }
  const repositoryRoot = realpathSync(resolve(root));
  let head;
  let objectType;
  try {
    head = execFileSync('git', ['rev-parse', 'HEAD'], {
      cwd: repositoryRoot,
      encoding: 'utf8',
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    }).trim().toLowerCase();
    objectType = execFileSync('git', ['cat-file', '-t', releaseCandidate], {
      cwd: repositoryRoot,
      encoding: 'utf8',
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    }).trim();
  } catch {
    throw new Error('release candidate must resolve to a Git commit in this repository');
  }
  if (objectType !== 'commit') throw new Error('release candidate is not a Git commit');
  if (head !== releaseCandidate) {
    throw new Error('release candidate must exactly match the checked-out HEAD');
  }
  const artifact = repositoryPath(repositoryRoot, artifactPath, 'release artifact');
  const stats = statSync(artifact.absolute);
  if (!stats.isFile() || stats.size < 1) throw new Error('release artifact must be a non-empty file');
  return {
    gitCommit: releaseCandidate,
    artifact: {
      path: artifact.relative,
      sha256: sha256File(artifact.absolute),
      bytes: stats.size,
    },
  };
}

export function classifyEvidenceEnvironment(environment = process.env) {
  const runner = {
    system: environment.GITHUB_ACTIONS === 'true' ? 'github-actions' : 'local',
    environment: environment.RUNNER_ENVIRONMENT ?? 'unknown',
    event: environment.GITHUB_EVENT_NAME ?? 'unknown',
    repository: environment.GITHUB_REPOSITORY ?? 'unknown',
    workflow: environment.GITHUB_WORKFLOW ?? 'unknown',
    runId: environment.GITHUB_RUN_ID ?? 'unknown',
    runAttempt: environment.GITHUB_RUN_ATTEMPT ?? 'unknown',
    job: environment.GITHUB_JOB ?? 'unknown',
    runnerName: environment.RUNNER_NAME ?? 'unknown',
  };
  const productionLive = runner.system === 'github-actions'
    && runner.environment === 'self-hosted'
    && runner.event === 'workflow_dispatch'
    && /^[1-9][0-9]*$/u.test(runner.runId)
    && /^[1-9][0-9]*$/u.test(runner.runAttempt)
    && /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(runner.repository)
    && !['unknown', ''].includes(runner.workflow)
    && !['unknown', ''].includes(runner.job)
    && !['unknown', ''].includes(runner.runnerName);
  return {
    evidenceClass: productionLive ? 'production-live' : 'simulation',
    runner,
  };
}

export function productionProvenance({
  environment = process.env,
  generator,
  release,
}) {
  const classified = classifyEvidenceEnvironment(environment);
  return {
    schemaVersion: 1,
    evidenceClass: classified.evidenceClass,
    generator,
    releaseCandidate: release.gitCommit,
    releaseArtifact: release.artifact,
    runner: classified.runner,
  };
}

export function elapsedEvidence(startedAtMs, completedAtMs, monotonicDurationMs) {
  if (!Number.isFinite(startedAtMs) || !Number.isFinite(completedAtMs)
    || !Number.isFinite(monotonicDurationMs) || completedAtMs <= startedAtMs
    || monotonicDurationMs <= 0) {
    throw new Error('evidence timing is invalid');
  }
  return {
    startedAt: new Date(startedAtMs).toISOString(),
    completedAt: new Date(completedAtMs).toISOString(),
    wallClockDurationSeconds: (completedAtMs - startedAtMs) / 1_000,
    monotonicDurationSeconds: monotonicDurationMs / 1_000,
  };
}

export function fileEvidence(root, path, name = 'evidence file') {
  const artifact = repositoryPath(root, path, name);
  const stats = statSync(artifact.absolute);
  if (!stats.isFile() || stats.size < 1) throw new Error(`${name} must be a non-empty file`);
  return {
    path: artifact.relative,
    sha256: sha256File(artifact.absolute),
    bytes: stats.size,
  };
}

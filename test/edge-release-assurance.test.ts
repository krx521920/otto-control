import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { checkEdgeReleaseAssurance } from '../scripts/check-edge-release-assurance.mjs';

const now = Date.parse('2026-08-13T00:00:00.000Z');
let roots: string[] = [];

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'otto-edge-assurance-'));
  roots.push(root);
  await mkdir(join(root, 'evidence'));
  const auditBytes = Buffer.from('independent audit report', 'utf8');
  const dpaBytes = Buffer.from('countersigned provider DPA', 'utf8');
  const releaseArtifactBytes = Buffer.from('signed release artifact', 'utf8');
  const soakLedgerBytes = Buffer.from('{"request":1}\n', 'utf8');
  const costLedgerBytes = Buffer.from('{"request":2}\n', 'utf8');
  await writeFile(join(root, 'evidence', 'audit.pdf'), auditBytes);
  await writeFile(join(root, 'evidence', 'provider-dpa.pdf'), dpaBytes);
  await writeFile(join(root, 'evidence', 'release.bin'), releaseArtifactBytes);
  await writeFile(join(root, 'evidence', 'soak-ledger.ndjson'), soakLedgerBytes);
  await writeFile(join(root, 'evidence', 'cost-ledger.ndjson'), costLedgerBytes);
  const releaseCandidate = '1'.repeat(40);
  const formalReport = (
    profile: 'soak-24h' | 'cost-load',
    durationSeconds: number,
    ledgerName: string,
    ledgerBytes: Buffer,
  ) => ({
    version: 2,
    kind: 'otto_edge_gateway_acceptance',
    profile,
    result: 'passed',
    durationSeconds,
    timing: {
      wallClockDurationSeconds: durationSeconds,
      monotonicDurationSeconds: durationSeconds,
    },
    provenance: {
      schemaVersion: 1,
      evidenceClass: 'production-live',
      releaseCandidate,
      releaseArtifact: {
        path: 'evidence/release.bin',
        sha256: createHash('sha256').update(releaseArtifactBytes).digest('hex'),
        bytes: releaseArtifactBytes.byteLength,
      },
      runner: {
        system: 'github-actions',
        environment: 'self-hosted',
        event: 'workflow_dispatch',
        repository: 'krx521920/otto-control',
        workflow: 'Edge live acceptance',
        runId: '123',
        runAttempt: '1',
        job: 'acceptance',
        runnerName: 'controlled-runner-1',
      },
    },
    traffic: { succeeded: 1 },
    tokens: { reportedResponses: 1 },
    cost: { usageReportedFraction: 1, meteredEstimateUsd: 0.01 },
    violations: [],
    evidence: {
      ledger: {
        path: 'evidence/' + ledgerName,
        sha256: createHash('sha256').update(ledgerBytes).digest('hex'),
        bytes: ledgerBytes.byteLength,
      },
    },
  });
  const reports = {
    runtimeFailures: { drill: 'edge_runtime_failures', result: 'passed' },
    keyRevocation: { drill: 'edge_signing_key_revocation', result: 'passed' },
    billingReconciliation: { schemaVersion: 1, result: 'passed', issues: [] },
    soak24h: formalReport('soak-24h', 86_400, 'soak-ledger.ndjson', soakLedgerBytes),
    costLoad: formalReport('cost-load', 300, 'cost-ledger.ndjson', costLedgerBytes),
    esaInfrastructure: {
      kind: 'otto_aliyun_esa_infrastructure_acceptance', result: 'passed',
      publicRouteEnabled: true, publicRouteBypass: false, certificateStatus: 'issued',
      wafEnabled: true, tls10: false, tls11: false, tls12: true, tls13: true,
      secretMaterialInTerraform: false, terraformPlanSha256: 'a'.repeat(64),
    },
    esaRollout: {
      drill: 'esa_canary_rollout', result: 'promoted', startedPercent: 5,
      completedPercent: 100, rollbackDrill: 'passed', billingReady: true,
    },
    esaKeyringRevocation: {
      drill: 'esa_keyring_emergency_revocation', environment: 'preproduction',
      result: 'passed', publicKeyringVerified: true,
      nodeEvidence: [
        { oldTokenStatus: 401, replacementTokenStatus: 200 },
        { oldTokenStatus: 401, replacementTokenStatus: 204 },
      ],
    },
    multiNodeBilling: {
      kind: 'otto_edge_multi_node_billing_acceptance', result: 'passed', nodes: 2,
      activeNodes: 2, pending: 0, retrying: 0, deadLetter: 0, sequenceGaps: 0,
      reconciliationResult: 'passed',
    },
  };
  const technicalAcceptance = Object.fromEntries(await Promise.all(
    Object.entries(reports).map(async ([name, report]) => {
      const bytes = Buffer.from(JSON.stringify(report), 'utf8');
      const path = `evidence/${name}.json`;
      await writeFile(join(root, path), bytes);
      return [name, {
        status: 'passed',
        releaseCandidate,
        evidence: { path, sha256: createHash('sha256').update(bytes).digest('hex') },
        performedAt: '2026-08-03T00:00:00.000Z',
        expiresAt: '2027-08-03T00:00:00.000Z',
      }];
    }),
  ));
  return {
    root,
    status: {
      schemaVersion: 1,
      product: 'otto-edge-gateway',
      releaseCandidate,
      overallStatus: 'ready',
      externalSecurityAudit: {
        status: 'passed',
        auditor: 'Independent Security Laboratory',
        scope: [
          'authentication_and_policy',
          'provider_secret_handling',
          'network_boundary',
          'billing_integrity',
          'availability_and_abuse_resistance',
        ],
        report: {
          path: 'evidence/audit.pdf',
          sha256: createHash('sha256').update(auditBytes).digest('hex'),
        },
        openFindings: { critical: 0, high: 0, medium: 1, low: 2 },
        reviewedAt: '2026-08-01T00:00:00.000Z',
        expiresAt: '2027-08-01T00:00:00.000Z',
      },
      technicalAcceptance,
      providerDpaReviews: [{
        providerId: 'provider-cn',
        status: 'approved',
        legalReviewer: 'External Counsel',
        agreementReference: 'DPA-2026-001',
        dataResidency: 'CN-BJ',
        crossBorderTransferBasis: 'No cross-border transfer',
        modelTrainingUse: 'prohibited',
        subprocessorsReviewed: true,
        securityIncidentNoticeHours: 24,
        deletionCommitmentDays: 30,
        evidence: {
          path: 'evidence/provider-dpa.pdf',
          sha256: createHash('sha256').update(dpaBytes).digest('hex'),
        },
        reviewedAt: '2026-08-02T00:00:00.000Z',
        expiresAt: '2027-08-02T00:00:00.000Z',
      }],
    },
  };
}

afterEach(async () => {
  const { rm } = await import('node:fs/promises');
  await Promise.all(roots.map((root) => rm(root, { recursive: true, force: true })));
  roots = [];
});

describe('Edge Gateway external assurance release gate', () => {
  it('passes only with current, checksummed independent audit and DPA evidence', async () => {
    const { root, status } = await fixture();
    expect(checkEdgeReleaseAssurance(status, { root, now: () => now })).toMatchObject({
      result: 'passed',
      blockers: [],
    });
  });

  it('rejects a hand-written acceptance summary without production provenance and ledgers', async () => {
    const { root, status } = await fixture();
    const fake = Buffer.from(JSON.stringify({
      kind: 'otto_edge_gateway_acceptance',
      profile: 'soak-24h',
      result: 'passed',
      durationSeconds: 86_400,
    }));
    await writeFile(join(root, 'evidence', 'soak24h.json'), fake);
    status.technicalAcceptance.soak24h.evidence.sha256 = createHash('sha256')
      .update(fake).digest('hex');

    const report = checkEdgeReleaseAssurance(status, { root, now: () => now });

    expect(report.result).toBe('blocked');
    expect(report.blockers).toContain(
      'technical acceptance soak24h report does not prove the required result',
    );
  });

  it('does not treat declarations without real evidence as approval', async () => {
    const { root, status } = await fixture();
    status.externalSecurityAudit.report.sha256 = '0'.repeat(64);
    status.providerDpaReviews[0]!.modelTrainingUse = 'allowed';
    status.providerDpaReviews[0]!.subprocessorsReviewed = false;
    const report = checkEdgeReleaseAssurance(status, { root, now: () => now });
    expect(report.result).toBe('blocked');
    expect(report.blockers).toContain('external security audit evidence checksum does not match');
    expect(report.blockers).toContain('DPA provider-cn does not prohibit provider model training use');
    expect(report.blockers).toContain('DPA provider-cn subprocessors were not reviewed');
  });

  it('blocks absent or release-mismatched real-environment acceptance evidence', async () => {
    const { root, status } = await fixture();
    status.technicalAcceptance.soak24h.status = 'pending';
    status.technicalAcceptance.costLoad.releaseCandidate = 'sha256:different';
    const report = checkEdgeReleaseAssurance(status, { root, now: () => now });
    expect(report.blockers).toEqual(expect.arrayContaining([
      'technical acceptance soak24h has not passed',
      'technical acceptance costLoad is not bound to the release candidate',
    ]));
  });

  it('blocks open severe findings, missing audit scope, expiry, and weak DPA commitments', async () => {
    const { root, status } = await fixture();
    status.externalSecurityAudit.openFindings.high = 1;
    status.externalSecurityAudit.scope.pop();
    status.providerDpaReviews[0]!.securityIncidentNoticeHours = 96;
    status.providerDpaReviews[0]!.deletionCommitmentDays = 120;
    status.providerDpaReviews[0]!.expiresAt = '2026-08-12T00:00:00.000Z';
    const report = checkEdgeReleaseAssurance(status, { root, now: () => now });
    expect(report.result).toBe('blocked');
    expect(report.blockers).toEqual(expect.arrayContaining([
      'external audit scope is missing availability_and_abuse_resistance',
      'external audit has unresolved critical or high findings',
      'DPA provider-cn incident notice exceeds 72 hours',
      'DPA provider-cn deletion commitment exceeds 90 days',
      'DPA provider-cn approval is expired',
    ]));
  });

  it('blocks placeholders and path escape attempts', async () => {
    const { root, status } = await fixture();
    status.releaseCandidate = 'UNSET';
    status.providerDpaReviews[0]!.providerId = 'CONFIGURE_PROVIDER';
    status.externalSecurityAudit.report.path = '../outside.pdf';
    const report = checkEdgeReleaseAssurance(status, { root, now: () => now });
    expect(report.result).toBe('blocked');
    expect(report.blockers).toEqual(expect.arrayContaining([
      'releaseCandidate is a placeholder',
      'DPA CONFIGURE_PROVIDER uses a placeholder provider',
    ]));
    expect(report.blockers.some((entry) => entry.includes('escapes the repository'))).toBe(true);
  });
});

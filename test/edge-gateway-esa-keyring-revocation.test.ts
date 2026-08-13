import { describe, expect, it } from 'vitest';

import { runEsaKeyringRevocationAcceptance } from '../scripts/drill-esa-keyring-revocation.mjs';
import type { EdgeScenarioResult } from '../scripts/drill-edge-runtime-failures.mjs';

function scenario(status: number, code: string | null = null): EdgeScenarioResult {
  return { scenario: 'success', status, code, durationMs: 20, bodyTerminated: false };
}

function input() {
  return {
    controlUrl: new URL('https://control.pre.example.test'),
    nodeUrls: [
      new URL('https://node-a.pre.example.test'),
      new URL('https://node-b.pre.example.test'),
    ],
    identity: {
      licenseId: 'lic_pre',
      deploymentId: 'deployment_pre',
      organizationId: 'organization_pre',
      machineFingerprint: 'a'.repeat(64),
    },
    leaseToken: 'lease-token-that-is-at-least-thirty-two-characters',
    requesterToken: 'requester-token-that-is-at-least-thirty-two-characters',
    approverToken: 'approver-token-that-is-at-least-thirty-two-characters',
    auditorToken: 'auditor-token-that-is-at-least-thirty-two-characters',
    subjectId: 'esa_acceptance',
    model: 'otto-acceptance',
    keyId: 'aaaaaaaaaaaaaaaa',
    replacementKeyId: 'bbbbbbbbbbbbbbbb',
    reason: 'preproduction incident simulation',
    changeTicket: 'SEC-2026-0813',
    requestTimeoutMs: 90_000,
    refreshTimeoutMs: 300_000,
    pollIntervalMs: 1_000,
  };
}

describe('ESA keyring emergency revocation acceptance', () => {
  it('proves revocation convergence and replacement-key recovery on every node', async () => {
    let now = 1_786_633_200_000;
    const tokens = ['old-token', 'new-token'];
    const calls = new Map<string, number>();
    const report = await runEsaKeyringRevocationAcceptance(input(), {
      now: () => now,
      sleep: async (milliseconds) => { now += milliseconds; },
      issueToken: async () => tokens.shift() ?? 'unexpected-token',
      scenario: async (node, token) => {
        const key = `${node.hostname}:${token}`;
        calls.set(key, (calls.get(key) ?? 0) + 1);
        if (token === 'old-token' && calls.get(key) === 1) return scenario(200);
        if (token === 'old-token') return scenario(401, 'EDGE_UNAUTHORIZED');
        return scenario(200);
      },
      revoke: async () => ({
        version: 1,
        drill: 'signing_key_emergency_revocation',
        startedAt: new Date(now).toISOString(),
        completedAt: new Date(now).toISOString(),
        result: 'passed',
        revokedKeyId: 'aaaaaaaaaaaaaaaa',
        activeKeyId: 'bbbbbbbbbbbbbbbb',
        approvalId: 'approval-pre',
        reason: 'preproduction incident simulation',
        publicKeyringVerified: true,
        auditEvidence: null,
      }),
    });

    expect(report).toMatchObject({
      result: 'passed',
      environment: 'preproduction',
      changeTicket: 'SEC-2026-0813',
      revokedKeyId: 'aaaaaaaaaaaaaaaa',
      activeKeyId: 'bbbbbbbbbbbbbbbb',
      publicKeyringVerified: true,
      nodeEvidence: [
        { oldTokenStatus: 401, replacementTokenStatus: 200 },
        { oldTokenStatus: 401, replacementTokenStatus: 200 },
      ],
    });
    expect(JSON.stringify(report)).not.toContain('old-token');
    expect(JSON.stringify(report)).not.toContain('new-token');
    expect(JSON.stringify(report)).not.toContain('node-a.pre.example.test');
  });

  it('fails closed when the node inventory is not independently distributed', async () => {
    const value = input();
    value.nodeUrls = [value.nodeUrls[0]!, value.nodeUrls[0]!];
    await expect(runEsaKeyringRevocationAcceptance(value, {})).rejects.toThrow(
      'must be distinct',
    );
  });

  it('never reports success before every node rejects the revoked key', async () => {
    let now = 1_786_633_200_000;
    let call = 0;
    await expect(runEsaKeyringRevocationAcceptance(
      { ...input(), refreshTimeoutMs: 500, pollIntervalMs: 500 },
      {
        now: () => now,
        sleep: async (milliseconds) => { now += milliseconds; },
        issueToken: async () => 'old-token',
        scenario: async () => {
          call += 1;
          return call <= 2 ? scenario(200) : scenario(401, 'EDGE_UNAUTHORIZED');
        },
        revoke: async () => ({
          version: 1,
          drill: 'signing_key_emergency_revocation',
          startedAt: new Date(now).toISOString(),
          completedAt: new Date(now).toISOString(),
          result: 'passed',
          revokedKeyId: 'aaaaaaaaaaaaaaaa',
          activeKeyId: 'bbbbbbbbbbbbbbbb',
          approvalId: 'approval-pre',
          reason: 'test',
          publicKeyringVerified: true,
          auditEvidence: null,
        }),
      },
    )).rejects.toThrow('was not observed on every ESA preproduction node');
  });
});

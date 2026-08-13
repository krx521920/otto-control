import { describe, expect, it } from 'vitest';

import {
  assertEdgeScenario,
  runEdgeRuntimeFailureAcceptance,
  type EdgeRuntimeFailureInput,
  type EdgeRuntimeScenario,
  type EdgeScenarioResult,
} from '../scripts/drill-edge-runtime-failures.mjs';
import { runEdgeKeyRevocationAcceptance } from '../scripts/drill-edge-key-revocation.mjs';
import { edgeFaultScenario } from '../scripts/edge-fault-provider.mjs';

function result(
  scenario: EdgeRuntimeScenario,
  status: number,
  code: string | null = null,
  bodyTerminated = false,
): EdgeScenarioResult {
  return { scenario, status, code, durationMs: 10, bodyTerminated };
}

function runtimeInput(): EdgeRuntimeFailureInput {
  return {
    gatewayUrl: new URL('https://edge.example.test'),
    controlUrl: new URL('https://control.example.test'),
    identity: {
      licenseId: 'lic_test',
      deploymentId: 'deployment_test',
      organizationId: 'organization_test',
      machineFingerprint: 'a'.repeat(64),
    },
    leaseToken: 'lease-token-that-is-at-least-thirty-two-characters',
    subjectId: 'edge_acceptance',
    model: 'otto-acceptance',
    workingDirectory: '/workspace',
    composeFile: '/workspace/compose.production.yaml',
    environmentFile: '/workspace/.env.production',
    projectName: 'otto-control',
    redisService: 'edge-redis',
    gatewayService: 'edge-gateway',
    controlServices: ['control-a', 'control-b', 'control-c'],
    requestTimeoutMs: 10_000,
    providerRequestTimeoutMs: 90_000,
    failureDetectionTimeoutMs: 60_000,
    recoveryTimeoutMs: 300_000,
    policyExpiryTimeoutMs: 1_020_000,
    pollIntervalMs: 1_000,
  };
}

describe('Edge Gateway failure acceptance tooling', () => {
  it('recognizes only explicit fault-provider markers', () => {
    expect(edgeFaultScenario({ messages: [{ content: 'OTTO_EDGE_ACCEPTANCE:timeout' }] }))
      .toBe('timeout');
    expect(edgeFaultScenario({ input: 'OTTO_EDGE_ACCEPTANCE:slow_stream' }))
      .toBe('slow_stream');
    expect(edgeFaultScenario({ input: 'please timeout' })).toBeNull();
  });

  it('enforces the expected timeout, slow-stream, rate-limit, and 5xx outcomes', () => {
    expect(() => assertEdgeScenario(result('success', 200))).not.toThrow();
    expect(() => assertEdgeScenario(result('timeout', 502, 'EDGE_UPSTREAM_UNAVAILABLE')))
      .not.toThrow();
    expect(() => assertEdgeScenario(result('slow_stream', 200, null, true))).not.toThrow();
    expect(() => assertEdgeScenario(result('429', 429))).not.toThrow();
    expect(() => assertEdgeScenario(result('500', 500))).not.toThrow();
    expect(() => assertEdgeScenario(result('503', 502, 'EDGE_UPSTREAM_UNAVAILABLE')))
      .not.toThrow();
    expect(() => assertEdgeScenario(result('slow_stream', 200))).toThrow(
      'slow provider stream was not terminated',
    );
  });

  it('restores Redis and Control after proving failure detection and policy expiry', async () => {
    const composeCalls: Array<{ action: string; services: string[] }> = [];
    const readiness = [200, 503, 200, 200, 200, 503, 200];
    const scenarioCalls: EdgeRuntimeScenario[] = [];
    let now = 1_700_000_000_000;
    let successCount = 0;
    const report = await runEdgeRuntimeFailureAcceptance(runtimeInput(), {
      now: () => now,
      sleep: async (milliseconds) => { now += milliseconds; },
      compose: (action, services) => { composeCalls.push({ action, services }); },
      readiness: async () => readiness.shift() ?? 200,
      issueToken: async () => 'signed-edge-token',
      scenario: async (_token, scenario) => {
        scenarioCalls.push(scenario);
        if (scenario === 'success') {
          successCount += 1;
          if (successCount === 2) return result('success', 503, 'EDGE_RATE_LIMIT_UNAVAILABLE');
          return result('success', 200);
        }
        if (scenario === 'slow_stream') return result(scenario, 200, null, true);
        if (scenario === 'timeout') return result(scenario, 502, 'EDGE_UPSTREAM_UNAVAILABLE');
        if (scenario === '503') return result(scenario, 503);
        return result(scenario, Number(scenario));
      },
    });

    expect(report).toMatchObject({ result: 'passed', drill: 'edge_runtime_failures' });
    expect(composeCalls).toEqual([
      { action: 'stop', services: ['edge-redis'] },
      { action: 'start', services: ['edge-redis'] },
      { action: 'restart', services: ['edge-gateway'] },
      { action: 'stop', services: ['control-a', 'control-b', 'control-c'] },
      { action: 'start', services: ['control-a', 'control-b', 'control-c'] },
    ]);
    expect(scenarioCalls).toEqual([
      'success', 'success', 'success', '429', '500', '503', 'slow_stream', 'timeout',
    ]);
  });

  it('proves an old token is rejected and a replacement-key token is accepted', async () => {
    let now = 1_700_000_000_000;
    const issued = ['old-token', 'new-token'];
    let oldTokenCalls = 0;
    const report = await runEdgeKeyRevocationAcceptance({
      ...runtimeInput(),
      requesterToken: 'requester-token-that-is-at-least-thirty-two-characters',
      approverToken: 'approver-token-that-is-at-least-thirty-two-characters',
      auditorToken: 'auditor-token-that-is-at-least-thirty-two-characters',
      keyId: 'aaaaaaaaaaaaaaaa',
      replacementKeyId: 'bbbbbbbbbbbbbbbb',
      reason: 'acceptance drill',
      refreshTimeoutMs: 300_000,
    }, {
      now: () => now,
      sleep: async (milliseconds) => { now += milliseconds; },
      issueToken: async () => issued.shift() ?? 'unexpected-token',
      scenario: async (token) => {
        if (token === 'old-token') {
          oldTokenCalls += 1;
          return oldTokenCalls === 1
            ? result('success', 200)
            : result('success', 401, 'EDGE_UNAUTHORIZED');
        }
        return result('success', 200);
      },
      readiness: async () => 200,
      revoke: async () => ({
        version: 1,
        drill: 'signing_key_emergency_revocation',
        startedAt: new Date(now).toISOString(),
        completedAt: new Date(now).toISOString(),
        result: 'passed',
        revokedKeyId: 'aaaaaaaaaaaaaaaa',
        activeKeyId: 'bbbbbbbbbbbbbbbb',
        approvalId: 'approval_acceptance',
        reason: 'acceptance drill',
        publicKeyringVerified: true,
        auditEvidence: null,
      }),
      restartGateway: async () => undefined,
    });

    expect(report).toMatchObject({
      result: 'passed',
      revokedKeyId: 'aaaaaaaaaaaaaaaa',
      activeKeyId: 'bbbbbbbbbbbbbbbb',
      oldTokenRejected: { status: 401, code: 'EDGE_UNAUTHORIZED' },
      replacementTokenAccepted: { status: 200 },
    });
  });
});

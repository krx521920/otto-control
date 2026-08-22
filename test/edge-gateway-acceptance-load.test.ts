import { createServer } from 'node:http';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import {
  EDGE_ACCEPTANCE_CONFIRMATION,
  parseEdgeAcceptanceArguments,
  runEdgeAcceptance,
} from '../scripts/edge-gateway-acceptance.mjs';

const directories: string[] = [];

afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

async function fixture() {
  const requests: unknown[] = [];
  const server = createServer((request, response) => {
    if (request.url === '/readyz') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end('{"status":"ready"}');
      return;
    }
    if (request.url === '/v1/operations/status') {
      response.writeHead(request.headers.authorization === 'Bearer operations-test-token' ? 200 : 401, {
        'content-type': 'application/json',
      });
      response.end(JSON.stringify({ service: 'otto-edge-gateway', concurrency: { globalLimit: 100 } }));
      return;
    }
    let body = '';
    request.on('data', (chunk) => { body += chunk; });
    request.on('end', () => {
      requests.push(JSON.parse(body));
      response.writeHead(200, {
        'content-type': 'application/json',
        'x-otto-edge-request-id': `edge-${requests.length}`,
        'x-upstream-request-id': `provider-${requests.length}`,
      });
      response.end(JSON.stringify({
        choices: [{ message: { content: 'OTTO_EDGE_OK' } }],
        usage: { prompt_tokens: 10, completion_tokens: 5 },
      }));
    });
  });
  await new Promise<void>((resolvePromise) => server.listen(0, '127.0.0.1', resolvePromise));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('test server did not bind');
  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    requests,
    close: () => new Promise<void>((resolvePromise, reject) => server.close((error) => error ? reject(error) : resolvePromise())),
  };
}

describe('Edge Gateway long-running and cost acceptance tool', () => {
  it('defines a real 24-hour soak profile and refuses unbudgeted paid profiles', () => {
    expect(() => parseEdgeAcceptanceArguments(['--profile=soak-24h', '--plan-only']))
      .toThrow('requires --budget-usd');
    const config = parseEdgeAcceptanceArguments([
      '--profile=soak-24h',
      '--budget-usd=20',
      '--input-price-per-million-usd=1',
      '--output-price-per-million-usd=2',
      '--control-url=https://control.acceptance.example.com',
      '--identity-file=secure/deployment-identity.json',
      '--lease-token-file=secure/lease-token',
      '--release-candidate=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      '--release-artifact=dist/otto-control.tar.gz',
      '--plan-only',
    ]);
    expect(config.durationSeconds).toBe(86_400);
    expect(config.maxRequests).toBe(Number.POSITIVE_INFINITY);
    expect(config.concurrency).toBeGreaterThan(1);
  });

  it('runs a bounded CI smoke and emits traffic, capacity, cost, resource, and ledger evidence', async () => {
    const mock = await fixture();
    const output = await mkdtemp(join(tmpdir(), 'otto-edge-acceptance-'));
    directories.push(output);
    try {
      const config = parseEdgeAcceptanceArguments([
        '--base-url', mock.baseUrl,
        '--duration-seconds=0.25',
        '--max-requests=8',
        '--concurrency=4',
        '--rps=100',
        '--sample-interval-ms=100',
        '--input-price-per-million-usd=2',
        '--output-price-per-million-usd=4',
        '--budget-usd=1',
        '--output', output,
        `--confirm=${EDGE_ACCEPTANCE_CONFIRMATION}`,
      ], {
        OTTO_EDGE_ACCEPTANCE_TOKEN: 'signed-edge-access-token',
        OTTO_EDGE_OPERATIONS_TOKEN: 'operations-test-token',
      });
      const report = await runEdgeAcceptance(config);
      expect(report.result).toBe('passed');
      expect(report.traffic).toMatchObject({ completed: 8, succeeded: 8, failed: 0 });
      expect(report.latency.p99Ms).toBeGreaterThan(0);
      expect(report.tokens).toMatchObject({ input: 80, output: 40, total: 120 });
      expect(report.cost.meteredEstimateUsd).toBeCloseTo(0.00032);
      expect(report.capacity.recommendedCeilingWithThirtyPercentHeadroom).toBeGreaterThan(0);
      expect(report.capacity.operationsStart).toMatchObject({ status: 200 });
      expect(report.resources.peakRssBytes).toBeGreaterThan(0);
      const ledger = await readFile(report.evidence.ledgerFile, 'utf8');
      expect(ledger.trim().split('\n')).toHaveLength(8);
      expect(ledger).not.toContain('signed-edge-access-token');
      expect(mock.requests).toHaveLength(8);
    } finally {
      await mock.close();
    }
  });

  it('caps launched requests at the worst-case token reservation budget', async () => {
    const mock = await fixture();
    const output = await mkdtemp(join(tmpdir(), 'otto-edge-budget-'));
    directories.push(output);
    try {
      const config = parseEdgeAcceptanceArguments([
        '--base-url', mock.baseUrl,
        '--duration-seconds=1',
        '--max-requests=100',
        '--concurrency=10',
        '--rps=100',
        '--estimated-input-tokens=1000',
        '--max-output-tokens=1000',
        '--input-price-per-million-usd=1',
        '--output-price-per-million-usd=1',
        '--budget-usd=0.005',
        '--output', output,
        `--confirm=${EDGE_ACCEPTANCE_CONFIRMATION}`,
      ], { OTTO_EDGE_ACCEPTANCE_TOKEN: 'signed-edge-access-token' });
      const report = await runEdgeAcceptance(config);
      expect(report.traffic.launched).toBe(2);
      expect(report.cost.reservedWorstCaseUsd).toBe(0.004);
      expect(report.cost.reservedWorstCaseUsd).toBeLessThanOrEqual(0.005);
    } finally {
      await mock.close();
    }
  });

  it('renews short-lived Control tokens without recording either credential', async () => {
    const mock = await fixture();
    const output = await mkdtemp(join(tmpdir(), 'otto-edge-renewal-'));
    const secure = await mkdtemp(join(tmpdir(), 'otto-edge-renewal-secrets-'));
    directories.push(output, secure);
    await import('node:fs/promises').then(({ writeFile }) => Promise.all([
      writeFile(join(secure, 'identity.json'), JSON.stringify({
        licenseId: 'license_test', deploymentId: 'deployment_test',
        organizationId: 'organization_test', machineFingerprint: 'a'.repeat(64),
      })),
      writeFile(join(secure, 'lease-token'), 'l'.repeat(48)),
    ]));
    let now = 1_000_000;
    let issued = 0;
    const config = parseEdgeAcceptanceArguments([
      '--base-url', mock.baseUrl,
      '--control-url=https://control.acceptance.example.com',
      `--identity-file=${join(secure, 'identity.json')}`,
      `--lease-token-file=${join(secure, 'lease-token')}`,
      '--duration-seconds=0.25', '--max-requests=3', '--concurrency=1', '--rps=100',
      '--token-refresh-before-ms=5000', '--output', output,
      `--confirm=${EDGE_ACCEPTANCE_CONFIRMATION}`,
    ]);
    try {
      const report = await runEdgeAcceptance(config, {
        now: () => { now += 2_000; return now; },
        issueCredential: async () => {
          issued += 1;
          return { encodedToken: `short-lived-token-${issued}`, expiresAtMs: now + 8_000 };
        },
      });
      expect(report.result).toBe('passed');
      expect(issued).toBe(3);
      const ledger = await readFile(report.evidence.ledgerFile, 'utf8');
      expect(ledger).not.toContain('short-lived-token');
      expect(ledger).not.toContain('l'.repeat(48));
    } finally {
      await mock.close();
    }
  });
});

import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

function argumentsMap(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 1) {
    const entry = argv[index];
    if (!entry?.startsWith('--')) throw new Error(`unexpected argument: ${entry}`);
    const [name, inlineValue] = entry.slice(2).split('=', 2);
    const value = inlineValue ?? argv[index + 1];
    if (!name || !value || value.startsWith('--')) throw new Error(`--${name} requires a value`);
    values.set(name, value);
    if (inlineValue === undefined) index += 1;
  }
  return values;
}

function required(values, name) {
  const value = values.get(name)?.trim();
  if (!value) throw new Error(`--${name} is required`);
  return value;
}

function controlOrigin(value) {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.pathname !== '/'
    || url.username || url.password || url.search || url.hash) {
    throw new Error('--control-url must be an HTTPS origin without credentials, query, or fragment');
  }
  return url;
}

async function request(origin, path, token, init = {}) {
  const response = await fetch(new URL(path, origin), {
    ...init,
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      ...init.headers,
    },
    redirect: 'error',
    signal: AbortSignal.timeout(30_000),
  });
  const text = await response.text();
  const body = text ? JSON.parse(text) : {};
  if (!response.ok) {
    throw new Error(`Control HTTP ${response.status}: ${body?.error?.message || 'request failed'}`);
  }
  return body;
}

export async function runAuditWormDrill(input) {
  const startedAt = new Date().toISOString();
  let recovered = { processed: 0, restored: 0, replayed: 0 };
  if (input.recover) {
    let continuationToken = null;
    do {
      const page = await request(
        input.controlUrl,
        '/v1/admin/audit-witness/worm/recover',
        input.token,
        {
          method: 'POST',
          body: JSON.stringify({ continuationToken, limit: input.limit }),
        },
      );
      recovered = {
        processed: recovered.processed + Number(page.processed || 0),
        restored: recovered.restored + Number(page.restored || 0),
        replayed: recovered.replayed + Number(page.replayed || 0),
      };
      continuationToken = page.continuationToken || null;
    } while (continuationToken);
  }
  await request(input.controlUrl, '/v1/admin/audit-witness/worm/poll', input.token, {
    method: 'POST', body: '{}',
  });
  const status = await request(
    input.controlUrl,
    `/v1/admin/audit-witness/worm/status?limit=${input.sampleSize}`,
    input.token,
  );
  if (!status.enabled || !status.healthy || Number(status.failed) > 0) {
    throw new Error('audit WORM evidence status is disabled or unhealthy');
  }
  const samples = (status.evidence ?? [])
    .filter((item) => item.status === 'stored')
    .slice(0, input.sampleSize);
  for (const item of samples) {
    await request(
      input.controlUrl,
      `/v1/admin/audit-witness/worm/${encodeURIComponent(item.receiptId)}/verify`,
      input.token,
      { method: 'POST', body: '{}' },
    );
  }
  return {
    version: 1,
    drill: 'audit_witness_worm',
    startedAt,
    completedAt: new Date().toISOString(),
    result: 'passed',
    recovered,
    verifiedSamples: samples.map((item) => item.receiptId),
    status: {
      pending: status.pending,
      retrying: status.retrying,
      storing: status.storing,
      stored: status.stored,
      failed: status.failed,
      latestVerifiedAt: status.latestVerifiedAt,
    },
  };
}

async function main() {
  const values = argumentsMap(process.argv.slice(2));
  if (required(values, 'confirm') !== 'VERIFY_OTTO_AUDIT_WORM') {
    throw new Error('--confirm=VERIFY_OTTO_AUDIT_WORM is required');
  }
  const token = readFileSync(resolve(required(values, 'token-file')), 'utf8').trim();
  if (token.length < 32) throw new Error('administrator session token file is invalid');
  const limit = Number(values.get('limit') ?? '500');
  const sampleSize = Number(values.get('sample-size') ?? '10');
  if (!Number.isInteger(limit) || limit < 1 || limit > 1_000) {
    throw new Error('--limit must be between 1 and 1000');
  }
  if (!Number.isInteger(sampleSize) || sampleSize < 1 || sampleSize > 100) {
    throw new Error('--sample-size must be between 1 and 100');
  }
  const report = await runAuditWormDrill({
    controlUrl: controlOrigin(required(values, 'control-url')),
    token,
    recover: values.get('recover') === 'true',
    limit,
    sampleSize,
  });
  const output = resolve(required(values, 'output'));
  writeFileSync(output, `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  process.stdout.write(`Audit WORM drill passed; report written to ${output}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}

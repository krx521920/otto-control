import { createHash, createHmac } from 'node:crypto';
import {
  chmodSync,
  createReadStream,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { request as httpsRequest } from 'node:https';
import { basename, dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const EMPTY_SHA256 = createHash('sha256').update('').digest('hex');
const BUCKET_PATTERN = /^(?!\d+\.\d+\.\d+\.\d+$)[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/u;
const REGION_PATTERN = /^[a-z0-9][a-z0-9-]{0,62}$/u;

function option(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function parseBoolean(value, name) {
  const normalized = String(value ?? '').trim().toLowerCase();
  if (!normalized) return false;
  if (normalized === 'true') return true;
  if (normalized === 'false') return false;
  throw new Error(`${name} must be true or false`);
}

function parsePositiveInteger(value, fallback, name, maximum) {
  const normalized = String(value ?? '').trim();
  if (!normalized) return fallback;
  const parsed = Number(normalized);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > maximum) {
    throw new Error(`${name} must be an integer between 1 and ${maximum}`);
  }
  return parsed;
}

function parseEnvironmentFile(path) {
  const values = {};
  for (const rawLine of readFileSync(path, 'utf8').split(/\r?\n/u)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const separator = line.indexOf('=');
    if (separator <= 0) continue;
    const key = line.slice(0, separator).trim();
    let value = line.slice(separator + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"'))
      || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    values[key] = value;
  }
  return values;
}

function readSecret(path, baseDirectory, name) {
  if (!path) throw new Error(`${name} file is required`);
  const absolutePath = resolve(baseDirectory, path);
  const metadata = statSync(absolutePath);
  if (!metadata.isFile()) throw new Error(`${name} must point to a regular file`);
  if (process.platform !== 'win32' && (metadata.mode & 0o077) !== 0) {
    throw new Error(`${name} file must not be readable by group or other users`);
  }
  const value = readFileSync(absolutePath, 'utf8').trim();
  if (!value) throw new Error(`${name} file is empty`);
  return value;
}

function normalizePrefix(value) {
  const prefix = String(value || 'otto-control').trim().replace(/^\/+|\/+$/gu, '');
  const segments = prefix.split('/');
  if (!prefix || prefix.length > 512 || segments.some((segment) => (
    !segment || segment === '.' || segment === '..' || /[\u0000-\u001f\u007f]/u.test(segment)
  ))) {
    throw new Error('CONTROL_BACKUP_S3_PREFIX is invalid');
  }
  return prefix;
}

export function loadBackupConfig({ envFile, environment = process.env }) {
  const fileValues = parseEnvironmentFile(envFile);
  const values = { ...fileValues, ...environment };
  const required = parseBoolean(
    values.CONTROL_BACKUP_OFFSITE_REQUIRED,
    'CONTROL_BACKUP_OFFSITE_REQUIRED',
  );
  const endpointValue = String(values.CONTROL_BACKUP_S3_ENDPOINT || '').trim();
  if (!endpointValue) {
    if (required) throw new Error('off-site backup is required but S3 endpoint is not configured');
    return { enabled: false, required };
  }
  const endpoint = new URL(endpointValue);
  if (endpoint.protocol !== 'https:' || endpoint.username || endpoint.password
    || endpoint.search || endpoint.hash || endpoint.pathname !== '/') {
    throw new Error('CONTROL_BACKUP_S3_ENDPOINT must be an HTTPS origin');
  }
  const bucket = String(values.CONTROL_BACKUP_S3_BUCKET || '').trim();
  if (!BUCKET_PATTERN.test(bucket) || bucket.includes('..')) {
    throw new Error('CONTROL_BACKUP_S3_BUCKET is invalid');
  }
  const region = String(values.CONTROL_BACKUP_S3_REGION || 'us-east-1').trim();
  if (!REGION_PATTERN.test(region)) throw new Error('CONTROL_BACKUP_S3_REGION is invalid');
  const addressingStyle = String(values.CONTROL_BACKUP_S3_ADDRESSING_STYLE || 'path').trim();
  if (addressingStyle !== 'path' && addressingStyle !== 'virtual') {
    throw new Error('CONTROL_BACKUP_S3_ADDRESSING_STYLE must be path or virtual');
  }
  const baseDirectory = dirname(resolve(envFile));
  const accessKeyId = readSecret(
    values.CONTROL_BACKUP_S3_ACCESS_KEY_ID_FILE,
    baseDirectory,
    'S3 access key ID',
  );
  const secretAccessKey = readSecret(
    values.CONTROL_BACKUP_S3_SECRET_ACCESS_KEY_FILE,
    baseDirectory,
    'S3 secret access key',
  );
  const sessionToken = values.CONTROL_BACKUP_S3_SESSION_TOKEN_FILE
    ? readSecret(
      values.CONTROL_BACKUP_S3_SESSION_TOKEN_FILE,
      baseDirectory,
      'S3 session token',
    )
    : null;
  if (accessKeyId.length < 3 || accessKeyId.length > 128) {
    throw new Error('S3 access key ID length is invalid');
  }
  if (secretAccessKey.length < 8 || secretAccessKey.length > 256) {
    throw new Error('S3 secret access key length is invalid');
  }
  return {
    enabled: true,
    required,
    endpoint,
    bucket,
    region,
    prefix: normalizePrefix(values.CONTROL_BACKUP_S3_PREFIX),
    addressingStyle,
    accessKeyId,
    secretAccessKey,
    sessionToken,
    maxAttempts: parsePositiveInteger(
      values.CONTROL_BACKUP_S3_MAX_ATTEMPTS,
      4,
      'CONTROL_BACKUP_S3_MAX_ATTEMPTS',
      10,
    ),
    requestTimeoutMs: parsePositiveInteger(
      values.CONTROL_BACKUP_S3_TIMEOUT_MS,
      120_000,
      'CONTROL_BACKUP_S3_TIMEOUT_MS',
      900_000,
    ),
  };
}

function rfc3986(value) {
  return encodeURIComponent(value).replace(/[!'()*]/gu, (character) => (
    `%${character.charCodeAt(0).toString(16).toUpperCase()}`
  ));
}

export function objectUrl(config, key) {
  const url = new URL(config.endpoint);
  const encodedKey = key.split('/').map(rfc3986).join('/');
  if (config.addressingStyle === 'virtual') {
    url.hostname = `${config.bucket}.${url.hostname}`;
    url.pathname = `/${encodedKey}`;
  } else {
    url.pathname = `/${rfc3986(config.bucket)}/${encodedKey}`;
  }
  return url;
}

function hmac(key, value, encoding) {
  return createHmac('sha256', key).update(value, 'utf8').digest(encoding);
}

function amzDate(value) {
  return value.toISOString().replace(/[:-]|\.\d{3}/gu, '');
}

function normalizeHeaderValue(value) {
  return String(value).trim().replace(/\s+/gu, ' ');
}

export function signS3Request(config, { method, url, payloadHash, headers = {}, now = new Date() }) {
  const timestamp = amzDate(now);
  const date = timestamp.slice(0, 8);
  const signed = {
    ...headers,
    host: url.host,
    'x-amz-content-sha256': payloadHash,
    'x-amz-date': timestamp,
  };
  if (config.sessionToken) signed['x-amz-security-token'] = config.sessionToken;
  const entries = Object.entries(signed)
    .map(([name, value]) => [name.toLowerCase(), normalizeHeaderValue(value)])
    .sort(([left], [right]) => left.localeCompare(right));
  const canonicalHeaders = `${entries.map(([name, value]) => `${name}:${value}`).join('\n')}\n`;
  const signedHeaders = entries.map(([name]) => name).join(';');
  const canonicalRequest = [
    method,
    url.pathname,
    '',
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join('\n');
  const scope = `${date}/${config.region}/s3/aws4_request`;
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    timestamp,
    scope,
    createHash('sha256').update(canonicalRequest).digest('hex'),
  ].join('\n');
  const dateKey = hmac(`AWS4${config.secretAccessKey}`, date);
  const regionKey = hmac(dateKey, config.region);
  const serviceKey = hmac(regionKey, 's3');
  const signingKey = hmac(serviceKey, 'aws4_request');
  const signature = hmac(signingKey, stringToSign, 'hex');
  return {
    ...signed,
    authorization: `AWS4-HMAC-SHA256 Credential=${config.accessKeyId}/${scope},SignedHeaders=${signedHeaders},Signature=${signature}`,
  };
}

function request(config, { method, url, payloadHash, headers, filePath }) {
  const signedHeaders = signS3Request(config, { method, url, payloadHash, headers });
  return new Promise((resolveRequest, rejectRequest) => {
    const outgoing = httpsRequest(url, { method, headers: signedHeaders }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => {
        if (chunks.reduce((total, item) => total + item.length, 0) < 8192) chunks.push(chunk);
      });
      response.on('end', () => resolveRequest({
        statusCode: response.statusCode ?? 0,
        headers: response.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      }));
    });
    outgoing.setTimeout(config.requestTimeoutMs, () => {
      outgoing.destroy(new Error('S3 backup request timed out'));
    });
    outgoing.on('error', rejectRequest);
    if (filePath) {
      const input = createReadStream(filePath);
      input.on('error', (error) => outgoing.destroy(error));
      input.pipe(outgoing);
    } else {
      outgoing.end();
    }
  });
}

function responseError(action, response) {
  const detail = response.body.trim().slice(0, 500);
  const error = new Error(
    `${action} failed with HTTP ${response.statusCode}${detail ? `: ${detail}` : ''}`,
  );
  error.retryable = response.statusCode === 0 || response.statusCode === 408
    || response.statusCode === 429 || response.statusCode >= 500;
  return error;
}

async function sha256File(path) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest('hex');
}

export async function inspectBackup(filePath, checksumPath) {
  const expectedLine = readFileSync(checksumPath, 'utf8').trim();
  const match = /^([a-f0-9]{64})\s+\*?(.+)$/u.exec(expectedLine);
  if (!match || basename(match[2]) !== basename(filePath)) {
    throw new Error('local backup checksum file is invalid');
  }
  const metadata = statSync(filePath);
  if (!metadata.isFile() || metadata.size < 1) throw new Error('local encrypted backup is invalid');
  const backupSha256 = await sha256File(filePath);
  if (backupSha256 !== match[1]) throw new Error('local encrypted backup checksum does not match');
  return {
    name: basename(filePath),
    sha256: backupSha256,
    sizeBytes: metadata.size,
    createdAt: metadata.mtime.toISOString(),
    checksumSha256: await sha256File(checksumPath),
    checksumSizeBytes: statSync(checksumPath).size,
  };
}

async function transferObject(config, object) {
  const url = objectUrl(config, object.key);
  const uploadHeaders = {
    'content-length': String(object.sizeBytes),
    'content-type': object.contentType,
    'if-none-match': '*',
    'x-amz-meta-sha256': object.sha256,
  };
  const uploaded = await request(config, {
    method: 'PUT',
    url,
    payloadHash: object.sha256,
    headers: uploadHeaders,
    filePath: object.path,
  });
  if (uploaded.statusCode !== 412 && (uploaded.statusCode < 200 || uploaded.statusCode >= 300)) {
    throw responseError(`upload ${object.key}`, uploaded);
  }
  const inspected = await request(config, {
    method: 'HEAD',
    url,
    payloadHash: EMPTY_SHA256,
    headers: {},
  });
  if (inspected.statusCode < 200 || inspected.statusCode >= 300) {
    throw responseError(`verify ${object.key}`, inspected);
  }
  if (Number(inspected.headers['content-length']) !== object.sizeBytes
    || inspected.headers['x-amz-meta-sha256'] !== object.sha256) {
    const error = new Error(`remote backup verification failed for ${object.key}`);
    error.retryable = false;
    throw error;
  }
}

function sleep(milliseconds) {
  return new Promise((resolveSleep) => setTimeout(resolveSleep, milliseconds));
}

export async function replicateBackup({
  config,
  filePath,
  checksumPath,
  backup,
  transfer = transferObject,
  wait = sleep,
}) {
  const inspected = backup ?? await inspectBackup(filePath, checksumPath);
  if (!config.enabled) return { status: 'disabled', objects: [], backup: inspected };
  const files = [
    {
      path: filePath,
      key: `${config.prefix}/${basename(filePath)}`,
      sha256: inspected.sha256,
      sizeBytes: inspected.sizeBytes,
      contentType: 'application/octet-stream',
    },
    {
      path: checksumPath,
      key: `${config.prefix}/${basename(checksumPath)}`,
      sha256: inspected.checksumSha256,
      sizeBytes: inspected.checksumSizeBytes,
      contentType: 'text/plain; charset=utf-8',
    },
  ];
  for (let attempt = 1; attempt <= config.maxAttempts; attempt += 1) {
    try {
      for (const file of files) await transfer(config, file);
      return {
        status: 'replicated',
        objects: files.map((file) => file.key),
        attempt,
        backup: inspected,
      };
    } catch (error) {
      const retryable = !(error && typeof error === 'object' && error.retryable === false);
      if (!retryable || attempt === config.maxAttempts) throw error;
      await wait(Math.min(30_000, 1000 * (2 ** (attempt - 1))));
    }
  }
  throw new Error('off-site backup replication exhausted its retry budget');
}

function safeError(error) {
  return (error instanceof Error ? error.message : String(error))
    .replace(/(authorization|secret|session[_ -]?token|credential)\s*[:=]\s*[^\s<]+/giu, '$1=[REDACTED]')
    .replace(/<[^>]+>/gu, ' ')
    .replace(/\b[A-Za-z0-9+/_=-]{32,}\b/gu, '[REDACTED]')
    .replace(/[A-Za-z]:\\[^\s]+|\/(?:[^\s/]+\/){2,}[^\s]*/gu, '[LOCAL_PATH]')
    .replace(/\s+/gu, ' ')
    .trim()
    .slice(0, 1000);
}

function reportTarget(config) {
  if (!config.enabled) return null;
  return {
    provider: 's3',
    endpoint: config.endpoint.origin,
    bucket: config.bucket,
    prefix: config.prefix,
    addressingStyle: config.addressingStyle,
  };
}

export function createBackupReport(config, backup, result, error, recordedAt) {
  const status = error ? 'failed' : result.status === 'replicated' ? 'verified' : 'disabled';
  return {
    version: 1,
    backup: {
      name: backup.name,
      sha256: backup.sha256,
      sizeBytes: backup.sizeBytes,
      createdAt: backup.createdAt,
      localVerifiedAt: recordedAt,
    },
    offsite: {
      status,
      required: config.required,
      target: reportTarget(config),
      objects: result?.objects ?? [],
      attempts: result?.attempt ?? (error ? config.maxAttempts : 0),
      verifiedAt: status === 'verified' ? recordedAt : null,
      error: error ? safeError(error) : null,
    },
    recordedAt,
  };
}

function writeAtomic(path, content) {
  const temporaryPath = `${path}.${process.pid}.part`;
  writeFileSync(temporaryPath, content, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  try {
    renameSync(temporaryPath, path);
    chmodSync(path, 0o644);
  } catch (error) {
    if (existsSync(temporaryPath)) unlinkSync(temporaryPath);
    throw error;
  }
}

export function writeBackupReport(directory, report) {
  if (!directory) return;
  mkdirSync(directory, { recursive: true, mode: 0o755 });
  chmodSync(directory, 0o755);
  const content = `${JSON.stringify(report, null, 2)}\n`;
  const historyTimestamp = new Date(report.recordedAt).toISOString()
    .replace(/[-:]/gu, '')
    .replace(/\.\d{3}Z$/u, 'Z');
  const historyPath = resolve(directory, `${report.backup.name}.${historyTimestamp}.json`);
  writeFileSync(historyPath, content, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  chmodSync(historyPath, 0o644);
  const latestPath = resolve(directory, 'latest.json');
  const latestTemporary = `${latestPath}.${process.pid}.part`;
  if (existsSync(latestTemporary)) unlinkSync(latestTemporary);
  writeAtomic(latestPath, content);
}

async function main() {
  const envFile = resolve(option('--env-file') || '.env.production');
  const filePath = resolve(option('--file') || '');
  const checksumPath = resolve(option('--checksum') || '');
  const reportDirectory = option('--report-directory')
    ? resolve(option('--report-directory'))
    : null;
  if (!option('--file') || !option('--checksum')) {
    throw new Error('usage: replicate-backup-s3.mjs --env-file FILE --file BACKUP --checksum SHA256');
  }
  const config = loadBackupConfig({ envFile });
  const backup = await inspectBackup(filePath, checksumPath);
  try {
    const result = await replicateBackup({ config, filePath, checksumPath, backup });
    writeBackupReport(
      reportDirectory,
      createBackupReport(config, backup, result, null, new Date().toISOString()),
    );
    if (result.status === 'disabled') {
      process.stdout.write('Off-site backup replication is disabled.\n');
    } else {
      process.stdout.write(`Off-site backup verified: s3://${config.bucket}/${result.objects[0]}\n`);
    }
  } catch (error) {
    writeBackupReport(
      reportDirectory,
      createBackupReport(config, backup, null, error, new Date().toISOString()),
    );
    if (config.required) throw error;
    process.stderr.write(`Optional off-site backup failed: ${error instanceof Error ? error.message : String(error)}\n`);
  }
}

const entrypoint = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : '';
if (entrypoint === import.meta.url) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}

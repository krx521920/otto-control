import { generateKeyPairSync, randomBytes } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

function option(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function options(name) {
  const values = [];
  for (let index = 0; index < process.argv.length; index += 1) {
    if (process.argv[index] === name && process.argv[index + 1]) values.push(process.argv[index + 1]);
  }
  return values;
}

function parseEnvironment(path) {
  const values = new Map();
  for (const rawLine of readFileSync(path, 'utf8').split(/\r?\n/u)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const separator = line.indexOf('=');
    if (separator < 1) throw new Error(`invalid environment line: ${rawLine}`);
    values.set(line.slice(0, separator), line.slice(separator + 1));
  }
  return values;
}

function resolveEnvironmentPath(environmentFile, value, name) {
  if (!value?.trim()) throw new Error(`${name} is required in the environment file`);
  return isAbsolute(value) ? value : resolve(dirname(environmentFile), value);
}

function readInput(name) {
  const path = option(name)?.trim();
  if (!path) throw new Error(`${name} is required`);
  return readInputFile(path, name);
}

function readInputFile(path, name) {
  const resolved = resolve(path);
  const stat = lstatSync(resolved);
  if (stat.isSymbolicLink() || !stat.isFile() || stat.size === 0) {
    throw new Error(`${name} must be a non-empty regular file, not a symbolic link`);
  }
  return readFileSync(resolved, 'utf8').trim();
}

function exactObject(value, fields, name) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).some((field) => !fields.includes(field))
    || fields.some((field) => !Object.hasOwn(value, field))) {
    throw new Error(`${name} has invalid fields`);
  }
  return value;
}

function validateInputs(input) {
  let publicKeys;
  let origins;
  let identity;
  try { publicKeys = JSON.parse(input.publicKeys); } catch { throw new Error('Control public keys must be JSON'); }
  try { origins = JSON.parse(input.origins); } catch { throw new Error('upstream origins must be JSON'); }
  try { identity = JSON.parse(input.identity); } catch { throw new Error('deployment identity must be JSON'); }
  if (!publicKeys || typeof publicKeys !== 'object' || Array.isArray(publicKeys)
    || Object.keys(publicKeys).length < 1
    || Object.values(publicKeys).some((value) => typeof value !== 'string' || !value.trim())) {
    throw new Error('Control public keys must be a non-empty key-id to public-key object');
  }
  if (!origins || typeof origins !== 'object' || Array.isArray(origins)
    || origins.version !== 2
    || Object.keys(origins).length !== 2
    || !Array.isArray(origins.allowedUpstreams)
    || origins.allowedUpstreams.length < 1
    || origins.allowedUpstreams.length > 256) {
    throw new Error('upstream origins must be a non-empty version 2 allowedUpstreams policy');
  }
  const bindings = new Set();
  for (const upstream of origins.allowedUpstreams) {
    if (!upstream || typeof upstream !== 'object' || Array.isArray(upstream)
      || Object.keys(upstream).length !== 2
      || typeof upstream.origin !== 'string'
      || !Array.isArray(upstream.authentications)
      || upstream.authentications.length < 1) {
      throw new Error('upstream origins contain an invalid rule');
    }
    let origin;
    try { origin = new URL(upstream.origin); } catch { throw new Error('upstream origin is invalid'); }
    if (origin.protocol !== 'https:' || origin.origin !== upstream.origin
      || origin.username || origin.password) {
      throw new Error('upstream origins must contain credential-free HTTPS origins');
    }
    for (const authentication of upstream.authentications) {
      const binding = authentication?.secretBinding;
      const expectedFields = authentication?.type === 'bearer'
        ? ['type', 'secretBinding']
        : authentication?.type === 'header' ? ['type', 'headerName', 'secretBinding'] : [];
      if (!authentication || typeof authentication !== 'object' || Array.isArray(authentication)
        || expectedFields.length === 0
        || Object.keys(authentication).length !== expectedFields.length
        || Object.keys(authentication).some((field) => !expectedFields.includes(field))
        || typeof binding !== 'string'
        || !/^[A-Z][A-Z0-9_]{2,127}$/u.test(binding)
        || (authentication.type === 'header'
          && (typeof authentication.headerName !== 'string'
            || !/^[a-zA-Z0-9!#$%&'*+.^_`|~-]{1,80}$/u.test(authentication.headerName)))) {
        throw new Error('upstream authentication binding is invalid');
      }
      bindings.add(binding);
    }
  }
  exactObject(identity, [
    'licenseId', 'deploymentId', 'organizationId', 'machineFingerprint',
  ], 'deployment identity');
  if (![identity.licenseId, identity.deploymentId, identity.organizationId]
    .every((value) => typeof value === 'string'
      && /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,159}$/u.test(value.trim()))
    || typeof identity.machineFingerprint !== 'string'
    || !/^[a-f0-9]{64}$/u.test(identity.machineFingerprint.trim().toLowerCase())) {
    throw new Error('deployment identity values are invalid');
  }
  if (input.leaseToken.length < 32 || input.leaseToken.length > 8_192
    || /\s/u.test(input.leaseToken)) {
    throw new Error('lease token is invalid');
  }
  return [...bindings].sort();
}

function providerSecretInputs(requiredBindings) {
  const result = new Map();
  for (const entry of options('--provider-secret')) {
    const separator = entry.indexOf('=');
    const binding = separator > 0 ? entry.slice(0, separator) : '';
    const path = separator > 0 ? entry.slice(separator + 1) : '';
    if (!/^[A-Z][A-Z0-9_]{2,127}$/u.test(binding) || !path || result.has(binding)) {
      throw new Error('--provider-secret must be a unique SECRET_BINDING=/secure/file value');
    }
    const value = readInputFile(path, '--provider-secret');
    if (!value || value.length > 8_192 || !/^[\x21-\x7e]+$/u.test(value)) {
      throw new Error(`provider secret ${binding} is invalid`);
    }
    result.set(binding, value);
  }
  if (result.size !== requiredBindings.length
    || requiredBindings.some((binding) => !result.has(binding))) {
    throw new Error(
      `--provider-secret must cover exactly these bindings: ${requiredBindings.join(', ')}`,
    );
  }
  return result;
}

function writeExclusive(path, value, mode = 0o600) {
  writeFileSync(path, `${value}\n`, { encoding: 'utf8', flag: 'wx', mode });
}

function runOpenSsl(arguments_, workingDirectory) {
  const result = spawnSync('openssl', arguments_, {
    cwd: workingDirectory,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (result.status !== 0) {
    throw new Error(`openssl failed: ${result.stderr.trim() || result.stdout.trim()}`);
  }
}

function createRedisTlsIdentity(secretDirectory) {
  const temporaryDirectory = mkdtempSync(join(tmpdir(), 'otto-edge-redis-tls-'));
  try {
    const caKey = join(temporaryDirectory, 'edge_redis_tls_ca_private_key.pem');
    const caCertificate = join(temporaryDirectory, 'edge_redis_tls_ca.pem');
    const serverKey = join(temporaryDirectory, 'edge_redis_tls_key.pem');
    const serverRequest = join(temporaryDirectory, 'edge_redis_tls.csr');
    const serverCertificate = join(temporaryDirectory, 'edge_redis_tls_cert.pem');
    const extensions = join(temporaryDirectory, 'edge_redis_tls.ext');
    const configuration = join(temporaryDirectory, 'openssl.cnf');
    writeFileSync(configuration, [
      '[req]',
      'distinguished_name=req_distinguished_name',
      '[req_distinguished_name]',
      '[v3_ca]',
      'basicConstraints=critical,CA:TRUE',
      'keyUsage=critical,keyCertSign,cRLSign',
      'subjectKeyIdentifier=hash',
      'authorityKeyIdentifier=keyid:always',
      '',
    ].join('\n'), { encoding: 'utf8', mode: 0o600 });
    writeFileSync(extensions, [
      'basicConstraints=critical,CA:FALSE',
      'keyUsage=critical,digitalSignature,keyEncipherment',
      'extendedKeyUsage=serverAuth',
      'subjectAltName=DNS:edge-redis,DNS:localhost,IP:127.0.0.1,IP:::1',
      '',
    ].join('\n'), { encoding: 'utf8', mode: 0o600 });
    runOpenSsl([
      'req', '-x509', '-newkey', 'rsa:3072', '-sha256', '-nodes', '-days', '3650',
      '-config', configuration, '-extensions', 'v3_ca',
      '-subj', '/CN=Otto Edge Redis CA', '-keyout', caKey, '-out', caCertificate,
    ], temporaryDirectory);
    runOpenSsl([
      'req', '-new', '-newkey', 'rsa:3072', '-sha256', '-nodes',
      '-config', configuration, '-subj', '/CN=edge-redis',
      '-keyout', serverKey, '-out', serverRequest,
    ], temporaryDirectory);
    runOpenSsl([
      'x509', '-req', '-in', serverRequest, '-CA', caCertificate, '-CAkey', caKey,
      '-CAcreateserial', '-out', serverCertificate, '-days', '825', '-sha256',
      '-extfile', extensions,
    ], temporaryDirectory);
    for (const name of [
      'edge_redis_tls_ca_private_key.pem',
      'edge_redis_tls_ca.pem',
      'edge_redis_tls_key.pem',
      'edge_redis_tls_cert.pem',
    ]) {
      writeExclusive(
        resolve(secretDirectory, name),
        readFileSync(resolve(temporaryDirectory, name), 'utf8').trim(),
      );
    }
  } finally {
    rmSync(temporaryDirectory, { recursive: true, force: true });
  }
}

function enableEdgeGateway(environmentFile, providerBindings) {
  const source = readFileSync(environmentFile, 'utf8');
  if (!/^OTTO_EDGE_ENABLED=false$/mu.test(source)) {
    throw new Error('environment file must contain OTTO_EDGE_ENABLED=false before provisioning');
  }
  for (const binding of providerBindings) {
    if (new RegExp(`^${binding}(?:_FILE)?=`, 'mu').test(source)) {
      throw new Error(`environment file already defines provider binding ${binding}`);
    }
  }
  const providerFiles = providerBindings
    .map((binding) => `${binding}_FILE=/run/otto-edge-provider-secrets/${binding}`)
    .join('\n');
  const next = `${source.replace(
    /^OTTO_EDGE_ENABLED=false$/mu,
    'OTTO_EDGE_ENABLED=true',
  ).trimEnd()}\n${providerFiles}\n`;
  const temporary = `${environmentFile}.edge-bootstrap.tmp`;
  writeFileSync(temporary, next, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
  renameSync(temporary, environmentFile);
  chmodSync(environmentFile, 0o600);
}

function main() {
  const environmentFile = resolve(option('--env-file') || '.env.production');
  const environment = parseEnvironment(environmentFile);
  if (environment.get('NODE_ENV') !== 'production') {
    throw new Error('Edge Gateway production bootstrap requires NODE_ENV=production');
  }
  const secretDirectory = resolveEnvironmentPath(
    environmentFile, environment.get('OTTO_CONTROL_SECRETS_DIR'), 'OTTO_CONTROL_SECRETS_DIR',
  );
  const configDirectory = resolveEnvironmentPath(
    environmentFile, environment.get('OTTO_EDGE_CONFIG_DIR'), 'OTTO_EDGE_CONFIG_DIR',
  );
  const providerSecretDirectory = resolveEnvironmentPath(
    environmentFile,
    environment.get('OTTO_EDGE_PROVIDER_SECRETS_DIR'),
    'OTTO_EDGE_PROVIDER_SECRETS_DIR',
  );
  const input = {
    publicKeys: readInput('--control-public-keys-file'),
    origins: readInput('--upstream-origins-file'),
    identity: readInput('--deployment-identity-file'),
    leaseToken: readInput('--lease-token-file'),
  };
  const providerBindings = validateInputs(input);
  const providerSecrets = providerSecretInputs(providerBindings);
  mkdirSync(secretDirectory, { recursive: true, mode: 0o700 });
  mkdirSync(configDirectory, { recursive: true, mode: 0o700 });
  mkdirSync(providerSecretDirectory, { recursive: true, mode: 0o700 });
  const targets = [
    resolve(configDirectory, 'control_public_keys.json'),
    resolve(configDirectory, 'upstream_origins.json'),
    resolve(configDirectory, 'deployment_identity.json'),
    resolve(secretDirectory, 'edge_lease_token'),
    resolve(secretDirectory, 'edge_rate_limit_key'),
    resolve(secretDirectory, 'edge_redis_password'),
    resolve(secretDirectory, 'edge_execution_receipt_private_key.pem'),
    resolve(secretDirectory, 'edge_operations_token'),
    resolve(secretDirectory, 'edge_redis_tls_ca_private_key.pem'),
    resolve(secretDirectory, 'edge_redis_tls_ca.pem'),
    resolve(secretDirectory, 'edge_redis_tls_key.pem'),
    resolve(secretDirectory, 'edge_redis_tls_cert.pem'),
    ...providerBindings.map((binding) => resolve(providerSecretDirectory, binding)),
  ];
  const existing = targets.find(existsSync);
  if (existing) throw new Error(`refusing to overwrite existing Edge Gateway file: ${existing}`);

  writeExclusive(targets[0], input.publicKeys);
  writeExclusive(targets[1], input.origins);
  writeExclusive(targets[2], input.identity);
  writeExclusive(targets[3], input.leaseToken);
  writeExclusive(targets[4], randomBytes(48).toString('base64url'));
  writeExclusive(targets[5], randomBytes(48).toString('base64url'));
  const { privateKey } = generateKeyPairSync('ed25519');
  writeExclusive(
    targets[6], privateKey.export({ type: 'pkcs8', format: 'pem' }).trim(),
  );
  writeExclusive(targets[7], randomBytes(48).toString('base64url'));
  for (const [binding, value] of providerSecrets) {
    writeExclusive(resolve(providerSecretDirectory, binding), value);
  }
  createRedisTlsIdentity(secretDirectory);
  enableEdgeGateway(environmentFile, providerBindings);
  process.stdout.write(
    `Edge Gateway production files created under ${configDirectory} and ${secretDirectory}.\n`,
  );
}

try {
  main();
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}

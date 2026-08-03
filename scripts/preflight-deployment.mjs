import {
  X509Certificate,
  createPrivateKey,
  createPublicKey,
} from 'node:crypto';
import {
  lstatSync,
  readFileSync,
} from 'node:fs';
import { lookup } from 'node:dns/promises';
import { dirname, isAbsolute, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function option(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function hasFlag(name) {
  return process.argv.includes(name);
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

function reservedHostname(hostname) {
  const value = hostname.toLowerCase();
  return value === 'localhost'
    || value.endsWith('.localhost')
    || value.endsWith('.example')
    || value.endsWith('.example.com')
    || value.endsWith('.example.net')
    || value.endsWith('.example.org')
    || value.endsWith('.invalid')
    || value.endsWith('.test');
}

function run(command, arguments_) {
  const result = spawnSync(command, arguments_, {
    cwd: repositoryRoot,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (result.status !== 0) {
    const detail = result.stderr.trim() || result.stdout.trim() || `exit ${result.status}`;
    throw new Error(`${command} ${arguments_.join(' ')} failed: ${detail}`);
  }
}

function readRequiredFile(path, errors, { privateFile = true } = {}) {
  try {
    const stat = lstatSync(path);
    if (stat.isSymbolicLink()) {
      errors.push(`${path} must not be a symbolic link`);
      return '';
    }
    if (!stat.isFile() || stat.size === 0) {
      errors.push(`${path} must be a non-empty regular file`);
      return '';
    }
    if (privateFile && process.platform !== 'win32' && (stat.mode & 0o077) !== 0) {
      errors.push(`${path} must not be readable or writable by group/other users`);
    }
    return readFileSync(path, 'utf8').trim();
  } catch (error) {
    errors.push(`${path} cannot be read: ${error instanceof Error ? error.message : String(error)}`);
    return '';
  }
}

function validatePostgresIdentity(secretDirectory, errors) {
  const caPath = resolve(secretDirectory, 'postgres_tls_ca.pem');
  const certificatePath = resolve(secretDirectory, 'postgres_tls_cert.pem');
  const keyPath = resolve(secretDirectory, 'postgres_tls_key.pem');
  const caPrivateKeyPath = resolve(secretDirectory, 'postgres_tls_ca_private_key.pem');
  const caPem = readRequiredFile(caPath, errors);
  const certificatePem = readRequiredFile(certificatePath, errors);
  const keyPem = readRequiredFile(keyPath, errors);
  const caPrivateKeyPem = readRequiredFile(caPrivateKeyPath, errors);
  if (!caPem || !certificatePem || !keyPem || !caPrivateKeyPem) return;
  try {
    const ca = new X509Certificate(caPem);
    const certificate = new X509Certificate(certificatePem);
    if (!ca.ca) errors.push('PostgreSQL CA certificate is not marked as a CA');
    const caPrivateKey = createPrivateKey(caPrivateKeyPem);
    const caPrivatePublicKey = createPublicKey(caPrivateKey).export({ type: 'spki', format: 'der' });
    const caCertificateKey = ca.publicKey.export({ type: 'spki', format: 'der' });
    if (!caCertificateKey.equals(caPrivatePublicKey)) {
      errors.push('PostgreSQL CA certificate and private key do not match');
    }
    if (!certificate.verify(ca.publicKey)) {
      errors.push('PostgreSQL server certificate is not signed by the generated CA');
    }
    for (const hostname of ['postgres-router', 'postgres-1', 'postgres-2', 'postgres-3']) {
      if (!certificate.checkHost(hostname)) {
        errors.push(`PostgreSQL server certificate does not cover ${hostname}`);
      }
    }
    const certificateKey = certificate.publicKey.export({ type: 'spki', format: 'der' });
    const privateKey = createPrivateKey(keyPem);
    const privatePublicKey = createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
    if (!certificateKey.equals(privatePublicKey)) {
      errors.push('PostgreSQL server certificate and private key do not match');
    }
  } catch (error) {
    errors.push(`PostgreSQL TLS identity is invalid: ${error instanceof Error ? error.message : String(error)}`);
  }
}

async function validateDns(hostnames, errors) {
  for (const hostname of hostnames) {
    try {
      await lookup(hostname, { all: true });
    } catch (error) {
      errors.push(`DNS lookup failed for ${hostname}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
}

async function main() {
  const environmentFile = resolve(option('--env-file') || '.env.production');
  const environment = parseEnvironment(environmentFile);
  const deploymentEnvironment = option('--environment')
    || environment.get('OTTO_CONTROL_DEPLOYMENT_ENVIRONMENT')
    || 'production';
  const errors = [];
  const requireValue = (name) => {
    const value = environment.get(name)?.trim();
    if (!value) errors.push(`${name} is required`);
    return value || '';
  };

  if (!['staging', 'production'].includes(deploymentEnvironment)) {
    errors.push('deployment environment must be staging or production');
  }
  if (environment.get('NODE_ENV') !== 'production') errors.push('NODE_ENV must be production');
  if (environment.get('OTTO_CONTROL_DEPLOYMENT_ENVIRONMENT') !== deploymentEnvironment) {
    errors.push('environment file deployment identity does not match --environment');
  }
  const expectedFileName = `.env.${deploymentEnvironment}`;
  if (environment.get('OTTO_CONTROL_ENV_FILE') !== expectedFileName) {
    errors.push(`OTTO_CONTROL_ENV_FILE must be ${expectedFileName}`);
  }
  requireValue('OTTO_CONTROL_STACK_NAME');
  const controlBaseUrl = requireValue('CONTROL_PUBLIC_BASE_URL');
  const federationBaseUrl = requireValue('FEDERATION_PUBLIC_BASE_URL');
  const controlDomain = requireValue('CONTROL_DOMAIN');
  const federationDomain = requireValue('FEDERATION_DOMAIN');
  let controlUrl;
  let federationUrl;
  try {
    controlUrl = new URL(controlBaseUrl);
    if (controlUrl.protocol !== 'https:' || controlUrl.origin !== controlBaseUrl) {
      errors.push('CONTROL_PUBLIC_BASE_URL must be an HTTPS origin');
    }
    if (controlUrl.hostname !== controlDomain) errors.push('CONTROL_DOMAIN does not match its URL');
  } catch {
    errors.push('CONTROL_PUBLIC_BASE_URL is invalid');
  }
  try {
    federationUrl = new URL(federationBaseUrl);
    if (federationUrl.protocol !== 'https:' || federationUrl.origin !== federationBaseUrl) {
      errors.push('FEDERATION_PUBLIC_BASE_URL must be an HTTPS origin');
    }
    if (federationUrl.hostname !== federationDomain) {
      errors.push('FEDERATION_DOMAIN does not match its URL');
    }
  } catch {
    errors.push('FEDERATION_PUBLIC_BASE_URL is invalid');
  }
  if (controlDomain === federationDomain) errors.push('Control and Federation domains must differ');

  if (environment.get('CONTROL_DATABASE_SSL') !== 'true') {
    errors.push('CONTROL_DATABASE_SSL must be true');
  }
  if (environment.get('FEDERATION_DATABASE_SSL') !== 'true') {
    errors.push('FEDERATION_DATABASE_SSL must be true');
  }
  if (environment.get('NODE_EXTRA_CA_CERTS') !== '/run/secrets/postgres_tls_ca') {
    errors.push('NODE_EXTRA_CA_CERTS must trust the mounted PostgreSQL CA');
  }

  const forbiddenInlineSecrets = [
    'CONTROL_ADMIN_TOKEN',
    'CONTROL_TOKEN_SECRET',
    'CONTROL_METRICS_TOKEN',
    'CONTROL_DATABASE_PASSWORD',
    'FEDERATION_ADMIN_TOKEN',
    'FEDERATION_METRICS_TOKEN',
    'FEDERATION_DATABASE_PASSWORD',
  ];
  for (const name of forbiddenInlineSecrets) {
    if (environment.get(name)?.trim()) errors.push(`${name} must use a file-backed secret instead`);
  }

  const secretDirectoryValue = requireValue('OTTO_CONTROL_SECRETS_DIR');
  const secretDirectory = isAbsolute(secretDirectoryValue)
    ? secretDirectoryValue
    : resolve(dirname(environmentFile), secretDirectoryValue);
  const backupDirectoryValue = requireValue('OTTO_CONTROL_BACKUP_DIR');
  const backupDirectory = isAbsolute(backupDirectoryValue)
    ? backupDirectoryValue
    : resolve(dirname(environmentFile), backupDirectoryValue);
  try {
    const backupStat = lstatSync(backupDirectory);
    if (!backupStat.isDirectory()) errors.push(`${backupDirectory} must be a directory`);
  } catch (error) {
    errors.push(
      `${backupDirectory} cannot be read: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  const opaqueSecrets = [
    'control_admin_token',
    'control_token_secret',
    'control_metrics_token',
    'federation_admin_token',
    'federation_metrics_token',
    'postgres_password',
    'postgres_superuser_password',
    'postgres_replication_password',
    'pgbackrest_cipher_pass',
    'backup_encryption_key',
    'alert_webhook_secret',
    'audit_anchor_token',
  ];
  for (const name of opaqueSecrets) {
    const value = readRequiredFile(resolve(secretDirectory, name), errors);
    if (value && value.length < 32) errors.push(`${name} must contain at least 32 characters`);
  }
  readRequiredFile(resolve(secretDirectory, 'control_signer_private_key.pem'), errors);
  readRequiredFile(resolve(secretDirectory, 'control_signer_keyring.json'), errors);
  validatePostgresIdentity(secretDirectory, errors);

  if (deploymentEnvironment === 'production') {
    if (reservedHostname(controlDomain) || reservedHostname(federationDomain)) {
      errors.push('production domains cannot use localhost or reserved example/test suffixes');
    }
    const productionValues = [
      ['ACME_EMAIL', requireValue('ACME_EMAIL')],
      ['CONTROL_DATA_REGION', requireValue('CONTROL_DATA_REGION')],
      ['CONTROL_PRIVACY_CONTROLLER', requireValue('CONTROL_PRIVACY_CONTROLLER')],
      ['CONTROL_PRIVACY_CONTACT', requireValue('CONTROL_PRIVACY_CONTACT')],
    ];
    for (const [name, value] of productionValues) {
      if (/example|staging|change[ -]?me|placeholder|待填写|示例/iu.test(value)) {
        errors.push(`${name} contains a placeholder value`);
      }
    }
    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/u;
    if (!emailPattern.test(environment.get('ACME_EMAIL') || '')) {
      errors.push('ACME_EMAIL must be a valid operator email address');
    }
    if (!emailPattern.test(environment.get('CONTROL_PRIVACY_CONTACT') || '')) {
      errors.push('CONTROL_PRIVACY_CONTACT must be a valid privacy email address');
    }
    if (!/^[A-Z]{2}(?:-[A-Z0-9]{2,8})+$/u.test(environment.get('CONTROL_DATA_REGION') || '')) {
      errors.push('CONTROL_DATA_REGION must be an explicit region code such as CN-BJ');
    }
    if (!hasFlag('--skip-dns') && controlUrl && federationUrl) {
      await validateDns([controlUrl.hostname, federationUrl.hostname], errors);
    }
  }

  if (!hasFlag('--skip-docker')) {
    try {
      run('docker', ['version']);
      run('docker', ['compose', 'version']);
      run('docker', [
        'compose',
        '-f', resolve(repositoryRoot, 'compose.production.yaml'),
        '--env-file', environmentFile,
        'config', '--quiet',
      ]);
    } catch (error) {
      errors.push(error instanceof Error ? error.message : String(error));
    }
  }

  const compose = readFileSync(resolve(repositoryRoot, 'compose.production.yaml'), 'utf8');
  if (compose.includes('postgres_tls_ca_private_key')) {
    errors.push('PostgreSQL CA private key must never be mounted by Compose');
  }

  if (errors.length > 0) {
    throw new Error(`deployment preflight failed:\n- ${errors.join('\n- ')}`);
  }
  process.stdout.write(
    `Deployment preflight passed for ${deploymentEnvironment}: ${controlDomain}, ${federationDomain}\n`,
  );
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});

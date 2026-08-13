import {
  X509Certificate,
  createPrivateKey,
  createPublicKey,
} from 'node:crypto';
import {
  lstatSync,
  readdirSync,
  readFileSync,
} from 'node:fs';
import { lookup } from 'node:dns/promises';
import { basename, dirname, isAbsolute, relative, resolve } from 'node:path';
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

function signingFile(signingDirectory, configuredPath, errors, options) {
  if (typeof configuredPath !== 'string' || !configuredPath.trim()) {
    errors.push('signing provider file path must be a non-empty string');
    return '';
  }
  if (isAbsolute(configuredPath)) {
    errors.push(`signing provider file must be relative to OTTO_CONTROL_SIGNING_DIR: ${configuredPath}`);
    return '';
  }
  if (basename(configuredPath) !== configuredPath) {
    errors.push(`signing provider files must be direct children of OTTO_CONTROL_SIGNING_DIR: ${configuredPath}`);
    return '';
  }
  const path = resolve(signingDirectory, configuredPath);
  const relativePath = relative(signingDirectory, path);
  if (relativePath.startsWith('..') || isAbsolute(relativePath)) {
    errors.push(`signing provider file escapes OTTO_CONTROL_SIGNING_DIR: ${configuredPath}`);
    return '';
  }
  return readRequiredFile(path, errors, options);
}

function validateSigningIdentity(signingDirectory, deploymentEnvironment, allowLocal, errors) {
  const manifestText = readRequiredFile(
    resolve(signingDirectory, 'control_signer_keyring.json'),
    errors,
  );
  if (!manifestText) return;
  let manifest;
  try {
    manifest = JSON.parse(manifestText);
  } catch {
    errors.push('control_signer_keyring.json must contain valid JSON');
    return;
  }
  if (!manifest || manifest.version !== 1 || !Array.isArray(manifest.keys)
    || manifest.keys.length < 1) {
    errors.push('control_signer_keyring.json must use version 1 and contain keys');
    return;
  }
  let externalProviderCount = 0;
  let awsKmsProviderCount = 0;
  const awsArnPattern = /^arn:(aws|aws-cn|aws-us-gov):kms:([a-z0-9-]{3,32}):(\d{12}):key\/(mrk-[a-f0-9]{32}|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$/u;
  for (const entry of manifest.keys) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      errors.push('signing keyring contains an invalid provider entry');
      continue;
    }
    if (entry.provider === 'local' || entry.provider === undefined) {
      if (deploymentEnvironment === 'production' && !allowLocal) {
        errors.push('production signing keyring must not contain a local signing private key');
      }
      const privateKeyPem = signingFile(signingDirectory, entry.privateKeyFile, errors);
      if (privateKeyPem) {
        try {
          if (createPrivateKey(privateKeyPem).asymmetricKeyType !== 'ed25519') {
            errors.push('local Control signing key must be Ed25519');
          }
        } catch (error) {
          errors.push(`local Control signing key is invalid: ${error instanceof Error ? error.message : String(error)}`);
        }
      }
      continue;
    }
    externalProviderCount += 1;
    if (entry.provider === 'kms' && entry.backend === 'aws_kms') {
      awsKmsProviderCount += 1;
      const parsed = Array.isArray(entry.keyArns)
        ? entry.keyArns.map((arn) => ({ arn, match: typeof arn === 'string' ? awsArnPattern.exec(arn) : null }))
        : [];
      if (parsed.length < 1 || parsed.length > 3 || parsed.some(({ match }) => !match)) {
        errors.push('AWS KMS signing provider must contain one to three immutable key ARNs');
        continue;
      }
      if (new Set(parsed.map(({ arn }) => arn)).size !== parsed.length) {
        errors.push('AWS KMS signing provider contains duplicate key ARNs');
      }
      if (parsed.length > 1) {
        const identities = parsed.map(({ match }) => `${match[1]}:${match[3]}:${match[4]}`);
        const regions = parsed.map(({ match }) => match[2]);
        if (!parsed.every(({ match }) => match[4].startsWith('mrk-'))
          || new Set(identities).size !== 1
          || new Set(regions).size !== regions.length) {
          errors.push('AWS KMS replicas must be one multi-Region key in distinct regions');
        }
      }
      if (entry.validateSignPermission !== true) {
        errors.push('production AWS KMS provider must validate Sign permission at startup');
      }
      continue;
    }
    if ((entry.provider !== 'kms' && entry.provider !== 'hsm')
      || entry.backend && entry.backend !== 'remote') {
      errors.push('signing keyring contains an unsupported external provider');
      continue;
    }
    try {
      const endpoint = new URL(entry.endpoint);
      if (endpoint.protocol !== 'https:' || endpoint.origin + endpoint.pathname !== entry.endpoint) {
        errors.push('remote KMS/HSM endpoint must be an HTTPS URL without query or fragment');
      }
    } catch {
      errors.push('remote KMS/HSM endpoint must be a valid HTTPS URL');
    }
    if (typeof entry.keyRef !== 'string' || !entry.keyRef.trim()) {
      errors.push('remote KMS/HSM keyRef is required');
    }
    const publicKeyPem = signingFile(
      signingDirectory,
      entry.publicKeyFile,
      errors,
      { privateFile: false },
    );
    if (publicKeyPem) {
      try {
        if (createPublicKey(publicKeyPem).asymmetricKeyType !== 'ed25519') {
          errors.push('remote Control signing public key must be Ed25519');
        }
      } catch (error) {
        errors.push(`remote Control signing public key is invalid: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
    const hasToken = typeof entry.bearerTokenFile === 'string' && entry.bearerTokenFile.trim();
    const hasCertificate = typeof entry.clientCertificateFile === 'string'
      && entry.clientCertificateFile.trim();
    const hasClientKey = typeof entry.clientKeyFile === 'string' && entry.clientKeyFile.trim();
    if (!hasToken && !(hasCertificate && hasClientKey)) {
      errors.push('remote KMS/HSM provider requires a bearer token or mTLS identity');
    }
    if (hasToken) signingFile(signingDirectory, entry.bearerTokenFile, errors);
    if (hasCertificate) signingFile(signingDirectory, entry.clientCertificateFile, errors);
    if (hasClientKey) signingFile(signingDirectory, entry.clientKeyFile, errors);
    if (entry.caFile) signingFile(signingDirectory, entry.caFile, errors, { privateFile: false });
  }
  if (deploymentEnvironment === 'production' && !allowLocal && externalProviderCount === 0) {
    errors.push('production signing keyring requires at least one KMS or HSM provider');
  }
  if (deploymentEnvironment === 'production'
    && !allowLocal
    && awsKmsProviderCount === manifest.keys.length) {
    try {
      const unexpectedFiles = readdirSync(signingDirectory)
        .filter((name) => name !== 'control_signer_keyring.json');
      if (unexpectedFiles.length > 0) {
        errors.push(
          `AWS KMS-only signing directory contains unexpected files: ${unexpectedFiles.join(', ')}`,
        );
      }
    } catch (error) {
      errors.push(
        `AWS KMS-only signing directory cannot be listed: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }
}

function validateArtifactAttestationIdentity(attestationDirectory, errors) {
  const manifestPath = resolve(attestationDirectory, 'artifact_attestation_keyring.json');
  const manifestText = readRequiredFile(manifestPath, errors, { privateFile: false });
  if (!manifestText) return;
  let manifest;
  try {
    manifest = JSON.parse(manifestText);
  } catch {
    errors.push('artifact_attestation_keyring.json must contain valid JSON');
    return;
  }
  if (!manifest || manifest.version !== 1 || !Array.isArray(manifest.keys)
    || manifest.keys.length < 1) {
    errors.push('artifact_attestation_keyring.json must use version 1 and contain keys');
    return;
  }
  const ids = new Set();
  for (const entry of manifest.keys) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)
      || typeof entry.id !== 'string'
      || !/^[a-zA-Z0-9_.-]{3,64}$/u.test(entry.id)
      || ids.has(entry.id)
      || typeof entry.publicKeyFile !== 'string'
      || basename(entry.publicKeyFile) !== entry.publicKeyFile) {
      errors.push('artifact attestation keyring contains an invalid or duplicate key');
      continue;
    }
    ids.add(entry.id);
    const publicKeyPem = readRequiredFile(
      resolve(attestationDirectory, entry.publicKeyFile),
      errors,
      { privateFile: false },
    );
    if (!publicKeyPem) continue;
    try {
      if (createPublicKey(publicKeyPem).asymmetricKeyType !== 'ed25519') {
        errors.push(`artifact attestation key ${entry.id} must be Ed25519`);
      }
    } catch (error) {
      errors.push(
        `artifact attestation key ${entry.id} is invalid: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
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
    for (const hostname of [
      'postgres-router',
      'postgres-1',
      'postgres-2',
      'postgres-3',
      'localhost',
    ]) {
      if (!certificate.checkHost(hostname)) {
        errors.push(`PostgreSQL server certificate does not cover ${hostname}`);
      }
    }
    if (!certificate.checkIP('127.0.0.1')) {
      errors.push('PostgreSQL server certificate does not cover 127.0.0.1');
    }
    if (!certificate.checkIP('::1')) {
      errors.push('PostgreSQL server certificate does not cover ::1');
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

function validateEdgeRedisIdentity(secretDirectory, errors) {
  const caPath = resolve(secretDirectory, 'edge_redis_tls_ca.pem');
  const certificatePath = resolve(secretDirectory, 'edge_redis_tls_cert.pem');
  const keyPath = resolve(secretDirectory, 'edge_redis_tls_key.pem');
  const caPrivateKeyPath = resolve(secretDirectory, 'edge_redis_tls_ca_private_key.pem');
  const caPem = readRequiredFile(caPath, errors);
  const certificatePem = readRequiredFile(certificatePath, errors);
  const keyPem = readRequiredFile(keyPath, errors);
  const caPrivateKeyPem = readRequiredFile(caPrivateKeyPath, errors);
  if (!caPem || !certificatePem || !keyPem || !caPrivateKeyPem) return;
  try {
    const ca = new X509Certificate(caPem);
    const certificate = new X509Certificate(certificatePem);
    if (!ca.ca) errors.push('Edge Redis CA certificate is not marked as a CA');
    if (!certificate.verify(ca.publicKey)) {
      errors.push('Edge Redis server certificate is not signed by its CA');
    }
    if (!certificate.checkHost('edge-redis')) {
      errors.push('Edge Redis server certificate does not cover edge-redis');
    }
    const caPrivateKey = createPrivateKey(caPrivateKeyPem);
    const caPrivatePublicKey = createPublicKey(caPrivateKey).export({ type: 'spki', format: 'der' });
    const caCertificateKey = ca.publicKey.export({ type: 'spki', format: 'der' });
    if (!caCertificateKey.equals(caPrivatePublicKey)) {
      errors.push('Edge Redis CA certificate and private key do not match');
    }
    const privateKey = createPrivateKey(keyPem);
    const privatePublicKey = createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
    const certificateKey = certificate.publicKey.export({ type: 'spki', format: 'der' });
    if (!certificateKey.equals(privatePublicKey)) {
      errors.push('Edge Redis server certificate and private key do not match');
    }
  } catch (error) {
    errors.push(`Edge Redis TLS identity is invalid: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function validateEdgeGateway(environmentFile, environment, secretDirectory, errors) {
  const enabled = environment.get('OTTO_EDGE_ENABLED') === 'true';
  if (!enabled) return false;
  const configDirectoryValue = environment.get('OTTO_EDGE_CONFIG_DIR')?.trim();
  const providerDirectoryValue = environment.get('OTTO_EDGE_PROVIDER_SECRETS_DIR')?.trim();
  if (!configDirectoryValue) errors.push('OTTO_EDGE_CONFIG_DIR is required when Edge Gateway is enabled');
  if (!providerDirectoryValue) {
    errors.push('OTTO_EDGE_PROVIDER_SECRETS_DIR is required when Edge Gateway is enabled');
  }
  const configDirectory = isAbsolute(configDirectoryValue || '')
    ? configDirectoryValue
    : resolve(dirname(environmentFile), configDirectoryValue || 'edge-config');
  const providerDirectory = isAbsolute(providerDirectoryValue || '')
    ? providerDirectoryValue
    : resolve(dirname(environmentFile), providerDirectoryValue || 'edge-provider-secrets');
  for (const [directory, name] of [
    [configDirectory, 'Edge Gateway configuration directory'],
    [providerDirectory, 'Edge Gateway provider-secret directory'],
  ]) {
    try {
      const stat = lstatSync(directory);
      if (stat.isSymbolicLink() || !stat.isDirectory()) {
        errors.push(`${name} must be a real directory`);
      } else if (process.platform !== 'win32' && (stat.mode & 0o077) !== 0) {
        errors.push(`${name} must not be accessible by group/other users`);
      }
    } catch (error) {
      errors.push(`${name} cannot be read: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  const publicKeysText = readRequiredFile(
    resolve(configDirectory, 'control_public_keys.json'), errors,
  );
  const originsText = readRequiredFile(resolve(configDirectory, 'upstream_origins.json'), errors);
  const identityText = readRequiredFile(
    resolve(configDirectory, 'deployment_identity.json'), errors,
  );
  try {
    const publicKeys = JSON.parse(publicKeysText);
    if (!publicKeys || typeof publicKeys !== 'object' || Array.isArray(publicKeys)
      || Object.keys(publicKeys).length < 1
      || Object.values(publicKeys).some((value) => typeof value !== 'string' || !value.trim())) {
      errors.push('Edge Gateway Control public keys are invalid');
    }
  } catch {
    errors.push('Edge Gateway Control public keys must contain JSON');
  }
  const providerBindings = new Set();
  try {
    const origins = JSON.parse(originsText);
    if (!origins || typeof origins !== 'object' || Array.isArray(origins)
      || origins.version !== 2
      || Object.keys(origins).length !== 2
      || !Array.isArray(origins.allowedUpstreams)
      || origins.allowedUpstreams.length < 1
      || origins.allowedUpstreams.length > 256) {
      errors.push('Edge Gateway upstream origins must use non-empty version 2 allowedUpstreams');
    } else {
      for (const upstream of origins.allowedUpstreams) {
        if (!upstream || typeof upstream !== 'object' || Array.isArray(upstream)
          || Object.keys(upstream).length !== 2
          || typeof upstream.origin !== 'string'
          || !Array.isArray(upstream.authentications)
          || upstream.authentications.length < 1) {
          errors.push('Edge Gateway upstream origins contain an invalid rule');
          continue;
        }
        try {
          const origin = new URL(upstream.origin);
          if (origin.protocol !== 'https:' || origin.origin !== upstream.origin
            || origin.username || origin.password) {
            errors.push('Edge Gateway upstream rules require credential-free HTTPS origins');
          }
        } catch {
          errors.push('Edge Gateway upstream origin is invalid');
        }
        for (const authentication of upstream.authentications) {
          const binding = authentication?.secretBinding;
          const expectedFields = authentication?.type === 'bearer'
            ? ['type', 'secretBinding']
            : authentication?.type === 'header'
              ? ['type', 'headerName', 'secretBinding']
              : [];
          if (!authentication || typeof authentication !== 'object'
            || Array.isArray(authentication)
            || expectedFields.length === 0
            || Object.keys(authentication).length !== expectedFields.length
            || Object.keys(authentication).some((field) => !expectedFields.includes(field))
            || typeof binding !== 'string'
            || !/^[A-Z][A-Z0-9_]{2,127}$/u.test(binding)
            || (authentication.type === 'header'
              && (typeof authentication.headerName !== 'string'
                || !/^[a-zA-Z0-9!#$%&'*+.^_`|~-]{1,80}$/u.test(authentication.headerName)))) {
            errors.push('Edge Gateway upstream authentication binding is invalid');
          } else {
            providerBindings.add(binding);
          }
        }
      }
    }
  } catch {
    errors.push('Edge Gateway upstream origins must contain JSON');
  }
  for (const binding of providerBindings) {
    if (environment.get(binding)?.trim()) {
      errors.push(`${binding} must use a file-backed provider secret`);
    }
    const expectedPath = `/run/otto-edge-provider-secrets/${binding}`;
    if (environment.get(`${binding}_FILE`) !== expectedPath) {
      errors.push(`${binding}_FILE must reference ${expectedPath}`);
    }
    const value = readRequiredFile(resolve(providerDirectory, binding), errors);
    if (value && (value.length > 8_192 || !/^[\x21-\x7e]+$/u.test(value))) {
      errors.push(`provider secret ${binding} is invalid`);
    }
  }
  try {
    const identity = JSON.parse(identityText);
    const fields = ['licenseId', 'deploymentId', 'organizationId', 'machineFingerprint'];
    if (!identity || typeof identity !== 'object' || Array.isArray(identity)
      || Object.keys(identity).some((field) => !fields.includes(field))
      || fields.some((field) => typeof identity[field] !== 'string')
      || !/^[a-f0-9]{64}$/u.test(identity.machineFingerprint)) {
      errors.push('Edge Gateway deployment identity is invalid');
    }
  } catch {
    errors.push('Edge Gateway deployment identity must contain JSON');
  }
  const leaseToken = readRequiredFile(resolve(secretDirectory, 'edge_lease_token'), errors);
  if (leaseToken && (leaseToken.length < 32 || leaseToken.length > 8_192 || /\s/u.test(leaseToken))) {
    errors.push('edge_lease_token is invalid');
  }
  for (const name of ['edge_rate_limit_key', 'edge_redis_password', 'edge_operations_token']) {
    const value = readRequiredFile(resolve(secretDirectory, name), errors);
    if (value && value.length < 32) errors.push(`${name} must contain at least 32 characters`);
  }
  const receiptKey = readRequiredFile(
    resolve(secretDirectory, 'edge_execution_receipt_private_key.pem'), errors,
  );
  if (receiptKey) {
    try {
      if (createPrivateKey(receiptKey).asymmetricKeyType !== 'ed25519') {
        errors.push('Edge execution receipt private key must be Ed25519');
      }
    } catch {
      errors.push('Edge execution receipt private key is invalid');
    }
  }
  validateEdgeRedisIdentity(secretDirectory, errors);
  return true;
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
  const allowLocalSigningForTest = deploymentEnvironment === 'production'
    && hasFlag('--allow-local-signing-for-test')
    && process.env.CI === 'true';
  const allowUnmanagedArtifactsForTest = deploymentEnvironment === 'production'
    && hasFlag('--allow-unmanaged-artifacts-for-test')
    && process.env.CI === 'true';
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
  const edgeDomain = requireValue('EDGE_DOMAIN');
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
  if ([controlDomain, federationDomain].includes(edgeDomain)) {
    errors.push('Control, Federation and Edge Gateway domains must differ');
  }

  if (environment.get('CONTROL_DATABASE_SSL') !== 'true') {
    errors.push('CONTROL_DATABASE_SSL must be true');
  }
  if (environment.get('FEDERATION_DATABASE_SSL') !== 'true') {
    errors.push('FEDERATION_DATABASE_SSL must be true');
  }
  if (environment.get('NODE_EXTRA_CA_CERTS') !== '/run/secrets/postgres_tls_ca') {
    errors.push('NODE_EXTRA_CA_CERTS must trust the mounted PostgreSQL CA');
  }
  if (environment.get('CONTROL_SIGNER_KEYRING_FILE')
    !== '/run/otto-runtime-secrets/control_signer_keyring.json') {
    errors.push('CONTROL_SIGNER_KEYRING_FILE must reference the staged signing keyring');
  }
  if (environment.get('CONTROL_SIGNER_PRIVATE_KEY_FILE')?.trim()) {
    errors.push('CONTROL_SIGNER_PRIVATE_KEY_FILE must not be used by production Compose');
  }

  const forbiddenInlineSecrets = [
    'CONTROL_ADMIN_TOKEN',
    'CONTROL_TOKEN_SECRET',
    'CONTROL_METRICS_TOKEN',
    'CONTROL_DATABASE_PASSWORD',
    'FEDERATION_ADMIN_TOKEN',
    'FEDERATION_METRICS_TOKEN',
    'FEDERATION_DATABASE_PASSWORD',
    'CONTROL_ARTIFACT_S3_ACCESS_KEY_ID',
    'CONTROL_ARTIFACT_S3_SECRET_ACCESS_KEY',
    'CONTROL_ARTIFACT_S3_SESSION_TOKEN',
  ];
  for (const name of forbiddenInlineSecrets) {
    if (environment.get(name)?.trim()) errors.push(`${name} must use a file-backed secret instead`);
  }

  const secretDirectoryValue = requireValue('OTTO_CONTROL_SECRETS_DIR');
  const secretDirectory = isAbsolute(secretDirectoryValue)
    ? secretDirectoryValue
    : resolve(dirname(environmentFile), secretDirectoryValue);
  const signingDirectoryValue = requireValue('OTTO_CONTROL_SIGNING_DIR');
  const signingDirectory = isAbsolute(signingDirectoryValue)
    ? signingDirectoryValue
    : resolve(dirname(environmentFile), signingDirectoryValue);
  const attestationDirectoryValue = requireValue('OTTO_CONTROL_ATTESTATION_DIR');
  const attestationDirectory = isAbsolute(attestationDirectoryValue)
    ? attestationDirectoryValue
    : resolve(dirname(environmentFile), attestationDirectoryValue);
  try {
    const signingStat = lstatSync(signingDirectory);
    if (signingStat.isSymbolicLink() || !signingStat.isDirectory()) {
      errors.push(`${signingDirectory} must be a real directory`);
    } else if (process.platform !== 'win32' && (signingStat.mode & 0o077) !== 0) {
      errors.push(`${signingDirectory} must not be accessible by group/other users`);
    }
  } catch (error) {
    errors.push(`${signingDirectory} cannot be read: ${error instanceof Error ? error.message : String(error)}`);
  }
  try {
    const attestationStat = lstatSync(attestationDirectory);
    if (attestationStat.isSymbolicLink() || !attestationStat.isDirectory()) {
      errors.push(`${attestationDirectory} must be a real directory`);
    } else if (process.platform !== 'win32' && (attestationStat.mode & 0o077) !== 0) {
      errors.push(`${attestationDirectory} must not be accessible by group/other users`);
    }
  } catch (error) {
    errors.push(
      `${attestationDirectory} cannot be read: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
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
  validateSigningIdentity(
    signingDirectory,
    deploymentEnvironment,
    allowLocalSigningForTest,
    errors,
  );
  validatePostgresIdentity(secretDirectory, errors);
  const edgeEnabled = validateEdgeGateway(
    environmentFile, environment, secretDirectory, errors,
  );

  const federationAttachmentStorageRequired =
    environment.get('FEDERATION_ATTACHMENT_STORAGE_REQUIRED') === 'true';
  if (
    deploymentEnvironment === 'production' &&
    !federationAttachmentStorageRequired &&
    !allowUnmanagedArtifactsForTest
  ) {
    errors.push('production must require federation attachment object storage');
  }
  if (federationAttachmentStorageRequired) {
    const endpointValue = requireValue('FEDERATION_ATTACHMENT_S3_ENDPOINT');
    const bucketValue = requireValue('FEDERATION_ATTACHMENT_S3_BUCKET');
    try {
      const endpoint = new URL(endpointValue);
      if (
        endpoint.protocol !== 'https:' || endpoint.username || endpoint.password ||
        endpoint.search || endpoint.hash
      ) {
        errors.push('FEDERATION_ATTACHMENT_S3_ENDPOINT must be a credential-free HTTPS origin');
      }
    } catch {
      errors.push('FEDERATION_ATTACHMENT_S3_ENDPOINT is invalid');
    }
    if (!/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/u.test(bucketValue)) {
      errors.push('FEDERATION_ATTACHMENT_S3_BUCKET is invalid');
    }
    for (const [name, expectedPath, localName] of [
      ['FEDERATION_ATTACHMENT_S3_ACCESS_KEY_ID_FILE', '/run/secrets/artifact_s3_access_key_id', 'artifact_s3_access_key_id'],
      ['FEDERATION_ATTACHMENT_S3_SECRET_ACCESS_KEY_FILE', '/run/secrets/artifact_s3_secret_access_key', 'artifact_s3_secret_access_key'],
    ]) {
      if (environment.get(name) !== expectedPath) {
        errors.push(`${name} must reference the Compose file-backed secret`);
      }
      readRequiredFile(resolve(secretDirectory, localName), errors);
    }
  }

  const artifactStorageRequired = environment.get('CONTROL_ARTIFACT_STORAGE_REQUIRED') === 'true';
  const unmanagedArtifactsTestMarker = environment.get('CI') === 'true'
    && environment.get('CONTROL_ALLOW_UNMANAGED_ARTIFACTS_FOR_TESTS') === 'true';
  if (unmanagedArtifactsTestMarker !== allowUnmanagedArtifactsForTest) {
    errors.push('unmanaged release artifact bypass must be generated and approved by CI explicitly');
  }
  if (deploymentEnvironment === 'production'
    && !artifactStorageRequired
    && !allowUnmanagedArtifactsForTest) {
    errors.push('production must require managed, signed release artifact storage');
  }
  if (artifactStorageRequired) {
    const artifactEndpoint = requireValue('CONTROL_ARTIFACT_S3_ENDPOINT');
    const artifactBucket = requireValue('CONTROL_ARTIFACT_S3_BUCKET');
    if (!/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/u.test(artifactBucket)) {
      errors.push('CONTROL_ARTIFACT_S3_BUCKET is invalid');
    }
    try {
      const endpoint = new URL(artifactEndpoint);
      if (endpoint.protocol !== 'https:' || endpoint.username || endpoint.password
        || endpoint.search || endpoint.hash) {
        errors.push('CONTROL_ARTIFACT_S3_ENDPOINT must be a credential-free HTTPS origin');
      }
    } catch {
      errors.push('CONTROL_ARTIFACT_S3_ENDPOINT is invalid');
    }
    const cdnValue = environment.get('CONTROL_ARTIFACT_CDN_BASE_URL')?.trim();
    if (cdnValue) {
      try {
        const cdn = new URL(cdnValue);
        if (cdn.protocol !== 'https:' || cdn.username || cdn.password || cdn.search || cdn.hash) {
          errors.push('CONTROL_ARTIFACT_CDN_BASE_URL must be a credential-free HTTPS origin');
        }
      } catch {
        errors.push('CONTROL_ARTIFACT_CDN_BASE_URL is invalid');
      }
    }
    if (environment.get('CONTROL_ARTIFACT_S3_OBJECT_LOCK_REQUIRED') !== 'true') {
      errors.push('production release artifacts must require S3 Object Lock');
    }
    const expectedArtifactFiles = [
      ['CONTROL_ARTIFACT_S3_ACCESS_KEY_ID_FILE', '/run/secrets/artifact_s3_access_key_id', 'artifact_s3_access_key_id'],
      ['CONTROL_ARTIFACT_S3_SECRET_ACCESS_KEY_FILE', '/run/secrets/artifact_s3_secret_access_key', 'artifact_s3_secret_access_key'],
    ];
    for (const [name, expectedPath, localName] of expectedArtifactFiles) {
      if (environment.get(name) !== expectedPath) {
        errors.push(`${name} must reference the Compose file-backed secret`);
      }
      readRequiredFile(resolve(secretDirectory, localName), errors);
    }
    if (environment.get('CONTROL_ARTIFACT_S3_SESSION_TOKEN_FILE')?.trim()) {
      if (environment.get('CONTROL_ARTIFACT_S3_SESSION_TOKEN_FILE')
        !== '/run/secrets/artifact_s3_session_token') {
        errors.push('CONTROL_ARTIFACT_S3_SESSION_TOKEN_FILE must reference its Compose secret');
      }
      readRequiredFile(resolve(secretDirectory, 'artifact_s3_session_token'), errors);
    }
    if (environment.get('CONTROL_ARTIFACT_ATTESTATION_KEYS_FILE')
      !== '/run/otto-attestations/artifact_attestation_keyring.json') {
      errors.push('CONTROL_ARTIFACT_ATTESTATION_KEYS_FILE must reference the read-only attestation keyring');
    }
    validateArtifactAttestationIdentity(attestationDirectory, errors);
  }

  if (deploymentEnvironment === 'production') {
    if (reservedHostname(controlDomain)
      || reservedHostname(federationDomain)
      || reservedHostname(edgeDomain)) {
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
      await validateDns([
        controlUrl.hostname,
        federationUrl.hostname,
        ...(edgeEnabled ? [edgeDomain] : []),
      ], errors);
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
      if (edgeEnabled) {
        run('docker', [
          'compose',
          '-f', resolve(repositoryRoot, 'compose.production.yaml'),
          '--env-file', environmentFile,
          '--profile', 'edge',
          'config', '--quiet',
        ]);
      }
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
    `Deployment preflight passed for ${deploymentEnvironment}: ${controlDomain}, ${federationDomain}, Edge Gateway ${edgeEnabled ? edgeDomain : 'disabled'}\n`,
  );
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});

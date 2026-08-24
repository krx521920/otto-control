import { createPublicKey, generateKeyPairSync, randomBytes } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

function option(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function hasFlag(name) {
  return process.argv.includes(name);
}

function awsKmsSigningKeyArns() {
  const raw = option('--aws-kms-key-arns')?.trim();
  if (!raw) return [];
  const arns = raw.split(',').map((value) => value.trim()).filter(Boolean);
  const pattern = /^arn:(aws|aws-cn|aws-us-gov):kms:([a-z0-9-]{3,32}):(\d{12}):key\/(mrk-[a-f0-9]{32}|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$/u;
  const parsed = arns.map((arn) => ({ arn, match: pattern.exec(arn) }));
  if (arns.length < 1 || arns.length > 3 || parsed.some((entry) => !entry.match)) {
    throw new Error('--aws-kms-key-arns must contain one to three immutable AWS KMS key ARNs');
  }
  if (new Set(arns).size !== arns.length) {
    throw new Error('--aws-kms-key-arns must not contain duplicate ARNs');
  }
  if (parsed.length > 1) {
    const identities = parsed.map(({ match }) => `${match[1]}:${match[3]}:${match[4]}`);
    const regions = parsed.map(({ match }) => match[2]);
    if (!parsed.every(({ match }) => match[4].startsWith('mrk-'))
      || new Set(identities).size !== 1
      || new Set(regions).size !== regions.length) {
      throw new Error('--aws-kms-key-arns replicas must be one multi-Region key in distinct regions');
    }
  }
  return arns;
}

function requiredPublicUrl() {
  const raw = option('--public-url');
  if (!raw) {
    throw new Error(
      'usage: npm run bootstrap:production -- --environment production --public-url https://control.example.com',
    );
  }
  const url = new URL(raw);
  if (url.protocol !== 'https:' || url.pathname !== '/' || url.search || url.hash) {
    throw new Error('--public-url must be an HTTPS origin without a path, query, or fragment');
  }
  return url;
}

function federationPublicUrl(controlUrl) {
  const raw = option('--federation-public-url');
  const url = raw ? new URL(raw) : new URL(`https://federation.${controlUrl.hostname}`);
  if (url.protocol !== 'https:' || url.pathname !== '/' || url.search || url.hash) {
    throw new Error('--federation-public-url must be an HTTPS origin without a path, query, or fragment');
  }
  return url;
}

function deploymentEnvironment() {
  const value = option('--environment')?.trim() || 'production';
  if (value !== 'staging' && value !== 'production') {
    throw new Error('--environment must be staging or production');
  }
  return value;
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

function requiredProductionOption(name, environment, fallback) {
  const value = option(name)?.trim() || fallback?.trim();
  if (environment === 'production' && !value) {
    throw new Error(`${name} is required for production deployments`);
  }
  return value || '';
}

function requiredInputFile(flag, environmentName) {
  const path = option(flag)?.trim() || process.env[environmentName]?.trim();
  if (!path) throw new Error(`${flag} is required when release artifact storage is enabled`);
  let value = '';
  try {
    value = readFileSync(resolve(path), 'utf8').trim();
  } catch {
    throw new Error(`${flag} could not be read`);
  }
  if (!value) throw new Error(`${flag} must not be empty`);
  return value;
}

function artifactStorageConfiguration(environmentName, allowUnmanagedForTest) {
  const endpointValue = option('--artifact-s3-endpoint')?.trim()
    || process.env.CONTROL_ARTIFACT_S3_ENDPOINT?.trim();
  if (!endpointValue) {
    if (environmentName === 'production' && !allowUnmanagedForTest) {
      throw new Error(
        'production requires --artifact-s3-endpoint and signed release artifact storage; '
        + 'only CI may use --allow-unmanaged-artifacts-for-test',
      );
    }
    return null;
  }
  let endpoint;
  try {
    endpoint = new URL(endpointValue);
  } catch {
    throw new Error('--artifact-s3-endpoint must be an absolute URL');
  }
  if ((environmentName === 'production' && endpoint.protocol !== 'https:')
    || !['https:', 'http:'].includes(endpoint.protocol)
    || endpoint.username
    || endpoint.password
    || endpoint.search
    || endpoint.hash) {
    throw new Error('--artifact-s3-endpoint must be a credential-free HTTPS origin in production');
  }
  const bucket = option('--artifact-s3-bucket')?.trim()
    || process.env.CONTROL_ARTIFACT_S3_BUCKET?.trim()
    || '';
  if (!/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/u.test(bucket)) {
    throw new Error('--artifact-s3-bucket is invalid');
  }
  const region = option('--artifact-s3-region')?.trim()
    || process.env.CONTROL_ARTIFACT_S3_REGION?.trim()
    || 'us-east-1';
  if (!/^[a-z0-9-]{3,40}$/u.test(region)) throw new Error('--artifact-s3-region is invalid');
  const cdnValue = option('--artifact-cdn-base-url')?.trim()
    || process.env.CONTROL_ARTIFACT_CDN_BASE_URL?.trim()
    || '';
  let cdnBaseUrl = '';
  if (cdnValue) {
    let cdn;
    try {
      cdn = new URL(cdnValue);
    } catch {
      throw new Error('--artifact-cdn-base-url must be an absolute URL');
    }
    if (cdn.protocol !== 'https:' || cdn.username || cdn.password || cdn.search || cdn.hash) {
      throw new Error('--artifact-cdn-base-url must be a credential-free HTTPS origin');
    }
    cdnBaseUrl = cdn.toString().replace(/\/$/u, '');
  }
  const attestationKeyId = option('--artifact-attestation-key-id')?.trim()
    || process.env.CONTROL_ARTIFACT_ATTESTATION_KEY_ID?.trim()
    || '';
  if (!/^[a-zA-Z0-9_.-]{3,64}$/u.test(attestationKeyId)) {
    throw new Error('--artifact-attestation-key-id is invalid');
  }
  const attestationPublicKey = requiredInputFile(
    '--artifact-attestation-public-key-file',
    'CONTROL_ARTIFACT_ATTESTATION_PUBLIC_KEY_FILE',
  );
  try {
    if (createPublicKey(attestationPublicKey).asymmetricKeyType !== 'ed25519') {
      throw new Error('not Ed25519');
    }
  } catch {
    throw new Error('--artifact-attestation-public-key-file must contain an Ed25519 public key');
  }
  const sessionTokenPath = option('--artifact-s3-session-token-file')?.trim()
    || process.env.CONTROL_ARTIFACT_S3_SESSION_TOKEN_SOURCE_FILE?.trim();
  return {
    endpoint: endpoint.toString().replace(/\/$/u, ''),
    bucket,
    region,
    cdnBaseUrl,
    accessKeyId: requiredInputFile(
      '--artifact-s3-access-key-id-file',
      'CONTROL_ARTIFACT_S3_ACCESS_KEY_ID_SOURCE_FILE',
    ),
    secretAccessKey: requiredInputFile(
      '--artifact-s3-secret-access-key-file',
      'CONTROL_ARTIFACT_S3_SECRET_ACCESS_KEY_SOURCE_FILE',
    ),
    sessionToken: sessionTokenPath
      ? requiredInputFile(
          '--artifact-s3-session-token-file',
          'CONTROL_ARTIFACT_S3_SESSION_TOKEN_SOURCE_FILE',
        )
      : null,
    attestationKeyId,
    attestationPublicKey,
  };
}

function writeSecret(path, value) {
  writeFileSync(path, `${value}\n`, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
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

function createPostgresTlsIdentity(secretDirectory) {
  const temporaryDirectory = mkdtempSync(join(tmpdir(), 'otto-control-postgres-tls-'));
  try {
    const caKey = join(temporaryDirectory, 'postgres_tls_ca_private_key.pem');
    const caCertificate = join(temporaryDirectory, 'postgres_tls_ca.pem');
    const serverKey = join(temporaryDirectory, 'postgres_tls_key.pem');
    const serverRequest = join(temporaryDirectory, 'postgres_tls.csr');
    const serverCertificate = join(temporaryDirectory, 'postgres_tls_cert.pem');
    const extensions = join(temporaryDirectory, 'postgres_tls.ext');
    const openSslConfiguration = join(temporaryDirectory, 'openssl.cnf');
    writeFileSync(openSslConfiguration, [
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
      'subjectAltName=DNS:postgres-router,DNS:postgres-1,DNS:postgres-2,DNS:postgres-3,DNS:localhost,IP:127.0.0.1,IP:::1',
      '',
    ].join('\n'), { encoding: 'utf8', mode: 0o600 });
    runOpenSsl([
      'req', '-x509', '-newkey', 'rsa:3072', '-sha256', '-nodes', '-days', '3650',
      '-config', openSslConfiguration,
      '-extensions', 'v3_ca',
      '-subj', '/CN=Otto Control PostgreSQL CA', '-keyout', caKey, '-out', caCertificate,
    ], temporaryDirectory);
    runOpenSsl([
      'req', '-new', '-newkey', 'rsa:3072', '-sha256', '-nodes',
      '-config', openSslConfiguration,
      '-subj', '/CN=postgres-router', '-keyout', serverKey, '-out', serverRequest,
    ], temporaryDirectory);
    runOpenSsl([
      'x509', '-req', '-in', serverRequest, '-CA', caCertificate, '-CAkey', caKey,
      '-CAcreateserial', '-out', serverCertificate, '-days', '825', '-sha256',
      '-extfile', extensions,
    ], temporaryDirectory);
    for (const file of [
      'postgres_tls_ca_private_key.pem',
      'postgres_tls_ca.pem',
      'postgres_tls_key.pem',
      'postgres_tls_cert.pem',
    ]) {
      writeSecret(resolve(secretDirectory, file), readFileSync(join(temporaryDirectory, file), 'utf8').trim());
    }
  } finally {
    rmSync(temporaryDirectory, { recursive: true, force: true });
  }
}

function main() {
  const environmentName = deploymentEnvironment();
  const kmsKeyArns = awsKmsSigningKeyArns();
  const allowLocalSigningForTest = environmentName === 'production'
    && hasFlag('--allow-local-signing-for-test')
    && process.env.CI === 'true';
  const allowUnmanagedArtifactsForTest = environmentName === 'production'
    && hasFlag('--allow-unmanaged-artifacts-for-test')
    && process.env.CI === 'true';
  const publicUrl = requiredPublicUrl();
  const federationUrl = federationPublicUrl(publicUrl);
  const edgeUrl = new URL(`https://edge.${publicUrl.hostname}`);
  if (publicUrl.hostname === federationUrl.hostname) {
    throw new Error('Control and Federation must use different public hostnames');
  }
  if (environmentName === 'production'
    && (reservedHostname(publicUrl.hostname)
      || reservedHostname(federationUrl.hostname)
      || reservedHostname(edgeUrl.hostname))) {
    throw new Error('production deployments cannot use localhost or reserved example/test domains');
  }
  if (environmentName === 'production' && kmsKeyArns.length === 0 && !allowLocalSigningForTest) {
    throw new Error(
      'production requires --aws-kms-key-arns; local signing is available only to CI with --allow-local-signing-for-test',
    );
  }
  const artifactStorage = artifactStorageConfiguration(
    environmentName,
    allowUnmanagedArtifactsForTest,
  );
  const acmeEmail = requiredProductionOption('--acme-email', environmentName, process.env.ACME_EMAIL);
  const privacyController = requiredProductionOption(
    '--privacy-controller',
    environmentName,
    process.env.CONTROL_PRIVACY_CONTROLLER,
  );
  const privacyContact = requiredProductionOption(
    '--privacy-contact',
    environmentName,
    process.env.CONTROL_PRIVACY_CONTACT,
  );
  const dataRegion = requiredProductionOption(
    '--data-region',
    environmentName,
    process.env.CONTROL_DATA_REGION,
  ) || 'CN-BJ';
  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/u;
  if (acmeEmail && !emailPattern.test(acmeEmail)) {
    throw new Error('--acme-email must be a valid email address');
  }
  if (privacyContact && !emailPattern.test(privacyContact)) {
    throw new Error('--privacy-contact must be a valid email address');
  }
  if (!/^[A-Z]{2}(?:-[A-Z0-9]{2,8})+$/u.test(dataRegion)) {
    throw new Error('--data-region must be an explicit region code such as CN-BJ');
  }
  const root = resolve(option('--output') ?? '.');
  const environmentFileName = `.env.${environmentName}`;
  const secretDirectoryName = environmentName === 'production' ? 'secrets' : 'secrets-staging';
  const signingDirectoryName = environmentName === 'production' ? 'signing' : 'signing-staging';
  const attestationDirectoryName = environmentName === 'production'
    ? 'attestations'
    : 'attestations-staging';
  const backupDirectoryName = environmentName === 'production' ? 'backups' : 'backups-staging';
  const edgeConfigDirectoryName = environmentName === 'production'
    ? 'edge-config'
    : 'edge-config-staging';
  const edgeProviderSecretDirectoryName = environmentName === 'production'
    ? 'edge-provider-secrets'
    : 'edge-provider-secrets-staging';
  const secretDirectory = resolve(root, secretDirectoryName);
  const signingDirectory = resolve(root, signingDirectoryName);
  const attestationDirectory = resolve(root, attestationDirectoryName);
  const edgeConfigDirectory = resolve(root, edgeConfigDirectoryName);
  const edgeProviderSecretDirectory = resolve(root, edgeProviderSecretDirectoryName);
  const targets = [
    resolve(root, environmentFileName),
    resolve(signingDirectory, 'control_signer_keyring.json'),
    ...(kmsKeyArns.length === 0
      ? [resolve(signingDirectory, 'control_signer_private_key.pem')]
      : []),
    resolve(secretDirectory, 'control_admin_token'),
    resolve(secretDirectory, 'control_token_secret'),
    resolve(secretDirectory, 'control_metrics_token'),
    resolve(secretDirectory, 'federation_admin_token'),
    resolve(secretDirectory, 'federation_metrics_token'),
    resolve(secretDirectory, 'postgres_password'),
    resolve(secretDirectory, 'edge_ledger_postgres_password'),
    resolve(secretDirectory, 'postgres_superuser_password'),
    resolve(secretDirectory, 'postgres_replication_password'),
    resolve(secretDirectory, 'pgbackrest_cipher_pass'),
    resolve(secretDirectory, 'backup_encryption_key'),
    resolve(secretDirectory, 'alert_webhook_secret'),
    resolve(secretDirectory, 'audit_anchor_token'),
    resolve(secretDirectory, 'artifact_s3_access_key_id'),
    resolve(secretDirectory, 'artifact_s3_secret_access_key'),
    resolve(secretDirectory, 'artifact_s3_session_token'),
    resolve(secretDirectory, 'postgres_tls_ca_private_key.pem'),
    resolve(secretDirectory, 'postgres_tls_ca.pem'),
    resolve(secretDirectory, 'postgres_tls_key.pem'),
    resolve(secretDirectory, 'postgres_tls_cert.pem'),
    ...(artifactStorage
      ? [
          resolve(attestationDirectory, 'artifact_attestation_keyring.json'),
          resolve(attestationDirectory, 'artifact_attestation_public_key.pem'),
        ]
      : []),
  ];
  const existing = targets.find(existsSync);
  if (existing) throw new Error(`refusing to overwrite existing deployment identity file: ${existing}`);
  if (existsSync(signingDirectory) && readdirSync(signingDirectory).length > 0) {
    throw new Error(`refusing to reuse non-empty signing directory: ${signingDirectory}`);
  }
  if (existsSync(attestationDirectory) && readdirSync(attestationDirectory).length > 0) {
    throw new Error(`refusing to reuse non-empty attestation directory: ${attestationDirectory}`);
  }
  mkdirSync(secretDirectory, { recursive: true, mode: 0o700 });
  mkdirSync(signingDirectory, { recursive: true, mode: 0o700 });
  mkdirSync(attestationDirectory, { recursive: true, mode: 0o700 });
  mkdirSync(edgeConfigDirectory, { recursive: true, mode: 0o700 });
  mkdirSync(edgeProviderSecretDirectory, { recursive: true, mode: 0o700 });
  mkdirSync(resolve(root, backupDirectoryName), { recursive: true, mode: 0o700 });
  const backupReportDirectory = resolve(root, backupDirectoryName, 'reports');
  mkdirSync(backupReportDirectory, { recursive: true, mode: 0o755 });
  chmodSync(backupReportDirectory, 0o755);

  const keyring = kmsKeyArns.length > 0
    ? {
        version: 1,
        keys: [{
          provider: 'kms',
          backend: 'aws_kms',
          keyArns: kmsKeyArns,
          timeoutMs: 5_000,
          validateSignPermission: true,
        }],
      }
    : (() => {
        const { privateKey } = generateKeyPairSync('ed25519');
        writeSecret(
          resolve(signingDirectory, 'control_signer_private_key.pem'),
          privateKey.export({ type: 'pkcs8', format: 'pem' }),
        );
        return {
          version: 1,
          keys: [{
            provider: 'local',
            privateKeyFile: 'control_signer_private_key.pem',
          }],
        };
      })();
  writeSecret(
    resolve(signingDirectory, 'control_signer_keyring.json'),
    JSON.stringify(keyring, null, 2),
  );
  writeSecret(resolve(secretDirectory, 'control_admin_token'), randomBytes(48).toString('base64url'));
  writeSecret(resolve(secretDirectory, 'control_token_secret'), randomBytes(48).toString('base64url'));
  writeSecret(resolve(secretDirectory, 'control_metrics_token'), randomBytes(48).toString('base64url'));
  writeSecret(resolve(secretDirectory, 'federation_admin_token'), randomBytes(48).toString('base64url'));
  writeSecret(resolve(secretDirectory, 'federation_metrics_token'), randomBytes(48).toString('base64url'));
  writeSecret(resolve(secretDirectory, 'postgres_password'), randomBytes(48).toString('base64url'));
  writeSecret(
    resolve(secretDirectory, 'edge_ledger_postgres_password'),
    randomBytes(48).toString('base64url'),
  );
  writeSecret(
    resolve(secretDirectory, 'postgres_superuser_password'),
    randomBytes(48).toString('base64url'),
  );
  writeSecret(
    resolve(secretDirectory, 'postgres_replication_password'),
    randomBytes(48).toString('base64url'),
  );
  writeSecret(
    resolve(secretDirectory, 'pgbackrest_cipher_pass'),
    randomBytes(48).toString('base64url'),
  );
  writeSecret(resolve(secretDirectory, 'backup_encryption_key'), randomBytes(48).toString('base64url'));
  writeSecret(resolve(secretDirectory, 'alert_webhook_secret'), randomBytes(48).toString('base64url'));
  writeSecret(resolve(secretDirectory, 'audit_anchor_token'), randomBytes(48).toString('base64url'));
  writeSecret(
    resolve(secretDirectory, 'artifact_s3_access_key_id'),
    artifactStorage?.accessKeyId ?? 'disabled-for-this-deployment',
  );
  writeSecret(
    resolve(secretDirectory, 'artifact_s3_secret_access_key'),
    artifactStorage?.secretAccessKey ?? 'disabled-for-this-deployment',
  );
  writeSecret(
    resolve(secretDirectory, 'artifact_s3_session_token'),
    artifactStorage?.sessionToken ?? 'disabled-for-this-deployment',
  );
  if (artifactStorage) {
    writeSecret(
      resolve(attestationDirectory, 'artifact_attestation_public_key.pem'),
      artifactStorage.attestationPublicKey,
    );
    writeSecret(
      resolve(attestationDirectory, 'artifact_attestation_keyring.json'),
      JSON.stringify({
        version: 1,
        keys: [{
          id: artifactStorage.attestationKeyId,
          publicKeyFile: 'artifact_attestation_public_key.pem',
        }],
      }, null, 2),
    );
  }
  createPostgresTlsIdentity(secretDirectory);

  const environment = [
    'NODE_ENV=production',
    `CI=${allowUnmanagedArtifactsForTest ? 'true' : ''}`,
    `CONTROL_ALLOW_UNMANAGED_ARTIFACTS_FOR_TESTS=${allowUnmanagedArtifactsForTest ? 'true' : 'false'}`,
    `OTTO_CONTROL_DEPLOYMENT_ENVIRONMENT=${environmentName}`,
    `OTTO_CONTROL_STACK_NAME=otto-control-${environmentName}`,
    `OTTO_CONTROL_ENV_FILE=${environmentFileName}`,
    `OTTO_CONTROL_SECRETS_DIR=./${secretDirectoryName}`,
    `OTTO_CONTROL_SIGNING_DIR=./${signingDirectoryName}`,
    `OTTO_CONTROL_ATTESTATION_DIR=./${attestationDirectoryName}`,
    `OTTO_CONTROL_BACKUP_DIR=./${backupDirectoryName}`,
    `OTTO_EDGE_CONFIG_DIR=./${edgeConfigDirectoryName}`,
    `OTTO_EDGE_PROVIDER_SECRETS_DIR=./${edgeProviderSecretDirectoryName}`,
    'OTTO_EDGE_ENABLED=false',
    'OTTO_EDGE_IMAGE=otto-control-edge:local',
    'OTTO_EDGE_REDIS_IMAGE=redis:7.4-alpine',
    'OTTO_EDGE_LOG_MAX_SIZE=20m',
    'OTTO_EDGE_LOG_MAX_FILES=5',
    'OTTO_CONTROL_VERSION=0.34.0',
    `ACME_EMAIL=${acmeEmail || `operations@${publicUrl.hostname}`}`,
    `ACME_CA=${environmentName === 'production'
      ? 'https://acme-v02.api.letsencrypt.org/directory'
      : 'https://acme-staging-v02.api.letsencrypt.org/directory'}`,
    'CONTROL_HOST=0.0.0.0',
    'CONTROL_PORT=7788',
    'CONTROL_LOG_LEVEL=info',
    'CONTROL_TRUST_PROXY=true',
    `CONTROL_PUBLIC_BASE_URL=${publicUrl.origin}`,
    `CONTROL_DOMAIN=${publicUrl.hostname}`,
    `FEDERATION_DOMAIN=${federationUrl.hostname}`,
    `EDGE_DOMAIN=${edgeUrl.hostname}`,
    `FEDERATION_PUBLIC_BASE_URL=${federationUrl.origin}`,
    'FEDERATION_HOST=0.0.0.0',
    'FEDERATION_PORT=7790',
    'FEDERATION_LOG_LEVEL=info',
    'FEDERATION_TRUST_PROXY=true',
    'FEDERATION_DATABASE_HOST=postgres-router',
    'FEDERATION_DATABASE_PORT=5432',
    'FEDERATION_DATABASE_NAME=otto_control',
    'FEDERATION_DATABASE_USER=otto_control',
    'FEDERATION_DATABASE_PASSWORD_FILE=/run/secrets/postgres_password',
    'FEDERATION_DATABASE_SSL=true',
    'FEDERATION_ADMIN_TOKEN_FILE=/run/secrets/federation_admin_token',
    'FEDERATION_METRICS_TOKEN_FILE=/run/secrets/federation_metrics_token',
    'FEDERATION_MAX_CIPHERTEXT_BYTES=1048576',
    'FEDERATION_MAX_CLAIM_BYTES=4194304',
    'FEDERATION_MAX_ENVELOPE_TTL_MS=604800000',
    'FEDERATION_MAX_CLOCK_SKEW_MS=300000',
    'FEDERATION_CLAIM_TTL_MS=60000',
    'FEDERATION_CLEANUP_INTERVAL_MS=60000',
    'FEDERATION_DELIVERED_RETENTION_MS=604800000',
    'FEDERATION_MAX_ATTACHMENT_BYTES=1073741824',
    `FEDERATION_ATTACHMENT_STORAGE_REQUIRED=${artifactStorage ? 'true' : 'false'}`,
    `FEDERATION_ATTACHMENT_S3_ENDPOINT=${artifactStorage?.endpoint ?? ''}`,
    `FEDERATION_ATTACHMENT_S3_BUCKET=${artifactStorage?.bucket ?? ''}`,
    `FEDERATION_ATTACHMENT_S3_REGION=${artifactStorage?.region ?? 'us-east-1'}`,
    'FEDERATION_ATTACHMENT_S3_PREFIX=otto-federation-attachments',
    'FEDERATION_ATTACHMENT_S3_FORCE_PATH_STYLE=true',
    `FEDERATION_ATTACHMENT_S3_ACCESS_KEY_ID_FILE=${artifactStorage ? '/run/secrets/artifact_s3_access_key_id' : ''}`,
    `FEDERATION_ATTACHMENT_S3_SECRET_ACCESS_KEY_FILE=${artifactStorage ? '/run/secrets/artifact_s3_secret_access_key' : ''}`,
    `FEDERATION_ATTACHMENT_S3_SESSION_TOKEN_FILE=${artifactStorage?.sessionToken ? '/run/secrets/artifact_s3_session_token' : ''}`,
    'FEDERATION_ATTACHMENT_S3_ENCRYPTION=AES256',
    'FEDERATION_ATTACHMENT_S3_KMS_KEY_ID=',
    'FEDERATION_ATTACHMENT_UPLOAD_TTL_SECONDS=900',
    'FEDERATION_ATTACHMENT_DOWNLOAD_TTL_SECONDS=300',
    'CONTROL_DATABASE_HOST=postgres-router',
    'CONTROL_DATABASE_PORT=5432',
    'CONTROL_DATABASE_NAME=otto_control',
    'CONTROL_DATABASE_USER=otto_control',
    'CONTROL_DATABASE_PASSWORD_FILE=/run/secrets/postgres_password',
    'CONTROL_DATABASE_SSL=true',
    'NODE_EXTRA_CA_CERTS=/run/secrets/postgres_tls_ca',
    'CONTROL_ADMIN_TOKEN_FILE=/run/secrets/control_admin_token',
    'CONTROL_TOKEN_SECRET_FILE=/run/secrets/control_token_secret',
    'CONTROL_METRICS_TOKEN_FILE=/run/secrets/control_metrics_token',
    'CONTROL_SIGNER_KEYRING_FILE=/run/otto-runtime-secrets/control_signer_keyring.json',
    'CONTROL_LEASE_DURATION_MS=600000',
    'CONTROL_TELEMETRY_RETENTION_DAYS=90',
    'CONTROL_UPDATE_POLICY_DURATION_MS=300000',
    `CONTROL_DATA_REGION=${dataRegion}`,
    `CONTROL_ALLOWED_DATA_REGIONS=${process.env.CONTROL_ALLOWED_DATA_REGIONS?.trim() || dataRegion}`,
    'CONTROL_CROSS_BORDER_ENABLED=false',
    'CONTROL_CROSS_BORDER_ASSESSMENT_ID=',
    'CONTROL_PRIVACY_POLICY_VERSION=2026-08-01',
    'CONTROL_PRIVACY_POLICY_EFFECTIVE_AT=2026-08-01T00:00:00.000Z',
    `CONTROL_PRIVACY_CONTROLLER=${privacyController || 'Otto staging operator'}`,
    `CONTROL_PRIVACY_CONTACT=${privacyContact || `privacy@${publicUrl.hostname}`}`,
    'CONTROL_CUSTOMER_ERASURE_GRACE_DAYS=14',
    'CONTROL_PRIVACY_REQUEST_SLA_DAYS=15',
    'CONTROL_BILLING_RETENTION_DAYS=1095',
    'CONTROL_GOVERNANCE_AUDIT_RETENTION_DAYS=2555',
    'CONTROL_DATA_EXPORT_RECORD_RETENTION_DAYS=30',
    'CONTROL_DATA_RETENTION_POLL_INTERVAL_HOURS=24',
    `CONTROL_ARTIFACT_STORAGE_REQUIRED=${artifactStorage ? 'true' : 'false'}`,
    `CONTROL_ARTIFACT_S3_ENDPOINT=${artifactStorage?.endpoint ?? ''}`,
    `CONTROL_ARTIFACT_S3_BUCKET=${artifactStorage?.bucket ?? ''}`,
    `CONTROL_ARTIFACT_S3_REGION=${artifactStorage?.region ?? 'us-east-1'}`,
    'CONTROL_ARTIFACT_S3_PREFIX=otto-releases',
    'CONTROL_ARTIFACT_S3_FORCE_PATH_STYLE=true',
    `CONTROL_ARTIFACT_S3_ACCESS_KEY_ID_FILE=${artifactStorage ? '/run/secrets/artifact_s3_access_key_id' : ''}`,
    `CONTROL_ARTIFACT_S3_SECRET_ACCESS_KEY_FILE=${artifactStorage ? '/run/secrets/artifact_s3_secret_access_key' : ''}`,
    `CONTROL_ARTIFACT_S3_SESSION_TOKEN_FILE=${artifactStorage?.sessionToken ? '/run/secrets/artifact_s3_session_token' : ''}`,
    'CONTROL_ARTIFACT_S3_ENCRYPTION=AES256',
    'CONTROL_ARTIFACT_S3_KMS_KEY_ID=',
    'CONTROL_ARTIFACT_S3_OBJECT_LOCK_REQUIRED=true',
    'CONTROL_ARTIFACT_S3_RETENTION_DAYS=365',
    'CONTROL_ARTIFACT_UPLOAD_TTL_SECONDS=900',
    'CONTROL_ARTIFACT_DOWNLOAD_TTL_SECONDS=300',
    `CONTROL_ARTIFACT_CDN_BASE_URL=${artifactStorage?.cdnBaseUrl ?? ''}`,
    `CONTROL_ARTIFACT_ATTESTATION_KEYS_FILE=${artifactStorage ? '/run/otto-attestations/artifact_attestation_keyring.json' : ''}`,
    'CONTROL_BACKUP_RETENTION_DAYS=30',
    'CONTROL_BACKUP_REPORT_DIR=/var/lib/otto-control/backup-reports',
    'CONTROL_BACKUP_STATUS_MAX_AGE_HOURS=48',
    'CONTROL_ALERT_WEBHOOK_URL=',
    'CONTROL_ALERT_WEBHOOK_SECRET_FILE=',
    'CONTROL_ALERT_POLL_INTERVAL_MS=60000',
    'CONTROL_RECOVERY_ASSURANCE_INTERVAL_MS=900000',
    'CONTROL_ALERT_WEBHOOK_TIMEOUT_MS=10000',
    'CONTROL_ALERT_WEBHOOK_MAX_ATTEMPTS=8',
    'CONTROL_ALERT_RETENTION_DAYS=365',
    'CONTROL_AUDIT_ANCHOR_URL=',
    'CONTROL_AUDIT_ANCHOR_TOKEN_FILE=',
    'CONTROL_AUDIT_ANCHOR_INTERVAL_MS=900000',
    'CONTROL_AUDIT_ANCHOR_POLL_INTERVAL_MS=60000',
    'CONTROL_AUDIT_ANCHOR_TIMEOUT_MS=10000',
    'CONTROL_AUDIT_ANCHOR_MAX_ATTEMPTS=8',
    'CONTROL_AUDIT_WITNESS_SOURCES_FILE=',
    'CONTROL_AUDIT_WORM_REQUIRED=false',
    'CONTROL_AUDIT_WORM_S3_ENDPOINT=',
    'CONTROL_AUDIT_WORM_S3_BUCKET=',
    'CONTROL_AUDIT_WORM_S3_REGION=us-east-1',
    'CONTROL_AUDIT_WORM_S3_PREFIX=otto-audit-witness',
    'CONTROL_AUDIT_WORM_S3_FORCE_PATH_STYLE=true',
    'CONTROL_AUDIT_WORM_S3_ACCESS_KEY_ID_FILE=',
    'CONTROL_AUDIT_WORM_S3_SECRET_ACCESS_KEY_FILE=',
    'CONTROL_AUDIT_WORM_S3_SESSION_TOKEN_FILE=',
    'CONTROL_AUDIT_WORM_S3_ENCRYPTION=AES256',
    'CONTROL_AUDIT_WORM_S3_KMS_KEY_ID=',
    'CONTROL_AUDIT_WORM_S3_LOCK_MODE=COMPLIANCE',
    'CONTROL_AUDIT_WORM_RETENTION_DAYS=2555',
    'CONTROL_AUDIT_WORM_POLL_INTERVAL_MS=30000',
    'CONTROL_AUDIT_WORM_MAX_ATTEMPTS=20',
    'CONTROL_SLOW_REQUEST_THRESHOLD_MS=1000',
    'CONTROL_CAPACITY_SAMPLE_INTERVAL_MS=60000',
    'CONTROL_SLO_AVAILABILITY_TARGET=0.999',
    'CONTROL_SLO_LATENCY_TARGET_MS=500',
    'CONTROL_OTLP_TRACE_ENDPOINT=',
    'CONTROL_OTLP_HEADERS_FILE=',
    'CONTROL_TRACE_SAMPLE_RATIO=0.1',
    'CONTROL_BACKUP_OFFSITE_REQUIRED=false',
    'CONTROL_BACKUP_S3_ENDPOINT=',
    'CONTROL_BACKUP_S3_BUCKET=',
    'CONTROL_BACKUP_S3_REGION=us-east-1',
    'CONTROL_BACKUP_S3_PREFIX=otto-control',
    'CONTROL_BACKUP_S3_ADDRESSING_STYLE=path',
    'CONTROL_BACKUP_S3_ACCESS_KEY_ID_FILE=',
    'CONTROL_BACKUP_S3_SECRET_ACCESS_KEY_FILE=',
    'CONTROL_BACKUP_S3_SESSION_TOKEN_FILE=',
    'CONTROL_BACKUP_S3_MAX_ATTEMPTS=4',
    'CONTROL_BACKUP_S3_TIMEOUT_MS=120000',
    'CONTROL_DRILL_REPORT_RETENTION_DAYS=180',
    'CONTROL_DRILL_MAX_BACKUP_AGE_HOURS=48',
    'CONTROL_PITR_REPORT_RETENTION_DAYS=180',
    'CONTROL_PITR_MAX_BACKUP_AGE_HOURS=24',
    `OTTO_CONTROL_BACKUP_KEY_FILE=./${secretDirectoryName}/backup_encryption_key`,
    'POSTGRES_DB=otto_control',
    'POSTGRES_USER=otto_control',
    'ETCD_IMAGE=quay.io/coreos/etcd:v3.5.21',
    'PROMETHEUS_IMAGE=prom/prometheus:v3.13.0-distroless',
    'PROMETHEUS_RETENTION=30d',
    '',
  ].join('\n');
  writeFileSync(targets[0], environment, {
    encoding: 'utf8',
    flag: 'wx',
    mode: 0o600,
  });

  process.stdout.write(
    `${environmentName} secrets created under ${secretDirectory}; signing configuration created under ${signingDirectory}. Back them up securely before deployment.\n`,
  );
}

try {
  main();
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}

import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

function option(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function requiredPublicUrl() {
  const raw = option('--public-url');
  if (!raw) throw new Error('usage: npm run bootstrap:production -- --public-url https://control.example.com');
  const url = new URL(raw);
  if (url.protocol !== 'https:' || url.pathname !== '/' || url.search || url.hash) {
    throw new Error('--public-url must be an HTTPS origin without a path, query, or fragment');
  }
  return url;
}

function writeSecret(path, value) {
  writeFileSync(path, `${value}\n`, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
}

function main() {
  const publicUrl = requiredPublicUrl();
  const root = resolve(option('--output') ?? '.');
  const secretDirectory = resolve(root, 'secrets');
  const targets = [
    resolve(root, '.env.production'),
    resolve(secretDirectory, 'control_signer_private_key.pem'),
    resolve(secretDirectory, 'control_admin_token'),
    resolve(secretDirectory, 'control_token_secret'),
    resolve(secretDirectory, 'postgres_password'),
  ];
  const existing = targets.find(existsSync);
  if (existing) throw new Error(`refusing to overwrite existing production identity file: ${existing}`);
  mkdirSync(secretDirectory, { recursive: true, mode: 0o700 });

  const { privateKey } = generateKeyPairSync('ed25519');
  writeSecret(
    resolve(secretDirectory, 'control_signer_private_key.pem'),
    privateKey.export({ type: 'pkcs8', format: 'pem' }),
  );
  writeSecret(resolve(secretDirectory, 'control_admin_token'), randomBytes(48).toString('base64url'));
  writeSecret(resolve(secretDirectory, 'control_token_secret'), randomBytes(48).toString('base64url'));
  writeSecret(resolve(secretDirectory, 'postgres_password'), randomBytes(48).toString('base64url'));

  const environment = [
    'NODE_ENV=production',
    'CONTROL_HOST=0.0.0.0',
    'CONTROL_PORT=7788',
    'CONTROL_LOG_LEVEL=info',
    'CONTROL_TRUST_PROXY=true',
    `CONTROL_PUBLIC_BASE_URL=${publicUrl.origin}`,
    `CONTROL_DOMAIN=${publicUrl.hostname}`,
    'CONTROL_DATABASE_HOST=postgres',
    'CONTROL_DATABASE_PORT=5432',
    'CONTROL_DATABASE_NAME=otto_control',
    'CONTROL_DATABASE_USER=otto_control',
    'CONTROL_DATABASE_PASSWORD_FILE=/run/secrets/postgres_password',
    'CONTROL_DATABASE_SSL=false',
    'CONTROL_ADMIN_TOKEN_FILE=/run/secrets/control_admin_token',
    'CONTROL_TOKEN_SECRET_FILE=/run/secrets/control_token_secret',
    'CONTROL_SIGNER_PRIVATE_KEY_FILE=/run/secrets/control_signer_private_key.pem',
    'CONTROL_LEASE_DURATION_MS=600000',
    'CONTROL_TELEMETRY_RETENTION_DAYS=90',
    'CONTROL_UPDATE_POLICY_DURATION_MS=300000',
    'POSTGRES_DB=otto_control',
    'POSTGRES_USER=otto_control',
    '',
  ].join('\n');
  writeFileSync(targets[0], environment, {
    encoding: 'utf8',
    flag: 'wx',
    mode: 0o600,
  });

  process.stdout.write(
    `Production secrets created under ${secretDirectory}. Back them up securely before deployment.\n`,
  );
}

try {
  main();
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}

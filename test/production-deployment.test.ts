import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

function repositoryFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
}

describe('production deployment assets', () => {
  it('runs immutable, least-privilege GitHub quality and container gates', () => {
    const workflow = repositoryFile('.github/workflows/ci.yml');
    expect(workflow).toContain('pull_request:');
    expect(workflow).toContain('push:');
    expect(workflow).toContain('contents: read');
    expect(workflow).toContain('cancel-in-progress: true');
    expect(workflow).toContain('npm ci');
    expect(workflow).toContain('npm run check');
    expect(repositoryFile('package.json')).toContain('node --check scripts/smoke-federation.mjs');
    expect(workflow).toContain('image: postgres:17-alpine');
    expect(workflow).toContain('POSTGRES_DB: otto_control_test');
    expect(workflow).toContain('CONTROL_REQUIRE_POSTGRES_TEST: "true"');
    expect(workflow).toContain('npm run test:postgres');
    expect(workflow).toContain('Prove all Federation instances and encrypted relay are ready');
    expect(workflow).toContain('federation-a federation-b federation-c');
    expect(workflow).toContain('scripts/smoke-federation.mjs');
    expect(workflow).toContain('Prove the edge survives every Control replica failure');
    expect(workflow).toContain('compose.ci.resolved.yaml');
    expect(workflow).toContain('--env-file .env.production --profile ops config');
    expect(workflow).toContain('git diff --check');
    expect(workflow).toContain('needs: [quality, postgres-integration]');
    expect(workflow).toContain('docker build --tag otto-control:ci .');
    expect(workflow).toContain(
      'actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8',
    );
    expect(workflow).toContain(
      'actions/setup-node@a0853c24544627f65ddf259abe73b1d18a591444',
    );
    expect(workflow).not.toMatch(/permissions:\s*write-all/u);
  });

  it('keeps credentials out of the image build context', () => {
    const ignore = repositoryFile('.dockerignore');
    expect(ignore).toContain('secrets');
    expect(ignore).toContain('signing');
    expect(ignore).toContain('.env.*');
    expect(ignore).toContain('*.pem');
    expect(JSON.parse(repositoryFile('deploy/audit-witness-sources.example.json'))).toMatchObject({
      version: 1,
      sources: [{ id: 'primary-control' }],
    });
  });

  it('ships least-privilege native AWS KMS signing and production drills', () => {
    const manifest = JSON.parse(
      repositoryFile('deploy/control_signer_keyring.aws-kms.example.json'),
    );
    expect(manifest).toMatchObject({
      version: 1,
      keys: [{ provider: 'kms', backend: 'aws_kms', validateSignPermission: true }],
    });
    expect(manifest.keys[0].keyArns).toHaveLength(2);
    const policy = JSON.parse(repositoryFile('deploy/aws-kms-signing-policy.example.json'));
    expect(policy.Statement).toEqual(expect.arrayContaining([
      expect.objectContaining({
        Action: ['kms:DescribeKey', 'kms:GetPublicKey'],
      }),
      expect.objectContaining({
        Action: 'kms:Sign',
        Condition: {
          StringEquals: {
            'kms:SigningAlgorithm': 'ED25519_SHA_512',
            'kms:MessageType': 'RAW',
          },
        },
      }),
    ]));
    const serializedPolicy = JSON.stringify(policy);
    expect(serializedPolicy).not.toMatch(/kms:(Create|Disable|ScheduleKeyDeletion|PutKeyPolicy|Decrypt)/u);
    const signer = repositoryFile('src/crypto/aws-kms-ed25519-signer.ts');
    expect(signer).toContain('forbids static credentials');
    expect(signer).toContain("KeySpec !== 'ECC_NIST_EDWARDS25519'");
    expect(signer).toContain("SigningAlgorithm: 'ED25519_SHA_512'");
    expect(signer).toContain('failed in every configured Region');
    const rotation = repositoryFile('scripts/drill-signing-rotation.mjs');
    expect(rotation).toContain('ROTATE_OTTO_SIGNING_KEY');
    expect(rotation).toContain("operation: 'signing_key.activate'");
    expect(rotation).toContain("'x-otto-approval-id': approvalId");
    expect(rotation).toContain('legacyLicenseVerification');
    const revocation = repositoryFile('scripts/drill-signing-revocation.mjs');
    expect(revocation).toContain('REVOKE_OTTO_SIGNING_KEY');
    expect(revocation).toContain("operation: 'signing_key.revoke'");
    expect(revocation).toContain('publicKeyringVerified: true');
    const provider = repositoryFile('scripts/drill-signing-provider.mjs');
    expect(provider).toContain('PROBE_OTTO_SIGNING_PROVIDER');
    expect(provider).toContain('expected active location');
    expect(provider).toContain('minimumFailovers');
    const workflow = repositoryFile('.github/workflows/aws-kms-drill.yml');
    expect(workflow).toContain('id-token: write');
    expect(workflow).toContain('CONTROL_REQUIRE_AWS_KMS_TEST: "true"');
    expect(workflow).toContain('CONTROL_TEST_AWS_KMS_KEY_ARNS: ${{ inputs.kms_key_arns }}');
    expect(workflow).toContain(
      'aws-actions/configure-aws-credentials@d979d5b3a71173a29b74b5b88418bfda9437d885',
    );
    expect(workflow).toContain('role-duration-seconds: 900');
    expect(workflow).not.toContain('AWS_SECRET_ACCESS_KEY:');
    expect(workflow).not.toContain('secrets.AWS_');
    const primaryTemplate = repositoryFile('deploy/aws-kms-primary.template.yaml');
    const replicaTemplate = repositoryFile('deploy/aws-kms-replica.template.yaml');
    const roleTemplate = repositoryFile('deploy/aws-kms-github-role.template.yaml');
    expect(primaryTemplate).toContain('KeySpec: ECC_NIST_EDWARDS25519');
    expect(primaryTemplate).toContain('MultiRegion: true');
    expect(primaryTemplate).toContain('DeletionPolicy: Retain');
    expect(replicaTemplate).toContain('Type: AWS::KMS::ReplicaKey');
    expect(roleTemplate).toContain('sts:AssumeRoleWithWebIdentity');
    expect(roleTemplate).toContain('repo:${GitHubRepository}:environment:${GitHubEnvironment}');
    expect(roleTemplate).not.toMatch(/kms:(CreateKey|DisableKey|ScheduleKeyDeletion|Decrypt)/u);
    const operations = repositoryFile('docs/production-signing-operations.zh-CN.md');
    expect(operations).toContain('密钥负责人 A');
    expect(operations).toContain('drill:signing:revoke');
    expect(operations).toContain('--legacy-license-id');
  });

  it('isolates the HA database plane and hardens every control runtime', () => {
    const compose = repositoryFile('compose.production.yaml');
    expect(compose).toContain('  etcd-1:');
    expect(compose).toContain('  etcd-2:');
    expect(compose).toContain('  etcd-3:');
    expect(compose).toContain('  postgres-1:');
    expect(compose).toContain('  postgres-2:');
    expect(compose).toContain('  postgres-3:');
    expect(compose).toContain('  postgres-router:');
    expect(compose).toContain('name: ${OTTO_CONTROL_STACK_NAME:-otto-control}');
    expect(compose).toContain('${OTTO_CONTROL_SECRETS_DIR:-./secrets}');
    expect(compose).toContain('dockerfile: deploy/postgres-ha/Dockerfile');
    const postgresTools = compose.slice(
      compose.indexOf('  postgres-tools:'),
      compose.indexOf('  postgres-pitr-drill:'),
    );
    expect(postgresTools).toContain('dockerfile: deploy/postgres-ha/Dockerfile');
    expect(postgresTools).toContain(
      `"$$PGHOST" "$$PGPORT" '*' "$$PGUSER" "$$password"`,
    );
    expect(postgresTools).toContain(
      `"$$PGHOST" "$$PGPORT" '*' 'postgres' "$$superuser_password"`,
    );
    expect(postgresTools).toContain(
      'secrets: [postgres_password, postgres_superuser_password, postgres_tls_ca]',
    );
    expect(compose).toContain('postgres_superuser_password');
    expect(compose).toContain('postgres_replication_password');
    expect(compose).toContain('pgbackrest_cipher_pass');
    expect(compose).toContain('postgres_tls_ca');
    expect(compose).toContain('postgres_tls_cert');
    expect(compose).toContain('postgres_tls_key');
    expect(compose).not.toContain('postgres_tls_ca_private_key');
    expect(compose).toContain('database:');
    expect(compose).toContain('internal: true');
    expect(compose).toContain('read_only: true');
    expect(compose).toContain('no-new-privileges:true');
    expect(compose).toContain('cap_drop:');
    expect(compose).not.toContain('control_signer_private_key:');
    expect(compose).not.toContain('control_signer_keyring:');
    expect(compose).toContain(
      '${OTTO_CONTROL_SIGNING_DIR:-./signing}:/run/otto-secrets:ro',
    );
    expect(compose).toContain('- alert_webhook_secret');
    expect(compose).toContain(
      'file: ${OTTO_CONTROL_SECRETS_DIR:-./secrets}/alert_webhook_secret',
    );
    expect(compose).toContain('- audit_anchor_token');
    expect(compose).toContain(
      'file: ${OTTO_CONTROL_SECRETS_DIR:-./secrets}/audit_anchor_token',
    );
    const databasePlane = compose.slice(compose.indexOf('services:'), compose.indexOf('  control-a:'));
    expect(databasePlane).not.toContain('alert_webhook_secret');
    expect(databasePlane).not.toContain('audit_anchor_token');
    expect(compose).toContain('  control-a:');
    expect(compose).toContain('  control-b:');
    expect(compose).toContain('  control-c:');
    expect(compose).toContain('  federation-a:');
    expect(compose).toContain('  federation-b:');
    expect(compose).toContain('  federation-c:');
    expect(compose).toContain('FEDERATION_ADMIN_TOKEN_FILE: /run/secrets/federation_admin_token');
    expect(compose).toContain('command: ["node", "dist/federation-server.js"]');
    expect(compose).not.toMatch(/POSTGRES_PASSWORD:\s*[^\n]/u);
    const smoke = repositoryFile('scripts/smoke-federation.mjs');
    expect(smoke).toContain('FederationClient');
    expect(smoke).toContain('verifyFederationSignature');
    expect(smoke).toContain('http://federation-b:7790');
    expect(smoke).toContain('http://federation-c:7790');
    expect(smoke).toContain('Promise.all(claimUrls.map');
    expect(smoke).toContain('duplicated or lost an inbox lease');
    expect(smoke).not.toContain('BEGIN PRIVATE KEY');
    const federationOperations = repositoryFile('docs/federation-production-operations.zh-CN.md');
    expect(federationOperations).toContain('CAPACITY_EXCEEDED');
    expect(federationOperations).toContain('RATE_LIMITED');
    expect(federationOperations).toContain('三个无状态 Federation 实例');
  });

  it('routes only to the Patroni primary and removes unhealthy control instances', () => {
    const haproxy = repositoryFile('deploy/postgres-ha/haproxy.cfg');
    const caddy = repositoryFile('deploy/Caddyfile');
    expect(haproxy).toContain('option httpchk GET /primary');
    expect(haproxy).toContain('on-marked-down shutdown-sessions');
    expect(haproxy.match(/server postgres-[123]/gu)).toHaveLength(3);
    expect(caddy).toContain('control-a:7788 control-b:7788 control-c:7788');
    expect(caddy).toContain('federation-a:7790 federation-b:7790 federation-c:7790');
    expect(caddy).toContain('health_uri /health/ready');
    expect(caddy).toContain('lb_policy least_conn');
    expect(caddy).toContain('fail_duration 30s');
    expect(caddy).toContain('respond @internal_metrics 404');
    expect(caddy).toContain('@federation_admin path /v1/admin/federation/*');
    expect(caddy).toContain('respond @federation_admin 404');
    expect(caddy).toContain('admin off');
    expect(caddy).toContain('email {$ACME_EMAIL}');
    expect(caddy).toContain('acme_ca {$ACME_CA}');
  });

  it('ships an authenticated internal Prometheus profile with SLO and capacity rules', () => {
    const compose = repositoryFile('compose.production.yaml');
    const prometheus = repositoryFile('deploy/prometheus/prometheus.yml');
    const rules = repositoryFile('deploy/prometheus/rules/otto-control-slo.yml');
    expect(compose).toContain('prom/prometheus:v3.13.0-distroless');
    expect(compose).toContain('profiles: [observability]');
    expect(compose).toContain('"127.0.0.1:9090:9090"');
    expect(compose).toContain('control_metrics_token');
    expect(compose).toContain('federation_metrics_token');
    expect(compose).toMatch(/monitoring:\n\s+internal: true/u);
    expect(prometheus).toContain('credentials_file: /run/secrets/control_metrics_token');
    expect(prometheus.match(/control-[abc]:7788/gu)).toHaveLength(3);
    expect(prometheus.match(/federation-[abc]:7790/gu)).toHaveLength(3);
    expect(prometheus).toContain('credentials_file: /run/secrets/federation_metrics_token');
    expect(rules).toContain('OttoFederationTargetMissing');
    expect(rules).toContain('OttoFederationHttpErrorsHigh');
    expect(rules).toContain('OttoFederationLatencyHigh');
    expect(rules).toContain('OttoFederationPendingQueueHigh');
    expect(rules).toContain('OttoFederationPendingBytesHigh');
    expect(rules).toContain('OttoFederationCapacityRejected');
    expect(rules).toContain('OttoFederationRateLimitedHigh');
    expect(rules).toContain('otto_control:slo_availability:ratio_5m');
    expect(rules).toContain('OttoControlAvailabilityErrorBudgetBurnHigh');
    expect(rules).toContain('OttoControlPostgresPoolSaturated');
    expect(rules).toContain('otto_control:database_growth:bytes_24h');
  });

  it('enables synchronous Patroni failover and encrypted continuous WAL archiving', () => {
    const entrypoint = repositoryFile('deploy/postgres-ha/patroni-entrypoint.sh');
    const pgbackrest = repositoryFile('deploy/postgres-ha/pgbackrest.conf');
    expect(entrypoint).toContain('synchronous_mode: true');
    expect(entrypoint).toContain('synchronous_node_count: 1');
    expect(entrypoint).toContain('failsafe_mode: true');
    expect(entrypoint).toContain('hostssl replication replicator 0.0.0.0/0 scram-sha-256');
    expect(entrypoint.match(/hostssl all all 0\.0\.0\.0\/0 scram-sha-256/gu)).toHaveLength(2);
    expect(entrypoint).toContain("ssl: 'on'");
    expect(entrypoint).toContain("sslmode: verify-full");
    expect(entrypoint).toContain('sslrootcert: ${POSTGRES_TLS_CA_FILE}');
    expect(entrypoint).toContain('password_encryption: scram-sha-256');
    expect(entrypoint).toContain('umask 077');
    expect(entrypoint).toContain('chmod 0700 /var/lib/postgresql/data/pgdata');
    expect(entrypoint).toContain('archive_mode:');
    expect(entrypoint).toContain('archive-push %p');
    expect(entrypoint).toContain('archive-get %f %p');
    expect(entrypoint).toContain('use_pg_rewind: true');
    expect(entrypoint).toMatch(/postgresql:\n\s+use_pg_rewind:[\s\S]+?pg_hba:/u);
    expect(pgbackrest).toContain('repo1-cipher-type=aes-256-cbc');
    expect(pgbackrest).toContain('repo1-retention-full=4');
  });

  it('publishes only the TLS edge and runs the application image as non-root', () => {
    const compose = repositoryFile('compose.production.yaml');
    const dockerfile = repositoryFile('Dockerfile');
    expect(compose).toContain('"443:443"');
    expect(compose).not.toContain('"7788:7788"');
    expect(dockerfile).toContain('ENTRYPOINT ["/usr/local/bin/otto-control-entrypoint"]');
    const entrypoint = repositoryFile('deploy/control-entrypoint.sh');
    expect(entrypoint).toContain('exec su-exec node "$@"');
    expect(entrypoint).toContain('/run/otto-runtime-secrets');
    expect(compose).toContain('/run/otto-runtime-secrets:rw,noexec,nosuid');
  });

  it('stages host-only production secrets before dropping container privileges', () => {
    const compose = repositoryFile('compose.production.yaml');
    const patroni = repositoryFile('deploy/postgres-ha/patroni-entrypoint.sh');
    const control = repositoryFile('deploy/control-entrypoint.sh');
    const pitr = repositoryFile('deploy/drill-pitr-postgres.sh');
    const pgbackrest = repositoryFile('deploy/postgres-ha/otto-pgbackrest');
    expect(patroni).toContain('stage_secret /run/secrets/postgres_password');
    expect(patroni).toContain(
      'OTTO_PGBACKREST_CIPHER_FILE=/run/patroni/pgbackrest_cipher_pass',
    );
    expect(control).toContain('CONTROL_DATABASE_PASSWORD_FILE');
    expect(control).toContain('CONTROL_SIGNER_KEYRING_FILE');
    expect(control).toContain('stage_environment_file NODE_EXTRA_CA_CERTS');
    expect(control).toContain('staged Control signing keyring is missing or empty');
    expect(control).toContain('FEDERATION_ADMIN_TOKEN_FILE');
    expect(control).toContain('FEDERATION_DATABASE_PASSWORD_FILE');
    expect(control).toContain('dist/federation-server.js');
    expect(compose).toContain('exec gosu postgres tail -f /dev/null');
    expect(compose).toContain('DAC_READ_SEARCH');
    expect(pitr).toContain('--user postgres postgres-pitr-drill');
    expect(pitr).toContain('otto-pgbackrest --stanza=otto-control check');
    expect(pitr).toContain('isolated PITR restore failed:');
    expect(pitr.indexOf('mkdir -p "$PGDATA"')).toBeLessThan(
      pitr.indexOf('find "$PGDATA" -mindepth 1 -delete'),
    );
    const physicalBackup = repositoryFile('deploy/backup-pitr-postgres.sh');
    expect(physicalBackup).toContain(
      'compose exec -T --user postgres "$PRIMARY" otto-pgbackrest',
    );
    expect(pgbackrest).toContain('exec gosu postgres "$0" "$@"');
    expect(pgbackrest).toContain('/run/patroni/pgbackrest_cipher_pass');
    expect(pgbackrest).toContain('PGBACKREST_REPO1_CIPHER_PASS=$(cat "$CIPHER_FILE")');
    expect(pgbackrest).toContain('OTTO_PGBACKREST_CIPHER_FILE');
    expect(pgbackrest).not.toContain('--repo1-cipher-pass=');
  });

  it('creates atomic verified backups and requires a safety backup before restore', () => {
    const backup = repositoryFile('deploy/backup-postgres.sh');
    const restore = repositoryFile('deploy/restore-postgres.sh');
    const timer = repositoryFile('deploy/systemd/otto-control-backup.timer');
    expect(backup).toContain('--format custom');
    expect(backup).toContain('pg_restore --no-password --list');
    expect(backup).toContain('.dump.enc');
    expect(backup).toContain('backup-crypto.mjs');
    expect(backup).toContain('decrypt-run');
    expect(backup).toContain('mkfifo');
    expect(backup).toContain('sha256sum');
    expect(backup).toContain('replicate-backup-s3.mjs');
    expect(backup).toContain('--report-directory');
    expect(backup).toContain('CONTROL_BACKUP_RETENTION_DAYS');
    expect(restore).toContain('--confirm=RESTORE_OTTO_CONTROL');
    expect(restore.indexOf('backup-postgres.sh')).toBeLessThan(
      restore.indexOf('compose stop control-a control-b control-c'),
    );
    expect(backup).toContain('compose exec -T postgres-tools pg_dump');
    expect(backup).toContain('--no-password');
    expect(backup).not.toContain('--file -');
    expect(restore).toContain('exec -T postgres-tools pg_restore');
    expect(restore).toContain('decrypt-run');
    expect(restore).not.toContain('RESTORE_PIPE');
    expect(restore).toContain('--username "$DB_ADMIN_USER"');
    expect(restore).toContain('sha256sum --check');
    expect(restore).toContain('backup-crypto.mjs');
    expect(restore).toContain('/health/ready');
    expect(timer).toContain('Persistent=true');
    const backupService = repositoryFile('deploy/systemd/otto-control-backup.service');
    expect(backupService).toContain('network-online.target');
    expect(repositoryFile('compose.production.yaml')).toContain(
      '${OTTO_CONTROL_BACKUP_DIR:-./backups}/reports:/var/lib/otto-control/backup-reports:ro',
    );
  });

  it('restores the latest backup into an isolated disposable database for weekly drills', () => {
    const drill = repositoryFile('deploy/drill-restore-postgres.sh');
    const service = repositoryFile('deploy/systemd/otto-control-restore-drill.service');
    const timer = repositoryFile('deploy/systemd/otto-control-restore-drill.timer');
    expect(drill).toContain('otto_drill_');
    expect(drill).toContain('--template template0');
    expect(drill).toContain('control_schema_migrations');
    expect(drill).toContain('control_deployment_update_assignments');
    expect(drill).toContain('control_signing_keys');
    expect(drill).toContain('result=passed');
    expect(drill).toContain('CONTROL_DRILL_MAX_BACKUP_AGE_HOURS');
    expect(drill).toContain('backup_age_seconds');
    expect(drill).toContain('decrypt-run');
    expect(drill).toContain('--no-password');
    expect(drill).not.toContain('RESTORE_PIPE');
    expect(drill).toContain('dropdb');
    expect(drill).not.toContain('compose stop control');
    expect(service).toContain('TimeoutStartSec=2h');
    expect(timer).toContain('OnCalendar=Sun');
    expect(timer).toContain('Persistent=true');
  });

  it('ships physical backup, PITR, and automatic failover drills', () => {
    const backup = repositoryFile('deploy/backup-pitr-postgres.sh');
    const pitr = repositoryFile('deploy/drill-pitr-postgres.sh');
    const failover = repositoryFile('deploy/drill-postgres-failover.sh');
    const pgBackRestWrapper = repositoryFile('deploy/postgres-ha/otto-pgbackrest');
    const postgresStore = repositoryFile('src/storage/postgres-store.ts');
    expect(backup).toContain('--type="$TYPE" backup');
    expect(backup).toContain('otto-pgbackrest --stanza=otto-control check');
    expect(pitr).toContain('postgres-pitr-drill');
    expect(pitr).toContain('--cmd=/usr/local/bin/otto-pgbackrest');
    expect(pitr).toContain('--type=time --target="$PITR_TARGET"');
    expect(pitr).toContain('CONTROL_PITR_MAX_BACKUP_AGE_HOURS');
    expect(pitr).toContain('backup_age_seconds');
    expect(pitr).toContain('control_schema_migrations');
    expect(pitr).toContain('recovery-data-manifest.sh');
    expect(pitr).toContain('database_fingerprint_sha256');
    expect(pitr).toContain('rpo_seconds');
    expect(pitr).toContain('rto_seconds');
    expect(repositoryFile('.github/workflows/ci.yml')).toContain(
      'customer_pitr_recovery_probe',
    );
    expect(repositoryFile('.github/workflows/ci.yml')).toMatch(
      /psql --username postgres --dbname otto_control --no-password\s+\\\n\s+--set=ON_ERROR_STOP=1 --command='SELECT pg_switch_wal\(\)'/u,
    );
    expect(pgBackRestWrapper).toContain('--config|--config=*');
    expect(pgBackRestWrapper).toContain('exec pgbackrest "$@"');
    expect(failover).toContain('--confirm=FAILOVER_OTTO_CONTROL');
    expect(failover).toContain('http://127.0.0.1:8008/synchronous');
    expect(failover).toContain('stable_rounds');
    expect(failover).toContain(
      'cannot run failover drill without a stable synchronous standby',
    );
    expect(failover).toContain('compose kill -s SIGKILL "$OLD_PRIMARY"');
    expect(failover).toContain('CREATE TEMP TABLE otto_control_failover_probe');
    expect(failover).toContain('until probe_write; do');
    expect(failover).toContain(
      'HAProxy did not route a successful write within 30 seconds of promotion',
    );
    expect(failover).toContain('former_primary_rejoined=true');
    expect(failover).toContain('prepared_candidate=%s');
    expect(postgresStore).toContain("pool.on('error'");
    expect(repositoryFile('deploy/systemd/otto-control-pitr-full.timer')).toContain(
      'Persistent=true',
    );
    expect(repositoryFile('deploy/systemd/otto-control-pitr-diff.timer')).toContain(
      'OnCalendar=Mon..Sat',
    );
    expect(repositoryFile('deploy/systemd/otto-control-pitr-drill.timer')).toContain(
      'OnCalendar=Sun',
    );
  });

  it('provisions and drills immutable audit evidence instead of trusting configuration', () => {
    const template = repositoryFile('deploy/aws-audit-worm.template.yaml');
    const drill = repositoryFile('scripts/drill-object-lock.mjs');
    const manifest = repositoryFile('deploy/recovery-data-manifest.sh');
    expect(template).toContain('ObjectLockEnabled: true');
    expect(template).toContain('Mode: COMPLIANCE');
    expect(template).toContain('SSEAlgorithm: aws:kms');
    expect(template).toContain('s3:DeleteObjectVersion');
    expect(template).toContain('DeletionPolicy: Retain');
    expect(drill).toContain('DELETE_LOCKED_AUDIT_EVIDENCE');
    expect(drill).toContain('delete-capable-principal');
    expect(drill).toContain('COMPLIANCE object deletion unexpectedly succeeded');
    expect(drill).toContain('objectIntactAfterDeletionAttempt: true');
    expect(manifest).toContain('database_fingerprint_sha256');
    expect(manifest).toContain('control_credit_transactions');
    expect(manifest).toContain('control_audit_witness_evidence');
    expect(manifest).toContain('REPEATABLE READ READ ONLY');
    expect(manifest).toContain('__OTTO_TABLE__');
    expect(manifest).toContain('__OTTO_END__');
  });

  it('fails unhealthy deployments before launch and drills every Control replica', () => {
    const preflight = repositoryFile('scripts/preflight-deployment.mjs');
    const drill = repositoryFile('deploy/drill-control-failover.sh');
    expect(preflight).toContain('deployment preflight failed');
    expect(preflight).toContain('CONTROL_DATABASE_SSL must be true');
    expect(preflight).toContain('production domains cannot use localhost');
    expect(preflight).toContain("'docker', ['version']");
    expect(preflight).toContain("'config', '--quiet'");
    expect(drill).toContain('--confirm=FAILOVER_OTTO_CONTROL_REPLICAS');
    expect(drill).toContain('control-a control-b control-c');
    expect(drill).toContain('public Control edge became unavailable');
    expect(drill).toContain('replicas_tested=control-a,control-b,control-c');
    const ciCaddy = repositoryFile('deploy/Caddyfile.ci');
    expect(ciCaddy).toContain('auto_https off');
    expect(ciCaddy).toContain(':8080');
    expect(repositoryFile('compose.ci.yaml')).toContain('127.0.0.1:18080:8080');
  });
});

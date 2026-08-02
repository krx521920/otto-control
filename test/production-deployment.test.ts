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
    expect(workflow).toContain('image: postgres:17-alpine');
    expect(workflow).toContain('POSTGRES_DB: otto_control_test');
    expect(workflow).toContain('CONTROL_REQUIRE_POSTGRES_TEST: "true"');
    expect(workflow).toContain('npm run test:postgres');
    expect(workflow).toContain('Prove all Federation instances and encrypted relay are ready');
    expect(workflow).toContain('federation-a federation-b federation-c');
    expect(workflow).toContain('scripts/smoke-federation.mjs');
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
    expect(compose).toContain('dockerfile: deploy/postgres-ha/Dockerfile');
    const postgresTools = compose.slice(
      compose.indexOf('  postgres-tools:'),
      compose.indexOf('  postgres-pitr-drill:'),
    );
    expect(postgresTools).toContain('dockerfile: deploy/postgres-ha/Dockerfile');
    expect(compose).toContain('postgres_superuser_password');
    expect(compose).toContain('postgres_replication_password');
    expect(compose).toContain('pgbackrest_cipher_pass');
    expect(compose).toContain('database:');
    expect(compose).toContain('internal: true');
    expect(compose).toContain('read_only: true');
    expect(compose).toContain('no-new-privileges:true');
    expect(compose).toContain('cap_drop:');
    expect(compose).toContain('- source: control_signer_private_key');
    expect(compose).toContain('target: control_signer_private_key.pem');
    expect(compose).toContain('- source: control_signer_keyring');
    expect(compose).toContain('target: control_signer_keyring.json');
    expect(compose).toContain('file: ./secrets/control_signer_private_key.pem');
    expect(compose).toContain('file: ./secrets/control_signer_keyring.json');
    expect(compose).not.toContain('./secrets:/run/otto-secrets:ro');
    expect(compose).toContain('- alert_webhook_secret');
    expect(compose).toContain('file: ./secrets/alert_webhook_secret');
    expect(compose).toContain('- audit_anchor_token');
    expect(compose).toContain('file: ./secrets/audit_anchor_token');
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
    expect(smoke).not.toContain('BEGIN PRIVATE KEY');
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
    expect(entrypoint).toContain('host replication replicator 0.0.0.0/0 scram-sha-256');
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
    expect(control).toContain('stage_file /run/secrets/control_signer_private_key.pem');
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
    expect(backup).toContain('pg_restore --list');
    expect(backup).toContain('.dump.enc');
    expect(backup).toContain('backup-crypto.mjs');
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
    expect(restore).toContain('compose exec -T postgres-tools pg_restore');
    expect(restore).toContain('sha256sum --check');
    expect(restore).toContain('backup-crypto.mjs');
    expect(restore).toContain('/health/ready');
    expect(timer).toContain('Persistent=true');
    const backupService = repositoryFile('deploy/systemd/otto-control-backup.service');
    expect(backupService).toContain('network-online.target');
    expect(repositoryFile('compose.production.yaml')).toContain(
      './backups/reports:/var/lib/otto-control/backup-reports:ro',
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
});

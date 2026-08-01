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
    expect(compose).toContain('file: ./secrets/control_signer_private_key.pem');
    expect(compose).toContain('./secrets:/run/otto-secrets:ro');
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
    expect(compose).not.toMatch(/POSTGRES_PASSWORD:\s*[^\n]/u);
  });

  it('routes only to the Patroni primary and removes unhealthy control instances', () => {
    const haproxy = repositoryFile('deploy/postgres-ha/haproxy.cfg');
    const caddy = repositoryFile('deploy/Caddyfile');
    expect(haproxy).toContain('option httpchk GET /primary');
    expect(haproxy).toContain('on-marked-down shutdown-sessions');
    expect(haproxy.match(/server postgres-[123]/gu)).toHaveLength(3);
    expect(caddy).toContain('control-a:7788 control-b:7788 control-c:7788');
    expect(caddy).toContain('health_uri /health/ready');
    expect(caddy).toContain('lb_policy least_conn');
    expect(caddy).toContain('fail_duration 30s');
  });

  it('enables synchronous Patroni failover and encrypted continuous WAL archiving', () => {
    const entrypoint = repositoryFile('deploy/postgres-ha/patroni-entrypoint.sh');
    const pgbackrest = repositoryFile('deploy/postgres-ha/pgbackrest.conf');
    expect(entrypoint).toContain('synchronous_mode: true');
    expect(entrypoint).toContain('synchronous_node_count: 1');
    expect(entrypoint).toContain('failsafe_mode: true');
    expect(entrypoint).toContain('host replication replicator 0.0.0.0/0 scram-sha-256');
    expect(entrypoint).toContain('password_encryption: scram-sha-256');
    expect(entrypoint).toContain('archive_mode:');
    expect(entrypoint).toContain('archive-push %p');
    expect(entrypoint).toContain('archive-get %f %p');
    expect(entrypoint).toContain('use_pg_rewind: true');
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
    expect(patroni).toContain('PGBACKREST_CIPHER_FILE=/run/patroni/pgbackrest_cipher_pass');
    expect(control).toContain('CONTROL_DATABASE_PASSWORD_FILE');
    expect(control).toContain('CONTROL_SIGNER_KEYRING_FILE');
    expect(compose).toContain('exec gosu postgres tail -f /dev/null');
    expect(compose).toContain('DAC_READ_SEARCH');
    expect(pitr).toContain('--user postgres postgres-pitr-drill');
    expect(pgbackrest).toContain('PGBACKREST_REPO1_CIPHER_PASS=$(cat "$CIPHER_FILE")');
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
    expect(backup).toContain('--type="$TYPE" backup');
    expect(backup).toContain('otto-pgbackrest --stanza=otto-control check');
    expect(pitr).toContain('postgres-pitr-drill');
    expect(pitr).toContain('--type=time --target="$PITR_TARGET"');
    expect(pitr).toContain('CONTROL_PITR_MAX_BACKUP_AGE_HOURS');
    expect(pitr).toContain('backup_age_seconds');
    expect(pitr).toContain('control_schema_migrations');
    expect(failover).toContain('--confirm=FAILOVER_OTTO_CONTROL');
    expect(failover).toContain('compose stop "$OLD_PRIMARY"');
    expect(failover).toContain('CREATE TEMP TABLE otto_control_failover_probe');
    expect(failover).toContain('former_primary_rejoined=true');
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

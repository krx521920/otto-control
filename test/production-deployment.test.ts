import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

function repositoryFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
}

describe('production deployment assets', () => {
  it('keeps credentials out of the image build context', () => {
    const ignore = repositoryFile('.dockerignore');
    expect(ignore).toContain('secrets');
    expect(ignore).toContain('.env.*');
    expect(ignore).toContain('*.pem');
  });

  it('isolates PostgreSQL and hardens the control runtime', () => {
    const compose = repositoryFile('compose.production.yaml');
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
    const postgresService = compose.slice(
      compose.indexOf('  postgres:'),
      compose.indexOf('  control:'),
    );
    const controlService = compose.slice(
      compose.indexOf('  control:'),
      compose.indexOf('  caddy:'),
    );
    expect(postgresService).not.toContain('alert_webhook_secret');
    expect(postgresService).not.toContain('audit_anchor_token');
    expect(controlService).toContain('- alert_webhook_secret');
    expect(controlService).toContain('- audit_anchor_token');
    expect(compose).not.toMatch(/POSTGRES_PASSWORD:\s*[^\n]/u);
  });

  it('publishes only the TLS edge and runs the application image as non-root', () => {
    const compose = repositoryFile('compose.production.yaml');
    const dockerfile = repositoryFile('Dockerfile');
    expect(compose).toContain('"443:443"');
    expect(compose).not.toContain('"7788:7788"');
    expect(dockerfile).toContain('USER node');
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
    expect(restore.indexOf('backup-postgres.sh')).toBeLessThan(restore.indexOf('compose stop control'));
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
});

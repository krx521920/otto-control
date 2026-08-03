#!/bin/sh
set -eu

umask 077

if [ "$#" -gt 1 ]; then
  printf 'Usage: %s [/absolute/path/to/backup.dump.enc]\n' "$0" >&2
  exit 1
fi

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
COMPOSE_FILE=${OTTO_CONTROL_COMPOSE_FILE:-"$ROOT/compose.production.yaml"}
ENV_FILE=${OTTO_CONTROL_ENV_FILE:-"$ROOT/.env.production"}

read_env() {
  sed -n "s/^$1=//p" "$ENV_FILE" | tail -n 1
}

BACKUP_DIR=${OTTO_CONTROL_BACKUP_DIR:-$(read_env OTTO_CONTROL_BACKUP_DIR)}
BACKUP_DIR=${BACKUP_DIR:-"$ROOT/backups"}
case "$BACKUP_DIR" in
  /*) ;;
  *) BACKUP_DIR="$ROOT/${BACKUP_DIR#./}" ;;
esac
REPORT_DIR="$BACKUP_DIR/drills"
mkdir -p "$BACKUP_DIR" "$REPORT_DIR"
EXPECTED_MANIFEST=${OTTO_CONTROL_RECOVERY_EXPECTED_MANIFEST:-}

if [ "$#" -eq 1 ]; then
  BACKUP_PATH=$1
else
  set -- "$BACKUP_DIR"/otto-control-*.dump.enc
  if [ ! -e "$1" ]; then
    printf '%s\n' 'no encrypted Otto Control backup is available for a restore drill' >&2
    exit 1
  fi
  BACKUP_PATH=$(ls -1t -- "$@" | head -n 1)
fi

if [ ! -f "$BACKUP_PATH" ] || [ ! -f "$BACKUP_PATH.sha256" ]; then
  printf '%s\n' 'backup and matching .sha256 file are required' >&2
  exit 1
fi
BACKUP_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$BACKUP_PATH")" && pwd)
BACKUP_NAME=$(basename -- "$BACKUP_PATH")
BACKUP_PATH="$BACKUP_DIRECTORY/$BACKUP_NAME"

DB_USER=$(read_env POSTGRES_USER)
BACKUP_KEY_FILE=$(read_env OTTO_CONTROL_BACKUP_KEY_FILE)
REPORT_RETENTION_DAYS=$(read_env CONTROL_DRILL_REPORT_RETENTION_DAYS)
MAX_BACKUP_AGE_HOURS=$(read_env CONTROL_DRILL_MAX_BACKUP_AGE_HOURS)
DB_USER=${DB_USER:-otto_control}
BACKUP_KEY_FILE=${BACKUP_KEY_FILE:-"$ROOT/secrets/backup_encryption_key"}
REPORT_RETENTION_DAYS=${REPORT_RETENTION_DAYS:-180}
MAX_BACKUP_AGE_HOURS=${MAX_BACKUP_AGE_HOURS:-48}
case "$BACKUP_KEY_FILE" in
  /*) ;;
  *) BACKUP_KEY_FILE="$ROOT/$BACKUP_KEY_FILE" ;;
esac
case "$DB_USER" in
  ''|*[!A-Za-z0-9_]*)
    printf '%s\n' 'database user may contain only letters, digits, and underscores' >&2
    exit 1
    ;;
esac
case "$REPORT_RETENTION_DAYS" in
  ''|*[!0-9]*)
    printf '%s\n' 'CONTROL_DRILL_REPORT_RETENTION_DAYS must be a positive integer' >&2
    exit 1
    ;;
esac
if [ "$REPORT_RETENTION_DAYS" -lt 1 ]; then
  printf '%s\n' 'CONTROL_DRILL_REPORT_RETENTION_DAYS must be at least 1' >&2
  exit 1
fi
case "$MAX_BACKUP_AGE_HOURS" in
  ''|*[!0-9]*)
    printf '%s\n' 'CONTROL_DRILL_MAX_BACKUP_AGE_HOURS must be a positive integer' >&2
    exit 1
    ;;
esac
if [ "$MAX_BACKUP_AGE_HOURS" -lt 1 ]; then
  printf '%s\n' 'CONTROL_DRILL_MAX_BACKUP_AGE_HOURS must be at least 1' >&2
  exit 1
fi
if [ ! -f "$BACKUP_KEY_FILE" ]; then
  printf '%s\n' 'backup encryption key file is missing' >&2
  exit 1
fi

if docker compose version >/dev/null 2>&1; then
  COMPOSE_MODE=plugin
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE_MODE=standalone
else
  printf '%s\n' 'Docker Compose is required' >&2
  exit 1
fi

compose() {
  if [ "$COMPOSE_MODE" = plugin ]; then
    docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" "$@"
  else
    docker-compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" "$@"
  fi
}

LOCK_DIR="$BACKUP_DIR/.operation.lock"
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  printf '%s\n' 'another Otto Control backup, restore, or drill is already running' >&2
  exit 1
fi

DRILL_DATABASE=''
REPORT_TEMP=''
MANIFEST_TEMP=''
cleanup() {
  if [ -n "$REPORT_TEMP" ]; then rm -f -- "$REPORT_TEMP"; fi
  if [ -n "$MANIFEST_TEMP" ]; then rm -f -- "$MANIFEST_TEMP"; fi
  if [ -n "$DRILL_DATABASE" ]; then
    compose exec -T postgres-tools dropdb \
      --username "$DB_USER" --no-password --if-exists --force "$DRILL_DATABASE" >/dev/null 2>&1 || true
  fi
  rmdir "$LOCK_DIR" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

(
  cd "$BACKUP_DIRECTORY"
  sha256sum --check "$BACKUP_NAME.sha256"
)

NOW_SECONDS=$(date '+%s')
BACKUP_SECONDS=$(stat -c '%Y' "$BACKUP_PATH")
BACKUP_AGE_SECONDS=$((NOW_SECONDS - BACKUP_SECONDS))
MAX_BACKUP_AGE_SECONDS=$((MAX_BACKUP_AGE_HOURS * 3600))
if [ "$BACKUP_AGE_SECONDS" -lt 0 ] || [ "$BACKUP_AGE_SECONDS" -gt "$MAX_BACKUP_AGE_SECONDS" ]; then
  printf 'latest backup age is outside the allowed %s-hour recovery window\n' \
    "$MAX_BACKUP_AGE_HOURS" >&2
  exit 1
fi

STARTED_AT=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
STARTED_SECONDS=$NOW_SECONDS
DRILL_DATABASE="otto_drill_$(date -u '+%Y%m%d%H%M%S')_$$"
compose exec -T postgres-tools createdb \
  --username "$DB_USER" \
  --no-password \
  --owner "$DB_USER" \
  --template template0 \
  "$DRILL_DATABASE"

if [ "$COMPOSE_MODE" = plugin ]; then
  set -- docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE"
else
  set -- docker-compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE"
fi
if ! node "$ROOT/scripts/backup-crypto.mjs" decrypt-run \
  --input "$BACKUP_PATH" \
  --key-file "$BACKUP_KEY_FILE" \
  -- "$@" exec -T postgres-tools pg_restore \
    --username "$DB_USER" \
    --dbname "$DRILL_DATABASE" \
    --no-password \
    --no-owner \
    --exit-on-error
then
  printf '%s\n' 'restore drill failed while loading PostgreSQL' >&2
  exit 1
fi

REQUIRED_TABLES='control_schema_migrations control_customers control_deployments control_licenses control_signing_keys control_audit_events control_telemetry_events control_update_distributions control_update_releases control_deployment_update_assignments control_admin_accounts control_admin_roles control_admin_sessions control_admin_approvals control_admin_approval_decisions'
for TABLE in $REQUIRED_TABLES; do
  EXISTS=$(compose exec -T postgres-tools psql \
    --username "$DB_USER" --dbname "$DRILL_DATABASE" --no-password --tuples-only --no-align \
    --command "SELECT CASE WHEN to_regclass('public.$TABLE') IS NULL THEN 'missing' ELSE 'ok' END")
  if [ "$EXISTS" != ok ]; then
    printf 'restore drill is missing required table: %s\n' "$TABLE" >&2
    exit 1
  fi
done

query_count() {
  compose exec -T postgres-tools psql \
    --username "$DB_USER" --dbname "$DRILL_DATABASE" --no-password --tuples-only --no-align \
    --command "SELECT COUNT(*) FROM $1"
}

MIGRATION_COUNT=$(query_count control_schema_migrations)
CUSTOMER_COUNT=$(query_count control_customers)
DEPLOYMENT_COUNT=$(query_count control_deployments)
LICENSE_COUNT=$(query_count control_licenses)
AUDIT_COUNT=$(query_count control_audit_events)
case "$MIGRATION_COUNT" in
  ''|*[!0-9]*|0)
    printf '%s\n' 'restore drill found no applied schema migration' >&2
    exit 1
    ;;
esac

MANIFEST_NAME="restore-drill-$(date -u '+%Y%m%dT%H%M%SZ').manifest"
MANIFEST_FILE="$REPORT_DIR/$MANIFEST_NAME"
MANIFEST_TEMP="$REPORT_DIR/.$MANIFEST_NAME.part.$$"
set -- \
  --service postgres-tools \
  --database "$DRILL_DATABASE" \
  --user "$DB_USER" \
  --output "$MANIFEST_TEMP"
if [ -n "$EXPECTED_MANIFEST" ]; then
  set -- "$@" --expected "$EXPECTED_MANIFEST"
fi
sh "$ROOT/deploy/recovery-data-manifest.sh" "$@"
DATABASE_FINGERPRINT=$(sed -n 's/^database_fingerprint_sha256=//p' "$MANIFEST_TEMP" | tail -n 1)
if [ -z "$DATABASE_FINGERPRINT" ]; then
  printf '%s\n' 'restore drill did not produce a database fingerprint' >&2
  exit 1
fi

compose exec -T postgres-tools dropdb \
  --username "$DB_USER" --no-password --if-exists --force "$DRILL_DATABASE"
DRILL_DATABASE=''

COMPLETED_AT=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
DURATION_SECONDS=$(($(date '+%s') - STARTED_SECONDS))
BACKUP_SHA256=$(sed -n '1s/[[:space:]].*$//p' "$BACKUP_PATH.sha256")
REPORT_NAME="restore-drill-$(date -u '+%Y%m%dT%H%M%SZ').txt"
REPORT_TEMP="$REPORT_DIR/$REPORT_NAME.part"
REPORT_FILE="$REPORT_DIR/$REPORT_NAME"
{
  printf 'result=passed\n'
  printf 'backup=%s\n' "$BACKUP_NAME"
  printf 'backup_sha256=%s\n' "$BACKUP_SHA256"
  printf 'backup_age_seconds=%s\n' "$BACKUP_AGE_SECONDS"
  printf 'started_at=%s\n' "$STARTED_AT"
  printf 'completed_at=%s\n' "$COMPLETED_AT"
  printf 'duration_seconds=%s\n' "$DURATION_SECONDS"
  printf 'schema_migrations=%s\n' "$MIGRATION_COUNT"
  printf 'customers=%s\n' "$CUSTOMER_COUNT"
  printf 'deployments=%s\n' "$DEPLOYMENT_COUNT"
  printf 'licenses=%s\n' "$LICENSE_COUNT"
  printf 'audit_events=%s\n' "$AUDIT_COUNT"
  printf 'database_fingerprint_sha256=%s\n' "$DATABASE_FINGERPRINT"
  printf 'recovery_manifest=%s\n' "$MANIFEST_NAME"
  if [ -n "$EXPECTED_MANIFEST" ]; then
    printf 'expected_manifest=%s\n' "$(basename -- "$EXPECTED_MANIFEST")"
    printf 'expected_manifest_matched=true\n'
  else
    printf 'expected_manifest_matched=not_requested\n'
  fi
} > "$REPORT_TEMP"
mv -- "$REPORT_TEMP" "$REPORT_FILE"
REPORT_TEMP=''
mv -- "$MANIFEST_TEMP" "$MANIFEST_FILE"
MANIFEST_TEMP=''

find "$REPORT_DIR" -type f -name 'restore-drill-*.txt' \
  -mtime "+$REPORT_RETENTION_DAYS" -delete

printf 'Restore drill passed: %s\n' "$REPORT_FILE"

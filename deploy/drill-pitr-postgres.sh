#!/bin/sh
set -eu

umask 077

if [ "$#" -gt 1 ]; then
  printf 'Usage: %s [RFC3339-target-time]\n' "$0" >&2
  exit 1
fi

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
COMPOSE_FILE=${OTTO_CONTROL_COMPOSE_FILE:-"$ROOT/compose.production.yaml"}
ENV_FILE=${OTTO_CONTROL_ENV_FILE:-"$ROOT/.env.production"}
TARGET=${1:-}
if [ -n "$TARGET" ]; then
  TARGET=$(date -u --date="$TARGET" '+%Y-%m-%d %H:%M:%S+00') || {
    printf '%s\n' 'PITR target must be a valid RFC3339 timestamp' >&2
    exit 1
  }
fi

read_env() {
  sed -n "s/^$1=//p" "$ENV_FILE" | tail -n 1
}

BACKUP_DIR=$(read_env OTTO_CONTROL_BACKUP_DIR)
BACKUP_DIR=${BACKUP_DIR:-"$ROOT/backups"}
case "$BACKUP_DIR" in
  /*) ;;
  *) BACKUP_DIR="$ROOT/${BACKUP_DIR#./}" ;;
esac
REPORT_DIR=${OTTO_CONTROL_PITR_REPORT_DIR:-"$BACKUP_DIR/reports/pitr"}
REPORT_RETENTION_DAYS=$(read_env CONTROL_PITR_REPORT_RETENTION_DAYS)
MAX_BACKUP_AGE_HOURS=$(read_env CONTROL_PITR_MAX_BACKUP_AGE_HOURS)
REPORT_RETENTION_DAYS=${REPORT_RETENTION_DAYS:-180}
MAX_BACKUP_AGE_HOURS=${MAX_BACKUP_AGE_HOURS:-24}
EXPECTED_MANIFEST=${OTTO_CONTROL_RECOVERY_EXPECTED_MANIFEST:-}
for value in "$REPORT_RETENTION_DAYS" "$MAX_BACKUP_AGE_HOURS"; do
  case "$value" in
    ''|*[!0-9]*|0)
      printf '%s\n' 'PITR retention and maximum backup age must be positive integers' >&2
      exit 1
      ;;
  esac
done

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

find_primary() {
  for candidate in postgres-1 postgres-2 postgres-3; do
    if compose exec -T "$candidate" curl --fail --silent \
      http://127.0.0.1:8008/primary >/dev/null 2>&1
    then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

mkdir -p "$REPORT_DIR"
LOCK_DIR="$ROOT/backups/.operation.lock"
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  printf '%s\n' 'another Otto Control backup, restore, or drill is already running' >&2
  exit 1
fi
DRILL_STARTED=false
DATABASE_STARTED=false
MANIFEST_TEMP=''
cleanup() {
  if [ "$DATABASE_STARTED" = true ]; then
    compose --profile ops exec -T --user postgres postgres-pitr-drill \
      pg_ctl -D /var/lib/postgresql/data/pgdata -m fast -w stop >/dev/null 2>&1 || true
  fi
  if [ "$DRILL_STARTED" = true ]; then
    compose --profile ops stop postgres-pitr-drill >/dev/null 2>&1 || true
  fi
  if [ -n "$MANIFEST_TEMP" ]; then rm -f -- "$MANIFEST_TEMP"; fi
  rmdir "$LOCK_DIR" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

PRIMARY=$(find_primary) || {
  printf '%s\n' 'cannot validate PITR without a healthy Patroni primary' >&2
  exit 1
}
# After a failover, force an archive check on the new timeline before restoring.
# This waits until the required history and WAL are durable in pgBackRest.
compose exec -T --user postgres "$PRIMARY" \
  otto-pgbackrest --stanza=otto-control check

compose --profile ops up --detach postgres-pitr-drill
DRILL_STARTED=true
STARTED_AT=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
STARTED_SECONDS=$(date '+%s')

LATEST_BACKUP_SECONDS=$(compose --profile ops exec -T --user postgres postgres-pitr-drill sh -ec '
  otto-pgbackrest --stanza=otto-control --output=json info |
    python3 /usr/local/bin/otto-pgbackrest-latest-backup
')
BACKUP_AGE_SECONDS=$(($(date '+%s') - LATEST_BACKUP_SECONDS))
MAX_BACKUP_AGE_SECONDS=$((MAX_BACKUP_AGE_HOURS * 3600))
if [ "$BACKUP_AGE_SECONDS" -lt 0 ] || [ "$BACKUP_AGE_SECONDS" -gt "$MAX_BACKUP_AGE_SECONDS" ]; then
  printf 'latest physical backup is outside the allowed %s-hour recovery window\n' \
    "$MAX_BACKUP_AGE_HOURS" >&2
  exit 1
fi

if DRILL_OUTPUT=$(compose --profile ops exec -T --user postgres -e PITR_TARGET="$TARGET" postgres-pitr-drill \
  sh -ec '
    pg_ctl -D "$PGDATA" -m immediate stop >/dev/null 2>&1 || true
    mkdir -p "$PGDATA"
    find "$PGDATA" -mindepth 1 -delete
    chmod 0700 "$PGDATA"
    if [ -n "$PITR_TARGET" ]; then
      otto-pgbackrest --stanza=otto-control \
        --cmd=/usr/local/bin/otto-pgbackrest \
        --type=time --target="$PITR_TARGET" --target-action=promote restore
    else
      otto-pgbackrest --stanza=otto-control \
        --cmd=/usr/local/bin/otto-pgbackrest \
        --type=immediate --target-action=promote restore
    fi
    pg_ctl -D "$PGDATA" \
      -o "-p 55432 -c listen_addresses= -c archive_mode=off" -w start
    printf "%s\n" "isolated_database_started=true"
  ' 2>&1)
then
  DATABASE_STARTED=true
else
  DRILL_STATUS=$?
  printf 'isolated PITR restore failed:\n%s\n' "$DRILL_OUTPUT" >&2
  exit "$DRILL_STATUS"
fi

psql_drill_value() {
  compose --profile ops exec -T --user postgres postgres-pitr-drill psql \
    --port=55432 --dbname=otto_control --tuples-only --no-align \
    --set=ON_ERROR_STOP=1 --command="$1"
}

MIGRATION_COUNT=$(psql_drill_value 'SELECT COUNT(*) FROM control_schema_migrations')
case "$MIGRATION_COUNT" in
  ''|*[!0-9]*|0)
    printf '%s\n' 'PITR restore contains no schema migrations' >&2
    exit 1
    ;;
esac
RECOVERY_STATE=$(psql_drill_value 'SELECT pg_is_in_recovery()')
RECOVERED_XACT_AT=$(psql_drill_value \
  "SELECT COALESCE(to_char(pg_last_xact_replay_timestamp() AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), 'unknown')")

MANIFEST_NAME="pitr-drill-$(date -u '+%Y%m%dT%H%M%SZ').manifest"
MANIFEST_FILE="$REPORT_DIR/$MANIFEST_NAME"
MANIFEST_TEMP="$REPORT_DIR/.$MANIFEST_NAME.part.$$"
set -- \
  --service postgres-pitr-drill \
  --profile ops \
  --container-user postgres \
  --database otto_control \
  --user postgres \
  --port 55432 \
  --output "$MANIFEST_TEMP"
if [ -n "$EXPECTED_MANIFEST" ]; then
  set -- "$@" --expected "$EXPECTED_MANIFEST"
fi
sh "$ROOT/deploy/recovery-data-manifest.sh" "$@"
DATABASE_FINGERPRINT=$(sed -n 's/^database_fingerprint_sha256=//p' "$MANIFEST_TEMP" | tail -n 1)
if [ -z "$DATABASE_FINGERPRINT" ]; then
  printf '%s\n' 'PITR drill did not produce a database fingerprint' >&2
  exit 1
fi

RPO_SECONDS=unknown
if [ "$RECOVERED_XACT_AT" != unknown ]; then
  RECOVERED_SECONDS=$(date -u --date="$RECOVERED_XACT_AT" '+%s')
  if [ -n "$TARGET" ]; then
    TARGET_SECONDS=$(date -u --date="$TARGET" '+%s')
  else
    TARGET_SECONDS=$(date '+%s')
  fi
  if [ "$TARGET_SECONDS" -ge "$RECOVERED_SECONDS" ]; then
    RPO_SECONDS=$((TARGET_SECONDS - RECOVERED_SECONDS))
  else
    RPO_SECONDS=0
  fi
fi

DURATION_SECONDS=$(($(date '+%s') - STARTED_SECONDS))
REPORT_FILE="$REPORT_DIR/pitr-drill-$(date -u '+%Y%m%dT%H%M%SZ').txt"
{
  printf 'result=passed\n'
  printf 'started_at=%s\n' "$STARTED_AT"
  printf 'duration_seconds=%s\n' "$DURATION_SECONDS"
  printf 'rto_seconds=%s\n' "$DURATION_SECONDS"
  printf 'rpo_seconds=%s\n' "$RPO_SECONDS"
  printf 'backup_age_seconds=%s\n' "$BACKUP_AGE_SECONDS"
  if [ -n "$TARGET" ]; then
    printf 'target_time=%s\n' "$TARGET"
  else
    printf 'target_time=latest-consistent-point\n'
  fi
  printf 'last_replayed_transaction_at=%s\n' "$RECOVERED_XACT_AT"
  printf 'schema_migrations=%s\n' "$MIGRATION_COUNT"
  printf 'still_in_recovery=%s\n' "$RECOVERY_STATE"
  printf 'database_fingerprint_sha256=%s\n' "$DATABASE_FINGERPRINT"
  printf 'recovery_manifest=%s\n' "$MANIFEST_NAME"
  if [ -n "$EXPECTED_MANIFEST" ]; then
    printf 'expected_manifest=%s\n' "$(basename -- "$EXPECTED_MANIFEST")"
    printf 'expected_manifest_matched=true\n'
  else
    printf 'expected_manifest_matched=not_requested\n'
  fi
  printf '%s\n' "$DRILL_OUTPUT"
} > "$REPORT_FILE"

mv -- "$MANIFEST_TEMP" "$MANIFEST_FILE"
MANIFEST_TEMP=''

find "$REPORT_DIR" -type f -name 'pitr-drill-*.txt' \
  -mtime "+$REPORT_RETENTION_DAYS" -delete

printf 'Isolated PITR drill passed: %s\n' "$REPORT_FILE"

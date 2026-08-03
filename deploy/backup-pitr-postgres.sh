#!/bin/sh
set -eu

umask 077

TYPE=${1:-diff}
case "$TYPE" in
  full|diff|incr) ;;
  *)
    printf 'Usage: %s [full|diff|incr]\n' "$0" >&2
    exit 1
    ;;
esac

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
COMPOSE_FILE=${OTTO_CONTROL_COMPOSE_FILE:-"$ROOT/compose.production.yaml"}
ENV_FILE=${OTTO_CONTROL_ENV_FILE:-"$ROOT/.env.production"}

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
REPORT_RETENTION_DAYS=${REPORT_RETENTION_DAYS:-180}
case "$REPORT_RETENTION_DAYS" in
  ''|*[!0-9]*|0)
    printf '%s\n' 'CONTROL_PITR_REPORT_RETENTION_DAYS must be a positive integer' >&2
    exit 1
    ;;
esac

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
trap 'rmdir "$LOCK_DIR" 2>/dev/null || true' EXIT HUP INT TERM

PRIMARY=$(find_primary) || {
  printf '%s\n' 'Patroni does not currently expose a writable primary' >&2
  exit 1
}
STARTED_AT=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
STARTED_SECONDS=$(date '+%s')

compose exec -T --user postgres "$PRIMARY" otto-pgbackrest --stanza=otto-control stanza-create
compose exec -T --user postgres "$PRIMARY" otto-pgbackrest --stanza=otto-control check
compose exec -T --user postgres "$PRIMARY" otto-pgbackrest \
  --stanza=otto-control --type="$TYPE" backup
compose exec -T --user postgres "$PRIMARY" otto-pgbackrest --stanza=otto-control expire

COMPLETED_AT=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
DURATION_SECONDS=$(($(date '+%s') - STARTED_SECONDS))
REPORT_FILE="$REPORT_DIR/physical-backup-$(date -u '+%Y%m%dT%H%M%SZ').txt"
{
  printf 'result=passed\n'
  printf 'backup_type=%s\n' "$TYPE"
  printf 'primary=%s\n' "$PRIMARY"
  printf 'started_at=%s\n' "$STARTED_AT"
  printf 'completed_at=%s\n' "$COMPLETED_AT"
  printf 'duration_seconds=%s\n' "$DURATION_SECONDS"
  compose exec -T --user postgres "$PRIMARY" otto-pgbackrest --stanza=otto-control info
} > "$REPORT_FILE"

find "$REPORT_DIR" -type f -name 'physical-backup-*.txt' \
  -mtime "+$REPORT_RETENTION_DAYS" -delete

printf 'Encrypted physical backup completed: %s\n' "$REPORT_FILE"

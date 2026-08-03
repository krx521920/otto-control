#!/bin/sh
set -eu

umask 077

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
DB_USER=$(read_env POSTGRES_USER)
DB_NAME=$(read_env POSTGRES_DB)
RETENTION_DAYS=$(read_env CONTROL_BACKUP_RETENTION_DAYS)
BACKUP_KEY_FILE=$(read_env OTTO_CONTROL_BACKUP_KEY_FILE)
DB_USER=${DB_USER:-otto_control}
DB_NAME=${DB_NAME:-otto_control}
RETENTION_DAYS=${RETENTION_DAYS:-30}
BACKUP_KEY_FILE=${BACKUP_KEY_FILE:-"$ROOT/secrets/backup_encryption_key"}
case "$BACKUP_KEY_FILE" in
  /*) ;;
  *) BACKUP_KEY_FILE="$ROOT/$BACKUP_KEY_FILE" ;;
esac

case "$DB_USER" in
  ''|*[!A-Za-z0-9_]*)
    printf '%s\n' 'database user and name may contain only letters, digits, and underscores' >&2
    exit 1
    ;;
esac
case "$DB_NAME" in
  ''|*[!A-Za-z0-9_]*)
    printf '%s\n' 'database user and name may contain only letters, digits, and underscores' >&2
    exit 1
    ;;
esac
case "$RETENTION_DAYS" in
  ''|*[!0-9]*)
    printf '%s\n' 'CONTROL_BACKUP_RETENTION_DAYS must be a positive integer' >&2
    exit 1
    ;;
esac
if [ "$RETENTION_DAYS" -lt 1 ]; then
  printf '%s\n' 'CONTROL_BACKUP_RETENTION_DAYS must be at least 1' >&2
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

mkdir -p "$BACKUP_DIR"
LOCK_DIR="$BACKUP_DIR/.operation.lock"
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  printf '%s\n' 'another Otto Control backup or restore is already running' >&2
  exit 1
fi

DUMP_PIPE=''
DUMP_PID=''
TEMP_FILE=''
cleanup() {
  if [ -n "$DUMP_PID" ]; then kill "$DUMP_PID" 2>/dev/null || true; fi
  if [ -n "$DUMP_PIPE" ]; then rm -f -- "$DUMP_PIPE"; fi
  if [ -n "$TEMP_FILE" ]; then rm -f -- "$TEMP_FILE"; fi
  rmdir "$LOCK_DIR" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

TIMESTAMP=$(date -u '+%Y%m%dT%H%M%SZ')
BACKUP_NAME="otto-control-$TIMESTAMP.dump.enc"
TEMP_FILE="$BACKUP_DIR/$BACKUP_NAME.part"
FINAL_FILE="$BACKUP_DIR/$BACKUP_NAME"
DUMP_PIPE="$BACKUP_DIR/.dump-$$.pipe"
mkfifo "$DUMP_PIPE"

compose exec -T postgres-tools pg_dump \
  --username "$DB_USER" \
  --dbname "$DB_NAME" \
  --no-password \
  --format custom \
  --compress 9 \
  --no-owner > "$DUMP_PIPE" &
DUMP_PID=$!

node "$ROOT/scripts/backup-crypto.mjs" encrypt \
  --input "$DUMP_PIPE" \
  --output "$TEMP_FILE" \
  --key-file "$BACKUP_KEY_FILE"
if ! wait "$DUMP_PID"; then
  DUMP_PID=''
  printf '%s\n' 'PostgreSQL backup stream failed' >&2
  exit 1
fi
DUMP_PID=''
rm -f -- "$DUMP_PIPE"
DUMP_PIPE=''

if [ ! -s "$TEMP_FILE" ]; then
  printf '%s\n' 'PostgreSQL produced an empty backup' >&2
  exit 1
fi
if [ "$COMPOSE_MODE" = plugin ]; then
  set -- docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE"
else
  set -- docker-compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE"
fi
if ! node "$ROOT/scripts/backup-crypto.mjs" decrypt-run \
  --input "$TEMP_FILE" \
  --key-file "$BACKUP_KEY_FILE" \
  --command-stdout ignore \
  -- "$@" exec -T postgres-tools pg_restore --no-password --list
then
  printf '%s\n' 'encrypted PostgreSQL backup validation failed' >&2
  exit 1
fi
mv -- "$TEMP_FILE" "$FINAL_FILE"
TEMP_FILE=''

(
  cd "$BACKUP_DIR"
  sha256sum "$BACKUP_NAME" > "$BACKUP_NAME.sha256"
)

node "$ROOT/scripts/replicate-backup-s3.mjs" \
  --env-file "$ENV_FILE" \
  --file "$FINAL_FILE" \
  --checksum "$FINAL_FILE.sha256" \
  --report-directory "$BACKUP_DIR/reports"

find "$BACKUP_DIR" -type f \
  \( -name 'otto-control-*.dump.enc' -o -name 'otto-control-*.dump.enc.sha256' \) \
  -mtime "+$RETENTION_DAYS" -delete
find "$BACKUP_DIR/reports" -type f -name 'otto-control-*.dump.enc.*.json' \
  -mtime "+$RETENTION_DAYS" -delete

printf 'Backup created: %s\n' "$FINAL_FILE"

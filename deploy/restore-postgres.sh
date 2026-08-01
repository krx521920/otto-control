#!/bin/sh
set -eu

umask 077

if [ "$#" -ne 2 ] || [ "$2" != '--confirm=RESTORE_OTTO_CONTROL' ]; then
  printf 'Usage: %s /absolute/path/to/backup.dump --confirm=RESTORE_OTTO_CONTROL\n' "$0" >&2
  exit 1
fi

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
COMPOSE_FILE=${OTTO_CONTROL_COMPOSE_FILE:-"$ROOT/compose.production.yaml"}
ENV_FILE=${OTTO_CONTROL_ENV_FILE:-"$ROOT/.env.production"}
BACKUP_PATH=$1

if [ ! -f "$BACKUP_PATH" ] || [ ! -f "$BACKUP_PATH.sha256" ]; then
  printf '%s\n' 'backup and matching .sha256 file are required' >&2
  exit 1
fi

BACKUP_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$BACKUP_PATH")" && pwd)
BACKUP_NAME=$(basename -- "$BACKUP_PATH")
BACKUP_PATH="$BACKUP_DIRECTORY/$BACKUP_NAME"
(
  cd "$BACKUP_DIRECTORY"
  sha256sum --check "$BACKUP_NAME.sha256"
)

read_env() {
  sed -n "s/^$1=//p" "$ENV_FILE" | tail -n 1
}

DB_USER=$(read_env POSTGRES_USER)
DB_NAME=$(read_env POSTGRES_DB)
BACKUP_KEY_FILE=$(read_env OTTO_CONTROL_BACKUP_KEY_FILE)
DB_USER=${DB_USER:-otto_control}
DB_NAME=${DB_NAME:-otto_control}
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

# Authenticate the encrypted archive and verify PostgreSQL can parse it before any write is stopped.
BACKUP_DIR=${OTTO_CONTROL_BACKUP_DIR:-"$ROOT/backups"}
mkdir -p "$BACKUP_DIR"
VERIFY_PIPE="$BACKUP_DIR/.restore-verify-$$.pipe"
VERIFY_PID=''
cleanup_verify() {
  if [ -n "$VERIFY_PID" ]; then kill "$VERIFY_PID" 2>/dev/null || true; fi
  rm -f -- "$VERIFY_PIPE"
}
trap cleanup_verify EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
mkfifo "$VERIFY_PIPE"
node "$ROOT/scripts/backup-crypto.mjs" decrypt \
  --input "$BACKUP_PATH" \
  --output - \
  --key-file "$BACKUP_KEY_FILE" > "$VERIFY_PIPE" &
VERIFY_PID=$!
if ! compose exec -T postgres-tools pg_restore --list < "$VERIFY_PIPE" >/dev/null; then
  kill "$VERIFY_PID" 2>/dev/null || true
  wait "$VERIFY_PID" 2>/dev/null || true
  VERIFY_PID=''
  rm -f -- "$VERIFY_PIPE"
  printf '%s\n' 'backup archive validation failed' >&2
  exit 1
fi
if ! wait "$VERIFY_PID"; then
  VERIFY_PID=''
  rm -f -- "$VERIFY_PIPE"
  printf '%s\n' 'backup decryption or authentication failed' >&2
  exit 1
fi
VERIFY_PID=''
rm -f -- "$VERIFY_PIPE"
trap - EXIT HUP INT TERM

# A restorable snapshot of the current state is mandatory before destructive work.
sh "$ROOT/deploy/backup-postgres.sh"

LOCK_DIR="$BACKUP_DIR/.operation.lock"
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  printf '%s\n' 'another Otto Control backup or restore is already running' >&2
  exit 1
fi

RESTORE_COMPLETE=false
RESTORE_PIPE=''
RESTORE_PID=''
cleanup() {
  if [ -n "$RESTORE_PID" ]; then kill "$RESTORE_PID" 2>/dev/null || true; fi
  if [ -n "$RESTORE_PIPE" ]; then rm -f -- "$RESTORE_PIPE"; fi
  rmdir "$LOCK_DIR" 2>/dev/null || true
  if [ "$RESTORE_COMPLETE" != true ]; then
    printf '%s\n' 'restore did not complete; the control service is not confirmed ready' >&2
  fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

compose stop control-a control-b control-c
compose exec -T postgres-tools dropdb \
  --username "$DB_USER" \
  --if-exists \
  --force \
  "$DB_NAME"
compose exec -T postgres-tools createdb \
  --username "$DB_USER" \
  --owner "$DB_USER" \
  "$DB_NAME"
RESTORE_PIPE="$BACKUP_DIR/.restore-$$.pipe"
mkfifo "$RESTORE_PIPE"
node "$ROOT/scripts/backup-crypto.mjs" decrypt \
  --input "$BACKUP_PATH" \
  --output - \
  --key-file "$BACKUP_KEY_FILE" > "$RESTORE_PIPE" &
RESTORE_PID=$!
if ! compose exec -T postgres-tools pg_restore \
  --username "$DB_USER" \
  --dbname "$DB_NAME" \
  --no-owner \
  --exit-on-error < "$RESTORE_PIPE"
then
  kill "$RESTORE_PID" 2>/dev/null || true
  wait "$RESTORE_PID" 2>/dev/null || true
  RESTORE_PID=''
  printf '%s\n' 'PostgreSQL restore failed' >&2
  exit 1
fi
if ! wait "$RESTORE_PID"; then
  RESTORE_PID=''
  printf '%s\n' 'backup decryption or authentication failed during restore' >&2
  exit 1
fi
RESTORE_PID=''
rm -f -- "$RESTORE_PIPE"
RESTORE_PIPE=''
compose start control-a control-b control-c

ATTEMPT=0
until compose exec -T control-a node -e \
  "fetch('http://127.0.0.1:7788/health/ready').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
do
  ATTEMPT=$((ATTEMPT + 1))
  if [ "$ATTEMPT" -ge 30 ]; then
    printf '%s\n' 'control service did not become ready after restore' >&2
    exit 1
  fi
  sleep 2
done

RESTORE_COMPLETE=true
printf 'Restore completed from %s\n' "$BACKUP_PATH"

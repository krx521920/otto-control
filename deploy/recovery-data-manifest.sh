#!/bin/sh
set -eu

umask 077

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
COMPOSE_FILE=${OTTO_CONTROL_COMPOSE_FILE:-"$ROOT/compose.production.yaml"}
ENV_FILE=${OTTO_CONTROL_ENV_FILE:-"$ROOT/.env.production"}
SERVICE=postgres-tools
DATABASE=otto_control
DATABASE_USER=otto_control
DATABASE_PORT=5432
CONTAINER_USER=''
COMPOSE_PROFILE=''
OUTPUT=''
EXPECTED=''

usage() {
  printf '%s\n' \
    "Usage: $0 --output FILE [--expected FILE] [--service NAME] [--database NAME] [--user NAME] [--port PORT] [--container-user NAME] [--profile NAME]" >&2
  exit 1
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) OUTPUT=${2:-}; shift 2 ;;
    --expected) EXPECTED=${2:-}; shift 2 ;;
    --service) SERVICE=${2:-}; shift 2 ;;
    --database) DATABASE=${2:-}; shift 2 ;;
    --user) DATABASE_USER=${2:-}; shift 2 ;;
    --port) DATABASE_PORT=${2:-}; shift 2 ;;
    --container-user) CONTAINER_USER=${2:-}; shift 2 ;;
    --profile) COMPOSE_PROFILE=${2:-}; shift 2 ;;
    *) usage ;;
  esac
done

if [ -z "$OUTPUT" ]; then usage; fi
for value in "$SERVICE" "$DATABASE" "$DATABASE_USER"; do
  case "$value" in
    ''|*[!A-Za-z0-9_-]*)
      printf '%s\n' 'service, database, and user may contain only letters, digits, underscores, and hyphens' >&2
      exit 1
      ;;
  esac
done
case "$CONTAINER_USER" in
  ''|*[!A-Za-z0-9_-]*)
    if [ -n "$CONTAINER_USER" ]; then
      printf '%s\n' 'container user may contain only letters, digits, underscores, and hyphens' >&2
      exit 1
    fi
    ;;
esac
case "$COMPOSE_PROFILE" in
  ''|*[!A-Za-z0-9_-]*)
    if [ -n "$COMPOSE_PROFILE" ]; then
      printf '%s\n' 'Compose profile may contain only letters, digits, underscores, and hyphens' >&2
      exit 1
    fi
    ;;
esac
case "$DATABASE_PORT" in
  ''|*[!0-9]*)
    printf '%s\n' 'database port must be an integer' >&2
    exit 1
    ;;
esac
if [ "$DATABASE_PORT" -lt 1 ] || [ "$DATABASE_PORT" -gt 65535 ]; then
  printf '%s\n' 'database port must be between 1 and 65535' >&2
  exit 1
fi
if [ -e "$OUTPUT" ]; then
  printf 'refusing to overwrite recovery manifest: %s\n' "$OUTPUT" >&2
  exit 1
fi
if [ -n "$EXPECTED" ] && { [ ! -f "$EXPECTED" ] || [ -L "$EXPECTED" ]; }; then
  printf 'expected recovery manifest is missing or unsafe: %s\n' "$EXPECTED" >&2
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
    if [ -n "$COMPOSE_PROFILE" ]; then
      docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" --profile "$COMPOSE_PROFILE" "$@"
    else
      docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" "$@"
    fi
  else
    if [ -n "$COMPOSE_PROFILE" ]; then
      docker-compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" --profile "$COMPOSE_PROFILE" "$@"
    else
      docker-compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" "$@"
    fi
  fi
}

service_exec() {
  if [ -n "$CONTAINER_USER" ]; then
    compose exec -T --user "$CONTAINER_USER" "$SERVICE" "$@"
  else
    compose exec -T "$SERVICE" "$@"
  fi
}

OUTPUT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$OUTPUT")" && pwd)
OUTPUT="$OUTPUT_DIRECTORY/$(basename -- "$OUTPUT")"
TEMP_FILE="$OUTPUT.part.$$"
BODY_FILE="$OUTPUT.body.$$"
cleanup() {
  rm -f -- "$TEMP_FILE" "$BODY_FILE"
}
trap cleanup EXIT HUP INT TERM

psql_value() {
  service_exec psql \
    --username "$DATABASE_USER" \
    --dbname "$DATABASE" \
    --port "$DATABASE_PORT" \
    --set=ON_ERROR_STOP=1 \
    --tuples-only --no-align \
    --command "$1"
}

table_manifest() {
  table=$1
  exists=$(psql_value "SELECT CASE WHEN to_regclass('public.$table') IS NULL THEN 'missing' ELSE 'ok' END")
  if [ "$exists" != ok ]; then
    printf 'recovery manifest is missing required table: %s\n' "$table" >&2
    exit 1
  fi
  count=$(psql_value "SELECT COUNT(*) FROM $table")
  case "$count" in
    ''|*[!0-9]*)
      printf 'invalid row count while fingerprinting table: %s\n' "$table" >&2
      exit 1
      ;;
  esac
  sha256=$(service_exec psql \
    --username "$DATABASE_USER" \
    --dbname "$DATABASE" \
    --port "$DATABASE_PORT" \
    --set=ON_ERROR_STOP=1 \
    --command "COPY (SELECT row_to_json(source_row)::text FROM $table AS source_row ORDER BY row_to_json(source_row)::text COLLATE \"C\") TO STDOUT" |
    sha256sum | awk '{print $1}')
  case "$sha256" in
    [a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9]*) ;;
    *)
      printf 'invalid SHA-256 while fingerprinting table: %s\n' "$table" >&2
      exit 1
      ;;
  esac
  if [ "${#sha256}" -ne 64 ]; then
    printf 'invalid SHA-256 length while fingerprinting table: %s\n' "$table" >&2
    exit 1
  fi
  printf 'table.%s.count=%s\n' "$table" "$count" >> "$BODY_FILE"
  printf 'table.%s.sha256=%s\n' "$table" "$sha256" >> "$BODY_FILE"
}

: > "$BODY_FILE"
CONTROL_TABLES=$(psql_value \
  "SELECT string_agg(tablename, E'\\n' ORDER BY tablename) FROM pg_catalog.pg_tables WHERE schemaname = 'public' AND tablename LIKE 'control\\_%' ESCAPE '\\'")
if [ -z "$CONTROL_TABLES" ]; then
  printf '%s\n' 'recovery manifest found no Control tables' >&2
  exit 1
fi
for required_table in \
  control_schema_migrations \
  control_customers \
  control_deployments \
  control_licenses \
  control_signing_keys \
  control_credit_transactions \
  control_audit_events \
  control_audit_chain_state \
  control_audit_witness_evidence
do
  if ! printf '%s\n' "$CONTROL_TABLES" | grep -F -x -q "$required_table"; then
    printf 'recovery manifest is missing required table: %s\n' "$required_table" >&2
    exit 1
  fi
done
printf '%s\n' "$CONTROL_TABLES" | while IFS= read -r table; do
  case "$table" in
    control_*) ;;
    *)
      printf 'unsafe Control table name encountered: %s\n' "$table" >&2
      exit 1
      ;;
  esac
  case "$table" in
    ''|*[!a-z0-9_]*)
      printf 'unsafe Control table name encountered: %s\n' "$table" >&2
      exit 1
      ;;
  esac
  table_manifest "$table"
done

DATABASE_FINGERPRINT=$(sha256sum "$BODY_FILE" | awk '{print $1}')
{
  printf 'version=1\n'
  printf 'algorithm=sha256-postgresql-row-json-v1\n'
  printf 'captured_at=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  cat "$BODY_FILE"
  printf 'database_fingerprint_sha256=%s\n' "$DATABASE_FINGERPRINT"
} > "$TEMP_FILE"

if [ -n "$EXPECTED" ]; then
  EXPECTED_FINGERPRINT=$(awk -F= '$1 == "database_fingerprint_sha256" { value=$2 } END { print value }' "$EXPECTED")
  if [ -z "$EXPECTED_FINGERPRINT" ] || [ "$EXPECTED_FINGERPRINT" != "$DATABASE_FINGERPRINT" ]; then
    printf '%s\n' 'recovered database fingerprint does not match the expected manifest' >&2
    while IFS='=' read -r key expected_value; do
      case "$key" in
        table.*.count|table.*.sha256)
          actual_value=$(awk -F= -v expected_key="$key" \
            '$1 == expected_key { value=$2 } END { print value }' "$TEMP_FILE")
          if [ "$actual_value" != "$expected_value" ]; then
            printf 'mismatch: %s\n' "$key" >&2
          fi
          ;;
      esac
    done < "$EXPECTED"
    exit 1
  fi
fi

mv -- "$TEMP_FILE" "$OUTPUT"
TEMP_FILE=''
printf 'Recovery data manifest created: %s\n' "$OUTPUT"

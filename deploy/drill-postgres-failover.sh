#!/bin/sh
set -eu

umask 077

if [ "${1:-}" != '--confirm=FAILOVER_OTTO_CONTROL' ]; then
  printf 'Usage: %s --confirm=FAILOVER_OTTO_CONTROL\n' "$0" >&2
  exit 1
fi

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
COMPOSE_FILE=${OTTO_CONTROL_COMPOSE_FILE:-"$ROOT/compose.production.yaml"}
ENV_FILE=${OTTO_CONTROL_ENV_FILE:-"$ROOT/.env.production"}
REPORT_DIR=${OTTO_CONTROL_FAILOVER_REPORT_DIR:-"$ROOT/backups/reports/failover"}

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

find_synchronous_standby() {
  primary=$1
  for candidate in postgres-1 postgres-2 postgres-3; do
    if [ "$candidate" = "$primary" ]; then
      continue
    fi
    if compose exec -T "$candidate" curl --fail --silent \
      http://127.0.0.1:8008/synchronous >/dev/null 2>&1
    then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

wait_for_stable_failover_candidate() {
  primary=$1
  attempt=0
  stable_rounds=0
  stable_candidate=''

  while [ "$attempt" -lt 30 ]; do
    candidate=$(find_synchronous_standby "$primary" || true)
    if [ -n "$candidate" ] && [ "$candidate" = "$stable_candidate" ]; then
      stable_rounds=$((stable_rounds + 1))
    elif [ -n "$candidate" ]; then
      stable_candidate=$candidate
      stable_rounds=1
    else
      stable_candidate=''
      stable_rounds=0
    fi

    # Multiple successful checks give Patroni time to persist the synchronous
    # candidate in the DCS before the leader disappears. Without this gate a
    # newly bootstrapped cluster can fail closed with no promotable standby.
    if [ "$stable_rounds" -ge 3 ]; then
      printf '%s\n' "$stable_candidate"
      return 0
    fi

    attempt=$((attempt + 1))
    sleep 2
  done

  return 1
}

mkdir -p "$REPORT_DIR"
OLD_PRIMARY=$(find_primary) || {
  printf '%s\n' 'cannot run failover drill without a healthy primary' >&2
  exit 1
}
FAILOVER_CANDIDATE=$(wait_for_stable_failover_candidate "$OLD_PRIMARY") || {
  printf '%s\n' \
    'cannot run failover drill without a stable synchronous standby' >&2
  exit 1
}
OLD_PRIMARY_RESTARTED=false
cleanup() {
  if [ "$OLD_PRIMARY_RESTARTED" != true ]; then
    compose start "$OLD_PRIMARY" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT HUP INT TERM

STARTED_AT=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
STARTED_SECONDS=$(date '+%s')
# A hard kill models the unplanned process/host failure that Patroni is
# expected to recover from. A graceful PostgreSQL stop writes a final shutdown
# checkpoint after replication disconnects and is a switchover, not a failover.
compose kill -s SIGKILL "$OLD_PRIMARY"

ATTEMPT=0
NEW_PRIMARY=''
while [ "$ATTEMPT" -lt 60 ]; do
  NEW_PRIMARY=$(find_primary || true)
  if [ -n "$NEW_PRIMARY" ] && [ "$NEW_PRIMARY" != "$OLD_PRIMARY" ]; then
    break
  fi
  ATTEMPT=$((ATTEMPT + 1))
  sleep 1
done
if [ -z "$NEW_PRIMARY" ] || [ "$NEW_PRIMARY" = "$OLD_PRIMARY" ]; then
  printf '%s\n' 'Patroni did not promote a standby within the 60-second RTO' >&2
  exit 1
fi

probe_write() {
  # A rolled-back write proves HAProxy selected a writable primary without
  # leaving drill data in the production schema. Retrying is safe because the
  # temporary table and transaction never persist.
  compose exec -T postgres-tools psql --set=ON_ERROR_STOP=1 <<'SQL'
BEGIN;
CREATE TEMP TABLE otto_control_failover_probe (value integer NOT NULL);
INSERT INTO otto_control_failover_probe (value) VALUES (1);
DO $$
BEGIN
  IF (SELECT COUNT(*) FROM otto_control_failover_probe) <> 1 THEN
    RAISE EXCEPTION 'failover write probe failed';
  END IF;
END
$$;
ROLLBACK;
SQL
}

# Patroni can expose the new primary just before HAProxy completes its next
# active health check. Count that routing convergence in the measured RTO.
ATTEMPT=0
until probe_write; do
  ATTEMPT=$((ATTEMPT + 1))
  if [ "$ATTEMPT" -ge 30 ]; then
    printf '%s\n' 'HAProxy did not route a successful write within 30 seconds of promotion' >&2
    exit 1
  fi
  sleep 1
done

RTO_SECONDS=$(($(date '+%s') - STARTED_SECONDS))
compose start "$OLD_PRIMARY"
OLD_PRIMARY_RESTARTED=true

ATTEMPT=0
until compose exec -T "$OLD_PRIMARY" curl --fail --silent \
  http://127.0.0.1:8008/readiness >/dev/null 2>&1
do
  ATTEMPT=$((ATTEMPT + 1))
  if [ "$ATTEMPT" -ge 60 ]; then
    printf '%s\n' 'former primary did not rejoin the Patroni cluster' >&2
    exit 1
  fi
  sleep 2
done

REPORT_FILE="$REPORT_DIR/failover-drill-$(date -u '+%Y%m%dT%H%M%SZ').txt"
{
  printf 'result=passed\n'
  printf 'started_at=%s\n' "$STARTED_AT"
  printf 'old_primary=%s\n' "$OLD_PRIMARY"
  printf 'prepared_candidate=%s\n' "$FAILOVER_CANDIDATE"
  printf 'new_primary=%s\n' "$NEW_PRIMARY"
  printf 'write_rto_seconds=%s\n' "$RTO_SECONDS"
  printf 'former_primary_rejoined=true\n'
} > "$REPORT_FILE"

printf 'Automatic failover drill passed: %s\n' "$REPORT_FILE"

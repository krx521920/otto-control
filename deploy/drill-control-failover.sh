#!/bin/sh
set -eu

umask 077

if [ "${1:-}" != '--confirm=FAILOVER_OTTO_CONTROL_REPLICAS' ]; then
  printf 'Usage: %s --confirm=FAILOVER_OTTO_CONTROL_REPLICAS\n' "$0" >&2
  exit 1
fi

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
COMPOSE_FILE=${OTTO_CONTROL_COMPOSE_FILE:-"$ROOT/compose.production.yaml"}
ENV_FILE=${OTTO_CONTROL_ENV_FILE:-"$ROOT/.env.production"}

read_env() {
  awk -F= -v key="$1" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$ENV_FILE"
}

DEPLOYMENT_ENVIRONMENT=$(read_env OTTO_CONTROL_DEPLOYMENT_ENVIRONMENT)
EDGE_URL=${OTTO_CONTROL_FAILOVER_EDGE_URL:-$(read_env CONTROL_PUBLIC_BASE_URL)}
BACKUP_DIR=$(read_env OTTO_CONTROL_BACKUP_DIR)
case "$BACKUP_DIR" in
  /*) ;;
  *) BACKUP_DIR="$ROOT/${BACKUP_DIR#./}" ;;
esac
REPORT_DIR=${OTTO_CONTROL_REPLICA_FAILOVER_REPORT_DIR:-"$BACKUP_DIR/reports/control-failover"}

if [ -z "$EDGE_URL" ]; then
  printf '%s\n' 'CONTROL_PUBLIC_BASE_URL is required' >&2
  exit 1
fi
if [ "${OTTO_CONTROL_FAILOVER_INSECURE_TLS:-false}" = true ] && \
   [ "$DEPLOYMENT_ENVIRONMENT" = production ]; then
  printf '%s\n' 'insecure TLS is forbidden for production failover drills' >&2
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

instance_ready() {
  compose exec -T "$1" node -e \
    "fetch('http://127.0.0.1:7788/health/ready').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
}

edge_ready() {
  if [ "${OTTO_CONTROL_FAILOVER_INSECURE_TLS:-false}" = true ]; then
    curl --insecure --fail --silent --show-error --max-time 10 "$EDGE_URL/health/ready" >/dev/null
  else
    curl --fail --silent --show-error --max-time 10 "$EDGE_URL/health/ready" >/dev/null
  fi
}

wait_for_instance() {
  instance=$1
  attempt=0
  until instance_ready "$instance" >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 60 ]; then
      printf 'Control instance did not become ready: %s\n' "$instance" >&2
      return 1
    fi
    sleep 2
  done
}

wait_for_edge() {
  attempt=0
  until edge_ready; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 30 ]; then
      printf '%s\n' 'public Control edge became unavailable during replica failure' >&2
      return 1
    fi
    sleep 1
  done
}

STOPPED_INSTANCE=''
cleanup() {
  if [ -n "$STOPPED_INSTANCE" ]; then
    compose start "$STOPPED_INSTANCE" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$REPORT_DIR"
STARTED_AT=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
wait_for_edge
for instance in control-a control-b control-c; do
  wait_for_instance "$instance"
done

for failed in control-a control-b control-c; do
  compose stop "$failed" >/dev/null
  STOPPED_INSTANCE=$failed
  wait_for_edge
  for survivor in control-a control-b control-c; do
    if [ "$survivor" != "$failed" ]; then
      wait_for_instance "$survivor"
    fi
  done
  compose start "$failed" >/dev/null
  wait_for_instance "$failed"
  STOPPED_INSTANCE=''
done

REPORT_FILE="$REPORT_DIR/control-failover-$(date -u '+%Y%m%dT%H%M%SZ').txt"
{
  printf 'result=passed\n'
  printf 'started_at=%s\n' "$STARTED_AT"
  printf 'completed_at=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf 'edge_url=%s\n' "$EDGE_URL"
  printf 'replicas_tested=control-a,control-b,control-c\n'
} > "$REPORT_FILE"

printf 'Control replica failover drill passed: %s\n' "$REPORT_FILE"

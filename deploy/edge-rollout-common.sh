#!/bin/sh
set -eu

COMPOSE_FILE=${OTTO_EDGE_COMPOSE_FILE:-compose.production.yaml}
ENV_FILE=${OTTO_CONTROL_ENV_FILE:-.env.production}
ROLLOUT_STATE_DIR=${OTTO_EDGE_ROLLOUT_STATE_DIR:-.edge-rollout}

edge_compose() {
  docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" "$@"
}

require_edge_enabled() {
  if ! grep -qx 'OTTO_EDGE_ENABLED=true' "$ENV_FILE"; then
    printf '%s\n' 'OTTO_EDGE_ENABLED=true is required before an Edge Gateway rollout' >&2
    exit 1
  fi
}

require_digest_image() {
  image=$1
  case "$image" in
    *@sha256:????????????????????????????????????????????????????????????????) ;;
    *)
      printf '%s\n' 'Edge Gateway image must use an immutable @sha256 digest' >&2
      exit 1
      ;;
  esac
}

require_immutable_image() {
  image=$1
  case "$image" in
    *@sha256:????????????????????????????????????????????????????????????????) ;;
    sha256:????????????????????????????????????????????????????????????????) ;;
    *)
      printf '%s\n' 'recorded Edge Gateway image is not immutable' >&2
      exit 1
      ;;
  esac
}

wait_for_healthy() {
  service=$1
  timeout_seconds=${2:-180}
  profile=${3:-edge}
  started_at=$(date +%s)
  while :; do
    container_id=$(edge_compose --profile "$profile" ps -q "$service")
    if [ -n "$container_id" ]; then
      health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container_id")
      case "$health" in
        healthy) return 0 ;;
        unhealthy|exited|dead) return 1 ;;
      esac
    fi
    now=$(date +%s)
    if [ $((now - started_at)) -ge "$timeout_seconds" ]; then
      return 1
    fi
    sleep 2
  done
}

write_rollout_state() {
  name=$1
  value=$2
  mkdir -p "$ROLLOUT_STATE_DIR"
  chmod 0700 "$ROLLOUT_STATE_DIR"
  temporary="$ROLLOUT_STATE_DIR/$name.tmp.$$"
  umask 077
  printf '%s\n' "$value" > "$temporary"
  mv "$temporary" "$ROLLOUT_STATE_DIR/$name"
}

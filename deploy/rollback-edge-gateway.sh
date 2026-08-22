#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/edge-rollout-common.sh"

confirmation=''
for argument in "$@"; do
  case "$argument" in
    --confirm=*) confirmation=${argument#--confirm=} ;;
    *) printf 'unknown argument: %s\n' "$argument" >&2; exit 1 ;;
  esac
done

if [ "$confirmation" != 'ROLLBACK_OTTO_EDGE' ]; then
  printf '%s\n' 'refusing rollback without --confirm=ROLLBACK_OTTO_EDGE' >&2
  exit 1
fi
require_edge_enabled
if [ ! -s "$ROLLOUT_STATE_DIR/previous-image" ]; then
  printf '%s\n' 'no verified previous Edge Gateway image is recorded' >&2
  exit 1
fi
previous_image=$(cat "$ROLLOUT_STATE_DIR/previous-image")
require_immutable_image "$previous_image"
current_container=$(edge_compose --profile edge ps -q edge-gateway)
if [ -z "$current_container" ]; then
  printf '%s\n' 'the production Edge Gateway is not running' >&2
  exit 1
fi
current_image=$(docker inspect --format '{{.Config.Image}}' "$current_container")
case "$current_image" in
  *@sha256:*|sha256:*) ;;
  *) current_image=$(docker inspect --format '{{.Image}}' "$current_container") ;;
esac
require_immutable_image "$current_image"

OTTO_EDGE_IMAGE=$previous_image edge_compose --profile edge up -d --no-deps edge-gateway
if ! wait_for_healthy edge-gateway 180 edge; then
  printf '%s\n' 'rollback image failed readiness; operator intervention is required' >&2
  exit 1
fi
write_rollout_state current-image "$previous_image"
write_rollout_state previous-image "$current_image"
printf 'Edge Gateway rolled back: %s -> %s\n' "$current_image" "$previous_image"

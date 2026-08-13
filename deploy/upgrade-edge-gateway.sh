#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/edge-rollout-common.sh"

image=''
confirmation=''
for argument in "$@"; do
  case "$argument" in
    --image=*) image=${argument#--image=} ;;
    --confirm=*) confirmation=${argument#--confirm=} ;;
    *) printf 'unknown argument: %s\n' "$argument" >&2; exit 1 ;;
  esac
done

if [ "$confirmation" != 'UPGRADE_OTTO_EDGE' ]; then
  printf '%s\n' 'refusing upgrade without --confirm=UPGRADE_OTTO_EDGE' >&2
  exit 1
fi
require_edge_enabled
require_digest_image "$image"

current_container=$(edge_compose --profile edge ps -q edge-gateway)
if [ -z "$current_container" ]; then
  printf '%s\n' 'the production Edge Gateway is not running' >&2
  exit 1
fi
previous_image=$(docker inspect --format '{{.Config.Image}}' "$current_container")
case "$previous_image" in
  *@sha256:*) ;;
  *) previous_image=$(docker inspect --format '{{.Image}}' "$current_container") ;;
esac
require_immutable_image "$previous_image"

docker pull "$image"

# Start the isolated canary with separate durable state. It must load the live
# signed policy, connect to TLS Redis and Control, and pass /readyz before cutover.
OTTO_EDGE_IMAGE=$image edge_compose --profile edge-rollout up -d --no-deps edge-gateway-canary
if ! wait_for_healthy edge-gateway-canary 180 edge-rollout; then
  edge_compose --profile edge-rollout logs --tail 100 edge-gateway-canary >&2 || true
  edge_compose --profile edge-rollout stop edge-gateway-canary || true
  edge_compose --profile edge-rollout rm -f edge-gateway-canary || true
  printf '%s\n' 'Edge Gateway canary failed; production was not changed' >&2
  exit 1
fi
edge_compose --profile edge-rollout stop edge-gateway-canary
edge_compose --profile edge-rollout rm -f edge-gateway-canary

write_rollout_state previous-image "$previous_image"
write_rollout_state pending-image "$image"
OTTO_EDGE_IMAGE=$image edge_compose --profile edge up -d --no-deps edge-gateway
if ! wait_for_healthy edge-gateway 180 edge; then
  edge_compose --profile edge logs --tail 100 edge-gateway >&2 || true
  OTTO_EDGE_IMAGE=$previous_image edge_compose --profile edge up -d --no-deps edge-gateway
  if ! wait_for_healthy edge-gateway 180 edge; then
    printf '%s\n' 'automatic rollback also failed; operator intervention is required' >&2
    exit 1
  fi
  printf '%s\n' 'new Edge Gateway failed readiness and was rolled back' >&2
  exit 1
fi
write_rollout_state current-image "$image"
rm -f "$ROLLOUT_STATE_DIR/pending-image"
printf 'Edge Gateway upgraded: %s -> %s\n' "$previous_image" "$image"

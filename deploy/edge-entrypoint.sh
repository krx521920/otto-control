#!/bin/sh
set -eu

RUNTIME_SECRET_DIR=${OTTO_EDGE_RUNTIME_SECRET_DIR:-/run/otto-runtime-secrets}
STATE_DIRECTORY=${OTTO_EDGE_STATE_DIRECTORY:-/var/lib/otto-edge}

if [ "$(id -u)" -ne 0 ]; then
  printf '%s\n' 'Otto Edge Gateway entrypoint must start as root before dropping privileges' >&2
  exit 1
fi

mkdir -p "$STATE_DIRECTORY"
chown node:node "$STATE_DIRECTORY"
chmod 0700 "$STATE_DIRECTORY"

if ! su-exec node test -w "$RUNTIME_SECRET_DIR"; then
  printf 'runtime secret directory is not writable by the node user: %s\n' \
    "$RUNTIME_SECRET_DIR" >&2
  exit 1
fi

stage_environment_file() {
  variable_name=$1
  eval "source_path=\${$variable_name:-}"
  [ -n "$source_path" ] || return
  if [ ! -s "$source_path" ]; then
    printf 'required Edge Gateway file is missing or empty: %s\n' "$source_path" >&2
    exit 1
  fi
  target_path="$RUNTIME_SECRET_DIR/$(basename "$source_path")"
  su-exec node sh -c 'umask 077; cat > "$1"' sh "$target_path" < "$source_path"
  export "$variable_name=$target_path"
}

stage_environment_file NODE_EXTRA_CA_CERTS

required_files='OTTO_EDGE_CONTROL_PUBLIC_KEYS_FILE
OTTO_EDGE_UPSTREAM_ORIGINS_FILE
OTTO_EDGE_DEPLOYMENT_IDENTITY_FILE
OTTO_EDGE_LEASE_TOKEN_FILE
OTTO_EDGE_RATE_LIMIT_KEY_FILE
OTTO_EDGE_REDIS_PASSWORD_FILE
OTTO_EDGE_REDIS_CA_FILE
OTTO_EDGE_EXECUTION_RECEIPT_KEY_FILE
OTTO_EDGE_REQUEST_LEDGER_DATABASE_PASSWORD_FILE
OTTO_EDGE_OPERATIONS_TOKEN_FILE'

for variable_name in $required_files; do
  stage_environment_file "$variable_name"
done

# Signed policies may introduce provider-specific bindings. Their matching
# *_FILE values must point only at the read-only provider-secret mount.
environment_names="$RUNTIME_SECRET_DIR/environment-file-names"
env | sed -n 's/=.*//p' > "$environment_names"
while IFS= read -r variable_name; do
  case "$variable_name" in
    ''|[0-9]*|*[!a-zA-Z0-9_]*) continue ;;
  esac
  case "$variable_name" in
    OTTO_EDGE_*_FILE) ;;
    *_FILE)
      eval "source_path=\${$variable_name:-}"
      case "$source_path" in
        /run/otto-edge-provider-secrets/*) stage_environment_file "$variable_name" ;;
      esac
      ;;
  esac
done < "$environment_names"
rm -f "$environment_names"

exec su-exec node "$@"

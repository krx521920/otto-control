#!/bin/sh
set -eu

RUNTIME_SECRET_DIR=${CONTROL_RUNTIME_SECRET_DIR:-/run/otto-runtime-secrets}

if [ "$(id -u)" -ne 0 ]; then
  printf '%s\n' 'Otto Control entrypoint must start as root before dropping privileges' >&2
  exit 1
fi
if ! su-exec node test -w "$RUNTIME_SECRET_DIR"; then
  printf 'runtime secret directory is not writable by the node user: %s\n' \
    "$RUNTIME_SECRET_DIR" >&2
  exit 1
fi

stage_file() {
  source_path=$1
  target_path="$RUNTIME_SECRET_DIR/$(basename "$source_path")"
  if [ ! -s "$source_path" ]; then
    printf 'required secret file is missing or empty: %s\n' "$source_path" >&2
    exit 1
  fi
  su-exec node sh -c 'umask 077; cat > "$1"' sh "$target_path" < "$source_path"
}

stage_environment_file() {
  variable_name=$1
  eval "source_path=\${$variable_name:-}"
  if [ -z "$source_path" ]; then
    return
  fi
  stage_file "$source_path"
  target_path="$RUNTIME_SECRET_DIR/$(basename "$source_path")"
  export "$variable_name=$target_path"
}

# Keep relative private-key references in a keyring valid after staging it.
if [ -d /run/otto-secrets ]; then
  for source_path in /run/otto-secrets/*; do
    [ -f "$source_path" ] || continue
    stage_file "$source_path"
  done
fi

case " $* " in
  *" dist/federation-server.js "*)
    secret_variables='FEDERATION_ADMIN_TOKEN_FILE
FEDERATION_METRICS_TOKEN_FILE
FEDERATION_DATABASE_PASSWORD_FILE'
    ;;
  *)
    if [ -e /run/secrets/control_signer_private_key.pem ]; then
      stage_file /run/secrets/control_signer_private_key.pem
    fi
    secret_variables='CONTROL_ADMIN_TOKEN_FILE
CONTROL_TOKEN_SECRET_FILE
CONTROL_METRICS_TOKEN_FILE
CONTROL_DATABASE_PASSWORD_FILE
CONTROL_SIGNER_PRIVATE_KEY_FILE
CONTROL_SIGNER_KEYRING_FILE
CONTROL_ALERT_WEBHOOK_SECRET_FILE
CONTROL_ALERT_CHANNELS_FILE
CONTROL_AUDIT_ANCHOR_TOKEN_FILE
CONTROL_AUDIT_WITNESS_SOURCES_FILE
CONTROL_AUDIT_WORM_S3_ACCESS_KEY_ID_FILE
CONTROL_AUDIT_WORM_S3_SECRET_ACCESS_KEY_FILE
CONTROL_AUDIT_WORM_S3_SESSION_TOKEN_FILE
CONTROL_OTLP_HEADERS_FILE
CONTROL_ARTIFACT_S3_ACCESS_KEY_ID_FILE
CONTROL_ARTIFACT_S3_SECRET_ACCESS_KEY_FILE
CONTROL_ARTIFACT_S3_SESSION_TOKEN_FILE
CONTROL_ARTIFACT_ATTESTATION_KEYS_FILE
CONTROL_BACKUP_S3_ACCESS_KEY_ID_FILE
CONTROL_BACKUP_S3_SECRET_ACCESS_KEY_FILE
CONTROL_BACKUP_S3_SESSION_TOKEN_FILE'
    ;;
esac

for variable_name in $secret_variables; do
  stage_environment_file "$variable_name"
done

exec su-exec node "$@"

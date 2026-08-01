#!/bin/sh
set -eu

CONNECTION=${1:-}
APP_PASSWORD_FILE=${POSTGRES_APP_PASSWORD_FILE:-/run/secrets/postgres_password}
if [ -z "$CONNECTION" ] || [ ! -s "$APP_PASSWORD_FILE" ]; then
  printf '%s\n' 'Patroni bootstrap connection or application password is missing' >&2
  exit 1
fi

APP_PASSWORD=$(cat "$APP_PASSWORD_FILE")
psql "$CONNECTION" --set=ON_ERROR_STOP=1 --set=app_password="$APP_PASSWORD" <<'SQL'
SELECT format('CREATE ROLE otto_control LOGIN PASSWORD %L', :'app_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'otto_control')
\gexec
SELECT format('ALTER ROLE otto_control LOGIN PASSWORD %L', :'app_password')
\gexec
SELECT 'CREATE DATABASE otto_control OWNER otto_control'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'otto_control')
\gexec
SQL

# Establish a recoverable base before the new cluster accepts production work.
otto-pgbackrest --stanza=otto-control stanza-create
otto-pgbackrest --stanza=otto-control check
otto-pgbackrest --stanza=otto-control --type=full backup

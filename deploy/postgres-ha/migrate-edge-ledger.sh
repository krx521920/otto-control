#!/bin/sh
set -eu

EDGE_PASSWORD_FILE=${EDGE_LEDGER_PASSWORD_FILE:-/run/secrets/edge_ledger_postgres_password}
if [ ! -s "$EDGE_PASSWORD_FILE" ]; then
  printf '%s\n' 'Edge ledger PostgreSQL password is missing' >&2
  exit 1
fi

EDGE_PASSWORD=$(cat "$EDGE_PASSWORD_FILE")
case "$EDGE_PASSWORD" in
  *[!A-Za-z0-9_-]*|'')
    printf '%s\n' 'Edge ledger PostgreSQL password must use base64url characters' >&2
    exit 1
    ;;
esac
if [ "${#EDGE_PASSWORD}" -lt 32 ]; then
  printf '%s\n' 'Edge ledger PostgreSQL password is too short' >&2
  exit 1
fi

psql --username=postgres --dbname="${PGDATABASE:-otto_control}" \
  --set=ON_ERROR_STOP=1 --set=edge_password="$EDGE_PASSWORD" <<'SQL'
SELECT format(
  'CREATE ROLE otto_edge_ledger LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION',
  :'edge_password'
)
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'otto_edge_ledger')
\gexec
SELECT format(
  'ALTER ROLE otto_edge_ledger LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION',
  :'edge_password'
)
\gexec

CREATE TABLE IF NOT EXISTS public.control_edge_request_ledger (
  request_id VARCHAR(128) PRIMARY KEY,
  record_json JSONB NOT NULL,
  record_hash CHAR(64) NOT NULL
    CHECK (record_hash ~ '^[a-f0-9]{64}$'),
  owner_id VARCHAR(160),
  lease_until_ms BIGINT,
  fencing_epoch BIGINT NOT NULL DEFAULT 0 CHECK (fencing_epoch >= 0),
  revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE public.control_edge_request_ledger
  ADD COLUMN IF NOT EXISTS owner_id VARCHAR(160),
  ADD COLUMN IF NOT EXISTS lease_until_ms BIGINT,
  ADD COLUMN IF NOT EXISTS fencing_epoch BIGINT NOT NULL DEFAULT 0;
ALTER TABLE public.control_edge_request_ledger OWNER TO otto_control;
REVOKE ALL ON TABLE public.control_edge_request_ledger FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO otto_edge_ledger;
GRANT SELECT, INSERT, UPDATE ON TABLE public.control_edge_request_ledger TO otto_edge_ledger;
SQL

unset EDGE_PASSWORD
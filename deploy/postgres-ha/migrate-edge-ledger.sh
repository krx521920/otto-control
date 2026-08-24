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
CREATE TABLE IF NOT EXISTS public.control_edge_billing_sequences (
  sequence_scope VARCHAR(160) PRIMARY KEY,
  last_sequence BIGINT NOT NULL CHECK (last_sequence > 0),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS public.control_edge_billing_outbox (
  request_id VARCHAR(128) PRIMARY KEY
    REFERENCES public.control_edge_request_ledger(request_id) ON DELETE RESTRICT,
  action_kind VARCHAR(16) NOT NULL
    CHECK (action_kind IN ('settle', 'release', 'uncertain')),
  action_json JSONB NOT NULL,
  action_hash CHAR(64) NOT NULL CHECK (action_hash ~ '^[a-f0-9]{64}$'),
  state VARCHAR(16) NOT NULL DEFAULT 'pending'
    CHECK (state IN ('pending', 'prepared', 'delivered', 'dead_letter')),
  sequence_scope VARCHAR(160),
  delivery_sequence BIGINT CHECK (delivery_sequence > 0),
  prepared_json JSONB,
  prepared_hash CHAR(64)
    CHECK (prepared_hash IS NULL OR prepared_hash ~ '^[a-f0-9]{64}$'),
  claim_owner VARCHAR(160),
  claim_until_ms BIGINT,
  claim_epoch BIGINT NOT NULL DEFAULT 0 CHECK (claim_epoch >= 0),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  next_attempt_at_ms BIGINT NOT NULL DEFAULT 0 CHECK (next_attempt_at_ms >= 0),
  last_error_code VARCHAR(128),
  delivered_at_ms BIGINT CHECK (delivered_at_ms >= 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CHECK ((claim_owner IS NULL) = (claim_until_ms IS NULL)),
  CHECK (
    (sequence_scope IS NULL AND delivery_sequence IS NULL
      AND prepared_json IS NULL AND prepared_hash IS NULL)
    OR
    (sequence_scope IS NOT NULL AND delivery_sequence IS NOT NULL
      AND prepared_json IS NOT NULL AND prepared_hash IS NOT NULL)
  ),
  CHECK (state NOT IN ('prepared', 'delivered') OR prepared_json IS NOT NULL)
);
CREATE UNIQUE INDEX IF NOT EXISTS control_edge_billing_outbox_sequence_uq
  ON public.control_edge_billing_outbox(sequence_scope, delivery_sequence)
  WHERE sequence_scope IS NOT NULL;
CREATE INDEX IF NOT EXISTS control_edge_billing_outbox_due_idx
  ON public.control_edge_billing_outbox(state, next_attempt_at_ms, created_at)
  WHERE state IN ('pending', 'prepared');
ALTER TABLE public.control_edge_request_ledger OWNER TO otto_control;
ALTER TABLE public.control_edge_billing_sequences OWNER TO otto_control;
ALTER TABLE public.control_edge_billing_outbox OWNER TO otto_control;
REVOKE ALL ON TABLE public.control_edge_request_ledger FROM PUBLIC;
REVOKE ALL ON TABLE public.control_edge_billing_sequences FROM PUBLIC;
REVOKE ALL ON TABLE public.control_edge_billing_outbox FROM PUBLIC;
REVOKE ALL ON TABLE public.control_edge_request_ledger FROM otto_edge_ledger;
REVOKE ALL ON TABLE public.control_edge_billing_sequences FROM otto_edge_ledger;
REVOKE ALL ON TABLE public.control_edge_billing_outbox FROM otto_edge_ledger;
GRANT USAGE ON SCHEMA public TO otto_edge_ledger;
GRANT SELECT, INSERT, UPDATE ON TABLE public.control_edge_request_ledger TO otto_edge_ledger;
GRANT SELECT, INSERT, UPDATE ON TABLE public.control_edge_billing_sequences TO otto_edge_ledger;
GRANT SELECT, INSERT, UPDATE ON TABLE public.control_edge_billing_outbox TO otto_edge_ledger;
SQL

unset EDGE_PASSWORD

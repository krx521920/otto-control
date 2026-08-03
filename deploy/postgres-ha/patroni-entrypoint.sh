#!/bin/sh
set -eu
umask 077

read_secret() {
  if [ ! -s "$1" ]; then
    printf 'required secret is missing: %s\n' "$1" >&2
    exit 1
  fi
  cat "$1"
}

validate_generated_secret() {
  case "$1" in
    ''|*[!A-Za-z0-9_-]*)
      printf '%s\n' 'Patroni database secrets must use base64url characters' >&2
      exit 1
      ;;
  esac
}

case "${PATRONI_NAME:-}" in
  postgres-1|postgres-2|postgres-3) ;;
  *)
    printf '%s\n' 'PATRONI_NAME must be postgres-1, postgres-2, or postgres-3' >&2
    exit 1
    ;;
esac

SUPERUSER_PASSWORD=$(read_secret /run/secrets/postgres_superuser_password)
REPLICATION_PASSWORD=$(read_secret /run/secrets/postgres_replication_password)
validate_generated_secret "$SUPERUSER_PASSWORD"
validate_generated_secret "$REPLICATION_PASSWORD"
if [ ! -s /run/secrets/postgres_password ] || [ ! -s /run/secrets/pgbackrest_cipher_pass ] || \
   [ ! -s /run/secrets/postgres_tls_ca ] || [ ! -s /run/secrets/postgres_tls_cert ] || \
   [ ! -s /run/secrets/postgres_tls_key ]; then
  printf '%s\n' 'application, pgBackRest, or PostgreSQL TLS secret is missing' >&2
  exit 1
fi

mkdir -p \
  /var/lib/postgresql/data/pgdata \
  /var/lib/pgbackrest \
  /var/log/pgbackrest \
  /var/run/postgresql \
  /run/patroni
chmod 0700 /var/lib/postgresql/data/pgdata
chown -R postgres:postgres \
  /var/lib/postgresql/data \
  /var/lib/pgbackrest \
  /var/log/pgbackrest \
  /var/run/postgresql \
  /run/patroni

stage_secret() {
  source_path=$1
  target_path=$2
  gosu postgres sh -c 'umask 077; cat > "$1"' sh "$target_path" < "$source_path"
}

POSTGRES_APP_PASSWORD_FILE=/run/patroni/postgres_password
OTTO_PGBACKREST_CIPHER_FILE=/run/patroni/pgbackrest_cipher_pass
POSTGRES_TLS_CA_FILE=/run/patroni/postgres_tls_ca.pem
POSTGRES_TLS_CERT_FILE=/run/patroni/postgres_tls_cert.pem
POSTGRES_TLS_KEY_FILE=/run/patroni/postgres_tls_key.pem
stage_secret /run/secrets/postgres_password "$POSTGRES_APP_PASSWORD_FILE"
stage_secret /run/secrets/pgbackrest_cipher_pass "$OTTO_PGBACKREST_CIPHER_FILE"
stage_secret /run/secrets/postgres_tls_ca "$POSTGRES_TLS_CA_FILE"
stage_secret /run/secrets/postgres_tls_cert "$POSTGRES_TLS_CERT_FILE"
stage_secret /run/secrets/postgres_tls_key "$POSTGRES_TLS_KEY_FILE"
export POSTGRES_APP_PASSWORD_FILE OTTO_PGBACKREST_CIPHER_FILE
export POSTGRES_TLS_CA_FILE POSTGRES_TLS_CERT_FILE POSTGRES_TLS_KEY_FILE

cat > /run/patroni/patroni.yml <<EOF
scope: otto-control
namespace: /service/
name: ${PATRONI_NAME}

restapi:
  listen: 0.0.0.0:8008
  connect_address: ${PATRONI_NAME}:8008

etcd3:
  hosts:
    - etcd-1:2379
    - etcd-2:2379
    - etcd-3:2379

bootstrap:
  dcs:
    loop_wait: 10
    maximum_lag_on_failover: 1048576
    retry_timeout: 10
    synchronous_mode: true
    synchronous_mode_strict: false
    synchronous_node_count: 1
    ttl: 30
    failsafe_mode: true
    postgresql:
      use_pg_rewind: true
      use_slots: true
      pg_hba:
        - local all all trust
        - hostssl replication replicator 0.0.0.0/0 scram-sha-256
        - hostssl all all 0.0.0.0/0 scram-sha-256
      parameters:
        archive_command: '/usr/local/bin/otto-pgbackrest --stanza=otto-control archive-push %p'
        archive_mode: 'on'
        archive_timeout: 60s
        hot_standby: 'on'
        max_replication_slots: 10
        max_wal_senders: 10
        password_encryption: scram-sha-256
        restore_command: '/usr/local/bin/otto-pgbackrest --stanza=otto-control archive-get %f %p'
        ssl: 'on'
        ssl_ca_file: '${POSTGRES_TLS_CA_FILE}'
        ssl_cert_file: '${POSTGRES_TLS_CERT_FILE}'
        ssl_key_file: '${POSTGRES_TLS_KEY_FILE}'
        wal_level: replica
        wal_log_hints: 'on'
  initdb:
    - encoding: UTF8
    - data-checksums
  post_bootstrap: /usr/local/bin/otto-post-bootstrap

postgresql:
  listen: 0.0.0.0:5432
  connect_address: ${PATRONI_NAME}:5432
  data_dir: /var/lib/postgresql/data/pgdata
  bin_dir: /usr/lib/postgresql/17/bin
  pgpass: /run/patroni/pgpass
  pg_hba:
    - local all all trust
    - hostssl replication replicator 0.0.0.0/0 scram-sha-256
    - hostssl all all 0.0.0.0/0 scram-sha-256
  authentication:
    replication:
      username: replicator
      password: ${REPLICATION_PASSWORD}
      sslmode: verify-full
      sslrootcert: ${POSTGRES_TLS_CA_FILE}
    superuser:
      username: postgres
      password: ${SUPERUSER_PASSWORD}
      sslmode: verify-full
      sslrootcert: ${POSTGRES_TLS_CA_FILE}
  create_replica_methods:
    - basebackup
  basebackup:
    checkpoint: fast
    max-rate: 100M
  parameters:
    ssl: 'on'
    ssl_ca_file: '${POSTGRES_TLS_CA_FILE}'
    ssl_cert_file: '${POSTGRES_TLS_CERT_FILE}'
    ssl_key_file: '${POSTGRES_TLS_KEY_FILE}'

watchdog:
  mode: 'off'
EOF

chown postgres:postgres /run/patroni/patroni.yml
chmod 0600 /run/patroni/patroni.yml
exec gosu postgres patroni /run/patroni/patroni.yml

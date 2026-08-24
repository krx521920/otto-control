FROM postgres:17-bookworm

ARG PATRONI_VERSION=4.1.4

RUN apt-get update \
  && apt-get install --yes --no-install-recommends \
    ca-certificates \
    curl \
    pgbackrest \
    python3 \
    python3-venv \
    tini \
  && python3 -m venv /opt/patroni \
  && /opt/patroni/bin/pip install --no-cache-dir \
    "patroni[etcd3]==${PATRONI_VERSION}" \
    "psycopg[binary]>=3.2,<4" \
  && rm -rf /var/lib/apt/lists/*

COPY deploy/postgres-ha/pgbackrest.conf /etc/pgbackrest/pgbackrest.conf
COPY deploy/postgres-ha/latest-backup-epoch.py /usr/local/bin/otto-pgbackrest-latest-backup
COPY deploy/postgres-ha/otto-pgbackrest /usr/local/bin/otto-pgbackrest
COPY deploy/postgres-ha/post-bootstrap.sh /usr/local/bin/otto-post-bootstrap
COPY deploy/postgres-ha/migrate-edge-ledger.sh /usr/local/bin/otto-migrate-edge-ledger
COPY deploy/postgres-ha/patroni-entrypoint.sh /usr/local/bin/otto-patroni-entrypoint

RUN chmod 0755 \
    /usr/local/bin/otto-patroni-entrypoint \
    /usr/local/bin/otto-pgbackrest-latest-backup \
    /usr/local/bin/otto-pgbackrest \
    /usr/local/bin/otto-post-bootstrap \
    /usr/local/bin/otto-migrate-edge-ledger \
  && mkdir -p /var/lib/pgbackrest /var/log/pgbackrest /run/patroni \
  && chown -R postgres:postgres \
    /var/lib/pgbackrest \
    /var/log/pgbackrest \
    /run/patroni

ENV PATH="/opt/patroni/bin:${PATH}"

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/otto-patroni-entrypoint"]

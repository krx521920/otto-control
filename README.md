# Otto Control

Otto Control is the commercial control plane for Otto private deployments. It
will own customer and deployment registration, signed License issuance, online
lease renewal, revocation, operational telemetry, update policy, and audit.

This repository contains Otto-specific business code. Fastify is used as the
MIT-licensed HTTP foundation; its license does not make this repository MIT.

## Current foundation

- TypeScript and Node.js 22
- Fastify 5 with a 1 MB default body limit
- GitHub CI for locked dependency installation, lint, type checking, tests,
  production compilation, whitespace validation, real PostgreSQL 17 integration,
  and production container builds
- Versioned `/v1` API surface
- Liveness and readiness endpoints
- Generated request IDs and a stable JSON error envelope
- Security and no-cache response headers
- Logger redaction for credentials and License/telemetry tokens
- Bearer-protected Prometheus metrics for HTTP traffic, process health,
  PostgreSQL pool pressure, slow requests, and bounded capacity trends
- Availability and latency SLO event counters, recording rules, and actionable
  Prometheus alerts for error-budget burn, queueing, saturation, and stale samples;
  SLOs are separated into lease, telemetry, billing, update, administration,
  platform-health, and general control API workloads
- Optional W3C trace propagation and OTLP/HTTP export across Fastify, outbound
  HTTP, and PostgreSQL with trace IDs correlated into structured logs
- Strict configuration validation
- Container build running as a non-root user
- PostgreSQL customer, deployment, License, replay-nonce, and audit tables
- Otto-compatible Ed25519 License envelopes and 10-minute online leases
- License binding to deployment ID, organization ID, and machine fingerprint
- Audited License renewal, seat expansion/downgrade, machine transfer, and
  same-customer deployment rebinding with optimistic concurrency protection
- Real-time active-seat reporting, monitor/enforce modes, and independently
  enforced expiration and seat-overage grace periods
- Administrator accounts with scrypt password hashes, TOTP MFA, one-time recovery
  codes, short-lived sessions, idle expiry, login lockout, and server-side revocation
- Built-in RBAC roles for super, security, License, release, and audit operators
- Request-bound dual-control approval for License revocation, signing-key changes,
  release activation, and rollback
- Persisted Ed25519 keyring with standby, active, retired, and revoked states
- Audited key activation and emergency revocation with atomic replacement
- Signed public keyring export plus local, KMS, and HSM signing providers
- Authenticated HTTPS remote signing with mTLS/bearer credentials, local signature
  verification, timeout bounds, provider health, and fail-closed circuit breaking
- Derived lease/telemetry tokens that are never stored as plaintext in PostgreSQL
- Authenticated operational telemetry ingest with HMAC, nonce replay protection,
  event integrity checks, idempotent storage, and retention cleanup
- Per-deployment health summaries without uploading chats, files, prompts, or transcripts
- Independent update distributions for Otto, Otto Green, and future private editions
- Draft, canary, stable, and required release policy with deterministic deployment cohorts
- SHA-256-pinned full and incremental manifests with short-lived Ed25519 policy envelopes
- Managed S3/MinIO release-artifact uploads with checksum-bound presigned requests,
  server-side encryption, optional KMS, Object Lock retention, version evidence,
  stable Control download URLs, and optional CDN delivery
- Isolated release-runner attestations for timestamped Windows Authenticode,
  notarized Apple Developer ID, and signed Linux/enterprise packages; Control
  stores only trusted Ed25519 attestation public keys
- Immutable release-artifact records binding distribution, release, source commit,
  platform, object version, size, SHA-256, and code-signing evidence into
  independently signed Ed25519 envelopes
- Fail-closed activation and rollback gates requiring a signed installer plus every
  referenced manifest; artifact revocation atomically pauses an active release
- Audited activation, pause, and rollback to the previous release policy
- Per-enterprise integer credit accounts keyed by customer and organization, with
  separate available and frozen balances
- Immutable top-up, freeze, capture, release, consumption, and refund transactions
- Centrally controlled per-module rates; private deployments report units, not prices
- Request idempotency, original-charge refund limits, and automatic expired-hold release
- Signed Otto execution policy with fail-closed module gates, pre-execution credit
  holds, durable capture/release recovery, and cross-repository conformance CI
- Organization/module statements plus UTF-8 CSV transaction exports
- Production Compose stack with a three-node Patroni/PostgreSQL cluster, etcd
  quorum, automatic primary failover, a stable HAProxy write endpoint, three
  Control instances, Caddy health-based load balancing, and file-mounted secrets
- One-command Ed25519 key and random credential bootstrap that refuses to
  overwrite an existing production identity
- AES-256-GCM encrypted PostgreSQL backups with atomic publication, integrity
  checks, retention, restore-before-write validation, and a systemd schedule
- S3/MinIO-compatible off-site replication of encrypted backups with SigV4,
  immutable writes, remote SHA-256 verification, and bounded retries
- RBAC-protected backup inventory with fresh, stale, missing, optional-failure,
  and required-failure states plus recovery alerts and bounded history parsing
- PostgreSQL-backed outbound alert outbox with HMAC-signed HTTPS webhooks,
  fingerprint deduplication, leased workers, bounded retries, and delivery audit
- Tamper-evident audit chain with exact filters, cursor pagination, sensitive-field
  redaction, CSV evidence export, and Ed25519-signed integrity receipts
- Durable external audit-anchor outbox with stable chain-head deduplication,
  leased workers, exponential retry, terminal-failure recovery, and destination status
- Independently deployable audit witness with pinned rotating Ed25519 keys, isolated
  source tokens, idempotent receipt storage, rollback detection, fork rejection,
  and independently encrypted S3/MinIO Object Lock evidence
- Same-origin operator console with MFA login, RBAC-filtered commercial inventory,
  customer/deployment/License onboarding, renewal, seat management, immutable
  lifecycle history, dual-control review and execution, backup readiness, alert
  retry, strict CSP, and tab-scoped sessions
- Independently deployable Fastify (MIT) federation gateway with a signed
  deployment directory, rotating Ed25519 public keys, replay-resistant E2EE
  envelopes, durable offline inbox leases, delivery acknowledgements, bilateral
  deployment blocks, bounded queues, and atomic scoped A2A grant consumption
- Three-instance federation production topology behind Caddy, authenticated
  Prometheus metrics, ciphertext-only payload storage, and a documented Otto
  private-server adapter contract
- Atomic replay protection and recipient capacity admission, bounded inbox
  response batches, and historical verification of non-revoked rotating keys

## Federation gateway

Run the cross-private-deployment gateway independently from Control:

```bash
npm run dev:federation
# production: npm run start:federation
```

The gateway uses Fastify as its MIT-licensed HTTP engine, but the federation
identity, signing, replay prevention, authorization, and delivery protocol are
Otto-specific. It accepts only E2EE ciphertext and never receives chat, file,
or A2A context decryption keys. See
[`docs/federation-protocol.zh-CN.md`](docs/federation-protocol.zh-CN.md) and
[`docs/otto-private-server-federation-adapter.zh-CN.md`](docs/otto-private-server-federation-adapter.zh-CN.md).
Production admission, key rotation, capacity, abuse response, and three-replica
acceptance are documented in
[`docs/federation-production-operations.zh-CN.md`](docs/federation-production-operations.zh-CN.md).
Production CI starts all three Federation instances and runs
`scripts/smoke-federation.mjs` across them to prove signed ciphertext relay,
cross-instance inbox leasing, signature verification, idempotency, and acknowledgement.

## Edge model gateway

The first independently deployable Otto Edge Gateway implementation lives in
this repository while remaining outside the Control request process:

```bash
npm run dev:edge
# production Node adapter: npm run start:edge
```

It validates short-lived Control-signed tokens and policies locally, pins model
provider routes, requires every signed route to also match an independently
managed exact HTTPS-origin and credential-binding allowlist before reading
provider secrets, and rejects empty, non-ASCII, control-character, or oversized
provider credentials before constructing an HTTP header or opening an upstream
connection. It enforces
request/rate bounds, performs bounded failover, and
streams provider responses without sending prompts or conversation context to
Control. Model API requests must use an exact endpoint path; query strings and
fragments are rejected instead of being silently ignored or forwarded. The Node
adapter uses a fixed internal origin and rejects ambiguous,
absolute, non-canonical, malformed-percent, non-ASCII, or oversized request targets
before policy or provider access; an untrusted Host header cannot select its
routing origin. Upstream headers are rebuilt from a fixed minimum set; client
cookies and provider-looking headers are never copied, while `Accept` is derived
from the validated `stream` flag. Provider response metadata is normalized too:
unknown media types become `application/octet-stream` with `nosniff`, and only
bounded visible request IDs are exposed. It also holds a global and per-subject concurrency slot
for the complete lifetime of every upstream response stream, preventing slow
clients from exhausting sockets, memory, or provider credit while remaining
inside a per-minute request limit. Explicit inbound header, request, keep-alive,
total-connection, header-count, and requests-per-socket bounds also reject slow
or oversized HTTP connections before they become unbounded process resources.
Repeated transport, retryable HTTP, and stream failures open a bounded per-route
circuit; requests use a signed fallback route
during cooldown, then exactly one half-open probe decides whether to restore the
primary. A separate local request-body hard cap defaults to 4 MiB and cannot be
expanded by signed Control policy, limiting memory and provider-cost exposure.
Signed policy also bounds upstream stream-idle time, and downstream
disconnects cancel provider work instead of continuing to consume tokens. A
separate local hard cap aborts responses that exceed 64 MiB or 15 minutes even
when a provider continuously sends data and never triggers the idle timeout;
metered requests remain explicitly uncertain instead of being undercharged. A
standard Web Service Worker adapter is provided for Alibaba Cloud
ESA. The Node adapter can also authenticate to Control, coalesce policy refreshes,
verify tenant-bound signatures before caching, and fail closed when the last
signed policy expires. It consumes Control's signed public keyring with two-phase
standby activation, bounded revocation polling, rollback protection, and a
bootstrap trust-root requirement. A Redis Lua adapter enforces atomic cross-replica
limits, HMAC-obscured subject keys, bounded abuse strikes, temporary bans, and
fail-closed behavior without falling back to process memory. In single-server
mode, metered routes reserve credits before provider access, extract only bounded
OpenAI-compatible usage, and atomically settle an Ed25519 receipt against the
hold. Pending settlement state is kept in a hash-chained, fsynced local journal
and replayed after restart. Liveness and readiness are separate, and an optional
file-backed operations token protects aggregate billing status and idempotent
queue retry endpoints without allowing receipt, sequence, or amount mutation.
SIGTERM and SIGINT initiate bounded graceful draining: readiness fails first,
new model work is rejected, and active response streams receive a configurable
completion window before remaining connections are forcibly closed.
Multi-instance deployments require a shared ordered
aggregator instead of sharing this file over NFS/SMB. See
[`docs/otto-edge-gateway.zh-CN.md`](docs/otto-edge-gateway.zh-CN.md) for
the trust boundary, configuration, and remaining production gates.

Control persists deployment-scoped Edge policies in PostgreSQL and exposes
authenticated policy-resolution and short-lived token-issuance APIs. They
validate the online License/deployment/organization/fingerprint binding, reject
replay with persisted nonces, apply enforced-billing admission, and never accept
prompt or conversation content.

## Managed release artifact distribution

Production releases can use a fail-closed upload and delivery pipeline instead
of registering an arbitrary download URL. The binary bytes live in an
S3-compatible object store or MinIO; PostgreSQL stores the immutable release
binding, object version, storage controls, and platform-signing evidence.

The sequence is:

1. A release operator creates a draft release and requests an upload through
   `POST /v1/admin/update-releases/:releaseId/artifact-uploads`.
2. Control signs a short-lived upload ticket and returns a presigned `PUT` URL
   plus the exact checksum, content length, encryption, and Object Lock headers.
3. The release runner uploads those exact bytes and verifies their real platform
   signature with Windows, macOS, or Linux-native tools.
4. The runner signs the verification evidence with its separate Ed25519
   attestation key. `POST .../artifact-uploads/complete` re-reads the object and
   verifies the ticket, SHA-256, size, encryption, retention, object version, and
   trusted platform evidence before one atomic PostgreSQL commit.
5. Release activation revalidates the object and evidence. Revocation pauses an
   active release and the stable download URL immediately stops resolving.

Clients download from
`GET /v1/release-artifacts/:artifactId/download`. Control returns a short-lived
S3 redirect without recording the temporary URL. When
`CONTROL_ARTIFACT_CDN_BASE_URL` is set, it must be an HTTPS origin serving only
the immutable object-key namespace; otherwise leave it unset and use signed S3
downloads.

Create the attestation key on an isolated release runner, not on the Control
host:

```bash
openssl genpkey -algorithm ED25519 -out release-attestation-private.pem
openssl pkey -in release-attestation-private.pem -pubout \
  -out release-attestation-public.pem
```

Copy only the public key to the dedicated Control attestation directory. Start from
`deploy/artifact-attestation-keys.example.json`, keep the public-key reference
relative to that manifest, and set
`CONTROL_ARTIFACT_ATTESTATION_KEYS_FILE=/run/otto-attestations/artifact_attestation_keyring.json`.
The private attestation key and platform code-signing credentials never belong
on Control.

After the installer or server archive has been signed by the platform-specific
publisher key, produce the bound evidence on the matching release runner:

```bash
npm run attest:release -- \
  --file ./otto-enterprise.tar.gz \
  --release-id rel_example1234567890 \
  --release-version 1.9.11 \
  --source-commit 0123456789abcdef0123456789abcdef01234567 \
  --kind enterprise_server \
  --platform linux-x64 \
  --linux-signature ./otto-enterprise.tar.gz.sig \
  --linux-public-key ./package-signing-public.pem \
  --attestation-key-id release-runner-2026-01 \
  --attestation-private-key-file ./release-attestation-private.pem \
  --output ./artifact-attestation.json
```

For `windows_installer`, the command must run on Windows and rejects a missing
or untimestamped Authenticode signature. For `macos_dmg`, it must run on macOS
and requires `codesign`, Gatekeeper assessment, and a stapled notarization
ticket. Linux and enterprise archives require an Ed25519 detached package
signature. Attestations older than 30 days or bound to another release, commit,
platform, digest, or size are rejected.

Configure managed storage with the following settings. Credentials are accepted
only through files. Production endpoints and CDN origins must use HTTPS.

| Setting | Purpose |
| --- | --- |
| `CONTROL_ARTIFACT_STORAGE_REQUIRED` | Defaults to `true` in production and rejects metadata-only legacy artifacts at activation. |
| `CONTROL_ARTIFACT_S3_ENDPOINT` / `CONTROL_ARTIFACT_S3_BUCKET` | S3 or MinIO origin and an Object-Lock-capable bucket. |
| `CONTROL_ARTIFACT_S3_ACCESS_KEY_ID_FILE` / `CONTROL_ARTIFACT_S3_SECRET_ACCESS_KEY_FILE` | Least-privilege file-backed upload, HEAD, and download credentials. |
| `CONTROL_ARTIFACT_S3_ENCRYPTION` | `AES256` or `aws:kms`; KMS also requires `CONTROL_ARTIFACT_S3_KMS_KEY_ID`. |
| `CONTROL_ARTIFACT_S3_OBJECT_LOCK_REQUIRED` | Requires active `GOVERNANCE` or `COMPLIANCE` retention; defaults to `true` in production. |
| `CONTROL_ARTIFACT_S3_RETENTION_DAYS` | Retention assigned to new objects, default 365 days. |
| `CONTROL_ARTIFACT_UPLOAD_TTL_SECONDS` / `CONTROL_ARTIFACT_DOWNLOAD_TTL_SECONDS` | Bounded presigned URL lifetimes. |
| `CONTROL_ARTIFACT_ATTESTATION_KEYS_FILE` | Trusted release-runner public-key manifest. Required whenever managed storage is enabled. |

The bucket must have versioning and Object Lock enabled when it is created;
these properties cannot be repaired by Control after the fact. Use a dedicated
storage identity restricted to the configured bucket and prefix. Control never
accepts object-store credentials in an API request or audit event.

The production bootstrap refuses to create a deployable identity without this
pipeline. Supply the object-store identity and the isolated runner's public
attestation key explicitly:

```bash
npm run bootstrap:production -- \
  --environment production \
  --public-url https://control.company.cn \
  --federation-public-url https://federation.company.cn \
  --aws-kms-key-arns "$CONTROL_SIGNING_KMS_KEY_ARN" \
  --acme-email operations@company.cn \
  --privacy-controller "Company legal name" \
  --privacy-contact privacy@company.cn \
  --data-region CN-BJ \
  --artifact-s3-endpoint https://s3.cn-north-1.amazonaws.com.cn \
  --artifact-s3-bucket company-otto-releases \
  --artifact-s3-region cn-north-1 \
  --artifact-s3-access-key-id-file ./inputs/release-access-key-id \
  --artifact-s3-secret-access-key-file ./inputs/release-secret-access-key \
  --artifact-attestation-key-id nsiet-release-2026-01 \
  --artifact-attestation-public-key-file ./inputs/release-attestation-public.pem \
  --artifact-cdn-base-url https://releases.company.cn
```

The bootstrap copies credentials into Compose secrets, copies only the public
attestation key into a separate read-only mount, and never writes either value
to the environment file. The unmanaged-artifact escape hatch is accepted only
when `CI=true`; it is not a production operating mode. See
`docs/release-activation-runbook.zh-CN.md` for the Otto and Otto Green release
procedure and rollback evidence.

## Development

```bash
npm install
npm run dev
```

The default listener is loopback-only at `http://127.0.0.1:7788`.

```bash
curl http://127.0.0.1:7788/health/live
curl http://127.0.0.1:7788/health/ready
curl http://127.0.0.1:7788/v1
```

The health-only development server starts without commercial configuration. A
production server fails at startup unless every commercial secret and database
setting below is present.

Run all local gates:

```bash
npm run check
```

The same gates run automatically for every pull request targeting `main` and
every push to `main`. The container job starts only after source quality gates
and PostgreSQL integration pass, so a green workflow proves the TypeScript
application, real migrations and transactions, and the production Dockerfile
build from the committed lockfile. GitHub Actions use read-only repository
permissions and are pinned to immutable commits.

Run the destructive PostgreSQL integration suite only against a disposable
database whose name ends in `_test`:

```bash
CONTROL_TEST_DATABASE_URL=postgresql://user:password@localhost/otto_control_test \
  CONTROL_REQUIRE_POSTGRES_TEST=true npm run test:postgres
```

The suite resets the public schema. It validates concurrent migration startup,
License and audit persistence across process reconnects, and billing idempotency
under concurrent requests. Normal `npm test` skips this suite when no explicit
test database URL is present.

## Production Compose deployment

Point two public DNS names at the server first. Production requires explicit
legal, residency, and ACME ownership metadata; the bootstrap no longer inserts
development placeholders. The complete fresh-Ubuntu procedure and acceptance
evidence are in
[`docs/production-deployment-runbook.zh-CN.md`](docs/production-deployment-runbook.zh-CN.md).

```bash
npm ci
npm run bootstrap:production -- \
  --environment production \
  --public-url https://control.company.cn \
  --federation-public-url https://federation.company.cn \
  --acme-email operations@company.cn \
  --privacy-controller "Your Company Ltd." \
  --privacy-contact privacy@company.cn \
  --data-region CN-BJ \
  --aws-kms-key-arns "$PRIMARY_KMS_ARN,$REPLICA_KMS_ARN"
npm run preflight:deployment -- --env-file .env.production
docker compose -f compose.production.yaml --env-file .env.production up -d --build
docker compose -f compose.production.yaml --env-file .env.production ps
curl https://control.company.cn/health/ready
```

The stack keeps etcd and every PostgreSQL instance on a database-only network.
HAProxy publishes the current Patroni primary only to the internal application
network. Three Control instances share the same PostgreSQL state and signing
identity; Caddy checks `/health/ready`, removes failed instances, and sends new
requests to the least-busy healthy instance. Only Caddy publishes ports 80 and
443. Control containers run without Linux capabilities, with read-only root
filesystems, and receive credentials through `/run/secrets` rather than image
layers or plain environment values. PostgreSQL requires TLS for network clients;
the Control, Federation, operations, and replication clients validate the
deployment CA instead of accepting an unauthenticated internal connection.

Staging uses `--environment staging`, `.env.staging`, `secrets-staging/`,
`signing-staging/`, `backups-staging/`, and a distinct Compose project name. Run it on a separate
host and separate domains; never copy production identity files into staging.

This Compose topology provides **process-level high availability on one Linux
host**. It tolerates a PostgreSQL or Control container/process failure, but it
does not survive loss of that host, its Docker daemon, its storage, its network,
or the single edge IP. Host-level production HA requires three PostgreSQL/etcd
nodes on separate failure domains, at least two Control/edge hosts behind an
external load balancer or floating IP, and the pgBackRest repository on encrypted
off-host object or replicated storage. Do not market the single-host profile as
datacenter or cross-region HA.

Back up the pgBackRest repository, encrypted logical backups, `secrets/`, and
the separately mounted `signing/` directory under separate access controls.
Never overwrite an existing signing identity. Add a new key to
`signing/control_signer_keyring.json`, restart
the control service so it is registered as `standby`, distribute the signed
public keyring, and only then activate it. The old key becomes `retired` and
continues to verify historical License envelopes. Use `revoked` only for a
compromise; online License leases signed by that key then fail closed. The
bootstrap command uses exclusive file creation and refuses to overwrite an
existing identity.

### Metrics, SLOs, and tracing

Production bootstrap creates a separate `control_metrics_token`. The `/metrics`
route requires that token and Caddy deliberately returns 404 for the public
route. Start the internal Prometheus profile when the host is ready to retain
metrics locally:

```bash
docker compose -f compose.production.yaml --env-file .env.production \
  --profile observability up -d prometheus
curl http://127.0.0.1:9090/-/healthy
curl http://127.0.0.1:9090/api/v1/targets
```

The production Compose stack exposes no Control port. Prometheus is bound to
`127.0.0.1:9090`, uses the same Docker secret, and scrapes all three Control
instances over an isolated monitoring network. Recording and alert rules live
under `deploy/prometheus/rules/`.
Retain or remotely write Prometheus data according to the customer's operations
policy; the default local retention is 30 days.

Distributed tracing is off by default. To enable it, set
`CONTROL_OTLP_TRACE_ENDPOINT` to a trusted HTTPS OTLP/HTTP endpoint ending in
`/v1/traces`. Put collector headers in a permission-`0600` JSON file and set
`CONTROL_OTLP_HEADERS_FILE`; never place collector credentials in the endpoint
or environment. `CONTROL_TRACE_SAMPLE_RATIO` defaults to `0.1` in production.
The instrumentation does not export request or response bodies, authentication
headers, SQL parameter values, or metrics requests. Common secret-bearing query
parameters are redacted, and PostgreSQL trace-context injection is disabled to
avoid doubling query round trips.

Existing production deployments must create the new metrics credential before
starting this version. Do not rerun the bootstrap command because it correctly
refuses to overwrite the deployment's signing identity. From the deployment
root, create only the missing secret and add its file reference:

```bash
test ! -e secrets/control_metrics_token
umask 077
openssl rand -base64 48 > secrets/control_metrics_token
printf '%s\n' 'CONTROL_METRICS_TOKEN_FILE=/run/secrets/control_metrics_token' \
  >> .env.production
docker compose -f compose.production.yaml --env-file .env.production config --quiet
```

Back up the new credential with the rest of `secrets/`. The application fails
closed in production when it is missing or shorter than 32 bytes; this prevents
an upgrade from silently exposing operational metrics without authentication.

### Backup and restore

Patroni enables continuous WAL archiving through pgBackRest. The repository is
encrypted with `secrets/pgbackrest_cipher_pass`; bootstrap creates the stanza and
first full physical backup before admitting production work. Install the full,
differential, and PITR drill schedules with the existing logical-backup units:

```bash
sudo install -m 0644 deploy/systemd/otto-control-pitr-* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now \
  otto-control-pitr-full.timer \
  otto-control-pitr-diff.timer \
  otto-control-pitr-drill.timer
```

Run and verify the three HA/DR paths manually before go-live:

```bash
sh deploy/backup-pitr-postgres.sh full
sh deploy/drill-pitr-postgres.sh
sh deploy/drill-pitr-postgres.sh 2026-08-02T10:15:00+08:00
sh deploy/drill-postgres-failover.sh --confirm=FAILOVER_OTTO_CONTROL
sh deploy/drill-control-failover.sh --confirm=FAILOVER_OTTO_CONTROL_REPLICAS
```

Before creating the backup, capture the expected commercial-state manifest and
pass it into the restore drill. The manifest contains only row counts and table
SHA-256 values, never customer rows. A restore is rejected when any protected
`control_*` table differs. Run this source-baseline sequence only in CI, staging,
or a quiesced production window. On an active production system, first create
and drill a fresh backup without `--expected`, then retain the manifest produced
from that isolated restored snapshot as the canonical baseline for later drills:

```bash
sh deploy/recovery-data-manifest.sh --output ./backups/reports/baseline.manifest
npm run backup:production
OTTO_CONTROL_RECOVERY_EXPECTED_MANIFEST="$PWD/backups/reports/baseline.manifest" \
  npm run drill:restore:production
```

The PITR drill restores physical files into the dedicated
`postgres_pitr_drill_data` volume and never points a server at the production
data directories. The failover drill stops the current primary, waits for
Patroni to promote a standby, proves the stable endpoint accepts a rolled-back
write, and then rejoins the former primary. Keep the existing AES-256-GCM logical
backup because it provides a portable schema/data export independent of the
physical PostgreSQL cluster.

An existing single-PostgreSQL deployment must create and verify an encrypted
logical backup **before** replacing its old Compose file. Start the new HA stack,
then restore that archive through `deploy/restore-postgres.sh`; the old
`postgres_data` volume is not silently attached to a Patroni member.

Create an encrypted backup immediately:

```bash
npm run backup:production
```

To install the daily 02:20 systemd schedule on a deployment checked out at
`/opt/otto-control`:

```bash
sudo install -m 0644 deploy/systemd/otto-control-backup.service /etc/systemd/system/
sudo install -m 0644 deploy/systemd/otto-control-backup.timer /etc/systemd/system/
sudo install -m 0644 deploy/systemd/otto-control-restore-drill.service /etc/systemd/system/
sudo install -m 0644 deploy/systemd/otto-control-restore-drill.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now otto-control-backup.timer
sudo systemctl enable --now otto-control-restore-drill.timer
systemctl list-timers 'otto-control-*'
```

Backups are written atomically under `backups/` as `.dump.enc` plus a matching
`.sha256` file. Database bytes are encrypted as a stream with AES-256-GCM, so an
unencrypted dump is never written to disk. Keep at least one independently
controlled off-site copy, but protect `secrets/backup_encryption_key` separately;
losing that key makes every encrypted backup unrecoverable.

For S3-compatible off-site replication, create separate permission-`0600`
credential files and set the `CONTROL_BACKUP_S3_*` values in `.env.production`.
The S3 identity needs only `s3:PutObject` and `s3:GetObject` for its configured
bucket prefix (`HEAD Object` is authorized by `s3:GetObject`); it does not need
list, delete, database, or control-plane access. Both the encrypted
archive and checksum are uploaded with create-only semantics, then verified by
remote size and SHA-256 metadata. Existing objects are accepted only when those
values match. Set `CONTROL_BACKUP_OFFSITE_REQUIRED=true` in production when a
backup job must fail visibly after all retry attempts instead of retaining only
the valid local copy. AWS S3 generally uses `virtual` addressing; MinIO commonly
uses `path` addressing.

Every completed local verification writes an immutable history report and
atomically refreshes `backups/reports/latest.json`. These status reports contain
no credentials, local paths, database rows, or backup contents, and are mounted
read-only into the non-root control container. Administrators with `backup.read`
can inspect the latest result, bounded history, age, and recovery alerts through
`GET /v1/admin/backups/status`. A missing, malformed, future-dated, or stale
latest report fails visibly; optional off-site failures are degraded, while
required off-site failures are failed.

### Outbound recovery alerts

Set `CONTROL_ALERT_WEBHOOK_URL` to an HTTPS endpoint to actively deliver backup
recovery warnings and failures. Production bootstrap creates a separate webhook
secret at `secrets/alert_webhook_secret`; the secret is mounted read-only and is
never stored in PostgreSQL. When no URL is configured, the worker remains inert
and the administrator status APIs continue to work without external traffic.

Each condition is first committed to the PostgreSQL outbox and deduplicated by a
SHA-256 condition fingerprint. Workers claim due rows with a lease, retry after
30 seconds with exponential backoff capped at one hour, and stop after the
configured attempt limit. Delivery state and audit records are updated in one
database transaction. Delivery is intentionally at-least-once: a receiver must
deduplicate `X-Otto-Alert-Id`, reject stale `X-Otto-Alert-Timestamp` values, and
verify `X-Otto-Alert-Signature` in constant time. The signature is lowercase
hex HMAC-SHA-256 over `timestamp + "\\n" + rawRequestBody`, prefixed with `v1=`.

Webhook payloads contain only backup status, reason, age, generated backup name,
alert codes, and timestamps. They do not contain database rows, credentials,
local paths, customer content, chats, prompts, files, or backup bytes. A 2xx
response acknowledges delivery; redirects and every other status are failures.
Administrators with `alert.read` can inspect delivery history, while
`alert.manage` is required to request an immediate poll or retry a terminally
failed delivery. Delivered and terminally failed rows are retained for
`CONTROL_ALERT_RETENTION_DAYS` and then pruned; pending work is never removed by
retention cleanup.

### Audit evidence

Migration `016_tamper_evident_audit` starts a SHA-256 chain for every new audit
event. Each event binds its sequence, previous hash, actor, action, target,
detail, and timestamp. The chain writer is serialized inside the same PostgreSQL
transaction as operations that already write audit records transactionally.
Records created before this migration remain available and are explicitly
reported as legacy, rather than being assigned unverifiable hashes later.

Administrators with `audit.read` can query exact actor, action, target, and time
filters with cursor pagination. `audit.export` permits a bounded UTF-8 CSV export.
API and CSV responses recursively redact password, secret, token, credential,
signature, ciphertext, and private-key fields. `audit.verify` recalculates the
chain in bounded batches, compares the persisted chain head, and signs the
resulting receipt with the currently active Ed25519 control key.

Store signed receipts outside the control database to create independent
checkpoints. A database superuser who can rewrite both all events and the chain
head is outside the protection boundary until a prior signed receipt is compared;
the feature is tamper-evident, not a substitute for off-site evidence retention.

Set `CONTROL_AUDIT_ANCHOR_URL` and `CONTROL_AUDIT_ANCHOR_TOKEN_FILE` together to
enable automatic external checkpoints. The worker creates a signed receipt at
the configured interval, deduplicates the same issuer/sequence/head, stores it in
the PostgreSQL outbox, and delivers it over HTTPS with bounded timeout, leases,
exponential retry, and manual terminal-failure recovery. The bearer token
authenticates delivery but is not the evidence: receivers must verify the nested
Ed25519 receipt against `/v1/signing-keyring` and retain it outside this database,
preferably in immutable or append-only storage. A 2xx response acknowledges
delivery; an optional `X-Otto-Audit-Anchor-Reference` response header is retained
as the external object or receipt identifier.

An Otto Control instance can run as the independent receiver by setting
`CONTROL_AUDIT_WITNESS_SOURCES_FILE`. Copy
`deploy/audit-witness-sources.example.json` into its read-only secrets directory,
create a separate 32-byte source token file, and pin one or more Ed25519 public
key files exported by the sending control plane. Paths in the manifest resolve
relative to the manifest. Multiple public keys allow a controlled rotation window.
Point the sender's `CONTROL_AUDIT_ANCHOR_URL` at
`https://WITNESS/v1/audit-witness/anchors` and give it the matching token.

The receiver verifies source authentication, issuer, receipt structure, stable
fingerprint, signing-key allowlist, Ed25519 signature, clock skew, and sequence
consistency before writing. Replays are idempotent; a lower sequence, reused
anchor ID, or different head at the same sequence is rejected.

For production evidence, configure the dedicated `CONTROL_AUDIT_WORM_*` storage
identity and set `CONTROL_AUDIT_WORM_REQUIRED=true`. The accepted receipt and a
pending evidence row are created in one PostgreSQL transaction. A leased worker
then writes canonical JSON to an independently encrypted, versioned S3/MinIO
bucket using `If-None-Match: *` and Object Lock. Object keys are fixed by source
and chain sequence, so a fork cannot occupy the same logical slot with different
bytes. Completion requires a real object version, SHA-256 checksum, expected
encryption, matching lock mode, sufficient retention, and a byte-for-byte GET
verification. Storage outages retry without rejecting new signed receipts;
terminal failures remain visible and auditable until an administrator retries.

Use a separate host, cloud account or MinIO tenant, bucket, credentials, and
administrator boundary from both Control PostgreSQL and release artifacts. The
least-privilege runtime identity needs Put, Get, Head, List, GetBucketVersioning,
and GetObjectLockConfiguration inside its
configured prefix and must not have delete, retention-bypass, bucket-policy, or
Object-Lock administration permission. Production required mode accepts only
`COMPLIANCE`; `GOVERNANCE` is limited to non-required development drills.

The status, poll, retry, byte-verification, and recovery endpoints live under
`/v1/admin/audit-witness/worm/*` and use existing audit RBAC. If PostgreSQL's
witness tables are lost, recovery lists immutable objects, verifies their pinned
source signatures and storage controls, and rebuilds the query index. Exercise
that path and sample stored bytes with an MFA administrator session:

```bash
npm run drill:audit:worm -- \
  --control-url https://witness.example.com \
  --token-file ./security-admin-session-token \
  --recover=true \
  --sample-size 10 \
  --output ./audit-worm-drill.json \
  --confirm=VERIFY_OTTO_AUDIT_WORM
```

AWS deployments can create a separate SSE-KMS bucket with a seven-year default
COMPLIANCE lock from `deploy/aws-audit-worm.template.yaml`. The runtime principal
has no delete permission. The separately approved drill principal is explicitly
allowed to request deletion, which lets the following drill prove that Object
Lock itself rejects deletion and that the exact object version remains intact:

```bash
npm run drill:audit:object-lock -- \
  --bucket otto-control-audit-evidence \
  --key otto-audit-witness/SOURCE/SEQUENCE.json \
  --version-id VERSION_ID \
  --expected-sha256 LOWERCASE_SHA256 \
  --expected-drill-principal-arn arn:aws:iam::123456789012:role/otto-object-lock-drill \
  --output ./object-lock-drill.json \
  --confirm=DELETE_LOCKED_AUDIT_EVIDENCE
```

Run this only with the dedicated drill role. The command verifies its live STS
identity and confirms the bucket policy explicitly grants that principal both
`s3:DeleteObjectVersion` and `s3:PutObjectRetention`. It then proves that AWS
rejects both shortening the COMPLIANCE retention date and deleting the exact
version, and re-reads the bytes and retention afterward. This prevents an
ordinary IAM denial from being misreported as Object Lock evidence. Preserve
the `0600` report, both denied CloudTrail data events, stack ID, workflow run,
and corresponding WORM receipt as one quarterly recovery evidence package.

Pointing a control plane at itself validates the protocol but does not protect
against that host's superuser. S3 Object Lock also cannot protect against loss of
the entire provider account, so independently export drill reports and monitor
the storage account. A later higher-sequence receipt proves a new signed state
but, without sensitive event preimages, cannot by itself prove every intermediate
event extends an earlier head; retain and periodically compare all receipts.

Restore requires the exact confirmation phrase:

```bash
npm run restore:production -- /absolute/path/otto-control-TIMESTAMP.dump.enc \
  --confirm=RESTORE_OTTO_CONTROL
```

The restore command checks SHA-256, authenticates and parses the encrypted dump,
and creates a fresh safety backup before stopping the control service. It starts
the service only after PostgreSQL restoration succeeds, then waits for the
readiness endpoint. A failed destructive restore deliberately leaves the control
service stopped so an operator cannot unknowingly write into partial data.

Run a non-destructive restore drill manually against the newest backup:

```bash
npm run drill:restore:production
```

An explicit encrypted backup path may be supplied after `--`. The drill restores
into a uniquely named `otto_drill_*` database while production remains online,
checks the migration ledger and all critical commercial-control tables, records
key row counts, drops the temporary database, and writes a pass report under
`backups/drills/`. The systemd timer performs this exercise every Sunday and
retries transient failures without touching the production database. A backup
older than the configured recovery window fails the drill instead of producing
a misleading success report.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `NODE_ENV` | `development` | `development`, `test`, or `production` |
| `CONTROL_HOST` | `127.0.0.1` | Listener address |
| `CONTROL_PORT` | `7788` | Listener port |
| `CONTROL_LOG_LEVEL` | `info` | Structured log level |
| `CONTROL_TRUST_PROXY` | `false` | Trust the configured edge proxy |
| `CONTROL_PUBLIC_BASE_URL` | empty | Public control-plane URL; HTTPS in production |
| `OTTO_CONTROL_VERSION` | `0.34.0` | Runtime version exposed by health APIs |
| `CONTROL_DATABASE_URL` | empty | PostgreSQL connection URL |
| `CONTROL_DATABASE_HOST` | empty | PostgreSQL host when component configuration is used |
| `CONTROL_DATABASE_PORT` | `5432` | PostgreSQL port for component configuration |
| `CONTROL_DATABASE_NAME` | empty | PostgreSQL database name for component configuration |
| `CONTROL_DATABASE_USER` | empty | PostgreSQL user for component configuration |
| `CONTROL_DATABASE_PASSWORD` | empty | PostgreSQL password; file-backed form is preferred |
| `CONTROL_DATABASE_PASSWORD_FILE` | empty | Read-only file containing the PostgreSQL password |
| `CONTROL_DATABASE_SSL` | production: `true` | Require verified TLS to PostgreSQL |
| `ETCD_IMAGE` | `quay.io/coreos/etcd:v3.5.21` | Pinned etcd image used by the production HA Compose profile |
| `CONTROL_ADMIN_TOKEN` | empty | 32-byte minimum emergency secret used only for first administrator bootstrap |
| `CONTROL_ADMIN_TOKEN_FILE` | empty | Read-only file containing the bootstrap secret |
| `CONTROL_TOKEN_SECRET` | empty | 32-byte minimum root secret used to derive scoped tokens |
| `CONTROL_TOKEN_SECRET_FILE` | empty | Read-only file containing the token derivation secret |
| `CONTROL_SIGNER_PRIVATE_KEY_FILE` | empty | Read-only Ed25519 PKCS#8 secret mount |
| `CONTROL_SIGNER_KEYRING_FILE` | empty | Version 1 local/KMS/HSM keyring manifest; mutually exclusive with the legacy single-key setting |
| `CONTROL_LEASE_DURATION_MS` | `600000` | Online lease lifetime; Otto refreshes every two minutes |
| `CONTROL_TELEMETRY_RETENTION_DAYS` | `90` | Central operational telemetry retention, from 1 to 3650 days |
| `CONTROL_UPDATE_POLICY_DURATION_MS` | `300000` | Signed update decision lifetime, from one minute to one hour |
| `CONTROL_LEGACY_USAGE_REPORTS_ALLOWED` | `false` in production | Temporary migration switch for the unsigned v1 usage endpoint; keep disabled for commercial settlement |
| `CONTROL_DATA_REGION` | `CN-BJ` | Persistently bound primary data region; explicitly required in production |
| `CONTROL_ALLOWED_DATA_REGIONS` | primary region | Comma-separated approved storage/processing regions |
| `CONTROL_CROSS_BORDER_ENABLED` | `false` | Explicit cross-border processing gate; never enabled by a UI-only flag |
| `CONTROL_CROSS_BORDER_ASSESSMENT_ID` | empty | Required assessment/contract/certification reference when cross-border is enabled |
| `CONTROL_PRIVACY_POLICY_VERSION` | `2026-08-01` | Version recorded in notices, acceptances, exports, and audits |
| `CONTROL_PRIVACY_POLICY_EFFECTIVE_AT` | `2026-08-01T00:00:00.000Z` | Policy effective timestamp |
| `CONTROL_PRIVACY_CONTROLLER` | development placeholder | Legal operator/controller name; explicitly required in production |
| `CONTROL_PRIVACY_CONTACT` | development placeholder | Privacy request contact; explicitly required in production |
| `CONTROL_CUSTOMER_ERASURE_GRACE_DAYS` | `14` | Cooling-off period before approved customer erasure can execute |
| `CONTROL_PRIVACY_REQUEST_SLA_DAYS` | `15` | Maximum calendar-day handling target recorded on every privacy request |
| `CONTROL_BILLING_RETENTION_DAYS` | `1095` | Product baseline for restricted minimum billing evidence; legal review required |
| `CONTROL_GOVERNANCE_AUDIT_RETENTION_DAYS` | `2555` | Product baseline for restricted security evidence; legal review required |
| `CONTROL_DATA_EXPORT_RECORD_RETENTION_DAYS` | `30` | Days before delivered export result detail is restricted to its minimal hash record |
| `CONTROL_DATA_RETENTION_POLL_INTERVAL_HOURS` | `24` | Automatic retention enforcement interval, from 1 to 168 hours |
| `CONTROL_BACKUP_RETENTION_DAYS` | `30` | Number of days encrypted local backups are retained |
| `CONTROL_BACKUP_REPORT_DIR` | empty | Read-only directory containing backup inventory reports |
| `CONTROL_BACKUP_STATUS_MAX_AGE_HOURS` | `48` | Maximum acceptable age of the latest completed backup report |
| `CONTROL_ALERT_CHANNELS_FILE` | empty | Preferred version 1 multi-channel alert manifest; cannot be combined with legacy webhook settings |
| `CONTROL_ALERT_WEBHOOK_URL` | empty | HTTPS endpoint receiving signed operational alerts; empty disables delivery |
| `CONTROL_ALERT_WEBHOOK_SECRET_FILE` | empty | Read-only file containing the webhook HMAC secret |
| `CONTROL_ALERT_POLL_INTERVAL_MS` | `60000` | Background outbox polling interval, from 5 seconds to 1 hour |
| `CONTROL_RECOVERY_ASSURANCE_INTERVAL_MS` | `900000` | Full audit-chain, witness, and WORM assurance scan interval |
| `CONTROL_ALERT_WEBHOOK_TIMEOUT_MS` | `10000` | Per-delivery timeout, from 500 to 30000 milliseconds |
| `CONTROL_ALERT_WEBHOOK_MAX_ATTEMPTS` | `8` | Maximum delivery attempts before a terminal failure |
| `CONTROL_ALERT_RETENTION_DAYS` | `365` | Days to retain delivered and terminally failed alert records |
| `CONTROL_AUDIT_ANCHOR_URL` | empty | HTTPS endpoint receiving signed audit-chain receipts; empty disables anchoring |
| `CONTROL_AUDIT_ANCHOR_TOKEN_FILE` | empty | Read-only file containing the external anchor bearer token; required with the URL |
| `CONTROL_AUDIT_ANCHOR_INTERVAL_MS` | `900000` | Minimum interval between newly generated chain-head receipts, from 1 minute to 24 hours |
| `CONTROL_AUDIT_ANCHOR_POLL_INTERVAL_MS` | `60000` | Background anchor outbox polling interval, from 5 seconds to 1 hour |
| `CONTROL_AUDIT_ANCHOR_TIMEOUT_MS` | `10000` | Per-delivery timeout, from 500 to 30000 milliseconds |
| `CONTROL_AUDIT_ANCHOR_MAX_ATTEMPTS` | `8` | Maximum delivery attempts before a terminal failure |
| `CONTROL_AUDIT_WITNESS_SOURCES_FILE` | empty | Version 1 trusted-source manifest for an independent witness receiver |
| `CONTROL_AUDIT_WORM_REQUIRED` | `false` | Fail startup when immutable witness storage is not fully configured |
| `CONTROL_AUDIT_WORM_S3_ENDPOINT` / `CONTROL_AUDIT_WORM_S3_BUCKET` | empty | Dedicated S3/MinIO Object-Lock-capable evidence namespace |
| `CONTROL_AUDIT_WORM_S3_REGION` / `CONTROL_AUDIT_WORM_S3_PREFIX` | `us-east-1` / `otto-audit-witness` | SigV4 region and isolated object prefix |
| `CONTROL_AUDIT_WORM_S3_ACCESS_KEY_ID_FILE` / `CONTROL_AUDIT_WORM_S3_SECRET_ACCESS_KEY_FILE` | empty | Optional file-backed credentials; omit both on AWS to use the workload IAM role |
| `CONTROL_AUDIT_WORM_S3_ENCRYPTION` | `AES256` | `AES256` or `aws:kms`; KMS requires its separate key ID |
| `CONTROL_AUDIT_WORM_S3_LOCK_MODE` | `COMPLIANCE` | Immutable retention mode; required production mode rejects `GOVERNANCE` |
| `CONTROL_AUDIT_WORM_RETENTION_DAYS` | `2555` | Retention assigned from receipt acceptance time, from 30 to 3650 days |
| `CONTROL_AUDIT_WORM_POLL_INTERVAL_MS` | `30000` | Leased worker poll interval |
| `CONTROL_AUDIT_WORM_MAX_ATTEMPTS` | `20` | Attempts before evidence enters explicit terminal-failure state |
| `CONTROL_BACKUP_OFFSITE_REQUIRED` | `false` | Fail the scheduled backup when remote replication cannot be verified |
| `CONTROL_BACKUP_S3_ENDPOINT` | empty | HTTPS origin for AWS S3, MinIO, or another S3-compatible service |
| `CONTROL_BACKUP_S3_BUCKET` | empty | Bucket receiving encrypted backup objects |
| `CONTROL_BACKUP_S3_REGION` | `us-east-1` | SigV4 signing region |
| `CONTROL_BACKUP_S3_PREFIX` | `otto-control` | Isolated object-key prefix for this control plane |
| `CONTROL_BACKUP_S3_ADDRESSING_STYLE` | `path` | S3 endpoint addressing: `path` or `virtual` |
| `CONTROL_BACKUP_S3_ACCESS_KEY_ID_FILE` | empty | Permission-restricted file containing the S3 access key ID |
| `CONTROL_BACKUP_S3_SECRET_ACCESS_KEY_FILE` | empty | Permission-restricted file containing the S3 secret key |
| `CONTROL_BACKUP_S3_SESSION_TOKEN_FILE` | empty | Optional permission-restricted temporary session token file |
| `CONTROL_BACKUP_S3_MAX_ATTEMPTS` | `4` | Bounded remote upload and verification attempts |
| `CONTROL_BACKUP_S3_TIMEOUT_MS` | `120000` | Per-request inactivity timeout for remote backup operations |
| `CONTROL_DRILL_REPORT_RETENTION_DAYS` | `180` | Number of days successful restore-drill reports are retained |
| `CONTROL_DRILL_MAX_BACKUP_AGE_HOURS` | `48` | Oldest encrypted backup accepted by a restore drill |
| `CONTROL_PITR_REPORT_RETENTION_DAYS` | `180` | Days to retain physical-backup and PITR drill reports |
| `CONTROL_PITR_MAX_BACKUP_AGE_HOURS` | `24` | Oldest physical backup accepted by a PITR drill |
| `OTTO_CONTROL_BACKUP_KEY_FILE` | empty | File containing the backup encryption key |

Multi-channel alert delivery is configured with a read-only JSON manifest such
as `deploy/alert-channels.example.json`. Each channel has a stable ID, display
name, HTTPS endpoint, separate HMAC secret file, enabled state, and minimum
severity. A backup alert is queued, retried, audited, and reported independently
for every matching channel. Disabling a channel pauses its queued deliveries
without consuming retry attempts; enabling it resumes them. The legacy single-webhook variables remain supported
for existing deployments, but must not be combined with the manifest.

## Commercial control flow

1. Bootstrap the first administrator, enroll TOTP MFA, then use the returned
   administrator session for `/v1/admin/*` operations.
2. Create a customer with `POST /v1/admin/customers`.
3. Read the Otto server's deployment ID, organization ID, and machine
   fingerprint, then register them with `POST /v1/admin/deployments`.
4. Issue an online or offline License with `POST /v1/admin/licenses`.
5. Configure the non-revoked public keys from `GET /v1/signing-keyring` as Otto
   License verification keys. Pin at least one trusted key out of band before
   accepting a downloaded keyring.
6. Import the signed envelope into Otto. Online deployments refresh
   `POST /v1/licenses/:licenseId/lease` every two minutes, report their current
   active enterprise-account count, and automatically install renewed License
   terms returned with the lease.
7. Configure `OTTO_TELEMETRY_ENDPOINT` on the private Otto server as
   `https://<control-host>/v1/telemetry/ingest`.

The control database stores License metadata, signatures, public keys, key
states, and a token version. It does not store private keys or plaintext
lease/telemetry tokens. Local private key paths must point to read-only secret
mounts. `PayloadSigner` is the provider boundary, so remote KMS/HSM providers
use the same key ID, public key, and asynchronous signing operation without
changing the License or update-policy services.

### Commercial License lifecycle

Online Licenses have a monotonically increasing `revision`. Renewal and seat
changes re-sign the License without rotating its derived client tokens, so a
healthy deployment keeps running and receives the new envelope on its next
lease refresh. Machine transfer and deployment rebinding increment both the
revision and token version, immediately invalidating the previous machine's
lease and telemetry credentials. Rebinding is restricted to another active
deployment owned by the same customer.

Seat enforcement defaults to `monitor` for compatibility. Otto reports the
number of active, non-deleted enterprise accounts with every two-minute lease
request. In `enforce` mode, excess seats start the configured 0-30 day grace
period; leases expose the overage state during grace and fail closed afterward.
The same signed grace period applies after License expiry. Offline Licenses may
be monitored contractually but cannot claim real-time seat enforcement.

Every lifecycle change is immutable, actor-attributed, revisioned, and available
through the lifecycle API. Machine transfer and deployment rebinding require a
request-bound second-administrator approval. Seat usage is kept separately from
the signed contract so frequent reports do not rewrite License history.

### Credits and billing

Credits are positive integers. PostgreSQL stores one account per
`customerId + organizationId` for fast reads, but the immutable transaction
ledger is the source of truth. Top-ups,
rate changes, and refunds are audited; the HTTP routes require RBAC permissions,
and financial mutations require request-bound second-administrator approval.

Configure each customer's module rate before enabling usage. `unitSize` defines
one billing unit and `creditsPerUnit` defines its integer price. Otto submits only
the deployment/organization binding, stable module ID, aggregate units, and an
opaque request reference. The control plane calculates the charge, so a customer
server cannot submit a lower price. Prompts, replies, chats, files, filenames, and
meeting content are not part of the billing protocol.

Commercial settlement uses signed execution receipts. Each deployment registers
an Ed25519 public key through a second-administrator-approved operation, signs a
strict content-free receipt, and submits it to
`POST /v1/billing/execution-receipts`. Control verifies the deployment binding,
lease, key validity, signature, expiry, contiguous sequence, task uniqueness,
rate, and balance before persisting the receipt and debit atomically. Production
disables the legacy unsigned `/v1/billing/usage/consume` endpoint by default.
The complete privacy and replay contract is documented in
[`docs/otto-commercial-enforcement-v2.md`](docs/otto-commercial-enforcement-v2.md).

`POST /v1/billing/holds` freezes estimated credits before long work. Capture
settles the actual amount and immediately releases any remainder; explicit
release and automatic expiry both return unused credits. Direct usage calls and
every hold mutation require an enterprise-scoped idempotency key. Reusing that key
with different parameters fails with `409` instead of silently changing money.
`POST /v1/billing/holds/:holdId/execution-receipts` performs signature verification,
actual capture, unused-credit release, receipt persistence, and sequence advance in
one transaction so the Edge Gateway does not double charge by combining a hold
with direct receipt consumption. Insufficient hold balance is reported as HTTP
402 `CREDIT_REQUIRED` rather than inferred from mutable error text.

Administrators can query an enterprise account by passing `organizationId` to
`/v1/admin/billing/customers/:customerId/account`; top-ups must also include the
target `organizationId`. Rates, transactions, and period statements remain
available under `/v1/admin/billing/customers/:customerId/*`. The `export.csv` endpoint
includes balances, deltas, references, related refund transactions, and
idempotency keys for reconciliation. Refunds must reference a consume/capture
transaction, and cumulative refunds cannot exceed its billed amount.

Migration `028_enterprise_credit_accounts` moves an old customer-wide balance
only when exactly one organization can be proven. Ambiguous legacy balances are
quarantined in `control_legacy_credit_accounts` for explicit reconciliation and
cannot be consumed by any enterprise. Existing active holds are reconstructed in
their recorded enterprise accounts so capture or release can still complete.

### Commercial plans and customer delivery

`GET /v1/commercial/plans` is the single signed catalog for the Basic,
Enterprise, Park, and Government plans. License issuance rejects unknown plans,
modules outside the selected plan, missing required modules, and offline use on
plans that do not allow it. Enforcement defaults remain backward compatible:
seat and billing blocking must be selected explicitly, while the signed plan
still defines the permitted module and overage boundary.

Administrators with `customer_delivery.read` can download a signed JSON package
from `/v1/admin/customers/:customerId/delivery-package.json`. It joins the
current authorization, plan compliance, reporting boundary, privacy/controller
configuration, retention rules, period statement, customer rate card, and ROI
evidence into one hash-addressed artifact. The companion `roi-report.csv`
counts only verified v2 execution receipts. Labor value is left blank unless
the customer supplies `minutesSavedPerTask` and `laborCostCentsPerHour`; it is
never presented as guaranteed savings. The existing billing `export.csv`
remains the detailed reconciliation ledger.

Each privacy request records a durable `dueAt`, SLA state, completion time, and
manifest hash. The technical deadline is a product target, not a substitute for
the shorter period required by a customer contract or applicable law. See
[`docs/commercial-packages.zh-CN.md`](docs/commercial-packages.zh-CN.md).

### Administrator identity and approvals

`CONTROL_ADMIN_TOKEN` is not a normal administrator credential. It can only call
`POST /v1/admin-auth/bootstrap`, and bootstrap is permanently refused after the
first account exists. Store this secret offline after initialization.

```bash
curl -X POST https://control.example.com/v1/admin-auth/bootstrap \
  -H "Authorization: Bearer $CONTROL_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"username":"root.admin","displayName":"Root Admin","password":"CHANGE-ME-2026"}'
```

Scan the returned `otpauthUri` with a standard authenticator, then submit
`accountId`, `enrollmentToken`, and the six-digit `totpCode` to
`POST /v1/admin-auth/enroll/confirm`. The response shows ten recovery codes
exactly once. Store them in an offline password vault. Subsequent login uses
`POST /v1/admin-auth/login` with password plus TOTP (or one unused recovery
code). Sessions last eight hours, expire after thirty idle minutes, are stored
only as SHA-256 hashes, and are revoked immediately when an account is disabled
or its roles change.

The built-in roles are `super_admin`, `security_admin`, `license_admin`,
`release_admin`, and `auditor`. API authorization checks permissions at the
execution route, not only in an operator UI. The last active super administrator
cannot be disabled or stripped of that role.

High-risk operations require another administrator. The requester first calls
`POST /v1/admin/approvals` with the exact operation, target, and future request
body. A different account with `approval.decide` approves it. The requester then
repeats the protected call with `X-Otto-Approval-Id`. The approval is bound to a
canonical SHA-256 request digest, expires after thirty minutes, rejects
self-approval, and is consumed once. A normalized request snapshot is persisted
for the reviewer, but each operation has an explicit field allowlist and a
16 KiB limit so this channel cannot be used to store customer content. Supported
protected operation names are:

```text
license.revoke
license.transfer_machine
license.rebind_deployment
signing_key.activate
signing_key.retire
signing_key.revoke
update_release.activate
update_release.rollback
release_artifact.revoke
billing.rate.set
billing.topup
billing.refund
billing.execution_receipt_key.register
billing.execution_receipt_key.revoke
```

### Operator console

Open `https://control.example.com/admin` after the first administrator has been
enrolled. The console uses the same password plus TOTP or one-time recovery-code
login as the API. Its bearer session is kept in browser `sessionStorage`, never
in persistent local storage, and is removed on logout, expiry, or tab closure.

The console summarizes customers, deployments, License lifecycle risk, backup
readiness, and outbound alert delivery. Operators with the matching execution
permissions can also create a customer, register its deployment, and issue a
License through structured forms. Deployment IDs are generated with browser
cryptographic randomness; module grants are explicit checkboxes; offline
licenses automatically disable real-time seat enforcement and telemetry.

Selecting a License opens a permission-aware lifecycle view. `license.read`
exposes a dedicated redacted summary without the machine fingerprint, signature,
lease token, or telemetry token. `license.usage.read` adds active-seat state and
immutable revision history. `license.manage` adds renewal and seat/policy forms;
offline Licenses remain locked to monitor mode. Revoked Licenses are read-only.
The complete signed envelope endpoint requires the separate `license.export`
permission, which is intentionally not granted to the read-only auditor role.

The approval center lists pending and historical high-risk operations. A second
administrator with `approval.decide` sees the normalized request snapshot and
can approve or reject with a reason; self-approval is unavailable. The original
requester can execute an approved operation once, after which the approval is
atomically marked `executed`. License revocation requests can be created directly
from the License lifecycle dialog, and the generic executor covers every
server-supported approval operation. The console action catalog is checked
against all 18 server approval operation IDs at compile and test time, including
execution-receipt key rotation and data-governance actions. Unknown future
operations remain disabled instead of falling through to an unimplemented
button.

Newly issued or updated signed License envelopes, including their derived
deployment credentials, exist only in page memory and can be downloaded as JSON
for secure customer delivery. They are cleared when the result dialog closes
and are never put in browser persistent storage. Failed alerts can be returned
to the durable retry queue. Inventory and summary responses exclude machine
fingerprints, License signatures, bearer tokens, telemetry secrets, and customer
content.

`commercial.read` is granted to `super_admin`, `license_admin`, and `auditor`;
write buttons are permission-aware, and every API call is still authorized
server-side. Backup and alert panels degrade independently when the signed-in
role lacks their permissions. The page ships no third-party scripts and uses a
same-origin CSP with no inline script allowance.

### Signing key rotation

1. Generate a new Ed25519 key outside the application and add its read-only path
   to the version 1 keyring manifest. Restart; it appears as `standby`.
2. Export `GET /v1/signing-keyring`, verify its signature with an already trusted
   key, and distribute both old and new public keys to Otto deployments.
3. Activate with `POST /v1/admin/signing-keys/:keyId/activate`. The former active
   key becomes `retired`, so historical License files continue to verify.
4. After the longest License/update overlap window, remove the retired private
   key provider if desired, but retain its public record.
5. For compromise response, call `.../:keyId/revoke` with `reason` and, when the
   key is active, a signable `replacementKeyId`. The transition is atomic and
   audited. Offline License revocation cannot be instantaneous; keep offline
   validity short and distribute the revoked-key list through customer operations.

Revoking an online License prevents the next lease renewal, so normal access is
removed within the 10-minute lease window. Offline Licenses cannot receive live
revocation and must use short, explicit expiry periods appropriate to the
customer contract.

### Native AWS KMS Ed25519 signing

The production provisioning, ownership, rotation, emergency revocation, and
recovery procedure is documented in
[`docs/production-signing-operations.zh-CN.md`](docs/production-signing-operations.zh-CN.md).

AWS KMS can be used directly with `provider: "kms"` and
`backend: "aws_kms"`. The complete manifest is
`deploy/control_signer_keyring.aws-kms.example.json`; replace both example ARNs
with replicas of one customer-managed `ECC_NIST_EDWARDS25519` multi-Region key.
Only immutable key ARNs are accepted. At startup Control calls `DescribeKey` and
`GetPublicKey`, requires an enabled `SIGN_VERIFY` customer key with
`ED25519_SHA_512`, validates `kms:Sign` with `DryRun`, and verifies that every
configured replica exposes the same Ed25519 public key. See the AWS
[asymmetric key specifications](https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose-key-spec.html),
[`Sign` API](https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html),
and [multi-Region key behavior](https://docs.aws.amazon.com/kms/latest/developerguide/mrk-how-it-works.html).

The Control container never receives the private key. Long-lived access-key
pairs are rejected; credentials must come from EKS/OIDC Web Identity, an ECS
task role, an EC2 instance role, or a short-lived STS session that includes
`AWS_SESSION_TOKEN` (for example, GitHub Actions OIDC). Attach the narrow policy in
`deploy/aws-kms-signing-policy.example.json` to that workload role. It grants
only `DescribeKey`, `GetPublicKey`, and `Sign` for the exact ARNs, and constrains
signing to `MessageType=RAW` and `ED25519_SHA_512`. The role must not receive
key creation, policy mutation, disable, schedule-deletion, decrypt, or grant
management permissions. AWS documents the relevant
[KMS condition keys](https://docs.aws.amazon.com/kms/latest/developerguide/conditions-kms.html).

Raw AWS KMS messages are capped at 4096 bytes. Control signs only compact
canonical License, lease, update-policy, audit, and keyring envelopes. Every
returned signature is verified locally before use. Multiple regions are tried
only when their ARNs identify the same MRK material; there is no fallback to a
different, retired, local, or standby key. Three complete provider failures
open a 30-second circuit.

Before activation, `POST /v1/admin/signing-keys/:keyId/probe` performs a real
sign operation with a random challenge and independently verifies it. The
activation endpoint repeats this probe before changing database state. Probe
audit records contain only the key ID, backend health, and active region, never
the challenge or signature.

Use two separate MFA administrator sessions plus an independent read-only
auditor session for a production rotation:

```bash
npm run drill:signing:rotation -- \
  --control-url https://control.example.com \
  --requester-token-file ./secrets/requester-session \
  --approver-token-file ./secrets/security-session \
  --auditor-token-file ./secrets/auditor-session \
  --target-key-id 0123456789abcdef \
  --legacy-license-id lic_existing_license \
  --output ./backups/drills/signing-rotation.json \
  --confirm=ROTATE_OTTO_SIGNING_KEY
```

The command probes the standby key, creates a request-bound approval, has the
second administrator approve it, activates the key, verifies that the previous
key is retired, and uses an independent `audit.read`/`audit.verify` session to
prove every drill action is present in the tamper-evident chain. The `0600`
report contains event sequence/hash evidence plus a digest of the signed
integrity receipt, without tokens or raw signatures. First
distribute and verify the signed public keyring on Otto deployments. Keep the
old key available for the full License/update overlap period, then remove its
signing provider while retaining the retired public database record.

For a regional disaster-recovery drill, temporarily deny `kms:Sign` for the
primary region at the test workload policy/SCP boundary, then run:

```bash
npm run drill:signing:provider -- \
  --control-url https://control.example.com \
  --token-file ./secrets/requester-session \
  --key-id 0123456789abcdef \
  --expect-location ap-northeast-1 \
  --minimum-failovers 1 \
  --output ./backups/drills/signing-provider-dr.json \
  --confirm=PROBE_OTTO_SIGNING_PROVIDER
```

Restore primary-region permission immediately after the drill. A passing report
must show a verified signature from the expected replica and an increased
failover counter. If every region is unavailable, License issuance and other
signed mutations fail closed; operators must restore KMS or perform a separately
approved key rotation. Do not add a local emergency private key to the AWS KMS
manifest. After migration, delete the old local private-key file from the host
and from every Control secret mount.

The manually dispatched `.github/workflows/aws-kms-drill.yml` exchanges GitHub
OIDC identity for a 15-minute AWS session and runs the opt-in live integration
test. Configure the repository's OIDC subject on a dedicated IAM role, then
provide only that role ARN, the region, and the KMS key ARNs when dispatching the
workflow. No AWS access key is stored in GitHub. A local or ordinary CI test run
skips the live test unless `CONTROL_TEST_AWS_KMS_KEY_ARNS` is explicitly set.

### Isolated remote KMS/HSM broker

The keyring manifest also accepts remote `provider: "kms"` and
`provider: "hsm"` entries.
Otto Control stores only the Ed25519 public key and a non-secret remote `keyRef`;
the private key stays inside the managed KMS, HSM, or its isolated signing
broker. See `deploy/control_signer_keyring.remote.example.json` for the complete
file layout. Relative credential paths resolve beside the manifest.

Each remote provider requires either a bearer token file or an mTLS client
certificate and key; both can be enabled together. Bearer tokens are read again
for every request so a mounted secret can rotate without restarting Otto
Control. Client certificates and CA bundles are loaded at startup. The endpoint
must be HTTPS, redirects are not followed, timeouts are bounded to 0.5-30
seconds, and responses over 32 KiB are rejected.

The signing broker receives this JSON body:

```json
{
  "version": 1,
  "requestId": "uuid",
  "keyId": "16-character-public-key-id",
  "keyRef": "production/otto-license/2026-rotation-01",
  "algorithm": "ed25519",
  "encoding": "base64",
  "payload": "canonical-json-bytes-as-base64"
}
```

It must return HTTP 200 with `application/json` and an object containing the
same `version`, `requestId`, `keyId`, `algorithm`, plus a raw 64-byte Ed25519
signature encoded as unpadded base64url. Otto Control verifies that signature
locally against the configured public key before accepting it. Three consecutive
provider failures open a 30-second circuit; there is deliberately no automatic
fallback to a retired or standby key. Remote provider health starts as
`unchecked`, becomes `available` only after a verified signature, and is exposed
by the administrator signing-key API without leaking endpoint credentials.

The backend must support Ed25519 signing of the raw canonical message. A KMS or
HSM that exposes only RSA/ECDSA or pre-hashed signing is not compatible with the
current Otto License contract; place a narrowly scoped Ed25519 signer behind
this protocol instead of changing verification semantics during a rotation.

To migrate, keep the current local entry and add the KMS/HSM entry, restart to
register it as `standby`, distribute the signed public keyring, obtain dual
approval, and activate the remote key. Only after the overlap window should the
old local private-key entry be removed. Its public database record remains
`retired`, so historical License envelopes continue to verify.

Telemetry accepts only signed operational events. Each request is bound to its
License, deployment, and machine fingerprint, permits five minutes of clock
skew, and consumes its nonce transactionally with the event batch. Duplicate
event IDs are idempotent. Keys associated with messages, files, attachments,
audio, transcripts, prompts, completions, and documents are rejected before
storage. The customer-side queue continues to retry independently when this
control service is unavailable.

## Update policy flow

1. Create independent distributions such as `otto` and `otto-green` with
   `POST /v1/admin/update-distributions`.
2. Allow each registered deployment to use one or more distributions with
   `PUT /v1/admin/deployments/:deploymentId/update-distribution`.
3. Register a draft release with HTTPS full and/or incremental manifest URLs.
   Every manifest reference requires its lowercase SHA-256 digest.
4. In production, upload every downloadable file through
   `POST /v1/admin/update-releases/:releaseId/artifact-uploads` and complete it
   with trusted platform-signing evidence. The metadata-only `artifacts` route
   remains a development migration path and cannot activate a release when the
   production storage gate is enabled. At least one platform installer and
   signed artifact records matching every referenced manifest are required.
5. Activate the release. A canary uses a stable 1-100 cohort derived from the
   distribution, release, and deployment IDs. Stable and required releases are
   always 100 percent; required responses set `mandatory: true`.
6. Otto signs `POST /v1/update-policy/resolve` with its derived lease token,
   timestamp, and one-time nonce. The returned policy is Ed25519 signed and
   expires after five minutes by default. It includes each active artifact's
   independently verifiable signed envelope.
7. Pause immediately stops new decisions. Rollback withdraws the selected
   policy and restores its previous active policy when available.

Revoking an artifact requires dual approval and atomically pauses its active
release. Policy resolution rechecks artifact signatures, signing-key state,
installer presence, and manifest bindings, so a stale database state fails
closed. These detached Ed25519 signatures protect Otto's release metadata and
download integrity. They complement, but do not replace, Windows Authenticode,
Apple Developer ID signing and notarization, or Linux package signing.

Policy rollback does not claim to downgrade clients that already installed an
artifact. Client-side component receipts and full-installer rollback remain
separate execution concerns. Distribution allowlists prevent a deployment from
requesting unapproved artifacts while allowing one enterprise server to serve
both Otto and Otto Green clients from the same accounts and collaboration data.

## Implemented APIs

```text
GET  /health/live
GET  /health/ready
GET  /v1
GET  /v1/privacy/notice
GET  /v1/privacy/data-map
GET  /v1/commercial/plans
POST /v1/admin-auth/bootstrap
POST /v1/admin-auth/enroll/confirm
POST /v1/admin-auth/login
POST /v1/admin-auth/logout
GET  /v1/admin-auth/me
GET  /v1/admin/overview?limit=12
GET  /v1/admin/accounts
POST /v1/admin/accounts
PUT  /v1/admin/accounts/:accountId/roles
PUT  /v1/admin/accounts/:accountId/status
GET  /v1/admin/roles
POST /v1/admin/approvals
GET  /v1/admin/approvals
POST /v1/admin/approvals/:approvalId/decide
GET  /v1/admin/data-governance/status
GET  /v1/admin/data-governance/requests/:id
POST /v1/admin/data-governance/privacy-acceptances
POST /v1/admin/customers/:customerId/data-exports
POST /v1/admin/customers/:customerId/erasure-requests
POST /v1/admin/data-governance/erasure-requests/:id/execute
POST /v1/admin/data-governance/legal-holds
POST /v1/admin/data-governance/legal-holds/:id/release
POST /v1/admin/data-governance/forensic-exports
POST /v1/admin/data-governance/retention/run
GET  /v1/admin/customers/:customerId/delivery-package.json
GET  /v1/admin/customers/:customerId/roi-report.csv
POST /v1/admin/customers
POST /v1/admin/deployments
POST /v1/admin/licenses
GET  /v1/admin/licenses/:licenseId
GET  /v1/admin/licenses/:licenseId/summary
POST /v1/admin/licenses/:licenseId/renew
POST /v1/admin/licenses/:licenseId/resize
POST /v1/admin/licenses/:licenseId/transfer-machine
POST /v1/admin/licenses/:licenseId/rebind-deployment
GET  /v1/admin/licenses/:licenseId/lifecycle?limit=50
GET  /v1/admin/licenses/:licenseId/seats
POST /v1/admin/licenses/:licenseId/revoke
GET  /v1/admin/signing-key
GET  /v1/admin/signing-keys
POST /v1/admin/signing-keys/:keyId/probe
POST /v1/admin/signing-keys/:keyId/activate
POST /v1/admin/signing-keys/:keyId/retire
POST /v1/admin/signing-keys/:keyId/revoke
GET  /v1/signing-keyring
GET  /v1/admin/deployments/:deploymentId/health?hours=24
GET  /v1/admin/backups/status?limit=20
GET  /v1/admin/alerts/deliveries?limit=50
POST /v1/admin/alerts/poll
POST /v1/admin/alerts/deliveries/:deliveryId/retry
GET  /v1/admin/audit/events
GET  /v1/admin/audit/export.csv
POST /v1/admin/audit/verify
GET  /v1/admin/audit/anchors?limit=50
POST /v1/admin/audit/anchors/poll
POST /v1/admin/audit/anchors/:anchorId/retry
POST /v1/audit-witness/anchors
GET  /v1/admin/audit-witness/receipts?sourceId=primary-control&limit=50
POST /v1/admin/update-distributions
PUT  /v1/admin/deployments/:deploymentId/update-distribution
POST /v1/admin/update-releases
GET  /v1/admin/update-distributions/:distributionId/releases
POST /v1/admin/update-releases/:releaseId/artifacts
GET  /v1/admin/update-releases/:releaseId/artifacts
POST /v1/admin/release-artifacts/:artifactId/revoke
POST /v1/admin/update-releases/:releaseId/activate
POST /v1/admin/update-releases/:releaseId/pause
POST /v1/admin/update-releases/:releaseId/rollback
POST /v1/licenses/:licenseId/lease
POST /v1/telemetry/ingest
POST /v1/update-policy/resolve

# Separate Otto Federation process (port 7790)
GET  /v1/federation/status
GET  /v1/federation/directory/:deploymentId
GET  /v1/federation/directory/:deploymentId/keys/:keyId
POST /v1/federation/envelopes
POST /v1/federation/inbox/claim
POST /v1/federation/inbox/ack
POST /v1/federation/a2a/grants
POST /v1/federation/a2a/grants/revoke
GET  /v1/admin/federation/deployments
GET  /v1/admin/federation/audit-events
GET  /v1/admin/federation/deployments/:deploymentId/operations
GET  /v1/admin/federation/status
POST /v1/admin/federation/deployments
PATCH /v1/admin/federation/deployments/:deploymentId/status
```

## Planned module boundaries

```text
Traefik
  -> Otto Control Fastify edge
       -> identity_admin (accounts, MFA, sessions, RBAC, dual control)
       -> customer_deployment (implemented foundation)
       -> license_authority (commercial lifecycle implemented)
       -> signing_key_rotation (implemented foundation)
       -> lease_revocation (implemented foundation)
       -> telemetry_health (implemented foundation)
       -> update_policy (implemented foundation)
       -> release_artifacts (implemented foundation)
       -> backup_status (implemented foundation)
       -> alert_delivery (implemented foundation)
       -> operator_console (implemented onboarding, License lifecycle, and dual control)
       -> audit (implemented query, export, and signed integrity verification)
       -> audit_anchor (implemented durable external evidence delivery)
       -> audit_witness (implemented independent verification and receipt retention)
       -> data_governance (implemented residency, privacy notice, export, erasure, legal hold, and forensics)
       -> commercial_delivery (implemented signed plans, delivery package, privacy SLA, and verified ROI)

Otto Federation Fastify edge (independently deployable, implemented v1)
  -> deployment_directory
  -> ed25519_request_auth_and_replay_guard
  -> ciphertext_relay_and_offline_inbox
  -> delivery_receipts_and_bilateral_blocks
  -> scoped_one_time_a2a_grants
```

The Otto private server and desktop adapter now consume this signed policy and
map it onto the existing `latest.json` and incremental manifest engines. The
Data-governance operating rules are documented in
`docs/data-governance-policy.zh-CN.md`, the customer-facing notice template in
`docs/privacy-notice.template.zh-CN.md`, and evidence handling in
`docs/forensic-evidence-procedure.zh-CN.md`. Federation v1 and its private-server
adapter contract are now implemented in this repository; the remaining integration
step is wiring that adapter into each Otto Server release after its E2EE module is enabled.

# Otto Control

Otto Control is the commercial control plane for Otto private deployments. It
will own customer and deployment registration, signed License issuance, online
lease renewal, revocation, operational telemetry, update policy, and audit.

This repository contains Otto-specific business code. Fastify is used as the
MIT-licensed HTTP foundation; its license does not make this repository MIT.

## Current foundation

- TypeScript and Node.js 22
- Fastify 5 with a 1 MB default body limit
- Versioned `/v1` API surface
- Liveness and readiness endpoints
- Generated request IDs and a stable JSON error envelope
- Security and no-cache response headers
- Logger redaction for credentials and License/telemetry tokens
- Strict configuration validation
- Container build running as a non-root user
- PostgreSQL customer, deployment, License, replay-nonce, and audit tables
- Otto-compatible Ed25519 License envelopes and 10-minute online leases
- License binding to deployment ID, organization ID, and machine fingerprint
- Administrator bearer authentication and fail-closed License revocation
- Derived lease/telemetry tokens that are never stored as plaintext in PostgreSQL
- Authenticated operational telemetry ingest with HMAC, nonce replay protection,
  event integrity checks, idempotent storage, and retention cleanup
- Per-deployment health summaries without uploading chats, files, prompts, or transcripts
- Independent update distributions for Otto, Otto Green, and future private editions
- Draft, canary, stable, and required release policy with deterministic deployment cohorts
- SHA-256-pinned full and incremental manifests with short-lived Ed25519 policy envelopes
- Audited activation, pause, and rollback to the previous release policy
- Production Compose stack with isolated PostgreSQL, automatic HTTPS, persistent
  volumes, read-only control runtime, and file-mounted secrets
- One-command Ed25519 key and random credential bootstrap that refuses to
  overwrite an existing production identity
- AES-256-GCM encrypted PostgreSQL backups with atomic publication, integrity
  checks, retention, restore-before-write validation, and a systemd schedule

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

## Production Compose deployment

Point a public DNS name at the server first. Then create the deployment identity
and secrets locally on that server:

```bash
npm ci
npm run bootstrap:production -- --public-url https://control.example.com
docker compose -f compose.production.yaml --env-file .env.production config
docker compose -f compose.production.yaml --env-file .env.production up -d --build
docker compose -f compose.production.yaml --env-file .env.production ps
curl https://control.example.com/health/ready
```

The stack keeps PostgreSQL on an internal-only network. Only Caddy publishes
ports 80 and 443; it obtains and renews the public TLS certificate. The control
container runs without Linux capabilities, with a read-only root filesystem,
and receives credentials through `/run/secrets` rather than image layers or
plain environment values.

Back up both the PostgreSQL volume and the `secrets/` directory. In particular,
do not regenerate `control_signer_private_key.pem` for an existing deployment:
replacing it changes the signing identity and makes previously issued License
and update-policy envelopes unverifiable. The bootstrap command uses exclusive
file creation and fails instead of overwriting an existing identity.

### Backup and restore

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
unencrypted dump is never written to disk. Copy encrypted backups and checksum
files to off-site storage, but protect `secrets/backup_encryption_key` separately;
losing that key makes every encrypted backup unrecoverable.

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
| `OTTO_CONTROL_VERSION` | `0.4.0` | Runtime version exposed by health APIs |
| `CONTROL_DATABASE_URL` | empty | PostgreSQL connection URL |
| `CONTROL_DATABASE_HOST` | empty | PostgreSQL host when component configuration is used |
| `CONTROL_DATABASE_PORT` | `5432` | PostgreSQL port for component configuration |
| `CONTROL_DATABASE_NAME` | empty | PostgreSQL database name for component configuration |
| `CONTROL_DATABASE_USER` | empty | PostgreSQL user for component configuration |
| `CONTROL_DATABASE_PASSWORD` | empty | PostgreSQL password; file-backed form is preferred |
| `CONTROL_DATABASE_PASSWORD_FILE` | empty | Read-only file containing the PostgreSQL password |
| `CONTROL_DATABASE_SSL` | production: `true` | Require verified TLS to PostgreSQL |
| `CONTROL_ADMIN_TOKEN` | empty | 32-byte minimum bearer token for `/v1/admin/*` |
| `CONTROL_ADMIN_TOKEN_FILE` | empty | Read-only file containing the administrator token |
| `CONTROL_TOKEN_SECRET` | empty | 32-byte minimum root secret used to derive scoped tokens |
| `CONTROL_TOKEN_SECRET_FILE` | empty | Read-only file containing the token derivation secret |
| `CONTROL_SIGNER_PRIVATE_KEY_FILE` | empty | Read-only Ed25519 PKCS#8 secret mount |
| `CONTROL_LEASE_DURATION_MS` | `600000` | Online lease lifetime; Otto refreshes every two minutes |
| `CONTROL_TELEMETRY_RETENTION_DAYS` | `90` | Central operational telemetry retention, from 1 to 3650 days |
| `CONTROL_UPDATE_POLICY_DURATION_MS` | `300000` | Signed update decision lifetime, from one minute to one hour |
| `CONTROL_BACKUP_RETENTION_DAYS` | `30` | Number of days encrypted local backups are retained |
| `CONTROL_DRILL_REPORT_RETENTION_DAYS` | `180` | Number of days successful restore-drill reports are retained |
| `CONTROL_DRILL_MAX_BACKUP_AGE_HOURS` | `48` | Oldest encrypted backup accepted by a restore drill |
| `OTTO_CONTROL_BACKUP_KEY_FILE` | empty | File containing the backup encryption key |

## Commercial control flow

1. Create a customer with `POST /v1/admin/customers`.
2. Read the Otto server's deployment ID, organization ID, and machine
   fingerprint, then register them with `POST /v1/admin/deployments`.
3. Issue an online or offline License with `POST /v1/admin/licenses`.
4. Configure the returned public key from `GET /v1/admin/signing-key` as an
   Otto License verification key.
5. Import the signed envelope into Otto. Online deployments refresh
   `POST /v1/licenses/:licenseId/lease` every two minutes.
6. Configure `OTTO_TELEMETRY_ENDPOINT` on the private Otto server as
   `https://<control-host>/v1/telemetry/ingest`.

The control database stores License metadata, signatures, and a token version.
It does not store the License private key or plaintext lease/telemetry tokens.
The private key path must point to a read-only secret mount. The signer is an
interface so a KMS/HSM adapter can replace the mounted-file signer without
changing the License service or HTTP contract.

Revoking an online License prevents the next lease renewal, so normal access is
removed within the 10-minute lease window. Offline Licenses cannot receive live
revocation and must use short, explicit expiry periods appropriate to the
customer contract.

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
4. Activate the release. A canary uses a stable 1-100 cohort derived from the
   distribution, release, and deployment IDs. Stable and required releases are
   always 100 percent; required responses set `mandatory: true`.
5. Otto signs `POST /v1/update-policy/resolve` with its derived lease token,
   timestamp, and one-time nonce. The returned policy is Ed25519 signed and
   expires after five minutes by default.
6. Pause immediately stops new decisions. Rollback withdraws the selected
   policy and restores its previous active policy when available.

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
POST /v1/admin/customers
POST /v1/admin/deployments
POST /v1/admin/licenses
GET  /v1/admin/licenses/:licenseId
POST /v1/admin/licenses/:licenseId/revoke
GET  /v1/admin/signing-key
GET  /v1/admin/deployments/:deploymentId/health?hours=24
POST /v1/admin/update-distributions
PUT  /v1/admin/deployments/:deploymentId/update-distribution
POST /v1/admin/update-releases
GET  /v1/admin/update-distributions/:distributionId/releases
POST /v1/admin/update-releases/:releaseId/activate
POST /v1/admin/update-releases/:releaseId/pause
POST /v1/admin/update-releases/:releaseId/rollback
POST /v1/licenses/:licenseId/lease
POST /v1/telemetry/ingest
POST /v1/update-policy/resolve
```

## Planned module boundaries

```text
Traefik
  -> Otto Control Fastify edge
       -> identity_admin
       -> customer_deployment (implemented foundation)
       -> license_authority (implemented foundation)
       -> lease_revocation (implemented foundation)
       -> telemetry_health (implemented foundation)
       -> update_policy (implemented foundation)
       -> audit
```

The Otto private server and desktop adapter now consume this signed policy and
map it onto the existing `latest.json` and incremental manifest engines. The
next phases are signing-key rotation, off-site backup delivery, operator-facing
administration, and eventually the separate federation gateway.

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
- Administrator accounts with scrypt password hashes, TOTP MFA, one-time recovery
  codes, short-lived sessions, idle expiry, login lockout, and server-side revocation
- Built-in RBAC roles for super, security, License, release, and audit operators
- Request-bound dual-control approval for License revocation, signing-key changes,
  release activation, and rollback
- Persisted Ed25519 keyring with standby, active, retired, and revoked states
- Audited key activation and emergency revocation with atomic replacement
- Signed public keyring export and stable signer-provider boundary for KMS/HSM adapters
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

Back up both the PostgreSQL volume and the `secrets/` directory. Never overwrite
an existing private key. Add a new key to `control_signer_keyring.json`, restart
the control service so it is registered as `standby`, distribute the signed
public keyring, and only then activate it. The old key becomes `retired` and
continues to verify historical License envelopes. Use `revoked` only for a
compromise; online License leases signed by that key then fail closed. The
bootstrap command uses exclusive file creation and refuses to overwrite an
existing identity.

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
| `OTTO_CONTROL_VERSION` | `0.6.0` | Runtime version exposed by health APIs |
| `CONTROL_DATABASE_URL` | empty | PostgreSQL connection URL |
| `CONTROL_DATABASE_HOST` | empty | PostgreSQL host when component configuration is used |
| `CONTROL_DATABASE_PORT` | `5432` | PostgreSQL port for component configuration |
| `CONTROL_DATABASE_NAME` | empty | PostgreSQL database name for component configuration |
| `CONTROL_DATABASE_USER` | empty | PostgreSQL user for component configuration |
| `CONTROL_DATABASE_PASSWORD` | empty | PostgreSQL password; file-backed form is preferred |
| `CONTROL_DATABASE_PASSWORD_FILE` | empty | Read-only file containing the PostgreSQL password |
| `CONTROL_DATABASE_SSL` | production: `true` | Require verified TLS to PostgreSQL |
| `CONTROL_ADMIN_TOKEN` | empty | 32-byte minimum emergency secret used only for first administrator bootstrap |
| `CONTROL_ADMIN_TOKEN_FILE` | empty | Read-only file containing the bootstrap secret |
| `CONTROL_TOKEN_SECRET` | empty | 32-byte minimum root secret used to derive scoped tokens |
| `CONTROL_TOKEN_SECRET_FILE` | empty | Read-only file containing the token derivation secret |
| `CONTROL_SIGNER_PRIVATE_KEY_FILE` | empty | Read-only Ed25519 PKCS#8 secret mount |
| `CONTROL_SIGNER_KEYRING_FILE` | empty | Version 1 local-provider keyring manifest; mutually exclusive with the legacy single-key setting |
| `CONTROL_LEASE_DURATION_MS` | `600000` | Online lease lifetime; Otto refreshes every two minutes |
| `CONTROL_TELEMETRY_RETENTION_DAYS` | `90` | Central operational telemetry retention, from 1 to 3650 days |
| `CONTROL_UPDATE_POLICY_DURATION_MS` | `300000` | Signed update decision lifetime, from one minute to one hour |
| `CONTROL_BACKUP_RETENTION_DAYS` | `30` | Number of days encrypted local backups are retained |
| `CONTROL_DRILL_REPORT_RETENTION_DAYS` | `180` | Number of days successful restore-drill reports are retained |
| `CONTROL_DRILL_MAX_BACKUP_AGE_HOURS` | `48` | Oldest encrypted backup accepted by a restore drill |
| `OTTO_CONTROL_BACKUP_KEY_FILE` | empty | File containing the backup encryption key |

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
   `POST /v1/licenses/:licenseId/lease` every two minutes.
7. Configure `OTTO_TELEMETRY_ENDPOINT` on the private Otto server as
   `https://<control-host>/v1/telemetry/ingest`.

The control database stores License metadata, signatures, public keys, key
states, and a token version. It does not store private keys or plaintext
lease/telemetry tokens. Local private key paths must point to read-only secret
mounts. `PayloadSigner` is the provider boundary: a KMS/HSM adapter supplies the
same key ID, public key, and asynchronous signing operation without changing
the License or update-policy services.

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
self-approval, and is consumed once. Supported protected operation names are:

```text
license.revoke
signing_key.activate
signing_key.retire
signing_key.revoke
update_release.activate
update_release.rollback
```

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
POST /v1/admin-auth/bootstrap
POST /v1/admin-auth/enroll/confirm
POST /v1/admin-auth/login
POST /v1/admin-auth/logout
GET  /v1/admin-auth/me
GET  /v1/admin/accounts
POST /v1/admin/accounts
PUT  /v1/admin/accounts/:accountId/roles
PUT  /v1/admin/accounts/:accountId/status
GET  /v1/admin/roles
POST /v1/admin/approvals
GET  /v1/admin/approvals
POST /v1/admin/approvals/:approvalId/decide
POST /v1/admin/customers
POST /v1/admin/deployments
POST /v1/admin/licenses
GET  /v1/admin/licenses/:licenseId
POST /v1/admin/licenses/:licenseId/revoke
GET  /v1/admin/signing-key
GET  /v1/admin/signing-keys
POST /v1/admin/signing-keys/:keyId/activate
POST /v1/admin/signing-keys/:keyId/retire
POST /v1/admin/signing-keys/:keyId/revoke
GET  /v1/signing-keyring
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
       -> identity_admin (accounts, MFA, sessions, RBAC, dual control)
       -> customer_deployment (implemented foundation)
       -> license_authority (implemented foundation)
       -> signing_key_rotation (implemented foundation)
       -> lease_revocation (implemented foundation)
       -> telemetry_health (implemented foundation)
       -> update_policy (implemented foundation)
       -> audit
```

The Otto private server and desktop adapter now consume this signed policy and
map it onto the existing `latest.json` and incremental manifest engines. The
next phases are an operator-facing administration UI, off-site backup delivery,
managed KMS/HSM provider adapters, and eventually the separate federation gateway.

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
- Immutable release-artifact records binding distribution, release, source commit,
  platform, URL, size, and SHA-256 into independently signed Ed25519 envelopes
- Fail-closed activation and rollback gates requiring a signed installer plus every
  referenced manifest; artifact revocation atomically pauses an active release
- Audited activation, pause, and rollback to the previous release policy
- Per-customer integer credit accounts with separate available and frozen balances
- Immutable top-up, freeze, capture, release, consumption, and refund transactions
- Centrally controlled per-module rates; private deployments report units, not prices
- Request idempotency, original-charge refund limits, and automatic expired-hold release
- Organization/module statements plus UTF-8 CSV transaction exports
- Production Compose stack with isolated PostgreSQL, automatic HTTPS, persistent
  volumes, read-only control runtime, and file-mounted secrets
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
- Same-origin operator console with MFA login, RBAC-filtered commercial inventory,
  customer/deployment/License onboarding, renewal, seat management, immutable
  lifecycle history, dual-control review and execution, backup readiness, alert
  retry, strict CSP, and tab-scoped sessions

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
| `OTTO_CONTROL_VERSION` | `0.17.0` | Runtime version exposed by health APIs |
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
| `CONTROL_SIGNER_KEYRING_FILE` | empty | Version 1 local/KMS/HSM keyring manifest; mutually exclusive with the legacy single-key setting |
| `CONTROL_LEASE_DURATION_MS` | `600000` | Online lease lifetime; Otto refreshes every two minutes |
| `CONTROL_TELEMETRY_RETENTION_DAYS` | `90` | Central operational telemetry retention, from 1 to 3650 days |
| `CONTROL_UPDATE_POLICY_DURATION_MS` | `300000` | Signed update decision lifetime, from one minute to one hour |
| `CONTROL_BACKUP_RETENTION_DAYS` | `30` | Number of days encrypted local backups are retained |
| `CONTROL_BACKUP_REPORT_DIR` | empty | Read-only directory containing backup inventory reports |
| `CONTROL_BACKUP_STATUS_MAX_AGE_HOURS` | `48` | Maximum acceptable age of the latest completed backup report |
| `CONTROL_ALERT_WEBHOOK_URL` | empty | HTTPS endpoint receiving signed operational alerts; empty disables delivery |
| `CONTROL_ALERT_WEBHOOK_SECRET_FILE` | empty | Read-only file containing the webhook HMAC secret |
| `CONTROL_ALERT_POLL_INTERVAL_MS` | `60000` | Background outbox polling interval, from 5 seconds to 1 hour |
| `CONTROL_ALERT_WEBHOOK_TIMEOUT_MS` | `10000` | Per-delivery timeout, from 500 to 30000 milliseconds |
| `CONTROL_ALERT_WEBHOOK_MAX_ATTEMPTS` | `8` | Maximum delivery attempts before a terminal failure |
| `CONTROL_ALERT_RETENTION_DAYS` | `365` | Days to retain delivered and terminally failed alert records |
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

Credits are positive integers. PostgreSQL stores an account summary for fast
reads, but the immutable transaction ledger is the source of truth. Top-ups,
rate changes, and refunds are audited; the HTTP routes require RBAC permissions,
and financial mutations require request-bound second-administrator approval.

Configure each customer's module rate before enabling usage. `unitSize` defines
one billing unit and `creditsPerUnit` defines its integer price. Otto submits only
the deployment/organization binding, stable module ID, aggregate units, and an
opaque request reference. The control plane calculates the charge, so a customer
server cannot submit a lower price. Prompts, replies, chats, files, filenames, and
meeting content are not part of the billing protocol.

`POST /v1/billing/holds` freezes estimated credits before long work. Capture
settles the actual amount and immediately releases any remainder; explicit
release and automatic expiry both return unused credits. Direct usage calls and
every hold mutation require a customer-scoped idempotency key. Reusing that key
with different parameters fails with `409` instead of silently changing money.

Administrators can query the account, rates, transactions, and period statement
under `/v1/admin/billing/customers/:customerId/*`. The `export.csv` endpoint
includes balances, deltas, references, related refund transactions, and
idempotency keys for reconciliation. Refunds must reference a consume/capture
transaction, and cumulative refunds cannot exceed its billed amount.

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
server-supported approval operation.

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

### Remote KMS/HSM signing

The keyring manifest accepts `provider: "kms"` and `provider: "hsm"` entries.
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

The backend must support Ed25519 signing of the raw canonical message. A cloud
KMS that exposes only RSA/ECDSA or pre-hashed signing is not compatible with the
current Otto License contract; place a narrowly scoped Ed25519 HSM signer behind
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
4. Register every downloadable file with
   `POST /v1/admin/update-releases/:releaseId/artifacts`. At least one platform
   installer and signed artifact records matching every referenced manifest are
   required. Artifact metadata is immutable after signing.
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
POST /v1/admin/signing-keys/:keyId/activate
POST /v1/admin/signing-keys/:keyId/retire
POST /v1/admin/signing-keys/:keyId/revoke
GET  /v1/signing-keyring
GET  /v1/admin/deployments/:deploymentId/health?hours=24
GET  /v1/admin/backups/status?limit=20
GET  /v1/admin/alerts/deliveries?limit=50
POST /v1/admin/alerts/poll
POST /v1/admin/alerts/deliveries/:deliveryId/retry
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
       -> audit
```

The Otto private server and desktop adapter now consume this signed policy and
map it onto the existing `latest.json` and incremental manifest engines. The
next phases are multi-channel alert routing, vendor-specific signer-broker
deployment recipes, and eventually the separate federation gateway.

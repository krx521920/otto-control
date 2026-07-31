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

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `NODE_ENV` | `development` | `development`, `test`, or `production` |
| `CONTROL_HOST` | `127.0.0.1` | Listener address |
| `CONTROL_PORT` | `7788` | Listener port |
| `CONTROL_LOG_LEVEL` | `info` | Structured log level |
| `CONTROL_TRUST_PROXY` | `false` | Trust the configured edge proxy |
| `CONTROL_PUBLIC_BASE_URL` | empty | Public control-plane URL; HTTPS in production |
| `OTTO_CONTROL_VERSION` | `0.3.0` | Runtime version exposed by health APIs |
| `CONTROL_DATABASE_URL` | empty | PostgreSQL connection URL |
| `CONTROL_DATABASE_SSL` | production: `true` | Require verified TLS to PostgreSQL |
| `CONTROL_ADMIN_TOKEN` | empty | 32-byte minimum bearer token for `/v1/admin/*` |
| `CONTROL_TOKEN_SECRET` | empty | 32-byte minimum root secret used to derive scoped tokens |
| `CONTROL_SIGNER_PRIVATE_KEY_FILE` | empty | Read-only Ed25519 PKCS#8 secret mount |
| `CONTROL_LEASE_DURATION_MS` | `600000` | Online lease lifetime; Otto refreshes every two minutes |
| `CONTROL_TELEMETRY_RETENTION_DAYS` | `90` | Central operational telemetry retention, from 1 to 3650 days |

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
POST /v1/licenses/:licenseId/lease
POST /v1/telemetry/ingest
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
       -> update_policy
       -> audit
```

The next phase is update policy and signed release-channel management. A richer
operator dashboard and federation remain separate later phases.

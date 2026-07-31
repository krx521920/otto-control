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
| `OTTO_CONTROL_VERSION` | `0.1.0` | Runtime version exposed by health APIs |

## Planned module boundaries

```text
Traefik
  -> Otto Control Fastify edge
       -> identity_admin
       -> customer_deployment
       -> license_authority
       -> lease_revocation
       -> telemetry_health
       -> update_policy
       -> audit
```

License private keys must never be stored in the database or ordinary runtime
configuration. The License authority module will receive a signer interface so
production deployments can use an offline signer, KMS, or HSM.

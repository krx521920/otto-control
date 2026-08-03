# Otto commercial enforcement protocol v2

Version 2 adds a signed execution receipt to the existing License, lease, credit
hold, and settlement protocol. Its purpose is to make a billed task traceable to
a registered customer deployment without uploading the task's business content.

## Trust boundary

Each deployment creates an Ed25519 execution-receipt key. Control stores only
the public key. The first key may be bootstrapped by the deployment at
`POST /v1/billing/execution-receipt-keys/bootstrap`: the request is bound to the
online License, deployment ID, primary organization, machine fingerprint and
short lease, and must contain a fresh claim signed by the private key being
registered. Control permits only the first key or an idempotent replay of that
same active key. Replacing, rotating, or revoking a key still requires
`billing.manage` and request-bound approval from a second administrator. A
revoked key cannot be bootstrapped again.

This proves that a receipt came from the registered deployment key and that its
fields were not modified in transit. It does not prove that a customer with
root access ran unmodified Otto software. Hardware-backed keys, independent
model-provider reconciliation, or remote attestation are separate higher
assurance controls.

## Receipt contract

`execution_receipt_v2` contains exactly these fields:

```json
{
  "version": 2,
  "receiptId": "exec_0123456789abcdef0123456789abcdef",
  "deploymentId": "dep_customer_a",
  "organizationId": "org_customer_a",
  "taskId": "task_opaque_123",
  "moduleId": "model_gateway",
  "units": 1200,
  "model": "deepseek-v3",
  "issuedAtMs": 1785739200000,
  "expiresAtMs": 1785742800000,
  "sequence": 42,
  "policyVersion": "commercial-v2"
}
```

The canonical JSON payload is signed with Ed25519 and submitted to
`POST /v1/billing/execution-receipts` together with the License ID, machine
fingerprint, signing key ID, and lease bearer token. Unknown receipt or envelope
fields are rejected. Prompts, replies, chat messages, filenames, files, meeting
content, user names, and personal identifiers are not accepted by this schema.

A private deployment may host multiple customer organizations. All receipts
remain bound to the same licensed deployment and customer credit account, while
`organizationId` provides per-enterprise attribution for statements and cost
reports. It does not grant access to an organization's business data and is not
used as an authentication credential.

## Verification and settlement

Control validates the License binding, active deployment, short lease, receipt
validity window, registered key, Ed25519 signature, centrally configured rate,
and available credits. PostgreSQL then performs the following in one transaction:

1. Lock the customer credit account and deployment sequence.
2. Return the original result for a byte-equivalent receipt-ID replay.
3. Require the next contiguous sequence number.
4. Reject a second receipt for the same deployment and task ID.
5. Debit the centrally calculated amount.
6. Persist the receipt, credit transaction, and new sequence.

A sequence gap is not skipped. The deployment must retain a durable outbox and
retry missing receipts in order. This prevents a later receipt from hiding an
earlier billed task and makes disconnect recovery deterministic.

Production disables the legacy unsigned usage endpoint by default. It may be
temporarily re-enabled with `CONTROL_LEGACY_USAGE_REPORTS_ALLOWED=true` only
during a documented migration window.

## Disputes and refunds

Administrators can list or retrieve verified receipts under
`/v1/admin/billing/customers/:customerId/execution-receipts`. Every receipt is
linked to its credit transaction. Billing CSV exports include the receipt ID and
verification status. A refund references the original credit transaction and
inherits its receipt linkage, preserving the dispute trail without storing task
content.

The machine-readable contract is
[`otto-commercial-enforcement-v2.json`](./otto-commercial-enforcement-v2.json).

# Otto commercial enforcement protocol v1

This contract connects a customer-operated Otto server to Otto Control. It
governs server-side module authorization and credit admission; hiding a button
in the desktop UI is never an authorization decision.

## Signed policy

Control signs `billingEnforcement` and `billingHoldEndpoint` into an online
License. Existing and offline Licenses use `disabled`. An offline License
cannot request real-time enforcement because it cannot obtain a Control hold.

Otto verifies the Ed25519 License, deployment ID, organization ID, machine
fingerprint and short lease before executing a protected route. It then checks
the signed module entitlement and the selected organization's feature switch.

## Credit admission

A charged mutation must carry `x-otto-idempotency-key`. Otto asks Control to
freeze the centrally priced amount before mutating data. Insufficient balance
fails closed with `402 insufficient_credits`; an unavailable policy or Control
fails closed with a stable 503 code.

The hold is persisted in `billing_admission_outbox` before business execution.
A successful response captures it, while a failed response releases it.
Delivery is idempotent and retried after network or process failure. An
interrupted operation with no known outcome is conservatively released after
the 15-minute admission window.

## Evidence boundary

Control's credit transactions and signed License/lease records are authoritative.
Seat counts, health, and usage counters reported by a customer-controlled server
are marked `customer_server_reported`: useful for operations and anomaly
detection, but not cryptographic proof. A customer with root access can patch
their own process. Higher assurance requires independent metering, remote
attestation, or reconciliation against provider-side model and payment records.

The machine-readable contract is
[`otto-commercial-enforcement-v1.json`](./otto-commercial-enforcement-v1.json).
Its v1 SHA-256 fingerprint is
`af4217872dae276edae3101f211a8b7e685cc58356263ff025a938ced53d6ec5`.
Control and Otto validate this same immutable fingerprint in their own private
repository CI. This detects protocol drift without granting either repository's
workflow token access to the other private repository.

For production usage settlement, this contract is superseded by
[`otto-commercial-enforcement-v2.md`](./otto-commercial-enforcement-v2.md),
which adds registered Ed25519 execution-receipt keys, strict replay protection,
and receipt-linked billing evidence.

# Debugging

- `connect-configuration-mismatch`: required and executed immutable
  configuration differ; no credential or provider call is allowed.
- `connect-source-capacity-exceeded`: the exact amount exceeds the
  basis-point ceiling after provider-observed commitments and local holds.
- `connect-platform-balance-insufficient`: fresh platform available balance
  cannot cover the transfer plus local holds.
- `connect-transfer-outcome-unknown`: retain every reservation and reconcile
  using the workflow id; never retry create blindly.
- `connect-replay`: return the durable record without a second provider effect.

Inspect `/healthz`, `/readyz`, `/api/v1/scenario`, and the server-only
`receipts.ndjson`. Receipt data is sanitized and must never include credentials
or full provider payloads.

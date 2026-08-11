# Production integration recipe

1. Pin `@auths-dev/sdk`, its lockfile, and the exact runtime contract.
2. Choose identity method and signature suite adapters by exact identifier and
   version. Keep resolution network I/O outside deterministic verification.
3. Supply a custody adapter that never exports private keys and passes
   `custodyConformance`.
4. Compile typed trust and lifecycle snapshots through Rust. Export the
   resulting offline bundle for reproducible decisions.
5. Choose an approval policy explicitly, including `none` when the trusted
   authority commits to no approval. Threshold providers must return exact
   transaction-bound responses.
6. Use a maintained closed profile or qualify an application profile with
   semantic mutation tests.
7. Execute only a gateway-parsed, verifier-minted command through
   `ClosedRuntime`. Require one domain idempotency key and a durable
   compare-and-set store.
8. Reconcile `outcome-unknown`; never translate it to success or retry the
   effect blindly.
9. Export only the redacted telemetry schema. Keep proofs, signatures,
   credentials, application bodies, and high-cardinality data out of events.
10. Run packed-package, hostile-boundary, adapter, scenario, runtime-contract,
    and performance checks against the artifact that will ship.

The separate `@auths-dev/runtime-json-store` reference under `adapters/` proves
durable substitution for one Node.js process. It deliberately does not claim
multi-host coordination. Production services should implement the same state
port over an existing transactional database.

Auths does not claim remote exactly-once execution, atomic authorization plus
provider effect, instantaneous revocation, or current global state for an
offline decision.

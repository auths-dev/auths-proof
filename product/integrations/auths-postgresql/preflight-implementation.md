# PostgreSQL update-preflight implementation inventory

Status: implemented in the static local-agent runtime; live qualification is
still a separate release gate.

The concrete implementation is split deliberately:

- `src/local_agent.rs` owns the preflight action, exact authorization mapping,
  prepared-token binding, static lifecycle functions, and result projection;
- `src/local_provider.rs` owns read-only catalog/row discovery, connection
  destination equality, transaction rechecks, the fixed update, and ledger
  reconciliation;
- `src/prepared_store.rs` owns durable
  `reserved -> ready -> claimed -> consumed | expired` transitions and
  pre-entry release; and
- `tests/generated_profile_api.rs`, `tests/connection_conformance.rs`, and the
  crate unit tests cover canonical input, closed scopes, policy mutation,
  restart, expiry, and CAS behavior.

This inventory is not release evidence. Production qualification still
requires the live PostgreSQL contract in AP-SPEC-042 section 9, including
real TLS/database execution, crash boundaries, receipt verification, and
replay/recovery evidence on the release revision.

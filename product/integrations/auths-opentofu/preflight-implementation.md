# OpenTofu plan-preflight implementation inventory

Status: implemented in the static local-agent runtime; live qualification is
still a separate release gate.

The concrete implementation is split deliberately:

- `src/local_agent.rs` owns the preflight action, authorization mapping,
  prepared-token binding, static lifecycle functions, and result projection;
- `src/local_provider.rs` owns the isolated protected workspace, fixed planner
  and apply commands, state equality checks, bounded process/file handling,
  and provider observation;
- `src/prepared_store.rs` owns durable
  `reserved -> ready -> claimed -> consumed | expired` transitions and
  pre-entry release; and
- `tests/generated_profile_api.rs`, `tests/connection_conformance.rs`, and the
  crate unit tests cover canonical input, closed scopes, destructive-policy
  denial, artifact integrity, restart, and CAS behavior.

This inventory is not release evidence. Production qualification still
requires the live OpenTofu contract in AP-SPEC-043 section 9, including real
backend planning/apply, crash boundaries, receipt verification, and conclusive
recovery evidence on the release revision.

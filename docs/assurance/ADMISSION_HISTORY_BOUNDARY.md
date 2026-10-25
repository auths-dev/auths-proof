# Concurrent admission and captured-write boundary

Status: AP-SPEC-069 E3/E4 implementation work; final verification pending.
The new history scripts and backend regression below have not run. Only the
historical 917 claims at their original revision are qualified. This document
does not qualify the current source revision or the complete execution claim.

The shipping boundary is `GatewayAttempts::claim_bounded` in
`product/runtime/auths-gateway/src/store.rs`, followed by `Run::claim` and
`Run::send` in `product/runtime/auths-gateway/src/submit.rs`. A committed batch
and a received acknowledgement are different events. The latter may yield the
private execution handle; losing it cannot authorize another provider write.

| Property | Readable proof or source refinement | Executable evidence |
| --- | --- | --- |
| The same logical operation cannot acquire a second owner after later workers, crashes, recovery or collection | `AdmissionOwnership.lean`: `every_history_suffix_preserves_durable_claim`, `a_committed_lost_ack_never_mints_a_later_handle` | Existing `conformance_lost_acknowledgements` and the claim/restart submission regressions |
| A lost acknowledgement cannot make the same operation charge another chain, value or counter arrangement after any finite suffix | `BoundedClaimHistory.lean`: `lost_acknowledgement_cannot_recharge_after_any_suffix`, `acknowledgement_does_not_change_aggregate_charge` | New `conformance_lost_batch_acknowledgement_retains_capacity` |
| A fixed-window collection fence survives every later history, including arrivals with older clock facts | `BoundedClaimHistory.lean`: `every_suffix_after_collection_preserves_capacity`, `collection_cannot_reopen_under_any_later_history` | Existing collection/fence/process-race cases and the new lost-batch-acknowledgement case |
| The permit history preserves the identical first command, evaluation time and selected requirements | `ClaimedInputRefinement.lean`: `capture_permit_history_exact_input`, `capture_permit_first_send_is_useful`; composes actual translated capture/empty/arm/consume functions | Existing claimed-command, deadline, missing-resource, cancellation and request-substitution regressions in `submit_permit_tests.rs` |

The new backend case is called by the shared `store_conformance` suite, so both
`file_store_passes_attempt_store_conformance` and
`postgres_store_passes_attempt_store_conformance` include it. It faults the
acknowledgement **after the real backend commits** a claim/count/sum batch,
opens another backend instance over the same durable state, and checks exact
retained bytes. Four retries propose different slot keys with the same claim;
none may insert a partial batch. Collection then removes the expired slots
while retaining the claim. An older collection sample cannot lower the fence,
and a fresh claim paired with old-window slots is refused atomically.

That raw-store case exercises the persistence mechanism. It does not mint a
private execution handle, decode a valid attempt record, or prove actual
counter derivation. The existing driver case separately checks that a lost
claim acknowledgement grants no lease/write permission, and that recovery is
read-only. Neither finite test replaces an arbitrary-history theorem.

## Remaining composition obligations

The reference histories still need a source-backed transition relation from
actual prepared counter batches and backend linearization to their abstract
charges, owners and fences. This must retain count/sum key framing, all policy
links, duplicate-counter aggregation, frontier search, checked arithmetic,
conflict retries, terminal refusals and complete atomic claim/slot membership.
Pre-commit failure must remain distinct from commit followed by lost
acknowledgement. A successful load or a supplied Boolean is not proof of a
winning durable acknowledgement.

The capture/permit refinement calls the translated shipping leaves, but its
resource flags do not establish claim identity, backend atomicity, connection
or credential generations, qualification, deadline samples or physical HTTP
entry. Compose those facts from the actual private handle and leased transport;
retain the exact request and its original authorization witness through every
await. See `GATEWAY_TRANSPORT_BOUNDARY.md` for the final transport contract.

Final evidence must include Lean elaboration and transitive axiom checks,
source/backend correspondence, both backend suites, required fault/mutation
campaigns, two independent clean translation reproductions, and hosted gates
on the exact release revision. The new public history scripts are registered
in `Auths.Theorems` for that final audit, without adding qualified claims to
the assurance manifest before their evidence exists.

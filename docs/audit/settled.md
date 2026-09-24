# Settled findings

Findings a pass has already decided. Reviewers read this before reporting.
Don't raise an entry again unless its "re-raise if" condition holds, and then
say which condition changed.

Each entry gives the claim as reviewers phrase it, the decision (rejected, or
documented limit), why, where it is documented, and when to raise it again.

## Kernel

### K-of-N counts proof references, not independent signers
- **Decision:** documented limit, by design.
- **Why:** the proof-carried plan is not the policy. Independent signers and roots come from the verifier context's `CompositionRequirement` (`minimum_distinct_actors`, `minimum_distinct_roots`).
- **Documented:** `core/spec/v1/protocol.md`, "Authorization plan": distinct proof references alone never imply independent signers or roots.
- **Re-raise if:** a context that needs independent signers doesn't set the minimums, or the spec changes.
- **Pass:** 2026-09-23, item 3.

### Count distinct verification keys instead of principals
- **Decision:** rejected.
- **Why:** OIDC-workload and Sigstore-keyless principals use a new key for each signature, so counting keys would count one signer many times.
- **Documented:** `docs/specs/0045-oidc-workload-principal-adapter.md`, `docs/specs/0046-sigstore-keyless-evidence-adapter.md`.
- **Re-raise if:** never in this form. The narrow case of one key under two methods (`did:key` and raw key) is still open; report it as principal aliasing.
- **Pass:** 2026-09-23, item 3.

### Author-side and verifier-side extension rules differ
- **Decision:** rejected.
- **Why:** the two rules applied to different edges. Both required equal extensions from grant to grant, and the author side had no check on the anchor's first grant. Per-extension attenuation (AP-SPEC-060 §17, merged in #141) has since replaced both.
- **Re-raise if:** a test shows the author accepting a child that the verifier rejects, or the reverse, on the same edge.
- **Pass:** 2026-09-23, item 15.

## Gateway and evidence

### Anyone with write access can copy or plant an echo token
- **Decision:** documented limit.
- **Why:** the echo is an unkeyed hash. It shows that a record is consistent with the action, not who wrote it.
- **Documented:** `docs/specs/0059-commitment-bound-provider-evidence.md` (the token is not a signature); `docs/product/SELF_HOSTED_CLAIM_LEDGER.md`; `product/runtime/auths-gateway/src/recipe.rs` ("a link, not a signature").
- **Re-raise if:** a doc or claim says the echo proves who wrote the record.
- **Pass:** 2026-09-23, item 21.

### Gateway observations are signed by the gateway's own key
- **Decision:** documented limit.
- **Why:** observer trust is operator trust. "Without trusting the gateway" holds only for an auditor who re-reads the provider record with their own credentials.
- **Documented:** `product/runtime/auths-gateway/src/observer.rs`; `docs/specs/0059-commitment-bound-provider-evidence.md`; `docs/specs/0060-evidence-conditioned-authority.md`; the claim ledger.
- **Re-raise if:** a claim drops that qualification.
- **Pass:** 2026-09-23, item 21.

### Gateway writes aren't conditional on the record being unchanged
- **Decision:** documented limit.
- **Why:** observation requirements are checked at verification time. The window, up to `max_age_seconds`, is by design, and a conditional write is left to each profile.
- **Documented:** `docs/specs/0060-evidence-conditioned-authority.md`; the claim ledger; the test `replaced_in_between_is_authorized_inside_the_documented_window` in `product/runtime/auths-gateway/src/observed_tests.rs`.
- **Re-raise if:** a claim says the write is conditional, or a profile promises a conditional write and doesn't use one.
- **Pass:** 2026-09-23, item 8.

### Stripe metadata doesn't carry an action-derived echo
- **Decision:** documented limit (scope).
- **Why:** AP-SPEC-059 limits the echo to gateway recipes and leaves Stripe out. The Stripe idempotency key is already derived from the action, and an unkeyed echo wouldn't stop anyone holding a Stripe API key.
- **Documented:** `docs/specs/0059-commitment-bound-provider-evidence.md`, non-goals.
- **Re-raise if:** a Stripe spec adopts an echo, or a claim says Stripe records carry one.
- **Pass:** 2026-09-23, item 4.

## Runtime and stores

### The journal, gateway store and lifecycle store are single-host
- **Decision:** documented limit.
- **Why:** single-host is the development default. Multi-host reuses the PostgreSQL lifecycle store under AP-SPEC-038 §9, which is on the board's queue.
- **Documented:** `docs/PROGRAM_BOARD.md` §3–§5; `docs/specs/0038-production-runtime-custody-observability-and-assurance.md` §9; `product/runtime/auths-gateway/src/store.rs` ("not a multi-host claim store"); `product/stores/auths-stores/src/operation.rs` ("Single-process").
- **Re-raise if:** a claim says multi-host. Blocking I/O inside async code is a separate finding, still open.
- **Pass:** 2026-09-23, item 9.

### The PostgreSQL lifecycle store takes one global lock and reloads every record
- **Decision:** documented limit.
- **Why:** capacity is computed across all records, and the design keeps the singleton lock until a measurement shows it is the bottleneck.
- **Documented:** `docs/specs/0038/epic_2.md` ("Do not replace it … until measurements prove it is the bottleneck"); `docs/PROGRAM_BOARD.md` §4, 2026-09-21.
- **Re-raise if:** a measurement shows the lock is the bottleneck.
- **Pass:** 2026-09-23, item 10.

## Docs and inventories

### `stripe-profiles.toml` is stale because only two profiles are `implemented`
- **Decision:** rejected.
- **Why:** `specified` is deliberate. Promotion needs the plan's gate, which includes a public deployment, and each demo's release evidence says why it isn't met yet.
- **Documented:** `docs/target-state/STRIPE_PROFILE_FAMILY_IMPLEMENTATION_PLAN.md`.
- **Re-raise if:** a profile meets the gate and isn't promoted. The file's real gap, the missing `exact-refund` entry, is tracked in the 2026-09-23 pass.
- **Pass:** 2026-09-23, item 18.

### Stripe coverage is overstated ("every Stripe action")
- **Decision:** rejected.
- **Why:** no such claim was found in the repository. Stripe profiles are hand-built, not derived from OpenAPI.
- **Re-raise if:** a doc states Stripe coverage without a measured figure, or says the profiles are generated.
- **Pass:** 2026-09-23, item 19.

### Airtable and Todoist exist only as fixtures
- **Decision:** rejected.
- **Why:** the live runs are recorded in the claim ledger, and its wording is already qualified ("It is not a provider qualification").
- **Documented:** `docs/product/SELF_HOSTED_CLAIM_LEDGER.md`.
- **Re-raise if:** a doc calls them supported or qualified without that qualification.
- **Pass:** 2026-09-23, item 20.

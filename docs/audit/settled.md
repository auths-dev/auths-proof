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
- **Why:** OIDC-workload and Sigstore-keyless principals use a new key for each signature, so counting keys would count one signer many times. `did:keri` keys rotate.
- **Documented:** `docs/specs/0045-oidc-workload-principal-adapter.md`, `docs/specs/0046-sigstore-keyless-evidence-adapter.md`.
- **Re-raise if:** never in this form. The narrow case of one key under two methods (`did:key` and raw key) is open (review pass 2026-09-24, package 2.7). Until it lands, `docs/product/APPROVAL_QUORUM.md` and the threat model say to anchor each member's key under one method (#163). It affects distinct-actor and distinct-root counts, the observer-in-authority-chain rule and the gateway's separation codes; report new consequences there.
- **Pass:** 2026-09-23, item 3; 2026-09-24, items 04-7, 04-n3, 06-n2, 06-3.

### Author-side and verifier-side extension rules differ
- **Decision:** rejected.
- **Why:** the two rules applied to different edges. Both required equal extensions from grant to grant, and the author side had no check on the anchor's first grant. Per-extension attenuation (AP-SPEC-060 §17, merged in #141) has since replaced both.
- **Re-raise if:** a test shows the author accepting a child that the verifier rejects, or the reverse, on the same edge.
- **Pass:** 2026-09-23, item 15.

### Unmet composition minimums return Denied even when indeterminate leaves could meet them
- **Decision:** documented limit, by design.
- **Why:** AP-SPEC-001 §5.4 makes a failed local floor `Denied(CompositionRequirementNotMet)`, not `Indeterminate`, and `error-codes.md` defines the code over authorized branches. The result never authorizes; only the verdict class and the retry hint are in question. Rust, Go and TS agree. §5.4's reason ("the verifier possesses all relevant branch results") fails when a leaf is indeterminate; #163 corrects that sentence.
- **Documented:** `docs/specs/0001-formal-attenuation-and-composition.md` §5.4; `core/spec/v1/error-codes.md`.
- **Re-raise if:** §5.4 or `error-codes.md` changes, or a doc tells hosts this denial cannot change after new trusted facts.
- **Pass:** 2026-09-24, item 01-4.

### Run the extension handler before the attenuation law, so a malformed child payload reports the handler's code
- **Decision:** rejected.
- **Why:** a handler failure inside a law is a refusal (AP-SPEC-060 §18 reading 1; `registry.md`: any law failure is `delegation-expanded`). Running the handler first would also turn the vector `critical-extension-marker-changed` from `delegation-expanded` into `local-policy-denied`. The real gap, that `registry.md` doesn't say a malformed or over-limit child payload is `observation-requirement-dropped` when the parent has requirements, is fixed in #167.
- **Documented:** `core/spec/v1/registry.md`; `docs/specs/0060-evidence-conditioned-authority.md` §18.
- **Re-raise if:** the author and the verifier refuse different edges, or §18 reading 1 changes.
- **Pass:** 2026-09-24, item 01-3.

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

### The offline audit reports `verified` for a refund the provider rejected
- **Decision:** rejected as a change to the verdict; the missing provider status is tracked.
- **Why:** `verified` means authorized and entered (`audit.rs`). Making it depend on a 2xx would merge authorization and provider acceptance into one verdict, which the boundary plan's UX contract forbids. The gap is that the signed outcome and the audit omit the recorded HTTP status; it is open (review pass 2026-09-24, board §3).
- **Documented:** `product/runtime/auths-gateway/src/audit.rs`; `docs/target-state/PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md`, "UX contract".
- **Re-raise if:** a doc says `verified` means Stripe accepted or settled the refund, or the audit still omits the status after that work closes.
- **Pass:** 2026-09-24, item 03-2.

### Gateway window counts are per actor and per fixed UTC window, not rolling
- **Decision:** documented limit.
- **Why:** 0025 §25 readings 5 and 7 key the count to the action's actor and use `floor(now / window)` at the gateway clock; only the terminal policy reserves a slot. No rolling or aggregate claim is made. The missing non-claim, that a parent's count doesn't bound its delegates in aggregate, is open (review pass 2026-09-24, board §3). The north-star agent cannot delegate (remaining depth 0).
- **Documented:** `docs/specs/0025-closed-bounded-authorization-policy.md` §25; `product/runtime/auths-gateway/src/bounds.rs`; `docs/product/SELF_HOSTED_CLAIM_LEDGER.md`.
- **Re-raise if:** a doc claims a rolling window or an aggregate bound across delegates, or a north-star agent gets a remaining depth above 0.
- **Pass:** 2026-09-24, item 06-2.

### Stripe metadata doesn't carry an action-derived echo
- **Decision:** documented limit (scope).
- **Why:** AP-SPEC-059 limits the echo to gateway recipes with a JSON body and an observation, and leaves the `auths-stripe` vertical out. There the Stripe idempotency key is already derived from the action, and an unkeyed echo wouldn't stop anyone holding a Stripe API key. The gateway's Stripe recipe (the north-star journey) has a form body and no observation, so it can't carry an echo. Beyond the gateway's claim, its only de-duplication is the derived `Idempotency-Key` from #146, which protects re-entry of the same operation, not a retry under a new operation ID.
- **Documented:** `docs/specs/0059-commitment-bound-provider-evidence.md`, non-goals; `docs/specs/0053-declarative-credential-isolated-gateway.md` §3.2.1 (from #146); `examples/stripe-refund-approval/README.md`, non-claims.
- **Re-raise if:** a Stripe spec adopts an echo, a claim says Stripe records carry one, or a claim says the gateway key stops a retry under a new operation ID.
- **Pass:** 2026-09-23, item 4; 2026-09-24, item 06-4.

## Runtime and stores

### The journal, the file stores and connection state are single-host
- **Decision:** documented limit.
- **Why:** single-host is the development default. Gateway attempts, evidence, outcome stages and window-count slots are multi-host on the PostgreSQL store (two-process conformance in `postgres-lifecycle.yml`), but that store's qualification (0038 Epic 2) is open, so it is not "qualified". The file attempt store, the journal, and the connection and credential stores stay single-host; each gateway process keeps its own copy of connection state, which AP-SPEC-038 §9's done gate covers.
- **Documented:** `docs/PROGRAM_BOARD.md` §3–§5; `docs/specs/0038-production-runtime-custody-observability-and-assurance.md` §9.5; `product/runtime/auths-gateway/src/store.rs`; `product/stores/auths-stores/src/operation.rs` ("Single-process").
- **Re-raise if:** a claim says qualified or production multi-host before 0038 Epic 2 closes, or says an admin change reaches every gateway process before §9's done gate holds. Blocking I/O inside async code is a separate open finding (review pass 2026-09-24, board §3).
- **Pass:** 2026-09-23, item 9; 2026-09-24, items 06-6, 02-6, 02-4.

### Same-UID processes satisfy the executable-hash and cgroup selectors
- **Decision:** documented limit.
- **Why:** AP-SPEC-040 §7.2.1 makes executable hashes and cgroup selectors defense in depth that can't be the sole discriminator; isolation needs distinct OS identities. Exec and descriptor hand-off by the same UID defeat them. The overclaim (evidence "bound to the accepted peer") and the cgroup parse bug are open (review pass 2026-09-24, package 2.4).
- **Documented:** `docs/specs/0040-generic-profile-sdk-and-contributor-system.md` §7.2.1.
- **Re-raise if:** a doc treats these selectors as the sole discriminator, or a layout relies on them without distinct OS identities.
- **Pass:** 2026-09-24, item 04-5.

### The production local agent can't run a provider effect
- **Decision:** documented limit, by design until qualification.
- **Why:** every built-in effect profile is `unqualified` in `product/runtime/auths-node/src/generated/profile_launch_projection.json`, and the production flavor serves only qualified profiles. Findings in the local-agent effect path are latent until a profile qualifies; they are not rejected.
- **Documented:** `docs/product/PRODUCTION_SDK_QUICKSTART.md`; `docs/product/LOCAL_AGENT_SDK_QUICKSTART.md`; `product/runtime/auths-node/src/profile_launch.rs`.
- **Re-raise if:** a profile is marked qualified without its live, crash, recovery, receipt and independent-review gates, or a doc says the production agent performs provider effects today.
- **Pass:** 2026-09-24, item 05-4.

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
- **Re-raise if:** a profile meets the gate and isn't promoted. The opposite case, a profile marked `implemented` without its gateway (0023), is a separate finding, and so is the missing `exact-refund` entry; both are fixed in #163.
- **Pass:** 2026-09-23, item 18; 2026-09-24, item 03-4.

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

### Provider clients should pin DNS like the gateway
- **Decision:** rejected.
- **Why:** for fixed provider hosts such as `api.stripe.com`, TLS certificate validation already binds the host, so a DNS pin adds little. reqwest drops `Authorization` on cross-host redirects, so only same-host redirects matter. The adopted fix is no proxy, no redirects and explicit timeouts (#160).
- **Re-raise if:** a provider client connects to a host taken from operator or runtime input, or skips TLS validation.
- **Pass:** 2026-09-24, item 03-8.

# AP074 assurance boundary and evidence map

This maps AP074 §9's six conditional properties to shipping source and required
runtime evidence. It is a producer/assumption map, not an execution receipt or a
whole-system proof. Every final claim still needs the corresponding exact-source
hosted artifacts. The acceptance ledger records that execution separately.

## Pure proof surface and runtime obligations

| Property | Shipping predicates and native owner | Evidence outside the pure proof |
| --- | --- | --- |
| Authority preservation | `effect::ApprovedEffect::validate_for_entry` recompiles the original native proof/action and compares the complete binding. `entry::EntryValidation::validate` reads connection/configuration dependencies and samples current time under the adapter fence before invoking it. `auths_gateway_kernel::order::next_step` orders the abstract validation/reservation/grant/send events. | Native signatures, trust installation, exact approval and clock authenticity are runtime obligations. Native dependency, mutation-entry and disclosure-entry corpora exercise independent authority/approval/observation expiry, changed threshold selection and withdrawal on both stores. Boolean ordering premises alone do not prove cryptographic authority. |
| Effect preservation | `auths_gateway_kernel::construct::{construct_write,construct_action_read,construct_credential_read}` implement the pure closed request leaves. `effect::BoundEffect` retains sealed native authority, the immutable binding and compiler result. `transition::valid_transition` requires unchanged fixed bytes and protocol/plan. | Reviewed recipe meaning, canonical codec correctness and credential insertion are explicit boundaries. The native effect/review corpus, two-recipe independent differential and installed owner journey compare the actual request against the exact approved review. TLS/provider behavior remains external. |
| Single-grant safety | `transition::{stage_transition_allowed,entry_kept,valid_transition}` permit an entry addition only at the reservation-to-grant edge and retain it afterward. `order::next_step` reaches send only after the new grant acknowledgement. Native mutation/acquisition/disclosure grant methods return consumed permits only after successful fenced persistence. | File/PostgreSQL atomicity and truthful durability acknowledgement are assumptions checked by independent-process races, process crashes, file failures, partial SQL batches and real lost COMMIT replies. Generated concurrent native histories add an independent set-of-entered-operations oracle. No persisted byte string recreates a permit. |
| Capacity conservation | Native `store::{reserve_with_claim,frontier,cumulative}` and the typed acquisition/disclosure allocation paths own reservations in the same admission batch. Final entry validates retained counters/allocation rather than charging again. Kernel transition fixed-byte equality preserves admitted charge facts. | Arithmetic/policy predicates do not prove database atomicity or actual occupancy. Native lifetime/fixed-window count and sum races, restart/retention and fault corpora check actual permanent/window rows on both adapters. Unknown stays charged; elapsed time, absent evidence or administrative annotation supplies no refund fact. |
| Revocation ordering | `entry::EntryValidation::validate`, `connection` validation and `configuration::SharedConfiguration::entry_snapshot` use snapshots held under the same fence as the final attempt replacement. Connection/configuration writers participate in that fence. | File `flock` is single-host; PostgreSQL uses the maintained transaction/advisory-lock contract across hosts. Native worker/operator schedules order withdrawal before versus after grants for mutation, acquisition and disclosure, including waits and physically distinct dependency records. Earlier committed grants retain their documented semantics. |
| Evidence soundness | `transition::{protocol_consistent,response_kept,acknowledgement_kept,valid_transition}` keep distinct protocol facts and immutable evidence. Native recipient authentication/ACK validation and recovery evidence-link validation establish the facts before projection. `observer` separates signed public history from full private audit; the auditor rechecks complete facts. | Signatures, recipient/channel/source binding, bounded HTTP evidence and provider linkage are not proved by nonempty model byte fields. Real recipient ACK substitution/loss, independent recovery, privacy and installed-interface tests supply that evidence. State equality, a response, an ACK and declared provider linkage remain distinct claims. |

The native adapters call the shared `store::valid_transition`, which invokes the
translated `auths_gateway_kernel::transition::valid_transition` over both typed
record projections **and** validates the complete new protocol record. The model
does not replace canonical record validation or reinterpret provider fields.

## Formal source link

The authoritative extraction inventory is
[`qualification.toml`](../../formal/qualification/aeneas/qualification.toml).
It names the actual shipping gateway-kernel files and selected functions,
including construction, submission order, transition/presence, recovery and
ratio leaves. The qualification reproduces translation twice under pinned
Charon/Aeneas toolchains. Generated Lean files and
[`Gateway.lean`](../../formal/qualification/aeneas/cases/Gateway.lean) feed the
reviewed refinement claims in
[`assurance-manifest-v1.toml`](../../formal/assurance-manifest-v1.toml).

The compiled assurance audit checks statement identities and transitive axioms;
Kani's record-table harness checks bounded representations, including every
protocol/stage pair and illegal edge under its byte bounds. Sequential generated
file-store properties and actual durable process histories complement this pure
surface. The existing formal mutation inventory includes gateway translations in
campaign s3. Its source freshness and adequacy must pass the existing release
gate; its presence in the repository is not a fresh execution result.

Codecs, cryptography, full verifier control flow, store implementation, clocks,
networking, recipient behavior and provider behavior remain outside the pure
gateway proof. Full API/record validation, current native authority and concrete
adapter/transport evidence are mandatory premises, never optional exclusions
that waive an AP074 security invariant.

## Operational limits of the claims

File durability assumes acknowledged sync/rename and private storage on one
trusted host. PostgreSQL durability assumes the maintained TLS/isolation/commit
configuration and participating writers. Both require current epoch/configuration
and declared retention/rollback floors. A malicious operator, malicious host,
unsupported whole-store rollback and independent external provider writers are
not prevented by Rust types or these tests.

The installed Linux inventory checks the actual unprivileged app account against
managed sockets, credentials, private files and every application/CLI route.
AP070 remains a separately application-owned reference with its own narrower
claims. It cannot receive managed grants, permits or credentials or supply a
second decision for the same managed operation. Its receipts are not native
entry, recovery or qualified execution evidence.

The [cost evidence](0074-native-cost-evidence.md) and
[generated concurrent histories](0074-generated-histories.md) describe additional
producers and their limitations. Neither a producer definition nor a successful
artifact constructor closes A01–A22; final exact-revision verification remains
required.

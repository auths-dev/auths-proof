# AP073 assurance boundaries and final acceptance map

Status: implementation closure audit. Exact-head hosted results remain pending.
This map distinguishes actual source-linked formal claims from product tests and
trusted deployment assumptions. It does not assert end-to-end formal verification.

## Formal claims actually consumed

| Property | Shipping source and checked relationship | Product boundary and evidence |
| --- | --- | --- |
| Native grant attenuation and composition | `core/crates/auths-authority/src/lib.rs` and `core/crates/auths-model/src/lib.rs`; `formal/Auths/Refinement/Production.lean::translated_delegation_refines_rich_spec` | `participant_enrollment.rs::native_invocation_for_audience` calls the maintained native verifier. Parent authorization, child acceptance, resource suffix and exact root checks are additional product checks, exercised by signed native enrollment/federation/installed corpora. The core theorem does not prove that product glue. |
| Exact closed request construction | `CompiledRecipe::closed_request` calls `auths_gateway_kernel::construct::construct_write`; `formal/Auths/Product/Refinement/Gateway.lean::translated_construct_write_refines_model` | Native compiled effect and approval bind verified command, recipe/connection/configuration, scope and planned charges. Native substitution/review corpora plus real HTTP histories check the composition. The compiler/profile-to-plan mapping and provider interpretation remain explicit premises. |
| No counter overflow or ceiling bypass | Existing ordinary gateway capacity calls `auths_bounded_policy::kernel::chain_sums_admit`; `formal/Auths/Product/Refinement.lean::translated_chain_sums_admit_refines_model` and `translated_checked_add_refines_nat` | Ancestor reservation row arithmetic now directly calls the same sum guard and checked-add primitive with the retained prefix total, exact amount and immutable ceiling. The lifecycle additive theorem is not cited as if it covered this allocator. Prefix integrity, immutable ceilings, faithful counter identity and atomic insertion remain store/product premises. |
| Credential/provider order | `submit.rs` drives `auths_gateway_kernel::order::start/next_step`; translated start/next-step refinement theorems in the gateway refinement module | Current authority/approval/configuration and engagement checks feed the existing final entry fence. File/PostgreSQL and installed revocation/crash histories establish operational ordering under adapter assumptions. A theorem about step enums alone is not proof of filesystem, SQL or provider behavior. |
| Replay and conservative Unknown | `store.rs::valid_transition` calls `auths_gateway_kernel::transition::valid_transition`; `translated_valid_transition_refines_model` | Native mutation/acquisition/disclosure records, permanent allocations and acknowledgement-before-permit checks remain the execution owner. Source-specific recovery is a separate currently authorized acquisition. Installed response/ACK loss, crash, late acknowledgement and no-reentry cases exercise real entry paths. |
| Truthful record claims | Existing gateway-kernel outcome/transition Kani harnesses, inventoried by `xtask/src/formal.rs` | Public history/private audit distinguish signed intent, admission, possible entry, provider response, observed linkage and unknown. Signatures do not establish human presence, provider truth, timestamp truth or current eligibility. |

All referenced translated source/model claims must pass the authoritative hosted
formal cohort for the eventual head. Existing base results are historical evidence,
not a substitute for that gate. No new model-only theorem or coverage-percentage
target is introduced to describe unproved product code as mechanically verified.

## Product relations without an end-to-end theorem

Enrollment tree validation, retained successor links and `capacity_origin`, scope
selection, actor/recipient path union, evidence-to-store dependency construction,
private/public projection, and backend transaction/fence implementations are
security-critical product code. Their native signed/malformed/boundary/property/
process/fault evidence is required. Existing core or counter theorems do not
mechanically refine these entire functions. In particular, counter conservation
assumes the faithfully derived immutable origin, and source lifetime accounting
assumes complete append-only prefixes and no unauthorized rollback.

The first lifecycle corpus exercises full native proofs at every accepted prefix
up to the actual sixteen-node bound, old holder/descendant refusal, fresh resource
suffixes, malformed decoding, immutable ceilings and generation endpoints. Actual
file histories preserve old reservations and Unknown across two recoveries and
lost publication replies; the installed case combines recovery with created-child
history. These are shipping-code evidence, not universal symbolic proofs.

The assurance contract retains these product relations as reviewed/tested trusted
glue and records them for independent review. It makes no unconditional theorem
of global non-resurrection, distributed storage honesty or provider causation.
Any stronger formal claim requires a justified refinement of those additional
relations; it cannot be obtained by citing the existing leaves again.

## Current acceptance sources

The dated ledger contains construction results and failed/repaired cohorts.
The following owner map replaces the old baseline table as a work selector;
reimplementing an already covered owner is not remaining work.

| Scenarios | Current evidence owner | Final required gate |
| --- | --- | --- |
| F01, F02, F06 | Native enrollment/effect/review/approval, mixed-method federation, malformed/oversized/boundary and property cases | Exact-head core/product/native test and applicable formal cohort |
| F03, F04, F05 | Scope/source/recipient isolation, permanent ancestor allocation, real cross-recipe/federation sibling races and replay | File plus configured TLS PostgreSQL, installed transport and package gates |
| F07 | Native explicit-time enforcement and corrected WebAuthn claim lifetime; expiry/lock-wait histories | Exact-head native/binding tests; no human-presence claim from scripted keys |
| F08, F09, F11 | Real disclosure receipt/ACK loss, late ACK, gateway process crashes, file faults, ambiguous commits and current shared writer fences | Exact-head configured PostgreSQL and source-free installed Linux evidence |
| F10 | Independent bounded created-resource projection oracle, original acquisition provenance, native admission/final fences and installed zero/multiple/incomplete/unique scenarios | Native corpus/oracle agreement, source-free installed scenario and PG counterpart |
| F12 | Commissioned successor lifecycle and retained capacity, native old descendants and private original audit | Native/file/PG plus installed recovery and explicit supported/unsupported lifecycle contract |
| F13, F14 | Fresh process-held owner/machine/A/B/reviewer keys, installed Python/npm/WASM, credential/files/memory/egress probes and canonical Rust-owned transport | Exact-head rebuilt source-free package, separate Linux UIDs, installed/public API and packaging checks |
| F15 | Configuration/generation dependencies, epoch separation, retained replay, independent-checkpoint audit and native malformed histories | Explicit restore protocol and stale-prefix check; external authenticated floor remains a deployment premise |
| F16 | Complete native private review, redacted public timeline, truthful Unknown/reconciliation and original control audit | Exact-head private/public conformance and packaged interface evidence |

The native records composition exercises the existing records service and sealed
store behind the protected dispatch credential. Domain proof/presentation and
AP073 participant authority remain distinct required facts. Native records policy
is provider-side state, not a second task journal. The resource's raw-key grant
expiry/revocation contract is not silently replaced by engagement withdrawal.

## Supported restore and topology assumptions

One protected authority store owns a root's native configuration and permanent
allocations. File mode is one coordinated host; multi-host mode uses the shared
TLS PostgreSQL adapter. Disconnected escrow, independently cloned admission stores,
automatic root recovery and automatic trust rollover are unsupported.

Restoring a complete self-consistent old store cannot authenticate its own
freshness. The trusted operator must retain an independently authenticated
checkpoint/floor, verify the restored private audit against that head and trusted
root/contexts, and keep the service quarantined when it does not match. Existing
`engagement-audit-verify` performs the evidence comparison; it does not create its
own trusted head or prove the operator followed the deployment protocol. A
missing/untrusted head is an explicit inability to establish safe restoration.
Do not describe audit rejection as a cryptographic whole-store rollback detector.

## Engineering closure and remaining acceptance

1. Native-records artifact construction is complete for the local boundary: all
   eight installed scenarios passed. Exact-head source-free Linux evidence remains
   a hosted gate.
2. The exact-source sum-guard reuse and reverse stale-prefix/current-checkpoint
   case passed their twelve affected artifact constructors, including all eight
   installed scenarios. Zero-byte arithmetic semantics and existing store/fence
   checks are preserved; configured PostgreSQL and broader acceptance remain hosted.
3. Required changed identities/inventories/fixtures and source-linked formal
   metadata are constructed. Publish the complete implementation, then run and inspect
   the authoritative exact-head hosted CI, formal, PG, binding, source-free package
   and release checks. Repair actual failures in a bounded collected cohort.

This map is not a passing result for any unrun gate. The goal remains active until
the complete supported contract and required exact-head evidence are established.

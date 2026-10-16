# AP-SPEC-069: Formal assurance from authorization to execution

- **Status:** Implementation in progress; resumed on 16 October 2026 after
  the owner's checkpoint pause. E1–E5 and M6 remain incomplete. See §13 for
  the saved checkpoint, evidence limits, and next implementation slice. This
  document does not itself add a proved claim.
- **Source baseline:** `3e01401fb5aa3fc9433da44bcdaa82ecc7214f1c`.
- **Purpose:** strengthen the claim that a person or agent can perform useful,
  narrowly authorized work without receiving the provider credential. Cover
  the five remaining assurance boundaries identified in the source review:
  canonical decoding, complete verification, authorized request construction,
  concurrent durable admission, and cryptographic integration.
- **Depends on:** [AP-SPEC-011](0011-rich-authority-refinement-and-bounded-authorization.md),
  [ADR 0011](../adr/0011-rich-authority-rust-lean-link.md),
  [AP-SPEC-026](0026-reservation-and-execution-state-semantics.md),
  [AP-SPEC-053](0053-declarative-credential-isolated-gateway.md),
  [AP-SPEC-060](0060-evidence-conditioned-authority.md),
  [AP-SPEC-061](0061-end-to-end-machine-checked-verifier.md),
  [AP-SPEC-063](0063-generalized-gateway.md),
  [AP-SPEC-064](0064-status-issuer-scope.md),
  [AP-SPEC-065](0065-native-k-of-n-approvals.md), and
  [AP-SPEC-066](0066-production-gateway-polish-and-recipe-qualification.md).
- **Governing boundary:** [profile and domain abstraction plan](../target-state/PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md).
  Provider writes remain data-only recipes in the generic gateway. Core stays
  offline, deterministic, bounded, and independent of credentials and stores.
- **Normative language:** **MUST**, **MUST NOT**, **SHOULD**, and **MAY** specify
  implementation requirements.

## 1. Decision and intended behavior

The product promise is limited authority with enforceable consequences. A
worker may possess an Auths signing key and delegated permission, yet must be
unable to turn an approval for one action into a different provider request,
use retries to obtain another execution, exceed a shared allowance through
delegates, or interpret an ambiguous response as fresh permission.

For example, an approval to attach an existing payment to a named invoice
must bind the exact payment, invoice, operator namespace, logical operation,
recipe, and any required case commitment. The gateway must derive its request
from that action. The business fact that those objects belong together is
owned by the profile, recipe author, and approval policy; a hash of a case
version alone does not establish that fact.

If the intended business invariant must hold when the provider mutates state,
the integration needs a qualified provider-supported conditional write or
reservation with that meaning. A signed snapshot or a fresh pre-entry read
cannot prove that another writer did not change state in the interval.

This program strengthens five links in one chain:

```text
 operator-owned trust / registry / recipe / connection
                |                         |
 untrusted proof + action bytes            |
                |                         |
       [E1 canonical decoding]             |
                |                         |
       [E5 exact signature boundary]       |
                |                         |
       [E2 complete verification]          |
                | sealed verified action  |
       [E3 checked mapping + driver] <-----+
                | exact request / operation / counters
       [E4 atomic claim + durable state]
                | entry checks + sealed credential lease
       [one bounded transport invocation] ------> provider
                |                                   |
       [recorded outcome / signed evidence] <--------+
```

The five workstreams are assurance extensions to existing mechanisms. They
are not a replacement gateway, a new policy language, or a second verifier.

### 1.1 Existing evidence and remaining boundaries

The baseline is the checked-in assurance evidence, not an inference that
production qualification is unfinished. Recipe/provider qualification and
software proof coverage answer different questions and retain their own
exact-artifact gates.

| Boundary | Already present | Extension required here |
| --- | --- | --- |
| Authority | Rich authority, attenuation, approval/observation predicates, and selected shipping-Rust refinements | Compose these results with the actual verifier stages and registered handlers |
| Codec | Canonical re-encoding checks, bounded constructors, corpus, and fuzzing | Prove decoding/encoding and their connection to constructor-valid carriers |
| Requests | `RequestConstruction` theorems and translated construction leaves | Prove source validation/lowering, verified argument projection, and the driver/transport handoff |
| Execution | `SubmitOrder.at_most_one_send`, recovery transitions, aggregate count/sum bounds, and store conformance | Prove their composition across concurrent submissions and durable storage transitions |
| Connections | Credential-generation and revocation model/refinement theorems | Connect those checks to the execution trace and state precisely when an administrative change takes effect |
| Cryptography | Central signature primitives and protocol preimage construction | Prove the surrounding encoding, selection, and message-binding logic under explicit primitive contracts |

Sources: [formal README](../../formal/README.md),
[assurance manifest](../../formal/assurance-manifest-v1.toml),
[coverage report](../assurance/PROOF_COVERAGE.md), and
[translation qualification](../../formal/qualification/aeneas/qualification.toml).
The coverage report's `decision` denominator excludes codec/crypto roles and
does not describe the whole gateway. A percentage increase alone is not a
completion criterion.

### 1.2 Relationship to AP-SPEC-061

AP-SPEC-061 owns the implementation route for E1, E5, and the core portion of
E2. This document coordinates their acceptance criteria with E3 and E4, the
gateway reference-monitor result that AP-SPEC-061 leaves for later work.
There MUST be one codec cutover and one production verification path for each
supported configuration, not competing implementations under the two specs.

Two details of AP-SPEC-061 are clarified here:

1. Unproved obligations stay in this specification until proved. The current
   assurance manifest accepts `proved`, `qualified`, and `assumed`, not
   `open`. A placeholder theorem or an `assumed` row MUST NOT satisfy a done
   gate for a proved obligation.
2. Crypto-library contracts are named explicit theorem premises, not new
   global Lean axioms. This preserves the current foundational axiom
   allowlist while making the conditional claim visible in both the theorem
   and the manifest. It does not prove the primitive contract itself.

## 2. Threat model and limits of the claim

The adversary controls the application and its network submissions. It may
own a legitimately delegated actor key, reorder or duplicate attachments,
mix authentic material from different requests, alter approved fields,
choose fresh operation IDs, race many workers, disconnect at any boundary,
and restart a process. Provider responses may be unavailable, delayed,
malformed, oversized, inconsistent, or produced by another authorized writer.

The proof MUST NOT assume that a request is honest because it is correctly
signed, that a controller key represents a human decision, or that the worker
will choose a stable business operation ID.

The trusted boundary is explicit:

| Premise | Meaning and enforcement evidence |
| --- | --- |
| Operator provisioning | Trust anchors, context, required verifier configuration, recipes, and connections come from the operator plane. Decoding a caller-supplied context does not make it trusted. |
| Cryptographic contracts | The selected primitive implements its stated function. Collision resistance and signature security, where used to interpret commitments or authenticity, remain separately named cryptographic assumptions. |
| Store contract | Successful acknowledged claims are durable; batches are atomic; compare-and-swap and uniqueness have the stated concurrency behavior. Backend conformance supplies evidence for this contract. |
| Clock contract | Verification uses the supplied evaluation time; runtime freshness and lease/entry deadlines use the named clock samples. Mathematical time predicates do not establish that a wall clock is correct. |
| Runtime and transport | The Rust compiler, OS isolation, credential adapter, HTTP/TLS stack, and external I/O satisfy the inventoried leaf contracts. Unproved parts remain named assumptions. |
| Provider contract | The provider interprets a request according to its independently reviewed API contract. Auths does not define provider business meaning. |

A compromised gateway host or operator, a stolen provider credential used
outside Auths, and rollback of all durable state to an undetectable old backup
are outside this claim. Backup/restore procedures MUST preserve claims,
counter history, and generation/fencing state; a missing or obsolete store
must not silently become a fresh installation under the same authority.

No theorem here claims provider exactly-once effects, settlement, constant
time, unforgeability, correctness of every principal adapter, or atomicity
between an external read and a later write.

## 3. Architecture, APIs, and user-visible behavior

### 3.1 Ownership and API invariants

| Surface | Required contract |
| --- | --- |
| Core `verify_v1` / sealed verifier | Explicit bounded inputs and trusted configuration; deterministic result; only the sealed authorized result can project a verified action |
| Gateway `submit(proof_cbor, action_cbor)` | Application supplies no provider URL, headers, credential selector, trust replacement, connection generation, or caller assertion that a check passed |
| Recipe compilation | Validates a closed source and exact profile lock; emits digest-bound plans; grants no execution authority |
| Durable admission | Claims the logical operation and every required counter slot before credential lease; only the winning acknowledged claim produces an execution handle |
| Credential/transport boundary | Uses the operator-bound generation and a bounded lease; accepts only the closed request attached to that handle; adds credentials only at the transport leaf |
| Recovery and audit | Preserve the original action, recipe, operation, observation plan, and outcome provenance; re-observation cannot mint a write handle |

Names for new Lean declarations below are proposed obligation names, not
claims that these declarations exist. Preserve current public Rust/SDK APIs
unless a phase identifies a missing invariant. Any required wire/result
change updates specifications, canonical fixtures, bindings, and independent
implementations atomically.

### 3.2 Approval and result UX

This program requires no new customer screen. Existing SDK review, approval,
receipt, and readiness surfaces MUST preserve these distinctions:

- Review data comes from the canonical action and installed recipe. Show the
  relevant account/resource identifiers, quantities, units, operation, and
  policy commitments without truncation that makes distinct actions look
  identical. If business data is represented by a commitment, the approving
  application must separately validate the committed data and display it.
- Editing any approval-bound field requires a new exact-action approval.
  A valid old approval must not be reused because a case label is unchanged.
- `Authorized`, transport entry, an HTTP response, a matched provider
  observation, and a confirmed business effect are different states.
  HTTP 200 alone cannot become a business-success assertion.
- Evidence identifies which data is native signed evidence and which is an
  unsigned provider read. An auditor verifies signatures against independently
  supplied trust and binds the evidence to the exact action and recipe.
- A future `proved_configuration` indication follows AP-SPEC-061. It is
  computed from actual executed handlers and exact build/configuration
  evidence, never supplied by an application or inferred from a green UI.

## 4. E1: Canonical, total, bounded decoding

**Risk:** the prover reasons about one value while the signer, SDK, or executor
interprets different bytes; hostile lengths or nesting bypass the resource
limits before a constructor can reject them.

**Owners:** `core/crates/auths-codec`, constructor invariants in `auths-model`,
and new `formal/Auths/Codec/` model/refinement/theorem modules. Use
AP-SPEC-061's in-repository extractable tokenizer and direct source cutover.
The old codec may remain only as a test oracle.

### 4.1 Required obligations

For each security-bearing object on the proved configuration's input/output
closure, including action, proof, context, grants, status, approvals,
observations, and critical-extension payloads:

| ID | Quantified property |
| --- | --- |
| E1.1 `decode_total_bounded` | For every byte string and valid deployment limits, decode returns a value or typed error without an out-of-bounds read, arithmetic overflow, or panic; input traversal, depth, collection counts, allocation requests, and abstract work stay within the specified bounds. |
| E1.2 `decode_encode_exact` | `decode(L, b) = ok v` implies constructor-valid `v`, complete input consumption, and `encode(v) = ok b`. |
| E1.3 `encode_decode_exact` | For every constructor-valid `v` whose encoding and structural dimensions fit `L`, `decode(L, encode(v)) = ok v`. |
| E1.4 `validated_carrier_refines` | Every successfully decoded carrier satisfies the representation premises used by the rich and translated authority, approval, observation, and policy proofs. |

E1.2 plus determinism gives one accepted encoding per decoded value. E1.3
MUST use a declared well-formedness relation and explicit limits; it cannot
quantify over values whose encoded form the deployment intentionally rejects.

The specification MUST define the allowed CBOR subset independently of the
implementation: definite lengths, shortest integers, ordered unique map keys,
well-formed text, permitted fields, exact types, and no trailing data. Check
declared lengths before allocating or iterating. A byte limit on the final
object does not justify an unbounded intermediate allocation.

Work bounds concern a named abstract operation counter and allocation model,
not a promise about wall-clock time or OS out-of-memory behavior. The bound
must include failed parses, re-encoding, and nested extension payloads.

### 4.2 Evidence and exit

The shipping codec's translated functions MUST refine the readable model;
tests of a second Lean decoder are insufficient. Add positive, malformed,
truncated, duplicate-key, non-minimal-integer, trailing-byte, invalid UTF-8,
oversized-length, deepest-nesting, and exact-limit fixtures. Differentially
check Rust, WASM, Python, TypeScript, and the existing independent verifier
implementations where applicable. Any changed existing wire decision is
resolved explicitly before cutover.

**Permitted claim:** canonical decoding for the named objects is
machine-checked for exactness, totality, and the stated resource bounds,
subject to the published translation/compiler boundary.

## 5. E2: Complete verifier soundness and useful authorization

**Risk:** individually correct predicates are skipped, fed the wrong values,
combined incorrectly, or followed by an unauthorized result projection.

**Owners:** `auths-verifier`, `auths-composition`, `auths-registries`, the
existing authority/model kernels, and new `formal/Auths/Verifier/` modules.
AP-SPEC-061's closed-registry entry point and extractable per-stage slices
remain the implementation route. Extend its proved set to include native
K-of-N approvals and AP-SPEC-064 status issuer scope.

### 5.1 Required obligations

| ID | Quantified property |
| --- | --- |
| E2.1 `verify_authorized_sound` | For every bounded proof/action input under operator-provisioned context and the declared primitive/adapter contracts, `Authorized` implies the independent rich authorization relation for those exact decoded values. |
| E2.2 `composition_refines_plan` | The shipping evaluator agrees with a structural Lean plan evaluator for every valid bounded plan, including `all_of`, `any_of`, `k_of_n`, structural invalidity, and the three-valued branch outcomes. |
| E2.3 `checks_and_projection_exact` | Required/executed configuration, all action-binding fields, handler dispatch, accepted branch selection, and the sealed result/action projection agree with their specifications. Stable denial/indeterminate codes retain the specified precedence. |
| E2.4 `verifier_total_bounded` | Every bounded input terminates within the declared complete verifier work bound; no failing branch, status lookup, attachment traversal, or composition recursion escapes it. |
| E2.5 `valid_requests_authorize` | Declared well-formed, sufficiently authorized requests are accepted. Prove a semantic completeness result for the closed proved configuration and concrete positive witnesses for each supported action/approval configuration. |

The authorization relation MUST be written independently of the implementation
result. Defining it as “the verifier returned Authorized” proves nothing.
Soundness alone also permits an implementation that refuses everything;
E2.5 prevents that failure mode.

The proof's check inventory MUST include:

- canonical action/body/profile/permission binding, audience, challenge,
  validity, exact required configuration, attachments, and shared action
  identity across the plan;
- trusted-root provenance, signature/principal control, every delegation edge,
  terminal coverage, registry acceptance, unknown critical extensions, and
  the executable extension-law implementations;
- status authenticity, issuer scope, freshness, and revocation according to
  the supplied context; evidence presence cannot substitute for a status
  decision;
- distinct counted approvers, correct requirement ID, exact action/audience/
  challenge binding, relevant grant and context requirements, and separation
  of approval from authority. Principal distinctness is the current contract;
  do not silently claim distinct humans or distinct underlying keys;
- observation signature/anchor/schema/subject/fact binding, freshness,
  authority-chain separation, and retained requirements through delegation;
- composition thresholds, distinct-actor/root floors, authorized branch
  selection, and every deciding pure registry predicate named by the
  check-site inventory.

Missing required evidence MUST remain denied or indeterminate according to
the protocol, never become authorized through fallback. Optional invalid or
stray approvals follow AP-SPEC-065's ignore/count rules; this requirement
must not accidentally turn them into blanket request denials.

### 5.2 Evidence and exit

Every deciding and refusal site in the proved configuration must map to a
translated, audited theorem with adequate strength. Prove the registry shell
dispatch/projection bridge or retain it as an explicitly tested boundary and
withhold the complete-verifier claim. A configuration commitment or a boolean
coverage flag by itself does not prove that bridge.

Adversarial fixtures must splice valid material across actions, contexts,
requirements, issuers, and profiles; duplicate approvers; mix authorized and
indeterminate branches; and exercise every threshold boundary. Include
multiple sufficient approval subsets so no positional or single-happy-path
implementation can satisfy E2.5.

**Permitted claim:** the exact proved verifier configuration refines the rich
authorization relation, conditionally on its published primitive, adapter,
translation, compiler, and provisioning contracts.

## 6. E3: Authorized action to exact outbound request

**Risk:** a correct approval/verifier is bypassed by a compiler field-index
mistake, a different JSON interpretation, a stale request object, or an I/O
driver that uses data not covered by the verified action.

**Owners:** `auths-gateway/src/recipe/{source,validate,lower,runtime}.rs`,
`recipe.rs`, `engine.rs`, `submit.rs`, and `auths-gateway-kernel`. Extend
`RequestConstruction`/`SubmitOrder` and their refinements; add focused
compilation and driver models rather than another request language.

### 6.1 Required obligations

| ID | Quantified property |
| --- | --- |
| E3.1 `compile_preserves_recipe` | For every accepted source/profile lock, source decoding, validation, digest canonicalization, and lowering preserve the independent declarative mapping and all bounds. |
| E3.2 `verified_projection_exact` | The command, named fields, positional argument vector, operation identity, scope, and policy inputs are lossless projections of the sealed canonical action; rejection cannot yield an executable value. |
| E3.3 `closed_request_refines_recipe` | For every accepted source and verified action, the constructed request tuple equals the source-level recipe interpretation: method, origin, path, declared headers, content type, and body. |
| E3.4 `driver_refines_commands` | Every security-relevant driver effect is exactly the command selected by the proved step machine, with the verified action, request, claim, connection binding, and lease from that same attempt. |
| E3.5 `execution_requires_authority` | Compose E2 with E3 and E4: each gateway write entry has a matching authorized action, approved mapping, winning durable claim, reserved counters, required entry checks, and exact request. |

Model the recipe's decoded source semantics independently of its lowered
plans. Proving two functions that both use an incorrect field index does not
establish the intended mapping. Source/lock JSON parsing and canonicalization
must either be included in the refinement or remain explicit external
contracts; in the latter case, publish only the smaller decoded-source claim.

The proof must establish header-name/value safety, exact enum/type checks,
JSON escaping and integer precision, form encoding, profile-field ordering,
and unambiguous operation/idempotency/echo commitment preimages. Prove that
unreferenced fields cannot affect a rendered component, and referenced fields
cannot be substituted by similarly named values from an unverified request.
Specify duplicate-member, number, and Unicode handling at each JSON boundary.
Recipe-source whitespace may normalize to the same decoded source and digest;
this is different from E1's canonical CBOR uniqueness. No consumer may review
one interpretation of a duplicate member while executing another.

For each security-relevant approved field, record whether it is emitted into
the request or checked by a named admission condition/commitment contract.
An opaque case commitment does not tell the generic gateway that a selected
invoice is correct or a database version is current. Such business meaning
needs an independently checked profile/approval oracle; it must not become a
provider-specific branch in the gateway.
Quantity contracts must state their units, currency where applicable, and
rounding rules. Agreement on an integer alone does not establish agreement
on its financial meaning.

### 6.2 Driver, transport, and credential boundary

The existing `SubmitOrder` proof already constrains the command sequence.
E3.4 must additionally cover the actual driver's command-to-I/O mapping,
event/result conversion, request ownership, cancellation, and one-use handle
consumption. Qualify the extraction route before restructuring that code.
If async code cannot translate, move decisions and payload/handle transitions
into a translatable closed kernel consumed by the shipping driver. Any
remaining interpreter correspondence assumption stays named; E3.4/E3.5 are
not complete merely because the kernel has a theorem.

The request property ends at the exact transport invocation. The HTTP leaf
must have a reviewed contract for URL parsing/normalization, credential-header
injection, default headers, DNS pinning, TLS hostname validation, no proxy,
no redirects, no automatic write retry, and response/time bounds. Include
an independent wire oracle for the actual pinned HTTP stack, covering
dot-segments, percent encoding, encoded separators, header collisions, and
body preservation. Do not claim that a theorem about a URL string proves
the request a client library puts on the wire.

Secret bytes remain outside action/proof/recipe/evidence data. Prove structural
confinement of credential access and explicit output projections; continue
isolation and redaction tests for actual secrets. This is not a proof of OS
isolation, all memory behavior, or absence of side channels.

**Permitted claim:** the named production mapping and driver boundary execute
only requests derived from the authorized action and installed recipe,
subject to the specifically retained transport/runtime contracts.

## 7. E4: Concurrent admission, crashes, and durable state

**Risk:** a theorem about one submission or sequential arrivals does not
establish safety of concurrent read/claim/retry sequences, lost commit
acknowledgements, recovery, or counter collection.

**Owners:** `auths-gateway/src/{bounds,store,submit,connection}.rs`,
`auths-connections`, and `auths-stores/src/gateway_attempt.rs`. Extend
`CeilingCount`, `Recovery`, `ConnectionGenerations`, and their refinements
with a global history model and the shipping admission algorithm.

### 7.1 State and transition model

Model arbitrarily many workers and arbitrary finite interleavings. State
includes logical-operation claims, count/sum slots and their cumulative
values, attempt records, connection/credential generations, collection
fences, and outstanding one-use execution handles. Crashes discard volatile
handles; they do not erase acknowledged durable state.

Use the actual identity `(operator_namespace, logical_operation_id)`. Prove
its framed key derivation under the declared hash assumption. Changing the
challenge, proof, actor, case version, recipe, process, or credential
generation must not clear an existing claim for that identity. A genuinely
different operation ID remains a different operation; see §7.4.

The store model MUST permit an error or lost acknowledgement after a batch
committed. The caller may proceed only after the success that grants its
execution handle. “An error occurred” must not imply “the claim is absent.”
Likewise, rollback of a transaction is distinct from rollback of the durable
database to an older snapshot.

### 7.2 Required obligations

| ID | Quantified property |
| --- | --- |
| E4.1 `claim_has_one_owner` | Every logical identity has at most one successful execution owner across workers/restarts. Replays, conflicts, indeterminate commits, and read-only recovery mint no new owner. |
| E4.2 `admission_refines_aggregate_bounds` | The actual counter derivation, smallest applicable capacities, frontier search, cumulative reads, conflict retries, and atomic claim/slot batch refine the existing aggregate count/sum specification for every interleaving. |
| E4.3 `every_history_preserves_capacity` | Every finite history preserves each applicable chain/partition/window bound; delegates, sibling workers, and alternate valid proofs cannot multiply a shared allowance. |
| E4.4 `crash_recovery_preserves_authority` | Every crash/restart prefix preserves claim identity, counter commitments, observation plan, checkpoint/response provenance, and valid compare-and-swap transitions. Uncertainty cannot grant another write or fabricated evidence. |
| E4.5 `collection_cannot_reopen_capacity` | Slot collection never reopens an admitted/reclaimed window, even after another process uses an earlier clock value; claims are not collected. |
| E4.6 `connection_checks_bind_entry` | A lease and write entry use the connection/credential generations that passed their specified reloads, readiness/qualification gates, account/scope guards, and authority-derived entry deadline. No stale-generation fallback or expired authorization may license a new entry. |

The gateway's present fixed-window slots are consumed at admission and are
never released within the window, including after a later pre-entry refusal
or unknown response. Preserve that contract. The older lifecycle model's
reserve/commit/release theorems do not authorize adding refunds to gateway
slots. Exhaustion may retain a terminal `not-entered` claim without slots;
contention exhaustion may safely refuse. Specify both cases exactly.

These are fixed windows, not rolling intervals. Adjacent windows can each
admit their full allowance near a boundary. Preserve and expose that policy
meaning; a rolling-period promise requires its own model and mechanism.

E4.5 requires a shared durable collection/admission fence, or an existing
shipping mechanism proved equivalent. The initial design is one monotone
`collected_through` cutoff in the shared gateway store:

1. Before deleting slots eligible at cutoff `t`, the sweeper durably advances
   the fence to at least `t`; a crash may leave fewer deletions, never an
   unrecorded deletion boundary.
2. A bounded admission atomically checks that its slot expiry is strictly
   greater than the current fence and inserts its claim/slots. A separate
   fence read followed by the old unconditional `insert_all` is insufficient.
3. Fence advancement and fenced admission have ordered linearization points.
   A stale worker cannot insert into a collected window after its slots have
   disappeared. Unknown commit outcomes retain the same conservative rules
   as claims. Mixed window lengths use their actual validated slot expiry.

This needs a narrow conditional-batch operation in the gateway store port and
both backends, not a caller-held boolean. A process-local last-sweep timestamp
is not sufficient. The fence may conservatively close an old window whose
slots were not deleted after a crash. Until this mechanism lands, any
window-safety claim must retain its clock/collection premise and cannot claim
tolerance of clock rollback. Correct wall-clock time remains a separate
assumption even with this fence.

### 7.3 Revocation, recovery, and backend evidence

E2 establishes validity at the supplied evaluation time. E4 must also prevent
an approval or grant that expires while the worker is waiting from licensing
a later entry. Project an internal `EntryNotAfter` from the exact sufficient
authorization witness: the relevant grants/action, counted approvals,
required observations/status freshness horizons, and installed time-limited
gates. Preserve inclusive/exclusive endpoints from the respective contracts.
It is the minimum of those applicable horizons and the existing maximum
verification-to-entry interval; it cannot come from caller JSON.

At the final deadline gate require a valid clock sample at or after the
evaluation time and within `EntryNotAfter`, together with the existing
monotonic elapsed-time limit and lease deadline. An expired horizon or
disallowed rollback must produce the existing typed pre-entry failure,
retain any claim/slots, and send no write. A proof that the earlier evaluation
time was valid, or that fewer than 60 seconds elapsed, is insufficient by
itself. This is an
execution-boundary extension; it does not change offline verification's
evaluation-time contract or promise cancellation of an in-flight request.

Use the existing connection semantics: a committed disable/revocation/rotation
is observed at the next shared-record reload. A submission that passed its
last entry reload may already be in flight. Prove that actual rule, including
the local drain and credential-retirement interval; do not describe it as
instant cancellation of requests already past the gate. A stronger global
quiescence contract would be separate work.

Re-observation is read-only and uses the stored observation plan. A response
locator cannot resolve a lost response that never recorded that locator.
Unlinked observations cannot become linked recovery evidence. Another
writer producing a matching field or token does not prove exclusive causation.

The abstract store contract must include atomic batches, unique keys,
compare-and-swap against exact expected record bytes, durable success,
fail-closed corrupt/unreadable loads, and the relevant collection fence.
Specify a linearization point for each operation. PostgreSQL may implement
the contract with its actual transaction isolation, unique constraints, and
rollback; do not assume the backend uses serializable isolation. File-store
evidence must cover locking, journal recovery, file and directory durability,
and every partial batch boundary.

Run the same backend conformance against multi-process races, commit-before-
acknowledgement loss, every persisted crash boundary, replacement races,
collection/admission races, and restart with missing/corrupt/obsolete state.
These tests support the external store premise; they are not a proof of the
database, filesystem, or storage hardware.

### 7.4 Business identity and progress

The application cannot be trusted to implement “once per payment” merely by
usually choosing the same operation ID. A product making that promise MUST
derive or enforce its stable business identity in the trusted profile,
approval issuer, or operator-owned workflow, bind it into the exact action,
and test fresh-ID attempts. This requirement is domain-owned; core must not
learn Stripe payment semantics. A fresh ID must also remain subject to the
same applicable aggregate budget.

Safety holds under arbitrary scheduling. Progress is conditional on available
dependencies, valid input, deadlines, and finite contention. Prove a positive
available-capacity admission witness and bounded termination of retries;
do not promise starvation freedom or availability during a partition.

**Permitted claim:** across the declared store/clock/runtime contracts, the
gateway admits one owner per logical operation, conserves the stated shared
allowances, and preserves these properties through the modeled failures.
This is at-most-once gateway write entry, not provider exactly-once effect.

## 8. E5: Exact cryptographic integration

**Risk:** a vetted primitive receives the wrong key, suite, object type,
profile, or signing bytes; a correct signature then authenticates a different
statement from the one the verifier uses.

**Owners:** `auths-codec/src/hash.rs`, `auths-signature-core`, the signature
adapters and proved principal/status handlers, plus new
`formal/Auths/Crypto/` integration modules. Use AP-SPEC-061's phase 2 route.

### 8.1 Required obligations

| ID | Quantified property |
| --- | --- |
| E5.1 `signing_preimage_exact` | Every object uses exactly its registered prefix, protocol/object/profile/version tags, length framing, canonical unsigned statement, and signature descriptor. |
| E5.2 `framing_is_unambiguous` | On the validated bounded domain, equality of preimage bytes implies equality of their framed inputs; different object/domain tags cannot share a preimage. This does not assert collision-free hashes. |
| E5.3 `suite_glue_refines_spec` | Key/signature decoding, suite dispatch, key/principal binding, low-S and other registry rules, and the exact message passed to the primitive refine the named suite specification. |
| E5.4 `commitments_bind_exact_inputs` | Core and gateway action/operation/recipe/account/echo/idempotency commitments use the specified preimages without omitted fields or ambiguous concatenation, under separately recorded hash assumptions. |

Cover approvals, observations, principal/grant status, grants, actions, and
any outcome signatures used by the composed execution claim. Keep different
protocol hash/signature domains distinct. Validate Ed25519 encodings against
the declared RFC 8032/registry contract and P-256's compressed-key, fixed-width
signature, point-validity, and low-S rules; do not assume a library constructor
enforces every protocol restriction. Coordinate any tightening of accepted
inputs and stable errors across the corpus and independent implementations.

The initial dependency choice is AP-SPEC-061's current-library route:
`ed25519-dalek`, `p256`, and `sha2`, with named implementation-meets-spec
premises. This specification adds no cryptographic dependency or advisory
exception. A later switch to a verified implementation needs its own evidence
and dependency review and retains the translation/compiler assumptions.

Represent primitive contracts as explicit parameters, for example:

```text
CryptoRefines(impl, spec) ->
  suite_verify(impl, key_bytes, message_bytes, signature_bytes) = accepted ->
  SuiteSpecAccepts(spec, key_bytes, message_bytes, signature_bytes)
```

This is a proposed statement shape, not an unconditional proof that the
libraries meet their specifications. Keep the existing foundational axiom
allowlist; forbid `sorryAx` and native-evaluation axioms in new public claims.
Every manifest entry and permitted claim sentence must expose the relevant
primitive premise. Collision resistance does not mean SHA-256 is injective
over all byte strings, and it must never be silently derived from functional
correctness of SHA-256.

Use published algorithm/encoding vectors and independent negative cases:
wrong domains/profiles/suites, modified lengths/descriptors, noncanonical or
small-order Ed25519 encodings as applicable to the declared suite, invalid
P-256 points/forms, high-S signatures, and actual P-256 positive tuples.

**Permitted claim:** signature and commitment integration is machine-checked
against the named specifications, conditional on the explicit primitive and
cryptographic assumptions. No claim that elliptic-curve arithmetic or
cryptographic security has been proved in Lean is introduced.

## 9. Composed claim and adequacy

The final reference-monitor statement is over every finite prefix of a
reachable system history, not one canned demonstration. Informally:

```text
For every supported installation I and history H,
  Provisioned(I) and ExternalContracts(I, H) and Reachable(I, H)
  imply that every GatewayWriteEntry in H has:
    an exact decoded and authorized action under I's supplied trust;
    all required approvals, evidence, and applicable product policy;
    a request equal to I's approved recipe applied to that action;
    one winning durable operation owner and its reserved counters;
    the required connection, credential, freshness, and entry checks;
    at most one write entry for that logical operation in H;
    outcome/evidence transitions justified by what was actually recorded.
```

`ExternalContracts` MUST enumerate the contracts in §2 and any smaller
remaining runtime/transport boundary. It cannot contain “all writes are
authorized,” “the driver behaves like the theorem,” or the desired budget
bound as a disguised premise. An intermediate result may retain a precisely
named driver/store bridge premise, but it cannot satisfy the corresponding
uncompleted E3/E4 obligation or the final M6 gate. Physical I/O and backend
contracts remain external as defined above; the shipping authorization,
mapping, and admission algorithms must be related to their specifications.

The public statement and all its definitions require review independently of
the proof implementation. Add positive witnesses and targeted mutations:

| Attack or defect | Required result |
| --- | --- |
| Change invoice, payment, account, amount/currency, case commitment, namespace, operation, or recipe while reusing the original approval | That approval cannot authorize the changed action; the unchanged proof cannot license a write |
| Reuse authentic approval/evidence under another audience, challenge, requirement, issuer, or profile | Refusal or indeterminate according to the protocol; no write |
| Duplicate an approver or count an authority principal as a required approver | Quorum is not inflated |
| Mis-index a field, drop a compiler guard, or substitute the original unverified JSON | Corresponding refinement/adequacy obligation fails |
| Replay with a fresh challenge, worker, process, or credential generation | No second owner/write for the same logical identity |
| Invent a fresh operation ID for the same business event | The domain-owned once-per-business-event rule rejects it where that rule is promised; otherwise it remains subject to all approvals and shared bounds |
| Race the last count/sum capacity across delegates and workers | At most the allowed aggregate admission; no partial claim/slot batch grants execution |
| Lose a commit acknowledgement or kill a process at a persistence/transport boundary | No duplicate permission; retained state is conservatively recoverable |
| Collect old slots, then use an old clock/window | The collection fence prevents renewed admission |
| Disable/rotate between checks | The next defined reload rejects stale state; requests past the last gate retain their explicitly stated in-flight semantics |
| Return a 2xx response, mismatched echo, missing locator, or malformed read | Preserve the appropriate response/unknown/observation classification; never invent confirmed business success |
| Replace the implementation with deny-all or panic | Completeness/positive witnesses or totality proofs fail |

Quantify over all bounded accepted inputs and arbitrary finite histories;
case fixtures and bounded Kani checks supplement those theorems. They cannot
replace an unbounded history invariant with a fixed worker count.

## 10. Delivery sequence, proof hygiene, and done gates

### 10.1 Bounded milestones

| Milestone | Deliverable | Prerequisites and exit |
| --- | --- | --- |
| M0: Claims and extraction slices | Independent semantic relations, theorem contracts, source/assumption/check-site map, and small positive/negative translation examples | Freeze the intended claims before proofs; demonstrate the route on real shipping functions without extraction-only semantics |
| M1: E1 codec | Tokenizer, constructors, encoding, all E1 proofs, and direct cutover | Corpus parity, hostile bounds cases, and exact-source qualification |
| M2: E5 crypto integration | Framing and suite-glue proofs with explicit primitive contracts | E1 for byte-level claims; cross-language vectors; no global axiom expansion |
| M3: E2 verifier | Pure registry/composition refinements, staged verifier proofs, complete sealed projection | E1/E5 for the complete byte-to-authority claim; approvals/status/observations included |
| M4: E3 mapping and driver | Source/lock/argument/plan refinements and the driver bridge | Existing request/order proofs reused; E2 supplies the complete authorization premise |
| M5: E4 history and storage | Admission algorithm refinement, crash/collection/connection invariants, backend conformance | May develop against an explicit authorization premise before M3; the complete claim waits for composition |
| M6: Composed assurance | E3.5, full history statement, release-bound evidence, and truthful SDK/operator reporting | Every prerequisite and remaining assumption visible on the exact release revision |

Each milestone is split into reviewable changes. First prove one complete
small path from shipping function to readable specification and a useful
positive action. Establish extraction/build cost on representative boundary
inputs before scaling. Reuse the pinned toolchain and qualified translation;
do not spend a phase proving an independent model with no production bridge.

### 10.2 Required evidence for every proved claim

1. The exact declaration and statement, full quantified domain, readable
   definitions, non-vacuity witnesses, residual premises, and source closure.
2. Mechanically translated shipping functions, exact production feature set,
   reviewed external models, strict warning gates, and two byte-identical
   translation reproductions when that closure changes.
3. Updates to `Auths.Theorems`, the compiled `Auths.AssuranceAudit`,
   `assurance-manifest-v1.toml`, and `theorem-kinds-v1.toml`. Prefer exact or
   verdict-exact refinement; a weaker lemma cannot satisfy an exactness gate.
4. Transitive axiom audit, including dependencies. No `sorry`, blanket opaque
   local predicate, extra global axiom, or native-evaluation admission may
   discharge a new public obligation.
5. A fail-closed check of theorem premises and representation validity; their
   source must not be replaced by a test-only constructor or trusted flag.
6. Updated check-site and coverage evidence with stable declared denominators.
   Report codec, verifier, compiler/driver, and stateful-store coverage
   separately; do not improve a headline by excluding hard code.
7. Corresponding adversarial, differential, property, fuzz, and mutation
   evidence. Required security mutants must be killed; an equivalent mutant
   needs a reviewed explanation. Results must match the release inputs.
8. Hosted CI on the exact revision, including the authoritative formal,
   translation, Kani, implementation, compliance, and secret gates appropriate
   to the change. Add clean proof rechecking with the pinned Lean toolchain's
   supported checker to the authoritative proof job; audit statements as well
   as proof terms.

Follow the repository's GitHub-first policy. This documentation change runs
no formal qualification. Implementation work uses focused translation slices
to construct changes and hosted CI for the authoritative result. A fast Lean
feedback build alone does not qualify a milestone.

### 10.3 Decisions fixed by this spec

- Keep one monorepo and the existing layer boundaries. Reuse current kernels
  and theorem modules; create no universal business-policy abstraction.
- Keep current crypto libraries for the initial proof route and use explicit
  premises. No new dependency, advisory exception, or global axiom is implied.
- Preserve canonical wire behavior and stable decisions except separately
  specified, reviewed security corrections such as stricter suite encodings.
- Preserve conservative gateway slot consumption and read-only recovery.
- Require a shared collection/admission fence before claiming tolerance of
  clock rollback after collection; global instantaneous revocation and
  provider-conditional business writes remain outside scope.
- Keep UI rendering, actual host isolation, and provider semantics supported
  by their own evidence rather than describing them as consequences of Lean.

Implementation choices within these contracts do not require changing the
public promise. A failed feasibility gate leaves its claim unearned; it does
not authorize weakening the theorem or moving the risk into an unnamed axiom.

## 11. Evidence and references

Local baseline references are listed in §1.1. Additional anchors:

- [Qualified Rust-to-Lean decision](../adr/0011-rich-authority-rust-lean-link.md).
- [Gateway ordering model](../../formal/Auths/Product/SubmitOrder.lean),
  [request construction](../../formal/Auths/Product/RequestConstruction.lean),
  [recovery](../../formal/Auths/Product/Recovery.lean),
  [aggregate bounds](../../formal/Auths/Product/CeilingCount.lean), and
  [connection generations](../../formal/Auths/Product/ConnectionGenerations.lean).
- [Protocol domain separation](../../core/spec/v1/domain-separation.md).
- [Lean proof validation](https://lean-lang.org/doc/reference/latest/ValidatingProofs/):
  statement meaning, transitive axioms, and proof rechecking are separate
  review concerns. Tool availability must be checked against the pinned Lean
  version rather than silently upgrading the toolchain.
- [Aeneas](https://github.com/AeneasVerif/aeneas): the repository's qualified
  pinned revision, not upstream's current branch, governs extraction here.
- [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032): Ed25519 decoding and
  verification specification referenced by E5 and AP-SPEC-061.

## 12. What must be built to support this decision

These are additions to the proof boundary, not assertions that existing
runtime features or provider qualifications are absent.

| Build item | Evidence for the gap | Completion evidence |
| --- | --- | --- |
| Extractable canonical codec and constructor bridge | `formal/README.md` and AP-SPEC-061 exclude codecs from the current proof surface | E1.1–E1.4 on the shipping codec and full input closure |
| Full composition/registry/stage and sealed-result proofs | `PROOF_COVERAGE.md` identifies these functions/check sites outside the refined closure | E2.1–E2.5 with every required check mapped |
| Source/lock compiler, argument conversion, and driver bridges | Gateway refinement residual assumptions in the assurance manifest explicitly exclude compilation/conversion and the async I/O correspondence | E3.1–E3.5, with any retained JSON/transport/interpreter boundary named |
| Global admission and crash refinement | Existing aggregate predicates assume derived counters and atomic store behavior; the actual `reserve_with_claim` protocol is outside that proof | E4.1–E4.4 and multi-process backend conformance under the actual transaction/file semantics |
| Shared closed-window/admission fence | Baseline slot collection uses gateway time; `last_sweep` is process-local and the current proofs assume the clock/store boundary | E4.5, including collect/rollback/old-worker races, without claiming a trusted wall clock was proved |
| Execution-time connection and qualification bridge | Current generation proofs do not by themselves prove which runtime path consumes a lease and sends a request | E4.6 composed with E3.4, preserving the existing next-reload/in-flight contract |
| Authority-derived entry expiry | The current runtime checks a fixed verification-to-entry interval; the new contract also needs the exact authorization witness's remaining validity | Internal `EntryNotAfter` projection and final checks, with expiry/rollback/queue-delay cases and no caller override |
| Domain-owned business-identity and intent evidence | Logical-operation deduplication and an opaque case hash do not themselves establish once-per-payment behavior or correct invoice selection | A reference workflow that enforces stable business identity, validates committed facts before approval, and independently checks the recipe's intended mapping |
| Suite/preimage proofs and explicit primitive premises | Codec/hash, signature suites, and full signature dispatch remain outside the present proof surface | E5.1–E5.4 and audited conditional claims |
| Final claim and independent adequacy review | Current claims are scoped component/refinement statements | The composed history theorem, positive useful-work witnesses, mutation evidence, and exact-release public claim |

The first implementation change should establish M0 and the smallest E1
tokenizer/constructor refinement slice. It must leave a positive accepted
object and a meaningful malformed/bounds rejection proved against the exact
shipping code. That is the starting point for the larger codec cutover,
without claiming the other four enhancements have been completed.


## 13. Pause checkpoint and resume instructions — 16 October 2026

The owner requested a pause after a coherent checkpoint and subsequently
requested continuation on 16 October 2026. The following records the pause
state; work has resumed at §13.4. The implementation is substantial but is
**not close to completing every requirement of this spec**. No E1–E5
workstream or M6 is declared complete. The claim count below measures audited
component statements, not a percentage of the end-to-end security promise.

### 13.1 Saved branch and review state

- Repository: `/Users/bordumb/workspace/repositories/auths-proof-base/auths-proof`.
- Branch: `codex/lean-enhancements`.
- Latest implementation checkpoint: `cdb2c837995c507d051a239864aa8fef880ee192`
  (`feat(formal): qualify selected temporal-witness expiry`).
- Its preceding local checkpoint: `98adcfb5c358510f2729abe7c8eb2c2cddda0b32`
  (`test(crypto): qualify shared independent P-256 corpus`).
- Draft review: [PR 209](https://github.com/auths-dev/auths-proof/pull/209).
  Do not merge on the strength of these component results.
- At the pause check, the remote branch remains at
  `59c56d5bf2a9db92b028fb430d997ff259e83ec2` (613-claim suite-adapter
  checkpoint). The corpus and temporal checkpoints are saved locally and
  have not been pushed, to avoid cancelling that revision's expensive
  authoritative replay. Recheck the remote before publishing later work.
- Unrelated research documents and two report PDFs are left untouched and
  untracked. No partially applied status-selector refactor is left in the
  production tree.

### 13.2 Evidence achieved at this checkpoint

The detailed component ledger is
[AP_SPEC_069_STATUS.md](../assurance/AP_SPEC_069_STATUS.md). The executable
claim inventory, full compiled statements and kernel constant references,
exact source closures, and theorem kinds are committed under `formal/`.

The latest construction qualification passes **634 compiled claims**, with
all 613 preceding complete audit records unchanged. It passes **16/16
qualification cases**, **22 reviewed external models**, zero unreviewed
models, zero compiled external axioms, and two byte-identical fresh
translations. The transitive axiom audit uses only `propext`,
`Classical.choice`, and `Quot.sound`. Production source closure:
`d0e1dba843ae5f0bba50a2b00cf8f779721756069e3bc1481feaab81d1b836d5`.
The manifest separately binds the complete semantic/proof source closure.
Release semantic-freeze and gateway semantic-closure artifacts are refreshed.

Completed component boundaries include canonical CBOR heads, accepted action
re-encoding/uniqueness, selected identifier validation, composition-plan
validation/evaluation and facade projection, shared signing/commitment framing
with exact bounds, native Ed25519/P-256 and one-shot SHA-256 integration under
explicit primitive contracts, linked signature-suite verification adapters,
collection/deadline leaves, and the new selected-witness expiry helpers.
These do not constitute complete-object decoding or a complete verifier.

The new temporal proofs cover the actual status decision/horizon and selected
assurance-horizon helpers, loop termination, missing requirement/timestamp
refusal, unbounded rules, inclusive endpoints, exact saturating addition and
minimum expiry. Five focused native cases use validated constructors. **They
are expiry-only claims:** they do not establish witness authenticity,
selection by the full evaluator, observation-time ordering, satisfaction of
all required policies, or runtime consumption of the complete witness.

The shared independent P-256 corpus contains **653 cases**, including all
262 pinned upstream Wycheproof cases and 173 admitted signatures over 98
public keys. Native Rust, independent Go and independent TypeScript tests
pass. Explicit high-S policy transformations and provenance are recorded in
`core/fixtures/crypto/README.md`; the offline importer reproduces exact bytes.
Tests support the primitive contracts; they do not prove crypto arithmetic.

Decision-code coverage is 127/1,044 functions, 1,552/11,535 lines and 23/82
check sites. Existing mutation campaigns predate the current proof sources
and must be refreshed before a release. Do not interpret this pause as release
qualification.

### 13.3 Hosted evidence still pending

The last confirmed fully successful hosted checkpoint is `e119ec92` (567
claims). At the pause check, the suite-adapter revision `59c56d5b` has passed
translation, but its authoritative Lean job is still running; no failed job
was reported by the current main-run query:

- [Main run 38904220615](https://github.com/auths-dev/auths-proof/actions/runs/38904220615).
- [Authoritative job 116999215585](https://github.com/auths-dev/auths-proof/actions/runs/38904220615/job/116999215585).

Neither local checkpoint `98adcfb5` nor `cdb2c837` has exact-revision hosted
results. On resumption, inspect the existing job and all required independent
workflows first. Preserve their actual conclusions, push the saved bounded
checkpoints, and obtain hosted evidence on the new exact revision. Update the
PR description with that distinction. Do not substitute a previous revision's
success or a local qualification for the required hosted merge gates.

### 13.4 First next implementation slice: actual status selection

Continue E2/E4 at the source that selects status evidence, before claiming
that the proved expiry helpers receive the right witnesses:

- `core/crates/auths-registries/src/lib.rs`: `ExactStatusMethod` principal and
  grant methods and `select_principal` / `select_grant`.
- `core/crates/auths-model/src/lib.rs`: `status_issuer_in_scope` and
  `status_issuer_visible`.

A disposable extraction experiment used the shipping trait implementation,
not a test wrapper. Charon extracted it, but Aeneas refused early returns
inside selector loops and lifetime constraints in iterator `find` reached via
filter/collect. No partial translation was admitted and no Auths selector was
replaced with an opaque premise. Prototype files under `/private/tmp` are
optional scratch material, not part of the saved implementation or a resume
dependency.

The next bounded change should:

1. Preserve the current selectors and visibility rules as **test-only**
   independent reference algorithms. Cover complete verdict, validity horizon
   and error precedence with validated native inputs and boundary/property
   cases before a direct production cutover.
2. Reshape the actual principal and grant selectors into explicit bounded
   scans with state flags, without early returns inside loops or iterator
   `find`/filter pipelines. Keep the two concrete typed selectors. Retain one
   shipping implementation and no compatibility switch. Rewrite the existing
   visibility helpers similarly; do not introduce a second visibility policy
   or change bounded-set membership without evidence.
3. Preserve the existing semantics: ExpiresOnly precedence, method and
   snapshot refusal order, issuer scope visibility, the first matching trust
   rule, rollback refusal for any trusted below-floor sequence, distinct
   missing/wrong-method/untrusted outcomes, highest-sequence tie handling,
   stale-before-revoked precedence, and the minimum of snapshot, statement
   and saturating age deadlines. Unknown issuers remain visible to the scope
   filter and are refused later as untrusted.
4. Re-extract that exact shipping closure with all Auths helpers transparent;
   prove full result refinement against an independent selection model,
   meaningful accepted/refused cases, termination and relevant bounds. Only
   then connect selection to temporal-witness construction.
5. Update source/claim/model inventories, check-site coverage, gateway closure
   and release identities together, reproduce translation twice, and obtain
   exact-revision hosted evidence. A native parity test alone earns no Lean
   selection claim.

### 13.5 Remaining program after that slice

| Workstream | Still required for completion |
| --- | --- |
| E1 / M1 | Full protocol-object/tokenizer/constructor validity closure; all-input refusal/totality and inverse completeness; resource/allocation bounds; complete shared-language codec corpus. |
| E5 / M2 | Suite constructors/IDs and closed registry dispatch; principal/key binding; actual caller unsigned-object and descriptor construction; every core/gateway commitment call; all required AP-SPEC-061 vectors. Existing crypto primitive contracts remain explicit. |
| E2 / M3 | Native callbacks and closed registries, approvals/status/observations, staged verifier, complete sealed projection and temporal-witness selection, required/executed configuration and work accounting, full byte-to-authority composition. |
| E3 / M4 | Actual source/lock parsing and compiler lowering, field/argument conversion, sealed projection to driver command, complete command-to-I/O bridge and independent wire oracle. |
| E4 / M5 | Actual counter derivation and admission refinement, arbitrary finite concurrency/crash/acknowledgement histories, backend correspondence, full witness and connection-generation consumption by the driver. Existing collection-fence and deadline components remain scoped evidence. |
| M6 | Composed history/reference-monitor theorem, independent adequacy review, useful positive actions, required mutation evidence and exact-release SDK/operator claims. |

Resume from the committed artifacts and this list. Do not restart completed
component proofs or describe the five enhancements as finished because the
claim count grew. The exit gates in §10 remain authoritative.


### 13.6 Resumption — 16 October 2026

The preceding `59c56d5b` checkpoint passed the authoritative Lean replay and
all ten hosted workflows, including main CI, translation, implementation,
secret scanning, PostgreSQL, Stripe, isolation and SDK qualification. The
saved corpus, temporal and documentation commits through `e4770a2b` have now
been pushed to the existing draft PR for exact-revision hosted verification.
The historical pending/local-only statements in §13.1 and §13.3 describe the
pause time, not the resumed branch state.

The next source slice is still status selection (§13.4). Its refactor and
extraction experiments are construction work until their complete source,
proof, inventory, reproducibility and hosted gates pass. The frozen old
algorithm is retained only under `#[cfg(test)]` as a differential oracle.


### 13.7 Approval-view status scan — 16 October 2026

The bounded source cutover in §13.4 now has one allocation-free indexed scan
per concrete principal/grant selector, plus indexed visibility and first-rule
lookup. The superseded algorithms exist only as independent test oracles.
More than 19,000 constructor-valid generated snapshot pairs compare complete
results in both anchor views and the approval view; dedicated cases cover
sequence/floor and saturating-time word limits. Focused native parity, lint,
and generated-context rejection checks pass.

The new Lean source claims establish total principal and grant port results
against the operational accumulator for the approval view, exact first-rule
selection and freshness, and nine actual-port positive/refusal witnesses.
The independent filter/max/tie-set specification is present, but equivalence
to the accumulator is **not yet proved**. Anchor-view refinement, sorted
scope-search membership, evidence authenticity and the full verifier remain
open. No whole enhancement or milestone is complete.

Fresh construction qualification passes **658 compiled claims**, preserving
all 634 preceding complete records, **17/17 cases**, **23 reviewed models**,
zero unreviewed models and zero compiled external axioms. Two clean
translations are byte-identical. Production source closure:
`597b19ee0354614b37b9f048c7248e5684e69cf2c0d05a92a8b224a0b1172c7f`.
Only the three permitted foundational axioms occur transitively.

The preceding 634-claim revision `e4770a2b` has passed main CI and all nine
independent hosted workflows; main run
[38931405294](https://github.com/auths-dev/auths-proof/actions/runs/38931405294)
completed successfully. The 658-claim source slice still needs its own hosted
replay. Current work connects the accumulator to the independent selection
specification, then closes the anchor-view scope-search boundary before
connecting selection to temporal-witness construction.


### 13.8 Independent status semantics — 16 October 2026

The semantic gap in §13.7 is now closed for the approval-view source path.
The pure accumulator equals the independent candidate/method/trust filters,
maximum-sequence tie-set specification and complete decision/horizon result
for every finite input, every view and every policy, without an input-validity
or desired-result premise. Both actual principal and grant approval-view port
methods compose with that theorem. The proof earns maximum attainment and
complete tie handling; stale or revoked latest evidence cannot be dropped by
scan order. The semantic proof modules import no generated Rust.

Fresh source qualification passes **661 compiled claims**, with all 658 prior
complete records unchanged, **17/17 cases**, **23 reviewed models**, zero
unreviewed models, zero compiled external axioms and two byte-identical clean
translations. Qualified production closure:
`678c19c1155869c45fed1cb7e849c147bca5bde0e07df567f413487335ab6669`.
The compiled audit uses only the permitted foundations.

Hosted checking of the preceding `85bc1e0f` found a stale gateway checksum for
the differential test file after its final lint cleanup. Refresh the generated
artifact and require the focused checksum check and exact-revision hosted
replay. Keep the checksum's complete input boundary intact.

Continue with anchor-view source visibility, including the actual sorted
scope binary search, then full verifier evidence authentication/dispatch and
selection-to-temporal-witness composition. The pure all-view equivalence does
not itself prove that the native anchor-view calls realize that model. E1–E5
and M6 remain open under §10 and the remaining-program table in §13.5.


### 13.9 All-view status source results — 16 October 2026

Both actual port methods now refine the independent specification in every
view, under the ordered listed-scope representation invariant. The actual
Auths lookup wrapper returns exact membership; its transparent pinned-standard
binary-search model has a kernel-checked terminating interval/membership proof
and bounded result index. Source visibility covers own, listed and universal
scopes. The unrestricted represented-input approval-view claims remain intact.

Five new cases cover first/last listed anchors, absent membership, active
status through the issuer own anchor, and hidden status through a different
anchor. The final two quantify over unrelated anchor fields. Their synthetic
status evidence proves selection behavior, not authenticity.

Fresh qualification passes **671 compiled claims**, all 661 preceding complete
records unchanged, **17/17 cases**, **23 reviewed models**, zero unreviewed
models and zero compiled external axioms. Two fresh translations match exactly.
Production closure:
`0e96ae702036cbe01af7fe60060ac560482b17fc4f473bb24e653ca35a6b5b60`.
Only permitted foundations occur. Exact-revision hosted gates remain required.
The preceding 661-claim revision is in hosted verification at main run
[38944751348](https://github.com/auths-dev/auths-proof/actions/runs/38944751348).

The next source slice derives ordered-scope validity from the actual
constructor/decoder. A disposable extraction of the current scope decoder
reached the constructor but was refused for early loop returns and the
constructor's windows/any iterator; no failed artifact is admitted. Prepare a
direct bounded loop cutover, independently comparing complete constructor
results and decoder result/cursor behavior against test-only former code.
Reject oversized constructor lists before sorting. Keep accepted values,
canonical ordering, stable errors and binary-search membership unchanged.
Then prove constructor validity and connect it to these conditional all-view
statements. Full E1–E5/M6 completion still follows §10 and §13.5.

### 13.10 Constructor-earned scope validity — 16 October 2026 (in progress)

The next source slice is implemented and its general Lean statements compile:

- `StatusScopeAnchors::new` rejects empty or oversized lists before sorting,
  sorts admitted carriers, and checks adjacent duplicates with a bounded indexed
  loop. The public API, sorted result and typed refusal remain the same.
- The scope field decoder uses an indexed collection loop with the same first
  error and cursor behavior. Independent test-only former implementations
  compare complete constructor results and decoder results/cursors, including
  randomized inputs, all tag bytes, truncated prefixes and limit boundaries.
- The actual constructor has an unconditional, total, result-complete refinement
  against nonempty/maximum-length/uniqueness validation and sorted permutation.
  Success earns the ordering used by actual binary-search membership. The
  constructor also supplies all-view principal/grant selector invariants when
  its constructed list is assigned to each supplied trust rule.
- Every successful actual scope decode earns structural scope validity. A
  fieldwise bridge between translations of the same Rust enum feeds that
  invariant into the actual native scope-coverage function, whose result equals
  the independent scope semantics.
- Kernel-checked decoder examples cover own/any/listed acceptance, unknown tags,
  truncation, empty listed scopes, invalid identifiers and collection limits.
  Multi-element sorted/refusal witnesses are being completed.

New `scope_codec` extraction starts at the actual shipping field decoder and
includes model bodies. Its inventory is 21 local/30 foreign function records;
all Auths bodies are transparent. Only four generated discriminant instance
names change. Standard interfaces reuse reviewed UTF-8, result/option,
conversion, comparison and stable key-sort models; ordinary sorting uses a
proved stateless identity key and concrete String comparison laws. This is not
an assurance claim about Rust standard-library machine code, arbitrary stateful
sorting callbacks, physical allocation or physical work.

The first 19 new statements compiled with only the permitted three foundations;
all prior 671 full compiled audit records remained unchanged. The fresh
qualification and final count/digests for this source slice remain pending.
Hosted CI is deliberately deferred while implementation continues, as requested.

Remaining within this slice: finish the multi-element witnesses, review the
complete statements and constants, reproduce both fresh translations, update
assurance evidence/coverage/freeze, then continue toward decoder totality and
complete canonical acceptance/rejection/round trips. Partial decoder safety
uses an actual successful-decode premise; it does not assume an authorization
result. Identifier-language completeness, per-rule/snapshot constructors,
evidence authentication, closed registry dispatch, full staged verification
and runtime/history consumption remain open. No whole E1–E5/M6 milestone is
closed by this slice.


### 13.11 Implementation-first continuation — 16 October 2026

Per the user's direction, broad translation/build qualification is deferred
until the remaining implementation batch is written. The 692-statement scope
slice compiled and its prior 671 records were unchanged; the fresh reproducer
completed two translations and started the Lean build before being deliberately
interrupted. It is not a qualified checkpoint. The assurance manifests,
coverage/freeze, gateway source checksums and final hosted evidence must be
regenerated and reviewed together after coding; do not reuse stale evidence.

The next batch cuts principal URI-scheme parsing over to a bounded byte scan
with an independent character oracle, extends status-trust decoding to an
indexed collection loop, and carries decoder-earned scope validity through
actual per-rule decoding and the complete trust-rule collection. Its source
translation root will be expanded from `status_scope` to `status_trust`.
The independent principal grammar/model is already written. No whole E1–E5/M6
completion is claimed; the remaining checklist is still §10 and §13.5.


Implementation-first batch written (not yet checked):

- Shipping `PrincipalId::parse` uses bounded identifier validation plus the
  ASCII scheme scanner before copying accepted strings; Unicode and adversarial
  scheme/capacity tests retain the former character-based parser as an oracle.
- Shipping status-trust decoding uses one rule helper and an indexed collection
  loop with first-error preservation. Its test oracle retains former control
  flow and former scope decoding, comparing exact results and cursors.
- `PrincipalSchemeModel` defines an independent first-letter/tail/remainder
  grammar and proves its Boolean evaluator equivalent. `PrincipalScheme`
  connects byte leaves, the bounded source loop and entry point to that grammar.
- `ScopeTrustSafety`, `ScopeTrustCollection` and `ScopeTrustSelectors` carry
  scope validity from actual per-rule decoding through the entire successful
  trust collection into both actual all-view status ports. These are source
  safety/composition obligations, with evidence authentication still separate.

Translation inventory counts and generated artifacts for the expanded
`status_trust` root are intentionally pending the final translation/check phase.
The new batch is not registered as achieved assurance until that phase passes.

The next E4 reference batch is also written in
`formal/Auths/Product/AdmissionHistory.lean` and `AdmissionOwnership.lean`.
It models arbitrary finite worker interleavings, duplicate-debit aggregation,
monotone collection fences, retained historical capacity, committed-but-lost
acknowledgements, process crashes, read-only recovery and one-use entry.
The stated invariants cover historical capacity and unique operation entry.
These modules await the final checking pass and source/store correspondence;
they do not yet establish the complete shipping admission or connection/driver
claims. No new public assurance claim is registered from unchecked modules.

The gateway claim API documentation now matches the PostgreSQL/store contract:
a returned storage error grants no execution handle, but may follow a committed
batch whose acknowledgement was lost. It no longer promises that every error
implies nothing was stored. Retries keep the same logical identity. The new
history model explicitly distinguishes this committed/no-handle outcome.

`AdmissionExamples.lean` adds executable-model witness statements for available
capacity, commit-before-lost-acknowledgement, refused replay ownership changes,
shared capacity exhaustion, no crash refunds, collection followed by an earlier
cutoff, and one-use entry. These are written and awaiting the deferred check
phase alongside their general history invariants and source-binding work.

E3 field-binding implementation is being included in the same coding batch.
The shipping recipe compiler now resolves names through the extractable
`auths-gateway-kernel::construct::field_index` leaf. It snapshots schema names
once in BTreeMap key order, preserving the existing verified-argument order.
The leaf uses exact byte equality and first-match indexed lookup; a test-only
iterator oracle covers duplicate, absent, empty, case-distinct and arbitrary
byte names. The independent named/positional correspondence model and actual
leaf refinement are next; full JSON/source/lock/driver correspondence remains
outside this component until separately composed and checked.

E3 source/lock ambiguity is now rejected by the shipping compiler before typed
parsing: duplicate decoded member names at any nesting depth, including escaped
spellings, produce the existing invalid-source/invalid-lock classification.
Previously a nested map could collapse duplicate names before validation.
The input byte bounds and serde_json recursion limit remain in force; valid
source/lock bytes retain their existing typed interpretation and digest.
The strict parser and its nested/escaped/trailing/depth cases are written and
await the final test pass. This strengthens the runtime boundary; it is not a
new claim that serde_json or canonicalization has been formally verified.

`SchemaIndex.lean` and `Refinement/SchemaIndex.lean` now contain the written
named-field grammar, exact first-match position, named/positional alignment,
undeclared-field refusal, preserved field rendering and actual indexed-leaf
refinement obligations. The gateway extraction roots now include `field_index`.
As with the rest of this implementation-first batch, generated symbol shapes,
proof elaboration, inventories, checksums and native/hosted checks are deferred
to the final pass; these files are not yet achieved assurance evidence.

E4/E5 logical identity now has shipping extractable leaves in the gateway
kernel. Namespace/operation token validation delegates to the exact bounded
ASCII byte scan; the gateway key hashes the leaf's explicit domain/namespace/
NUL/operation preimage. Validated wire behavior and digest framing are preserved.
No challenge, actor, recipe or case version enters the logical identity.
Independent token and framing oracles accompany the cutover. Token validity,
NUL-free separation and preimage-injectivity proofs are being written; hash
security remains an explicitly separate cryptographic contract.

`OperationIdentity.lean` and `Refinement/OperationIdentity.lean` now contain the
written independent token grammar, token-implies-NUL-free property, first-NUL
separator argument, exact preimage injectivity on validated namespace bytes,
and shipping token/preimage leaf refinements. The actual operation-key caller
now has an independent former incremental-hash oracle, including maximum
namespace/operation lengths. New caller/parser source files are explicitly
included in the source-closure inventory. This inventories their bytes without
pretending that hashing the source proves compiler/driver correspondence.


### 13.12 Batch implementation and verification — 16 October 2026

Following the request to code larger batches and defer full qualification,
the expanded implementation was written first and checked together. The full
Lean build passes for the initial expanded batch (721 inventoried statements),
and its compiled audit preserves all 671 previous declaration records exactly.
All compiled dependencies use only the three permitted foundational axioms;
there are no new opaque Auths algorithm assumptions or admitted proof terms.
This is compilation/audit evidence, not a completed translation qualification.

The affected native crates pass 325 library tests: 39 codec, 42 model, 22 gateway
kernel, and 222 gateway (26 gateway tests retain their existing ignored status).
The gateway tests were rerun with local socket access after the restricted
sandbox refused their listeners. New differential cases include every Unicode
scalar for principal IDs, exact status-trust result/cursor parity, exhaustive
one/two-byte token validation, field lookup, unchanged logical-operation key
framing, and nested/escaped duplicate JSON members. The duplicate-member
correction is exercised through both real source and profile-lock compilation.
The expanded xtask builds; affected-crate linting passes after preserving the
extractable scalar classifier with a narrowly documented style-lint allowance.

The next composition batch also connects the complete PrincipalId constructor
to the existing Unicode and new scheme policies, and connects native namespace
validation and native preimage production to exact namespace/operation binding.
It strengthens the lost-acknowledgement model statement to grant no handle in
any well-formed fresh-claim state, and includes the pre-commit-failure/retry and
terminal-refusal-without-capacity examples. These additions undergo the same
compiled statement audit before updating the reviewed inventory digest.

Remaining qualification work includes regenerating the final changed-source
translations, two reproducible complete translations, checksum/freeze and
coverage updates, compiled statement/constant review, and exact-revision hosted
gates. Do not interpret a count of compiled component claims as completion of
E1–E5 or M6. The remaining work in §13.5 still applies, especially complete
object decoding, authenticated verifier/registry composition, full compiler and
I/O correspondence, and actual reservation/backend refinement of the history
model. The existing runtime capabilities are not being declared absent.


### 13.13 Composed bounded-claim reference history

`BoundedClaimHistory.lean` combines the existing chain/count/ceiling/partition-
sum evaluator with durable claims and one-use worker handles for one fixed
window. Every arrival may carry a different chain and capacities: this removes
the fixed per-counter capacity limitation of the earlier small reference.
Lost acknowledgements still charge the admitted chain; crashes and read-only
recovery retain charges; occupied logical identities cannot charge again;
collection closes that window against subsequent admissions. The model uses
an atomic admission/claim step and retains historical charges separately from
physical slot deletion. It does not assume that the shipping reservation
protocol has already been proved to linearize to that step.

The finite-history invariant simultaneously preserves per-link count limits,
ceiling/count spending bounds, partition sum limits and one-use claim
ownership. Two kernel-checked concrete histories show useful delegation after
a lost acknowledgement, shared root capacity exhaustion, and read-only
recovery refusing to reissue the lost handle while the acknowledged delegate
can enter exactly once. This is independent model/composition evidence,
linked to the already proved bounded-policy semantics. Actual counter
derivation, frontier/conflict retry, claim-batch/backend linearization and
driver entry correspondence still require source proofs under §13.5.

The final changed-source scope and gateway units have also been re-extracted
and translated strictly from the current Rust. Their executable Lean bodies
are unchanged from the bodies used for the expanded proofs; only generated
source-location comments change. There are 62 scope-unit functions (25 local,
37 foreign) and 135 gateway functions, with zero opaque Auths bodies in either.
This focused comparison is not the required two full translation
reproductions or an exact-revision hosted qualification result.


### 13.14 Concurrent frontier source batch

The actual store `frontier` loop now delegates its interval decisions to
`auths-gateway-kernel::frontier::FrontierSearch` while retaining each storage
read and error at the runtime boundary. The independent model proves shrinking
intervals and termination within 64 read transitions over the entire u64 bound,
for arbitrary answers. With an append-only occupied-prefix contract, stale
reads produce a candidate at most the latest frontier; a successful atomic
insertion at a still-free candidate therefore inserts at exactly that frontier.
This is the concurrency argument needed before composing conflict retries and
claim/slot batching, rather than assuming a stable snapshot during search.

The new pure methods have strict transparent translations in the expanded
139-function gateway unit. Native comparisons cover every prefix up to 256,
every sparse 16-slot map, exact previous-loop read order, full-width bounds,
and changing monotone prefixes. The shipping loop uses the same probe, read
and observation order. The formal source-method bridges and their composed
answer-trace work bound are being checked as a batch. The trace is proof-owned;
the complete runtime read/transaction correspondence remains an E4 obligation.
The shared store's existing collection/admission fence is retained.


The frontier source-method bridges now compile on every represented source
state, including arithmetic safety. The proof-owned composition of actual Rust
methods also establishes the 64-read bound. The kernel's 24 library tests pass,
as do the gateway's 222 library tests after the shipping store refactor (26
retain their existing ignored status); affected-crate linting passes. The
expanded main inventory and final transitive axiom review are checked next.
The gateway source boundary is 139 local functions, zero external functions,
with the four new methods explicitly inventoried and no opaque Auths bodies.
Full translation reproduction and exact-revision hosted gates remain deferred.


### 13.15 Compiled statement identities in coverage

The full batch build and compiled audit pass at 741 declarations, preserving
all 671 previous complete records and allowing only the three established
foundational axioms. Full qualification caught a reporting defect: method dot
notation in Lean's displayed statements could hide the translated function's
qualified name. Coverage version 2 therefore uses the compiler's canonical
statement constants for live theorem mentions, and refuses live audits that
omit them. Historical study fixtures retain their original text scanner and
must still reproduce byte-identically. A regression also prevents printed
function-name text without a corresponding compiled constant from creating a
coverage edge.

Canonical identities add the actual lifecycle terminal-method claim and the
new composed status/frontier statements to the proper classifications. The
codec identifier helper's imported copy is no longer credited as a directly
named locally owned function merely because a suffix resembles the owner's
name. Its assurance source claim and transparent translation remain intact;
the owning model function retains its own audited refinements. This follows
the existing ownership rule, without adding denominator rows for imports or
relabelling the source claim as a model. Qualification and publication are
rerun after this reporting correction; E1–E5/M6 remain scoped as above.


### 13.16 Qualified 741-claim checkpoint

The complete batched qualification now passes after the coverage correction:
741 compiled/audited statements, all 671 previous complete records unchanged,
18/18 qualification cases, 24 reviewed external models, zero unreviewed models,
zero compiled external axioms and two byte-identical clean full translations.
Reviewed statement inventory:
`adba8d153e4bb16ed387ba05c9f102a36650a6a7e4e0e899180935726ad34852`.
Shipping source closure:
`f9041056a71f53030c45a3a9e0c4208da53fc5a56d26b03466ef119e54104549`.
Closed qualification boundary:
`89cbb9637b4ac2abe8d319601c55f89a69723633f9f1eae4a78a29ef549fd0f4`.
Affected native library tests: 327 passed; 26 gateway tests remain ignored.
Coverage regression/historical checks: 6 passed. Affected-crate linting and the
xtask build pass. Coverage v2 records 133/1046 decision functions,
1814/11544 decision code lines and 23/82 check sites in their declared scopes.

This saves the implementation-first batch; it does not finish §13.5 or any
whole E1–E5/M6 milestone. Exact-revision hosted gates remain required. The next
counter/slot commitment-framing slice is prepared separately: its independent
byte-framing injectivity model compiles, prototype byte-parity tests pass, and
its actual Rust prototype translates after replacing unsupported nested borrows
with fixed-field composition. It has not yet been cut over into production or
added to this qualified inventory. Continue with that source/primitive bridge,
then actual counter derivation and reservation/backend correspondence.


### 13.17 Counter and slot framing batch — qualified 757-claim checkpoint

The production counter/slot hashing callers now consume pure kernel builders for the exact preimages. The count/sum tags, eight-byte component lengths, namespace, link subject, evaluator, partition, fixed-window coordinates, 32-byte counter IDs and slot words are preserved. A frozen native incremental-hash oracle checks the actual callers, including Unicode, empty/unpartitioned values, embedded NUL and u64 boundaries. The pure kernel has 26 passing tests, and the affected Rust targets pass clippy.

The complete Lean build passes with 16 new inventoried results: exact source framing helpers and all four public builders, source-output identity binding for count/sum, independent counter/slot framing injectivity, and explicit framing-size bounds. Count and sum frames are at most 774 and 844 bytes on the production size domain. Hash equality is not assumed to imply preimage equality. The two existing standard checked-conversion/Result definitions were moved unchanged into a minimal shared bridge so gateway proofs do not import unrelated string/sort models.

The final audit qualifies **757 claims**, with all 741 previous complete declaration records unchanged, no unexpected axioms, **25 reviewed models**, zero unreviewed/compiled external axioms, **18/18 cases**, and **two byte-identical clean full translations**. Source closure: `8701bdf464825fa990591db6833a3b35dc58806769a80520651dcade26968222`. Statement review: `ap-spec-069-counter-slot-framing-2026-10-16`; inventory digest: `2709ec4fbc2601760e0937ff445a361dcb4b99fb866ea5ca3b573293858fab3d`; boundary contract: `cb3d1bff851332bd0f01c207b6b551a99c276beb4d0cc3022190b8db49593a4b`. All 224 active gateway tests and 26 kernel tests pass; the 26 existing ignored gateway tests are unchanged. Hosted exact-revision evidence remains required. Counter aggregation and runtime/backend correspondence remain open; a separate keyed-minimum aggregation prototype is prepared and is not part of this checkpoint.


### 13.18 Count and sum aggregation — qualified in the 798-claim checkpoint

The actual count-counter derivation now computes its existing namespace/subject/window keys and consumes a pure kernel aggregator. Source proofs cover exact public 32-byte ID equality, first-match lookup, first-key capacity tightening, and the complete contribution loop on the admitted 16-link domain. The complete Lean build passes with these results included. The actual loop earns unique IDs from its own empty state and matches an independent pointwise minimum-capacity specification for every key, without assuming a caller-provided uniqueness invariant or desired result.

Native parity compares the complete shipping chain derivation—including sorted count/sum records and sum slot bounds—to the frozen preceding implementation across repeated subjects, limits, partitions, partial zip inputs and extreme window coordinates. All 225 active gateway tests and the count kernel tests pass. The final combined count/sum/retry run passes 225 active gateway tests and 33 kernel tests. Literal formatting and checked test-index conversions corrected the focused lint findings; affected-target clippy now passes.

Sum aggregation now uses the same source-proved minimum-capacity semantics and explicitly retains the first count-slot bound. Both actual source loops and their global uniqueness/capacity corollaries compile in the complete Lean build. The combined final qualification passes with **798 compiled claims**, all 757 preceding complete declaration records unchanged, 25 reviewed models, zero unreviewed/compiled external axioms, 18/18 cases and two byte-identical clean full translations. Source closure: `d75d2be54aeef9a943fb35736ead1ff024ffe838c11565c10f9ef647b99193c4`. Statement review: `ap-spec-069-counter-aggregation-retries-2026-10-16`; inventory digest: `ebf3c737a69822f3d0ead1c0d656565c1af5138cf47b7fcc2a05784f4e7a0a17`; boundary contract: `cae0940641d0ad3ad51cebd5e091ce76771f6c67561ee40486e6045abb11471d`. Hosted exact-revision evidence remains required. The caller's authenticated-chain-to-contribution mapping, count/sum coupling, atomic store admission and full runtime/history composition remain separate E4 obligations.


### 13.19 Reservation retry interpretation — qualified in the 798-claim checkpoint

The shipping reservation loop now consumes a pure, total conflict interpreter. A conflict on entry zero is always Replay. Count conflicts advance exactly the identified count frontier. Sum conflicts read the exact conflicting slot before advancing, and validate the sum frontier, total and counter vector positions. Checked additions turn a corrupt maximal frontier into a typed Corrupt error instead of relying on an implicit arithmetic precondition. These branches grant no execution handle; the existing atomic-insert success remains the sole successful reservation path.

The sum-slot availability check now reuses the already proved chain-count predicate, including its exact vector-length check, rather than relying on a truncating zip. Existing admitted inputs retain their previous behavior. Native boundary tests cover batch ordering, missing vectors, invalid/maximum indices and word limits. The complete model/source retry refinement and replay/progress corollaries compile in the full Lean build. The complete combined batch passes the qualification recorded in §13.18. This does not yet close store linearization, cumulative-record decoding, claim-batch construction or full driver/history correspondence.


### 13.20 Complete slot-batch construction — shipping cutover in progress

The preceding shipping constructor paired count/sum metadata and frontiers using
zip. Its callers supply matching vectors; the new source cut makes that
invariant explicit and checked. A pure kernel constructor rejects
mismatched lengths, per-kind cardinalities above 16 and cumulative overflow,
then describes exactly one claim first, every count slot and every sum slot in
the order interpreted by the retry primitive. Both native boundary tests pass and the prototype translates without opaque
Auths code. The independent model establishes claim-first ordering, complete
entry count and at most 33 entries on success. The complete all-input source
constructor proof and both source loops compile, including a checked bridge
from the tail-recursive sum model to the independent list specification.

Shipping claim-batch assembly now consumes these complete descriptions to build
counter metadata and every canonical claim/slot record. The per-kind bound is
shared with the gateway chain limit. Its outputs
are record descriptions, not authorization or execution capabilities. The
cutover must retain the existing canonical record fields, counter
metadata, slot keys, expiries and all-or-none store insertion, and has passed
complete source/compiled review, native parity and final qualification. The
preceding complete shipping constructor is retained only as a frozen native
test oracle; mismatched-vector tests require a Corrupt refusal.


The slot-batch cutover's complete Lean build passes with **809 compiled claims**,
including all 798 preceding complete declaration records unchanged and no new
axioms. The 11 new reviewed statements include both actual source loops, a
checked operational-to-independent sum bridge, the complete all-input builder,
claim-first ordering, exact complete entry count and malformed-shape refusal.
All 227 active gateway tests, 35 kernel tests and affected-target clippy pass.
The complete shipping parity oracle covers all 289 aligned count/sum layouts,
checking canonical record bytes, every slot key and expiry. Mismatched vectors
must return Corrupt. An extraction experiment showed the idiomatic question-mark
form introduces two additional ordinary Try/FromResidual interfaces; the
explicit Some/None branch is retained with a narrowly documented lint allowance
so this component adds no external translation interface. Final qualification
replay passes as recorded below.


The coverage publication check exposed a tooling defect: numbered generated
loop wrappers were classified as whole Rust functions by a suffix heuristic.
Coverage tool version 3 consumes the translator's explicit loop metadata and
retains the historical fallback. All seven focused regression checks pass and
the pinned study still reproduces byte-identically. The published primary
measurement remains 133/1046 functions, 1814/11544 lines and 23/82 check sites;
no denominator or source claim was weakened to bypass the check.


The final slot-batch qualification passes: **809 compiled/audited claims**, all
798 preceding complete declaration records unchanged, **18/18 cases**, **25
reviewed models**, none unreviewed, no compiled external axioms, and two clean
full translations reproduced byte-identically. Source closure:
`339d80930b9e3b5cb85900bd15713284f49802820a7225c7d44afa5792a43d9e`.
Statement review: `ap-spec-069-complete-slot-batch-2026-10-16`; inventory digest:
`34b188789792dec4d1f15d74dc1e4f6900c2a78d5df6ef2e5184ec28aa1f68b4`;
boundary contract:
`fe1d1bedb6696b3346517bd2de9771cd6a5fac12586d897f71edfb410ef2be02`.
Actual backend atomicity, JSON decoding, authenticated caller mapping and full
runtime/history correspondence remain separate obligations. The next source
component validates the decoded cumulative sum-slot projection against the
exact schema, counter ID, slot and delta/cumulative relation. No complete
E1–E5/M6 milestone or exact-revision hosted evidence is claimed.


### 13.21 Decoded cumulative records and count/sum coupling — implementation batch

The shipping cumulative reader now calls a pure translated validator after its
existing storage lookup and strict serde decoding. The validator checks exact
schema bytes, the complete canonical lowercase encoding of the 32-byte counter,
the requested slot, and delta no larger than the returned cumulative total.
The independent model proves byte-domain counter-encoding injectivity. The
complete actual comparison loop and validator have all-input source proofs,
with accepted-record identity/numeric binding and invalid-record refusal.
JSON parsing, authenticated storage, append-only histories and backend
linearization remain separate obligations.

The count/sum coupling now uses an actual pure first-key capacity lookup and a
linked sum-contribution constructor. Their exact source refinements compose
with the actual count aggregator: a sum contribution's slot bound is earned
from the shared count-key minimum, without assuming input uniqueness or a
precomputed minimum. Both IDs remain explicit inputs; complete authenticated
ID derivation and the full caller graph remain open.

The new proofs compile individually. The complete batch build/audit and final
clean replay pass as recorded in §13.23. Native checks pass: 229 active gateway tests,
38 kernel tests and affected-target/xtask linting; 26 existing ignored gateway
tests remain unchanged. The shipping cumulative-reader parity oracle checks
486 decoded combinations through the actual file-store lookup and serde path,
plus missing/malformed/duplicate-field/word-boundary cases. Kernel tests cover
all 256 repeated counter byte values and every encoded digit mutation. A real
source success witness qualifies a valid cumulative record. Shared byte-equality
and hex-digit proofs were extracted into a minimal proof module; existing
public theorem statements are preserved. No new external interface or opaque
Auths function was introduced by either source cutover.


### 13.22 Complete ordered reservation decision — implementation batch

The shipping reservation loop now consumes one pure decision in the existing
bounded-policy kernel. The function combines every count frontier, every sum-slot
frontier and every cumulative sum, preserving window-exhaustion precedence and
the existing stable refusal codes. It neither inserts records nor grants handles.
Its independent specification uses complete pairwise relations over lists,
which earn matching lengths and every applicable numeric bound. The source
proof composes the existing exact count/sum leaves with the complete new guard;
no admission Boolean or desired result is an input premise.

Native parity covers 139,968 combinations of vector shapes, zero/one/u64-max
values and amounts, with 24 bounded-policy library tests passing. Source proofs
also connect Admit to complete vector shapes and u64-safe cumulative additions.
Full batch compilation, statement review, final native replay and qualification
pass as recorded in §13.23. Actual caller identity derivation, backend linearization
and full runtime/history composition remain open as described in §13.5.


### 13.23 Qualified reservation checkpoint — 17 October 2026

The batched implementation qualifies **832 compiled/audited claims**, preserving
all 798 complete declaration records from the previous pushed checkpoint (and
all 821 from the intermediate cumulative/coupling audit). All **18/18 cases**
pass; two clean full translations reproduce byte-identically. There are **25
reviewed external models**, none unreviewed, and zero compiled external axioms.
The new claims retain only the three established foundational axioms.

Production source closure:
`1a07b71048278076845fd283106a674087d05a89d4bd2dd3560c2f17dd99dce5`.
Statement review: `ap-spec-069-complete-reservation-admission-2026-10-17`;
inventory digest:
`2993b22fef971e4247d9fa1eaec1fa4a2bc5a1cbd1f0efa949ee7dd4e95b50ef`;
closed boundary:
`5c0656e2e8da9949ea2fce62426a19d378ed11a53954b9caeb468391009dd156`.

Native validation: **229 active gateway**, **38 gateway-kernel** and **24
bounded-policy** library tests pass; 26 existing ignored gateway tests are
unchanged. Affected-target and xtask linting pass. The final capacity-view
refactor computes named count/sum/slot limits once per reservation, retaining
them across retries; the final store aggregate scenarios pass. The decoded
reader's test fixtures use the real expiry envelope and independently require
18 successful cases and 468 refusals, preventing parity from passing vacuously
at the outer file decoder. Every malformed-record mutation starts from an
accepted complete record. Source qualification includes useful acceptance and
refusal witnesses. Historical study reproduction remains byte-identical;
coverage v3 measures 134/1047 decision functions, 1833/11563 code lines and
23/82 check sites in the declared scopes.

These results complete the source components in §§13.20–13.22. They do not
complete the whole §13.5/E1–E5/M6 program. Authenticated caller mapping, actual
backend/linearization correspondence, full runtime/history composition and
exact-revision hosted evidence remain open. Connection-entry workload/profile
membership is prepared separately as a private prototype; it has not yet been
cut over into shipping code or included in this qualified inventory. Continue
from that component and the remaining-program table without redoing these
completed proofs or waiting for GitHub CI during implementation.


### 13.24 Connection-entry membership — implementation batch

The shipping connection-entry check now calls a pure predicate over explicit
administrative state, workload bytes and full profile identifier/version pairs.
Both list scans have exact source refinements; a positive result earns active
state and both exact memberships. Disabled and revoked inputs always refuse,
including when their lists contain the request. The runtime's unchanged-record
comparison now consumes the previously proved exact-byte equality primitive.

The native adapter preserves the preceding full expression on 1,728 queries
against constructor-valid connection records: 126 positive and 1,602 negative
cases cover all states, workload case differences, absent identifiers and
profile-version mismatches. Every byte mutation of a canonical loaded record
changes the reload comparison. Projection allocations are bounded by the
connection constructor's existing workload/profile limits. Source qualification
includes useful positive, disabled and version-mismatch witnesses. This batch
also moves the reservation-loop comment back onto its intended function.

Complete qualification passes as recorded below. The record-to-projection mapping, complete
record decoder, actual reload/lease/write association and full E4.6 runtime
composition remain separate obligations. This predicate supplies necessary
entry checks, not an execution handle. The remaining §13.5 program and hosted
exact-revision gates are unchanged.


The final connection-entry batch qualifies **838 compiled/audited claims**,
with all 832 preceding complete declaration records unchanged and no new axioms.
The full 3,510-job Lean build, 18/18 qualification cases and two byte-identical
clean full translations pass. The inventory remains 25 reviewed models, none
unreviewed, with zero compiled external axioms. Native checks pass: 231 active
gateway tests, 39 kernel tests and affected-target/xtask linting; the existing
26 ignored gateway tests remain unchanged. The earlier 24 bounded-policy tests
are unchanged by this component. The semantic-closure manifest explicitly
includes the new kernel file and all earlier extracted modules.

Shipping source closure:
`dbdeafb8829de25fd97cdee75384bf275314efc725134b4fb388e1681a72a141`.
Statement review: `ap-spec-069-connection-entry-membership-2026-10-17`;
inventory digest:
`6b5d83e724e9cc0fc1eb6875881fe8e20f91df46e60176164b3311fd601e7eff`;
boundary:
`327f3b20152464c5d7e9d6d6295cdb47c576b24a1a00fd88c12d7414ac82a6ed`.
Coverage remains 134/1047 decision functions, 1833/11563 code lines and 23/82
check sites, with byte-identical historical reproduction. Hosted evidence and
the whole E1–E5/M6 program remain open. Constructor byte predicates are prepared
privately for the next component; they are not yet qualified shipping code.

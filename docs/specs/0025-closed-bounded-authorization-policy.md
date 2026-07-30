# AP-SPEC-025: Closed bounded-authorization policy contract

**Status:** Specified — implementation requires a separate Milestone 3 PR

**Evidence:** Seven-domain semantic inventory
`docs/research/domains/0003-seven-domain-bounded-authorization-semantic-inventory.md`

**Scope:** Pure product-layer policy commitments, explicit evaluation inputs,
checked bounds, eligibility outputs, tightening laws, and conformance

**Normative language:** **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are
requirements on conforming implementations.

## 1. Decision

Auths will implement a narrow product-layer semantic center for bounded
authorization. It binds immutable evaluator meaning to explicit inputs and
typed outputs without defining a universal policy language or provider
runtime.

The contract is:

```text
core-authorized exact action commitment
                +
closed domain policy and evaluator commitment
                +
canonical action, evidence and state commitments
                +
explicit verifier time
                +
required/executed configuration equality
                |
                v
eligible(reservation-intent commitment, obligation commitment)
| denied(domain stable code and stage)
| indeterminate(domain stable code and stage)
```

`eligible` is not execution authorization. Durable reservation, execution
intent, credentials, provider calls, outcome uncertainty, and reconciliation
are governed by Milestone 4 and domain specifications.

## 2. Goals

The implementation MUST:

- make policy/evaluator meaning immutable and content-bound;
- make every security-relevant input explicit;
- fail closed on required/executed mismatch;
- use closed, bounded, versioned domain evaluators;
- use checked arithmetic and explicit dimensions;
- retain domain-owned actions, evidence, codes, intents, obligations, and
  receipts;
- prove fixed-context tightening cannot expand eligibility or undercount
  required outputs;
- mechanically connect shipping pure Rust to Lean;
- preserve exact existing domain decisions during later migration.

## 3. Non-goals

This specification MUST NOT introduce:

- an expression language;
- arbitrary policy callbacks or plugins;
- a generic action/provider request union;
- a generic evidence schema or freshness policy;
- mutable reservation transitions or a store;
- credentials, gateways, provider retries, or reconciliation;
- a universal receipt payload;
- changes to core proof or canonical CBOR meaning;
- a hosted policy service required for verification.

## 4. Architectural ownership

The shared implementation belongs under `product/`, not `core/`.

`core/` continues to own proof validity, rich immutable authority,
attenuation, action commitment, and portable verification.

The shared product package may own:

- fixed policy/evaluator/configuration commitment carriers;
- explicit evaluation commitment carriers;
- checked unit/arithmetic and bounded-collection leaves;
- result-class and stable-code/stage carriers;
- reservation/obligation commitment mechanics;
- receipt envelope commitment mechanics;
- conformance registration and differential tooling.

Each domain permanently owns:

- policy, action, evidence, and configuration payload types;
- evaluator entry points and tightening deciders;
- domain stable codes and diagnostic order;
- reservation intent and obligation payloads;
- verified commands, gateways, credentials, and provider behavior;
- mutable state, observation, reconciliation, and canonical receipt payloads.

No shared production package may import a provider SDK or demo package.

## 5. Identity types and hard limits

All identifiers are validated ASCII and compared byte-for-byte.

The following V1 semantic identities are reserved:

| Surface | Identity |
| --- | --- |
| Contract | `auths.product.bounded-policy-contract/1` |
| Policy commitment carrier | `auths.product.policy-commitment/1` |
| Evaluation commitment carrier | `auths.product.evaluation-commitments/1` |
| Configuration equality gate | `auths.product.configuration-match/1` |
| Eligibility envelope | `auths.product.eligibility/1` |
| Checked arithmetic laws | `auths.product.checked-arithmetic/1` |
| Decision receipt envelope | `auths.product.bounded-decision-envelope/1` |
| Compatibility rules | `auths.product.bounded-policy-compatibility/1` |

These names reserve meaning; they do not claim implementation. Domain policy
and evaluator identifiers remain those registered by each domain.

| Value | Maximum |
| --- | ---: |
| Policy type identifier | 128 bytes |
| Evaluator semantic identifier | 128 bytes |
| Canonicalization identifier | 64 bytes |
| Configuration semantic identifier | 128 bytes |
| Stable code | 96 bytes |
| Stable stage | 64 bytes |
| Unit identifier | 64 bytes |
| Obligation identifier | 96 bytes |
| Reservation-intent identifier | 96 bytes |
| Policy/evidence/action/state bytes accepted by conformance tooling | 1 MiB each |
| Reservation intents returned by one evaluation | 32 |
| Obligations returned by one evaluation | 32 |
| Combined canonical intent/obligation bytes | 64 KiB |
| Nested canonical product-policy depth | 16 |

Identifiers MUST be non-empty, use a documented restricted character set, and
reject normalization aliases. Unknown versions, unknown fields, duplicate
keys/items, invalid ordering, invalid UTF-8, over-limit values, and
non-canonical bytes fail closed.

Limits are V1 protocol/product limits. Changing them requires a new compatible
implementation version and review; changing semantic meaning requires a new
semantic identifier.

## 6. Policy commitment

The logical carrier is:

```text
PolicyCommitmentV1 {
  policy_type
  policy_version
  canonicalization_id
  policy_digest
  evaluator_semantic_id
}
```

Requirements:

1. `policy_digest` is a 32-byte digest over domain-separated canonical policy
   bytes.
2. `policy_type` and `policy_version` select one closed schema.
3. `canonicalization_id` selects one immutable encoding/normalization
   algorithm.
4. `evaluator_semantic_id` selects one immutable total decision function.
5. A mutable policy name MUST NOT authorize an effect.
6. Policy bytes MAY be carried or content-addressed, but resolution MUST open
   to the committed digest before evaluation.
7. Changing boundary, rounding, missing-data, freshness, tightening, or output
   meaning requires a new evaluator semantic identifier.

Implementation/build provenance is separate. Two builds may claim the same
semantic identifier only after both refine that exact contract. Receipts still
record which implementation ran.

## 7. Explicit evaluation commitments

The shared carrier binds:

```text
EvaluationCommitmentsV1 {
  profile_id
  exact_action_digest
  policy_commitment
  evidence_schema_id
  evidence_digest
  evidence_source_id
  evidence_observed_at
  state_snapshot_schema_id
  state_snapshot_digest
  verifier_time
  required_configuration
  executed_configuration
}
```

The carrier contains commitments, not domain payloads.

The evaluator MUST NOT read a hidden clock, environment variable, network,
filesystem, credential, or mutable global. Domain code validates and supplies
typed action, policy, evidence, state snapshot, and time.

The exact action MUST bind the same policy/evaluator/canonicalization and
executor audience required by the authorization context.

## 8. Required and executed configuration

Each configuration commitment binds:

```text
ConfigurationCommitmentV1 {
  semantic_id
  canonicalization_id
  configuration_digest
  implementation_id
}
```

The semantic, canonicalization, and configuration commitments MUST match
before an evaluator can return `eligible`. If local policy pins an
implementation, the implementation identity MUST also match.

Mismatch returns a domain-projected denial with the shared cause
`configuration-mismatch`. It MUST happen before:

- durable decision/reservation state;
- verified-command construction;
- credential acquisition;
- provider I/O.

Both required and executed commitments MUST appear in the decision receipt.

## 9. Closed domain evaluators

The shared package MUST NOT accept arbitrary callbacks. A conforming evaluator
is registered in a closed machine-readable inventory containing:

- owning package and layer;
- profile and policy identifiers;
- evaluator semantic and implementation identifiers;
- canonicalization identifiers;
- concrete Rust evaluator symbol;
- Lean claim/refinement artifact;
- action, policy, evidence, state, result, intent, obligation, and receipt
  schemas;
- stable codes/stages;
- hard limits;
- fixtures, mutation corpus, fuzz/Kani/property coverage;
- reference evaluator and migration status.

Dispatch is by exact registered identity to a typed domain entry point.
Unregistered identities fail closed. The registry does not erase concrete
types into loosely typed JSON.

## 10. Eligibility result

The logical result is:

```text
EligibilityV1 {
  Eligible {
    reservation_intents_commitment,
    obligations_commitment
  }
  Denied {
    stable_code,
    stage
  }
  Indeterminate {
    stable_code,
    stage
  }
}
```

The three classes are disjoint and exhaustive for validated inputs.

Domain evaluators construct bounded typed intent/obligation sets, then commit
to their canonical bytes. The shared layer MUST NOT interpret their payloads
in Milestone 3.

Denied or indeterminate results have no reservation intents, obligations that
permit execution, execution token, credential, or provider capability.

## 11. Reservation intents

A pure reservation intent describes required state but does not mutate it.
Every intent MUST have:

- a domain/profile-owned schema and semantic identifier;
- a stable intent identifier;
- an exact scope/key commitment;
- an explicit unit or exclusivity kind;
- an exact amount where additive;
- an applicable window commitment where time-scoped;
- an action/policy/evidence commitment;
- canonical bytes and digest.

Milestone 3 only validates boundedness and commitment completeness. Milestone
4 specifies legal transitions, atomic multi-intent reservation, capacity,
expiry, cancellation, unknown outcomes, and reconciliation.

## 12. Obligations

Every obligation is classified as exactly one of:

- pre-execution condition;
- command-construction constraint;
- post-execution observation.

An obligation MUST have a stable identity, domain-owned typed payload,
canonical commitment, and explicit required discharge stage. No projection
may silently drop it.

An execution authorization may exist only after every pre-execution obligation
is discharged and every command obligation is incorporated. Post-execution
obligations remain pending in receipts until observed or reconciled. These
runtime rules are proved in Milestone 4; Milestone 3 proves output completeness
and commitment.

## 13. Checked arithmetic and dimensions

The shared leaves MUST:

- use integers, never floating point;
- use checked addition, subtraction, multiplication, and division;
- reject overflow, underflow, division by zero, and incompatible dimensions;
- identify units explicitly;
- define inclusive/exclusive boundaries;
- define rounding direction;
- use basis points for percentages;
- name the evidence denominator for relative calculations;
- validate fixed/rolling window boundaries;
- hard-bound collection and work complexity.

Currency conversion, pricing, rows, replicas, resources, disclosures, and
provider-specific capacity remain domain semantics.

## 14. Denied versus indeterminate

Shared mechanics do not choose domain vocabulary.

At minimum:

- malformed, unsupported, non-canonical, over-limit, digest-mismatched, and
  required/executed-mismatched input fails closed;
- missing or stale facts are denied or indeterminate exactly as the registered
  evaluator version specifies;
- unknown external truth MUST NOT become empty, zero, or unlimited;
- arithmetic failure is a stable non-eligible result;
- diagnostic ordering is immutable per evaluator version.

## 15. Tightening and result refinement

Every policy version defines:

```text
tightens(child, parent)
result_refines(child_result, parent_result)
```

and proves, for identical action, evidence, state snapshot, time, and
configuration:

```text
tightens(child, parent)
and evaluate(child, context) = eligible(child_result)
implies evaluate(parent, context) = eligible(parent_result)
    and result_refines(child_result, parent_result)
```

Requirements:

- `tightens` is reflexive and transitive over well-formed policies;
- a syntactic decider is proved sound for semantic tightening;
- antisymmetry is required only modulo declared semantic equivalence or
  canonical normal form;
- tightening may add obligations;
- tightening MUST NOT drop or undercount reservation intents required for the
  same action;
- the law is fixed-context only; evidence and mutable state are not generally
  monotone.

There is no universal ordering over arbitrary domain policy payloads.

## 16. Decision receipt envelope

Milestone 3 defines an envelope that commits to:

- envelope schema/version and profile;
- exact action and policy/evaluator commitments;
- evidence and state-snapshot commitments;
- verifier time;
- required and executed configuration;
- eligibility class, stable code, and stage;
- reservation-intent and obligation commitments;
- evaluator implementation/build provenance;
- canonical domain decision-receipt digest;
- optional previous-receipt digest.

The envelope MUST NOT claim provider acceptance, execution, propagation,
convergence, or observed success. Domain receipt bytes remain canonical and
authoritative.

## 17. Records API requirements

The records domain contributes two distinct profiles:

- `auths.demo.records.create/1`;
- `auths.demo.records.read/1`.

They MAY share commitment and arithmetic leaves. They MUST retain separate
actions, evaluator entry points, stable codes, capacity/disclosure intents,
obligations, and receipt payloads.

Identical canonical requests delivered over HTTPS and Iroh MUST produce the
same pure evaluation result and commitments. Transport metadata may appear in
delivery receipts but MUST NOT change policy eligibility unless an explicitly
versioned policy commits to a channel property.

## 18. Formal model and Rust refinement

Add a separate namespace:

```text
formal/Auths/Product/
  Commitment.lean
  Eligibility.lean
  Arithmetic.lean
  Tightening.lean
  Theorems.lean
```

Lean MUST prove:

- commitment/configuration equality laws;
- mismatch cannot yield eligibility;
- deterministic three-way partition;
- checked arithmetic and boundary laws;
- intent/obligation commitment completeness;
- fixed-context semantic tightening;
- registered concrete evaluator laws.

The shipping pure Rust reference implementation MUST be mechanically
translated with the qualified Aeneas route and proved to refine the Lean
semantics. Independently handwritten matching examples are insufficient.

Kani, property, mutation, fuzz, and fixture tests remain defense in depth and
must be described accurately as bounded/tested evidence.

## 19. Conformance and mutation

Every evaluator version MUST register:

- valid, exact-boundary, boundary-plus-one, malformed, stale, contradictory,
  and configuration-mismatch fixtures;
- required/executed evaluator and configuration mutations;
- zero, one, maximum integer, maximum collection, and maximum byte cases;
- overflow/underflow and rounding cases;
- tightening positive and counterexample cases;
- intent/obligation deletion and alteration mutations;
- native reference-versus-shipping differential vectors;
- Lean-refinement evidence;
- Kani/property/fuzz targets;
- stable work/allocation counters.

CI MUST reject fixture, registry, theorem, translated-source, source-closure,
or semantic-identity drift.

## 20. Compatibility and migration

Milestone 3 adds a reference implementation and conformance contract. It MUST
NOT immediately replace domain evaluators.

Milestone 5 migrates in this order:

1. Stripe;
2. Kubernetes;
3. PostgreSQL;
4. OpenTofu;
5. GitHub;
6. Radicle;
7. records create/read.

For each domain:

- retain the original pure evaluator as a test-only oracle;
- feed identical canonical inputs to old and new paths;
- require exact class, code, stage, calculations, intent/obligation
  commitments, and unchanged receipt bytes;
- retain minimized mismatch seeds;
- retain domain provider/lifecycle code;
- remove duplicate production evaluation only after complete CI;
- preserve a rollback path that does not reinterpret persisted state.

## 21. Implementation sequence

The Milestone 3 implementation PR series MUST proceed:

1. commitment, identifier, checked arithmetic, and hard-limit carriers;
2. explicit evaluation commitments and configuration gate;
3. eligibility/intent/obligation commitment envelope;
4. formal product model and Aeneas-linked Rust reference;
5. evaluator registry and conformance tooling;
6. concrete evaluator law/refinement registrations without production
   migration.

Each semantic tranche requires its specification commit first. No PR may mix
mutable Milestone 4 state or Milestone 5 domain migration into this series.

## 22. Acceptance criteria

Milestone 3 is complete only when:

- architecture and compliance register the shared product package;
- all public inputs are closed, typed, canonical, and hard bounded;
- every identifier has immutable versioned meaning;
- required/executed mismatch fails before eligibility and protected effects;
- eligible binds complete typed intent/obligation commitments;
- every registered evaluator proves deterministic partition, arithmetic,
  freshness, and fixed-context tightening laws;
- shipping pure Rust is mechanically linked to Lean;
- all seven domain reference corpora pass unchanged;
- records HTTPS/Iroh evaluation parity passes for create and read;
- mutation tests kill every registered semantic operator change;
- no provider SDK, credential, mutable store, or demo dependency enters the
  package;
- benchmark work/allocation counters are deterministic;
- formal, architecture, compliance, conformance, secrets, and dependency-aware
  CI pass on the exact revision.

## 23. Residual assumptions

This specification does not prove:

- canonical codec or cryptographic correctness beyond their existing boundary;
- evidence truth or acquisition;
- durable-store linearizability;
- credential broker correctness;
- external provider behavior;
- execution, observation, or reconciliation.

Those assumptions remain explicit in receipts and assurance manifests.

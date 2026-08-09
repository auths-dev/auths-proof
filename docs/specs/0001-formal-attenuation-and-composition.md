# AP-SPEC-001: Formal Attenuation and Composition Semantics

**Status:** Proposed
**Intended audience:** protocol authors, core implementers, auditors, and
independent verifier implementers
**Normative language:** the terms **MUST**, **MUST NOT**, **SHOULD**, and
**MAY** are to be interpreted as requirements on the implementation described
by this specification
**Scope:** Auths-Proof target V1 authority attenuation, action coverage,
three-valued authorization-plan composition, and verifier-local composition
requirements

## Abstract

This specification defines a machine-checked mathematical model for the two
closed algebras at the center of Auths-Proof:

1. authority attenuation along a trust-anchor-to-action chain; and
2. deterministic composition of authorized, denied, and indeterminate
   branches.

The formal model is authoritative for algebraic laws, not for wire encoding or
cryptographic validity. It is implemented in Lean 4, connected to the Rust
kernel through generated conformance vectors, and supplemented by bounded
model checking of the Rust implementation. The work is complete only when the
theorems in this document are proved, the Rust refinement suite agrees with the
formal evaluator, and every counterexample is reproducible as a minimized
repository artifact.

## 1. Existing implementation and authority boundary

The specification refines, rather than replaces, these current components:

| Concern | Current source |
| --- | --- |
| Effective chain state and grant application | [`core/crates/auths-authority/src/lib.rs`](../../core/crates/auths-authority/src/lib.rs), `EffectiveAuthority::delegate` |
| Terminal action coverage | [`core/crates/auths-authority/src/lib.rs`](../../core/crates/auths-authority/src/lib.rs), `EffectiveAuthority::authorizes` |
| Body-digest constraint ordering | [`core/crates/auths-model/src/lib.rs`](../../core/crates/auths-model/src/lib.rs), `ActionConstraint::attenuates` |
| Budget ordering | [`core/crates/auths-model/src/lib.rs`](../../core/crates/auths-model/src/lib.rs), `BudgetCeiling::attenuates` |
| Status ordering | [`core/crates/auths-authority/src/lib.rs`](../../core/crates/auths-authority/src/lib.rs), `status_attenuates` |
| Canonical plan construction and bounds | [`core/crates/auths-model/src/lib.rs`](../../core/crates/auths-model/src/lib.rs), `AuthorizationPlan` |
| Three-valued plan evaluation | [`core/crates/auths-composition/src/lib.rs`](../../core/crates/auths-composition/src/lib.rs), `evaluate` |
| Verifier-local branch and diversity floors | [`core/crates/auths-model/src/lib.rs`](../../core/crates/auths-model/src/lib.rs), `CompositionRequirement` |
| Integration into staged verification | [`core/crates/auths-verifier/src/lib.rs`](../../core/crates/auths-verifier/src/lib.rs), `verify_authority_measured` and `verify_branch_from_anchor` |
| Current property tests | [`core/crates/auths-composition/src/lib.rs`](../../core/crates/auths-composition/src/lib.rs), `tests` |

The formal project MUST NOT import networking, storage, custody, clocks, or
application-profile behavior. Cryptographic verification is represented by
already-classified leaf outcomes. This preserves the current kernel boundary:

```text
signed bytes + trusted context
              |
              v
    cryptographic/control checks
              |
              v
     formal authority branch
              |
              v
  formal three-valued composition
              |
              v
 A | Denied(code) | Indeterminate(code)
```

## 2. Goals and non-goals

### 2.1 Goals

The project MUST:

- give every attenuation dimension an explicit carrier set and ordering;
- prove that accepted delegation is monotone and cannot widen authority;
- prove that action authorization implies coverage by the terminal effective
  authority;
- define `all-of`, `any-of`, and `k-of-n` over three-valued branch results;
- prove plan evaluation is independent of construction order;
- prove canonical error selection is deterministic;
- prove every validated plan leaf is evaluated exactly once;
- prove plan evaluation terminates under target V1 limits;
- connect the Lean model to the shipping Rust implementation with generated
  vectors and bounded refinement checks;
- fail CI when a Rust semantic change is not reflected in the formal model.

### 2.2 Non-goals

This specification does not prove:

- SHA-256 collision resistance;
- Ed25519 or P-256 implementation correctness;
- CBOR encoder correctness;
- principal-adapter correctness;
- application-profile canonicalization;
- freshness of verifier-supplied status data;
- correctness of a configured trust anchor;
- confidentiality, side-channel resistance, or production security.

Those facts are assumptions at this model boundary or belong to separate
verification efforts.

## 3. Architecture and formal project layout

The following files are added:

```text
formal/
├── lakefile.toml
├── lean-toolchain
├── Auths/
│   ├── Base.lean
│   ├── Authority.lean
│   ├── Attenuation.lean
│   ├── Composition.lean
│   ├── Diversity.lean
│   ├── Theorems.lean
│   └── VectorExport.lean
└── README.md

core/crates/auths-formal-refinement/
├── Cargo.toml
├── src/lib.rs
└── tests/
    ├── attenuation.rs
    ├── composition.rs
    └── generated_vectors.rs

core/formal-vectors/v1/
├── manifest.json
├── attenuation-checks.json
└── threshold-counts.json
```

`auths-formal-refinement` is a non-shipping core test crate. It MAY depend on
`auths-model`, `auths-authority`, and `auths-composition`; shipping crates MUST
NOT depend on it or on Lean-generated code.

`core/formal-vectors/v1` contains semantic values, not canonical protocol wire
objects. It therefore does not fork the canonical CBOR corpus in
[`core/fixtures/v1`](../../core/fixtures/v1).

The Lean version MUST be pinned in `formal/lean-toolchain`. All dependencies in
`lakefile.toml` MUST be pinned to immutable revisions.

## 4. Authority domain

### 4.1 Effective authority

Let an effective authority value be:

\[
E = (r,s,P,p,M,T,U,C,B,d,g,a,\sigma)
\]

where:

| Symbol | Meaning | Rust representation |
| --- | --- | --- |
| \(r\) | selected root principal | `EffectiveAuthority::root` |
| \(s\) | current subject | `EffectiveAuthority::subject` |
| \(P\) | root-permitted profiles | `allowed_profiles` |
| \(p\) | selected exact profile, if any | `profile` |
| \(M\) | permission set | `PermissionSet` |
| \(T\) | validity window | `ValidityWindow` |
| \(U\) | audience set | `AudienceSet` |
| \(C\) | action-body constraint | `ActionConstraint` |
| \(B\) | optional budget ceiling | `Option<BudgetCeiling>` |
| \(d\) | remaining delegation depth | `u16` |
| \(g\) | last grant identifier | `Option<GrantId>` |
| \(a\) | assurance-policy identifier | `AssurancePolicyId` |
| \(\sigma\) | lifecycle status policy | `StatusPolicy` |

Root construction is a pure function:

\[
root : TrustAnchor \rightarrow E
\]

and MUST be definitionally equivalent to
`EffectiveAuthority::from_anchor`.

### 4.2 Component orderings

Write \(x \preceq y\) when `x` is no more permissive than `y`.

#### Permissions

\[
M_c \preceq_M M_p \iff M_c \subseteq M_p
\]

#### Validity

For inclusive windows \([n,e]\):

\[
[n_c,e_c] \preceq_T [n_p,e_p]
\iff n_p \le n_c \land e_c \le e_p
\]

#### Audiences

\[
U_c \preceq_U U_p \iff U_c \subseteq U_p
\]

#### Action-body constraints

Let `Any`, `Allowed(D)`, and `Exact(d)` denote the three V1 constructors.

\[
\begin{aligned}
x &\preceq_C Any \\
Exact(d) &\preceq_C Exact(d) \\
Exact(d) &\preceq_C Allowed(D) &&\text{iff } d \in D \\
Allowed(D_c) &\preceq_C Allowed(D_p) &&\text{iff } D_c \subseteq D_p
\end{aligned}
\]

No other action-constraint pairs are ordered.

#### Budgets

`None` in the parent denotes no ceiling. `None` in the child cannot attenuate a
bounded parent:

\[
B_c \preceq_B B_p =
\begin{cases}
true & B_p = None \\
false & B_p = Some(b_p) \land B_c = None \\
alg(b_c)=alg(b_p) \land value(b_c)\le value(b_p)
  & B_c=Some(b_c), B_p=Some(b_p)
\end{cases}
\]

#### Status

\[
\begin{aligned}
x &\preceq_\sigma ExpiryOnly \\
Snapshot(m,a_c) &\preceq_\sigma Snapshot(m,a_p)
  &&\text{iff } a_c \le a_p
\end{aligned}
\]

An `ExpiryOnly` child MUST NOT attenuate a snapshot-requiring parent, and a
status-method identifier MUST NOT change inside a snapshot-requiring chain.

#### Profile, assurance, and depth

After the first grant selects a profile, profile equality is required.
Assurance-policy identifiers are invariant. Delegation depth is strictly
decreasing:

\[
p_c = p_p,\quad a_c = a_p,\quad d_c < d_p
\]

### 4.3 Grant transition

A grant transition is defined only when:

1. `grant.issuer == effective.subject`;
2. `grant.parent == effective.last_grant`;
3. every authority dimension satisfies its ordering;
4. the assurance-policy identifier is unchanged; and
5. remaining depth strictly decreases.

In Lean:

```lean
structure EffectiveAuthority where
  root : Principal
  subject : Principal
  profiles : Finset Profile
  selectedProfile : Option Profile
  permissions : Finset Permission
  validity : Validity
  audiences : Finset Audience
  actionConstraint : ActionConstraint
  budget : Option Budget
  depth : Nat
  lastGrant : Option GrantId
  assurance : AssurancePolicyId
  status : StatusPolicy

def delegates (parent : EffectiveAuthority) (g : Grant) : Prop :=
  g.issuer = parent.subject ∧
  g.parent = parent.lastGrant ∧
  profileAttenuates g.profile parent ∧
  g.permissions ⊆ parent.permissions ∧
  validityAttenuates g.validity parent.validity ∧
  g.audiences ⊆ parent.audiences ∧
  constraintAttenuates g.actionConstraint parent.actionConstraint ∧
  budgetAttenuates g.budget parent.budget ∧
  statusAttenuates g.status parent.status ∧
  g.assurance = parent.assurance ∧
  g.depth < parent.depth
```

The Rust implementation remains structurally equivalent:

```rust
if self.remaining_depth == 0 || grant.remaining_depth() >= self.remaining_depth {
    return Err(DenialReason::DelegationExpanded);
}
if !grant.permissions().is_subset_of(&self.permissions)
    || !self.validity.contains_window(grant.validity())
    || !grant.audiences().is_subset_of(&self.audiences)
    || !grant.action_constraint().attenuates(&self.action_constraint)
{
    return Err(DenialReason::DelegationExpanded);
}
```

The complete code, including budget, status, profile, assurance, and exact
critical-extension-set checks,
remains in
[`core/crates/auths-authority/src/lib.rs`](../../core/crates/auths-authority/src/lib.rs).

### 4.4 Action coverage

An action \(A\) is covered by effective authority \(E\) iff:

- the actor is the terminal subject;
- the terminal-grant identifier matches;
- the action profile is permitted and exact after selection;
- the permission is in \(M\);
- the action validity window is contained by \(T\);
- the exact audience is in \(U\);
- \(C\) allows the canonical body digest; and
- the requested budget is covered by \(B\).

The formal model MUST retain the protocol’s current first-failure order for
stable denial codes. The logical coverage predicate and diagnostic ordering are
separate definitions.

## 5. Composition domain

### 5.1 Semantic values

Let the semantic truth domain be:

\[
V = \{D, I, A\}
\]

with order:

\[
D < I < A
\]

`Denied(reason)` projects to \(D\), `Indeterminate(requirement)` to \(I\), and
`Authorized` to \(A\). `StructurallyInvalid(reason)` projects to \(D\).

Diagnostics are paired with truth values:

```lean
inductive Outcome where
  | authorized
  | denied (reason : DenialReason)
  | indeterminate (requirement : Requirement)
  | structurallyInvalid (reason : DenialReason)
```

### 5.2 Operators

For child values \(v_1,\ldots,v_n\):

\[
all(v_1,\ldots,v_n) = \min(v_1,\ldots,v_n)
\]

\[
any(v_1,\ldots,v_n) = \max(v_1,\ldots,v_n)
\]

For threshold \(k\), define:

- \(a\): authorized-child count;
- \(i\): indeterminate-child count.

\[
kofn(k) =
\begin{cases}
A & a \ge k \\
I & a < k \land a+i \ge k \\
D & a+i < k
\end{cases}
\]

Diagnostic selection is independent of child construction order:

- a denied result selects the smallest stable `DenialReason::code()`;
- an indeterminate result selects the smallest stable
  `Requirement::code()`;
- a missing diagnostic where the truth value requires one is an internal model
  error and MUST NOT occur for validated inputs.

### 5.3 Evaluation strategy

The evaluator MUST visit every leaf exactly once, even when a parent result is
already logically determined. This is a protocol property, not merely a test
convenience: optional branches must not alter observable work by
short-circuiting.

The reference evaluator is:

```lean
def evaluate : Plan → (ProofRef → Outcome) → List ProofRef × Outcome
  | .proof ref, branch => ([ref], branch ref)
  | .allOf members, branch =>
      combineAll (members.map (fun child => evaluate child branch))
  | .anyOf members, branch =>
      combineAny (members.map (fun child => evaluate child branch))
  | .kOfN k members, branch =>
      combineThreshold k (members.map (fun child => evaluate child branch))
```

The returned proof-reference list exists solely to prove total visitation; it
is not a protocol output.

### 5.4 Verifier-local composition floor

Plan truth is necessary but not sufficient. After plan authorization, the
verifier applies `CompositionRequirement`:

\[
\begin{aligned}
|authorizedBranches| &\ge b_{min} \\
|distinctActors| &\ge a_{min} \\
|distinctRoots| &\ge r_{min}
\end{aligned}
\]

and, when present, the computed `PlanId` MUST equal `expected_plan`.

Failure of these local requirements is
`Denied(CompositionRequirementNotMet)`, not `Indeterminate`, because the
verifier possesses all relevant branch results and its own local policy.

## 6. Required theorems

All theorem names below are normative deliverables.

### 6.1 Component-order theorems

For permissions, validity, audiences, body constraints, budgets, and status:

- `attenuation_refl`: each well-formed value attenuates itself;
- `attenuation_trans`: attenuation is transitive;
- `attenuation_antisymm`: mutual attenuation implies semantic equality;
- `coverage_downward_closed`: if a child covers an action, every ancestor
  whose authority contains the child also covers it, excluding chain-link
  identity fields.

### 6.2 Chain theorems

- `delegate_preserves_root`: delegation never changes the selected root;
- `delegate_updates_subject`: an accepted grant’s subject becomes the
  effective subject;
- `delegate_strict_depth`: accepted delegation strictly decreases depth;
- `finite_chain`: a chain from depth \(d\) contains at most \(d\) accepted
  grant edges;
- `delegate_never_widens`: every accepted child effective authority is below
  its parent in the product ordering;
- `chain_transitive_attenuation`: the terminal authority is below the root
  authority;
- `authorized_action_covered`: `authorizes(E, A) = ok` implies the coverage
  predicate for every authority dimension.

### 6.3 Composition theorems

- `all_commutative`, `all_associative`, and `all_idempotent`;
- `any_commutative`, `any_associative`, and `any_idempotent`;
- `threshold_one_eq_any`;
- `threshold_n_eq_all`;
- `threshold_monotone_k`: increasing \(k\) cannot improve a result;
- `composition_permutation_invariant`;
- `canonical_diagnostic_permutation_invariant`;
- `every_leaf_visited_once`;
- `validated_plan_terminates`;
- `evaluation_cost_linear_in_nodes`;
- `authorized_implies_threshold_met`;
- `denied_implies_threshold_impossible`;
- `indeterminate_implies_threshold_reachable`.

### 6.4 Refinement theorem

The central cross-implementation property is:

\[
RustEval(encode(x)) = LeanEval(x)
\]

for every generated, model-valid authority or composition case.

Because arbitrary Rust execution is not proved inside Lean, this is delivered
as two complementary obligations:

1. Lean proves the reference evaluator’s laws and exports canonical semantic
   vectors.
2. Kani exhaustively checks the Rust evaluator over a bounded abstraction that
   covers every constructor, truth value, diagnostic ordering class, and target
   V1 plan limit relevant to the proof harness.

No claim of whole-program equivalence may be made until a verified extraction
or translation-validation mechanism replaces this refinement boundary.

## 7. APIs and Rust refinement harness

### 7.1 Semantic adapters

The refinement crate defines lossless test-only projections:

```rust
pub struct FormalAuthorityCase {
    pub parent: EffectiveAuthorityModel,
    pub grant: GrantModel,
    pub expected: Result<EffectiveAuthorityModel, DenialReason>,
}

pub struct FormalCompositionCase {
    pub plan: AuthorizationPlan,
    pub leaves: BTreeMap<ProofRef, BranchOutcome>,
    pub expected: BranchOutcome,
    pub expected_visit_order: Vec<ProofRef>,
}
```

The harness MUST call the public shipping APIs. It MUST NOT duplicate
`EffectiveAuthority::delegate`, `EffectiveAuthority::authorizes`, or
`auths_composition::evaluate`.

### 7.2 Bounded model checking

Kani harnesses belong in
`core/crates/auths-formal-refinement/src/lib.rs` behind a `kani` configuration:

```rust
#[kani::proof]
#[kani::unwind(17)]
fn threshold_matches_reference_for_target_v1() {
    let len: usize = kani::any();
    kani::assume((1..=16).contains(&len));
    let k: usize = kani::any();
    kani::assume((1..=len).contains(&k));

    let outcomes = symbolic_outcomes(len);
    let rust = evaluate_threshold(k, &outcomes);
    let reference = reference_threshold(k, &outcomes);

    assert_eq!(rust, reference);
}
```

The actual harness MUST use the shipping plan constructor and evaluator. Helper
functions may only generate bounded symbolic inputs and translate outputs.

### 7.3 Generated vectors

`formal/Auths/VectorExport.lean` emits canonical JSON with:

- schema identifier;
- Lean toolchain version;
- formal-source digest;
- case identifier;
- complete semantic input;
- expected result;
- theorem family exercised.

`cargo xtask formal --update` regenerates vectors in a temporary directory,
compares them byte-for-byte, and updates only when explicitly requested.
Normal `cargo xtask formal` MUST be read-only.

### 7.4 Developer UX

The complete local workflow is:

```text
$ cargo xtask formal
Lean theorems:              PASS
Formal inventory:           PASS
Generated semantic vectors: byte-stable
Rust refinement vectors:    PASS
Kani bounded harnesses:      PASS

$ cargo xtask formal --case composition/threshold/2-of-3
Lean outcome:  indeterminate/stale-status
Rust outcome:  indeterminate/stale-status
Leaves visited: 3/3
```

Failure output MUST name the theorem or refinement case, show the smallest
counterexample, and provide one exact reproduction command. It MUST NOT emit a
generic “formal verification failed” message without the failing obligation.

## 8. Drift control

The formal and Rust surfaces are synchronized by a checked inventory:

```json
{
  "schema": "auths-proof-formal-inventory/v1",
  "action_constraints": [
    "any-body",
    "exact-body-digest",
    "allowed-body-digests"
  ],
  "plan_nodes": ["proof", "all-of", "any-of", "k-of-n"],
  "outcomes": [
    "authorized",
    "denied",
    "indeterminate",
    "structurally-invalid"
  ]
}
```

A new Rust enum variant, denial class used by composition, or authority
dimension MUST cause the inventory check to fail until the Lean model and
theorem set are updated.

## 9. Validation and acceptance criteria

This specification is implemented only when all of the following hold:

1. `lake build` succeeds with no `sorry`, `admit`, or unsafe axioms in
   `formal/Auths`.
2. Every theorem in Section 6 exists and is checked.
3. `cargo xtask formal` reproduces every semantic vector byte-for-byte.
4. Rust refinement tests consume all generated vectors successfully.
5. Kani checks every declared harness without an unwinding assertion failure.
6. Mutation testing demonstrates that removing any one attenuation check
   breaks at least one theorem-derived vector or model-checking harness.
7. Mutation testing demonstrates that introducing short-circuit evaluation is
   detected by `every_leaf_visited_once`.
8. The existing canonical V1 corpus in
   [`core/fixtures/v1`](../../core/fixtures/v1) remains byte-stable.
9. Shipping core crates retain `no_std` capability and gain no dependency on
   the formal toolchain.
10. The published formal artifact records the exact repository revision,
    Lean version, Kani version, vector digest, and theorem inventory.

## 10. Publication artifact

Each release claiming formal coverage publishes:

```text
auths-proof-formal-v1/
├── FORMAL-CLAIMS.md
├── toolchain.json
├── theorem-inventory.json
├── source.tar.zst
├── formal-vectors.tar.zst
├── kani-results.json
└── SHA256SUMS
```

`FORMAL-CLAIMS.md` MUST repeat the non-goals in Section 2.2. The artifact MUST
not describe component-order proofs as verification of cryptography, parsers,
adapters, context correctness, or the whole Auths-Proof implementation.

## 11. Security consequences

This work eliminates a specific class of ambiguity: whether a delegation or
plan operation has the algebraic properties claimed by the protocol. It does
not eliminate incorrect inputs or compromised trusted context.

The formal model becomes security-sensitive. Changes require review from both a
protocol maintainer and a proof maintainer. Generated vectors are review aids,
not a substitute for reviewing changed definitions and theorem statements.

## 12. Implemented refinement boundary

[ADR 0010](../adr/0010-mechanical-rust-lean-refinement-boundary.md) strengthens
the implementation described here. A versioned algebra contract now generates
the production Rust kernel and the corresponding Lean definitions. Shipping
composition and delegation use that generated Rust boundary.

Lean generates 2,448 exhaustive threshold-count cases through the target V1
default deployment limit and all 2,048 Boolean projections of the eleven declared
attenuation dimensions. The Rust refinement suite consumes those artifacts
without a handwritten reference evaluator. Kani symbolically verifies the two
generated production functions at the same bound; the Lean theorems remain
unbounded.

This establishes alignment for aggregate composition truth and aggregate
attenuation acceptance. It does not prove the rich Rust projections themselves,
cryptography, decoding, adapters, or the whole verifier.

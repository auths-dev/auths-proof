# AP-SPEC-011: Rich Authority Refinement and Bounded Authorization

**Status:** In progress — Milestones 0–2 implemented; Milestone 3 is governed
by AP-SPEC-025 and the seven-domain execution plan

**Intended audience:** protocol authors, formal-methods engineers, core and
product implementers, auditors, and independent verifier implementers

**Normative language:** the terms **MUST**, **MUST NOT**, **SHOULD**, and
**MAY** are requirements on the implementation described by this specification

**Extends:** [AP-SPEC-001](0001-formal-attenuation-and-composition.md)

**Supersedes where inconsistent:** AP-SPEC-001 sections 4, 6.1–6.2, and the
rich-authority portions of 7–8; unrelated composition requirements remain

**Related plan:**
[Bounded Authorization Abstraction Plan](../target-state/BOUNDED_AUTHORIZATION_ABSTRACTION_PLAN.md)

**Scope:** the rich authority model, its mechanical refinement to shipping
Rust, proof-integrity controls, and the formal seam between core authority and
product-level bounded authorization

## Abstract

Auths currently has a mechanically shared Boolean boundary for attenuation and
composition. Lean proves the Boolean aggregation algebra, Rust consumes the
generated aggregation code, Lean emits all 2,048 possible eleven-dimensional
Boolean projections, and Rust checks those vectors.

The shipping verifier does more work before that boundary. It derives each
Boolean from rich values such as canonical permission sets, inclusive validity
windows, audience sets, action-body constraints, optional budgets, status
policies, profile selection, and assurance requirements. The current Lean
`EffectiveAuthority` represents those dimensions as `Nat` values and compares
them with `≤`. The repository correctly documents the mapping from rich Rust
values to the ten Booleans as trusted.

This specification defines the requirements and implementation sequence for
closing that assurance gap without replacing one independently written model
with another. It requires:

1. a complete mathematical model of the rich authority semantics;
2. a small pure production Rust authority kernel used by the shipping path;
3. a mechanically translated Lean representation of that exact Rust kernel;
4. proofs that the translated Rust semantics refine the rich mathematical
   model;
5. retention of the generated Boolean boundary as a useful corollary and
   fail-closed dimension inventory;
6. a separate product formalization for bounded policy and durable
   reservation/execution state; and
7. explicit proof claims, residual assumptions, statement-level drift checks,
   and mutation gates.

Implementation begins with a formal-claim/CI baseline and a reproducible
Aeneas GO / NO-GO qualification. The rich authority rewrite is blocked until
that decision is merged.

The OpenTofu and PostgreSQL verticals remain prerequisites for extracting a
generic bounded-authorization implementation. They are not prerequisites for
closing the existing core Rust–Lean projection gap. Those two workstreams
proceed in parallel and converge only after the seven-domain bounded-policy
inventory is complete.

## 1. Decision

Auths will use three distinct assurance layers:

1. **Core rich authority semantics** prove immutable grant attenuation,
   terminal action coverage, and composition.
2. **Rust refinement** proves that the pure functions called by shipping Rust
   implement those rich semantics.
3. **Product bounded-authorization semantics** prove pure bounded-policy
   evaluation and a separate reservation/execution transition system under an
   explicit durable-store contract.

The layers compose, but they MUST NOT be collapsed:

```text
 signed proof + trusted verifier context
                  |
                  v
 +-----------------------------------------------+
 | Core authority                               |
 | rich grant attenuation + exact action coverage|
 +----------------------+------------------------+
                        | CoreAuthorized(action commitment)
                        v
 +-----------------------------------------------+
 | Product policy                               |
 | policy + exact action + evidence + time/state |
 +----------------------+------------------------+
                        | Eligible(reservation intents, obligations)
                        v
 +-----------------------------------------------+
 | Product runtime                              |
 | config match + atomic reservation + claim     |
 +----------------------+------------------------+
                        | ExecutionAuthorization token
                        v
 +-----------------------------------------------+
 | Domain executor                              |
 | credential acquisition + exact effect         |
 +----------------------+------------------------+
                        |
                        v
             execution and observation receipts
```

Core proves what an immutable proof chain authorizes. Product policy decides
whether one exact action falls inside a standing, possibly evidence-relative
delegation. Product state decides whether shared capacity is still available
and reserves it atomically. An executor receives authority to construct a
provider command only after all three stages succeed.

### 1.1 Immediate execution priority

The first implementation work SHALL be one bounded tranche:

> establish an honest formal-claim baseline and produce a reproducible
> GO / NO-GO decision for mechanically translating exact shipping Rust with
> Aeneas/Charon.

This tranche precedes the rich `Authority.lean` rewrite and the generic bounded
policy/runtime implementation:

```text
current shipping Rust + current Lean
                 |
                 v
       formal claim/CI baseline
                 |
                 v
 exact production-source translation qualification
        /                         \
       v                           v
 GO: Aeneas route            NO-GO: fallback ADR
       |                           |
       +-------------+-------------+
                     v
          rich Lean authority model
                     |
                     v
       complete shipping-kernel refinement
```

#### 1.1.1 Included work

The first tranche MUST:

1. make the current formal command a pinned required hosted check and a clean
   release gate;
2. add the assurance manifest and baseline every existing public formal claim;
3. replace source-text theorem discovery with compiled declaration,
   statement-digest, and transitive-axiom inspection;
4. remove unsupported public claims and either strengthen weak theorems or
   rename them to their actual propositions;
5. qualify one pinned Lean environment against the Aeneas runtime and
   generated modules;
6. translate exact production-source examples of:
   - inclusive interval containment;
   - sorted-set membership and subset;
   - action-constraint attenuation and coverage;
   - optional numeric budgets;
   - status policy;
   - profile selection and equality;
   - grant linkage, attenuation, diagnostic selection, and accepted
     next-state construction; and
   - terminal action coverage and diagnostic selection;
7. add genuine three-window validity transitivity plus permission, audience,
   digest, constraint, budget, status, profile, and depth law/property tests;
8. exercise zero, maximum integer, maximum collection, optional-value, and
   every constructor boundary needed by those examples;
9. inventory every source dependency, feature, `cfg`, monomorphization,
   external model, stub, warning, generated axiom, and tool revision; and
10. publish one reviewed GO / NO-GO ADR.

The qualification target MUST be source compiled for production. It MAY
extract the current production functions directly. If translation requires a
pure-kernel reshape, the reshaped functions MUST replace the relevant shipping
logic and their callers MUST be routed through them in the same change.
Creating an uncalled “verification equivalent” is prohibited.

#### 1.1.2 Explicit non-goals

The first tranche MUST NOT:

- replace the current `Nat` authority coordinates with rich carriers;
- claim the rich projection gap is closed;
- translate the complete verifier, codecs, cryptography, adapters, or stores;
- introduce a generalized bounded-policy evaluator;
- introduce a generalized reservation or exact-effect runtime;
- abstract OpenTofu or PostgreSQL before either vertical works end to end; or
- change protocol or canonical wire semantics merely to accommodate a tool.

Small production refactors are permitted only when they isolate the exact pure
semantics needed for translation and preserve behavior through existing
fixtures, public-API tests, and a retained oracle where practical.

#### 1.1.3 Required artifacts

The tranche MUST produce:

```text
formal/assurance-manifest-v1.toml
formal/translation-toolchain.lock
formal/qualification/aeneas/
  qualification.toml
  source-closure.json
  generated/
  cases/
docs/adr/0011-rich-authority-rust-lean-link.md
```

The exact generated filenames MAY follow Aeneas conventions. Their required
content may not be omitted or replaced with prose.

`qualification.toml` records the qualification schema, production source
closure, semantic features and `cfg` values, tool revisions, Lean imports,
external models, warnings, cases, results, and final decision.

The ADR MUST select exactly one outcome:

- `GO-AENEAS`;
- `GO-AENEAS-WITH-PRODUCTION-RESHAPE`; or
- `NO-GO-AENEAS-USE-DECLARATIVE-CONTRACT`.

The ADR may not conclude “continue evaluating.” A failed Aeneas qualification
activates the fallback requirements in section 6.3; it does not permit two
handwritten implementations.

#### 1.1.4 GO criteria

An Aeneas GO decision requires all of the following:

- one clean pinned command reproduces the extraction and generated Lean
  byte-for-byte;
- the same semantic source, dependencies, features, and `cfg` values compile
  for shipping and extraction;
- the pinned Lean toolchain builds existing Auths proofs, the Aeneas runtime,
  and every generated qualification module together;
- representative leaf predicates, complete grant transition shape, and
  terminal action-coverage shape translate without a hand-written semantic
  shadow;
- accepted next-state construction and diagnostic selection are inside the
  translated boundary or a mechanically generated/proved wrapper;
- no semantic operation is replaced by an unreviewed stub or opaque external
  model;
- every introduced axiom and external model is explicit in the assurance
  manifest and inside the approved trusted-computing-base policy;
- translation warnings are either absent or individually classified as
  non-semantic and fail CI if they change;
- the output is deterministic across two clean reproductions; and
- changing the declared production source closure causes translation or
  assurance drift to fail.

`GO-AENEAS-WITH-PRODUCTION-RESHAPE` has the same criteria and additionally
requires exact old-versus-new shipping decisions, diagnostics, and accepted
next states across the complete existing fixture corpus and the new
qualification boundaries.

#### 1.1.5 NO-GO criteria

The result MUST be `NO-GO-AENEAS-USE-DECLARATIVE-CONTRACT` when any required
semantic operation depends on:

- a separate verification-only implementation;
- extraction-only semantic `cfg` behavior;
- an opaque or handwritten external model that contains authority logic;
- incompatible Lean/toolchain versions without a reproducible pinned
  resolution;
- nondeterministic or non-reproducible generated output;
- unsupported state construction or diagnostics that would remain trusted
  outside the intended boundary; or
- a production refactor whose compatibility cannot be established without
  changing protocol semantics.

Unsupported syntax alone is not an immediate NO-GO. One bounded production
reshape into simpler safe sequential Rust is allowed before applying these
criteria.

#### 1.1.6 Developer UX and exit report

The tranche MUST expose one command with concise output:

```text
$ cargo xtask formal qualify aeneas
Existing claim audit:              PASS
Hosted/release formal gate:        CONFIGURED
Production source closure:         <digest>
Shipping/extraction cfg parity:    PASS
Lean/Aeneas compatibility:         PASS
External models and axioms:        <count> reviewed, 0 unreviewed
Qualification cases:               <passed>/<declared> PASS
Clean reproduction:                byte-identical
Decision:                           GO-AENEAS
ADR:                                docs/adr/0011-rich-authority-rust-lean-link.md
```

Failures MUST identify the exact unsupported construct, production symbol,
generated artifact, external model, or axiom and provide one reproduction
command.

Milestone 1 may begin only after the ADR is merged. A GO selects section 6.2.
A NO-GO selects section 6.3. Neither outcome authorizes generalized bounded
product extraction before the OpenTofu and PostgreSQL gates.

## 2. Audit of the current implementation

### 2.1 What is mechanically connected today

The current implementation has a valuable but deliberately narrow mechanical
boundary:

| Component | Current guarantee |
| --- | --- |
| `formal/algebra-contract-v1.toml` | Inventories eleven attenuation Booleans and threshold expressions. |
| `formal/Auths/Generated/Algebra.lean` | Defines the generated Lean Boolean conjunction and threshold evaluator. |
| `core/crates/auths-algebra-kernel` | Provides generated shipping Rust for the same conjunction and threshold evaluator. |
| `formal/Auths/VectorExport.lean` | Exports every one of the \(2^{11}=2,048\) Boolean attenuation assignments. |
| `core/crates/auths-formal-refinement` | Confirms Rust and Lean agree after the eleven rich decisions have already become Booleans. |
| Kani harnesses | Check the generated Boolean conjunction and bounded threshold partition. |

This establishes that aggregate attenuation accepts exactly when every
declared dimension accepts. It does not establish that shipping Rust computed
each dimension correctly. The refinement test crate does not currently depend
on or call `auths-authority`.

### 2.2 The projection gap

`formal/Auths/Authority.lean` currently gives every authority and action
coordinate a `Nat` carrier. Its attenuation and coverage predicates use
equality or `≤`. `attenuation_kernel_refines` proves that a Boolean projection
created from those `Nat` comparisons agrees with the generated Boolean
conjunction.

Shipping Rust derives the projection using different operations:

- `PermissionSet::is_subset_of`;
- `ValidityWindow::contains_window`;
- `AudienceSet::is_subset_of`;
- `ActionConstraint::attenuates`;
- optional `BudgetCeiling` ordering;
- `StatusPolicy` ordering;
- initial profile selection followed by exact profile equality;
- assurance-policy equality; and
- strict remaining-depth decrease.

The current `root_preserved` projection returns `true` because the in-place
Rust transition never updates the root. Its justification is therefore a
transition invariant, not a comparison between two independently supplied root
coordinates.

Terminal action coverage is a separate relation. An action carries one
permission and one audience, so Rust checks membership, not action-set
inclusion. It also checks actor and terminal-grant linkage, profile, body
digest, validity, and requested budget.

The current 2,048-case refinement suite never constructs a rich parent, grant,
or action and never calls these production predicates. It starts with eleven
Booleans. This gap is explicitly disclosed in
[`formal/README.md`](../../formal/README.md) and
[ADR 0010](../adr/0010-mechanical-rust-lean-refinement-boundary.md). It is
therefore documented assurance debt, not evidence of a newly discovered
runtime exploit.

AP-SPEC-001 already specifies rich carriers, the real grant transition, and
terminal action membership as target-state requirements. The implemented Lean
model has not yet reached those proposed sections. This specification amends
their implementation and refinement strategy rather than presenting the rich
model as a newly invented requirement.

There are also multiple shipping owners of some rich decisions.
`auths-authority` and `auths-author` duplicate budget, status, and related
projection logic, while the verifier applies a registry-selected
`BudgetAlgebra` before applying `EffectiveAuthority::delegate`. The isolated
kernel work MUST inventory and remove these duplicate semantic owners.

### 2.3 Additional proof-integrity gaps

The long-term correction MUST also address these weaknesses:

- the current theorem inventory checks theorem names as source text rather
  than checking declaration types in the compiled Lean environment;
- the current prohibited-token scan is not a complete axiom-dependency audit;
- some composition theorem names are stronger than their current statements:
  `every_leaf_visited_once` follows from defining `visit = leaves`,
  `validated_plan_terminates` is an existential reflexivity statement, and
  `evaluation_cost_linear_in_nodes` follows from defining `cost = nodes`;
- `finite_chain` currently restates strict decrease for one edge rather than
  defining a chain and proving a length bound;
- `delegate_updates_subject` concerns a synthetic helper update rather than
  the result of the shipping accepted-grant transition;
- `composition_permutation_invariant` covers two binary truth values rather
  than arbitrary validated plans and canonical diagnostic selection;
- the Rust validity “transitivity” property test constructs only one contained
  child window rather than a three-window transitivity implication;
- permission-set and audience-set order laws are not property-tested; and
- rich semantic mutations can survive the Boolean-vector suite because the
  suite sees only the already-computed Booleans.

The implementation MUST either strengthen a theorem to match its published
name or narrow the claim and rename it. CI success MUST NOT be based on a
theorem name alone.

In addition, `cargo xtask formal` is currently a separately invoked command:
the general `xtask ci` and release-check paths do not invoke it, and the hosted
workflow does not install the pinned Lean and Kani toolchains. The formal gate
MUST become an explicit required hosted and release check before stronger
shipping claims are made.

## 3. Assessment of the external feedback

### 3.1 First review

The first review correctly identifies the projection gap and correctly asks
for rich set and interval semantics. Its proposed implementation is not a
complete fix:

- proving `Finset` inclusion in Lean does not prove that Rust
  `is_subset_of` implements the same relation;
- permissions, validity, and audiences are only three of the rich dimensions;
- terminal action authorization uses membership for its single permission and
  audience;
- root, subject, grant linkage, profile selection, assurance invariance, and
  strict depth are not all ordinary ordered coordinates; and
- strict delegation depth is irreflexive and well-founded, not a partial
  order.

Implementing that proposal verbatim would make the abstract model more
faithful while leaving the production correspondence trusted.

### 3.2 Second review

The second review is materially correct:

- the limitation is already documented;
- rich Lean definitions alone do not close the Rust correspondence;
- the model must cover every rich dimension and real action membership;
- the current Rust order-law testing is too thin; and
- a mechanical connection to the actual production predicates is the
  essential third layer.

Two qualifications are required:

1. Generating Rust and Lean from a shared declarative contract reduces drift
   but leaves the generator and the conversion into generated values trusted.
   It is a fallback, not the preferred proof of shipping Rust.
2. Kani is bounded model checking. It is excellent for fixed-width
   representation invariants, arithmetic, bounds, and mutation detection, but
   it does not replace an unbounded semantic equivalence proof.

## 4. Assurance architecture

The implementation will keep a readable mathematical specification separate
from the executable production algorithm, then prove them equivalent:

```text
                       handwritten rich Lean specification
                  (finite sets, intervals, closed policy types)
                                      ^
                                      | refinement theorems
                                      |
 production Rust ----> pinned mechanical translation to Lean
 pure authority kernel       (generated, never hand-edited)
         |
         +----> auths-authority shipping delegation and coverage
         |
         +----> rich semantic vectors, Kani, property and mutation tests
                                      |
                                      v
                           generated ten-Boolean projection
                                      |
                                      v
                    existing aggregation and composition proofs
```

The handwritten specification answers “what does attenuation mean?” The
translated Rust answers “what does the shipping implementation compute?” The
refinement theorem connects them. The Boolean boundary remains useful for
composition, dimension completeness, diagnostics, exhaustive regression, and
fail-closed evolution; it is no longer the only Rust–Lean connection.

## 5. Rich core authority semantics

### 5.1 Denotational safety foundation

The safety meaning of attenuation is containment of admitted complete
authorization facts:

```lean
def SemanticAttenuates
    (admits : Scope → AuthorizationFacts → Prop)
    (child parent : Scope) : Prop :=
  ∀ facts, admits child facts → admits parent facts
```

The model MUST distinguish:

```text
ActionCovers(scope, action)
EvidenceRequirementsSatisfied(scope, evidenceFacts)
Admits(scope, completeFacts)
  = ActionCovers(scope, completeFacts.action)
    and EvidenceRequirementsSatisfied(scope, completeFacts.evidence)
```

`AuthorizationFacts` contains the exact action plus explicit already-validated
status, assurance, time, and other trusted facts needed at the core boundary.
It does not perform I/O or acquire evidence. This split is necessary because
shipping `EffectiveAuthority::authorizes` checks terminal action coverage,
while other verifier stages establish status and assurance facts.

This definition directly states the security property: a narrowed child cannot
admit a request that its parent rejects. It is reflexive and transitive.
Mutual semantic containment yields semantic equivalence; canonical V1 carriers
MAY additionally prove syntactic antisymmetry.

The efficient structural V1 relation remains a separate decidable function.
Lean MUST prove it sound for semantic containment. Completeness MUST NOT be
confused with structural equality for representation-distinct but
extensionally equivalent scopes. `Exact(d)` and `Allowed({d})` admit the same
digest and the V1 transition relation accepts both directions. The raw action
constructors therefore form a preorder. Structural antisymmetry is proved only
for the explicitly normalized carrier in which singleton allow-lists are
represented as `Exact`. Partial-order laws alone are not enough to establish
action-coverage safety.

### 5.2 Semantic values versus runtime representations

The handwritten Lean model MUST describe logical values, not Rust allocation
or wire-layout details:

- identity-like values are opaque atoms with decidable equality;
- permission and audience scopes are finite sets;
- body-digest scopes use the exact target V1 constructors;
- validity is a well-formed inclusive interval;
- numeric values use mathematical integers or bounded subtypes as appropriate;
- canonical Rust collections are related to the mathematical sets through an
  explicit abstraction function; and
- canonical CBOR remains governed by `core/fixtures/v1`, not by the Lean
  in-memory representation.

Using `Nat` as an opaque identifier is acceptable. Ordering a permission,
audience, profile, principal, digest, or algebra identifier by its arbitrary
numeric encoding is not.

The representation bridge MUST prove:

- Rust model-to-view identity conversion is injective, or explicitly
  decision-adequate when irrelevant data is erased;
- Rust equality corresponds to Lean atom equality;
- binary-search ordering is total and consistent with equality;
- sorted, duplicate-free, non-empty, and cardinality bounds hold where
  required;
- binary-search membership and slice subset refine finite-set membership and
  subset; and
- `u16` and `u64` embed into Lean arithmetic with exact boundary behavior.

The current bridge relies on validation before these theorems are applied:
Lean naturals corresponding to production counters and timestamps are within
their Rust `u16`/`u64` ranges, and string-backed identifiers are the canonical,
bounded byte sequences accepted by the model and codec. The proofs do not
claim that arbitrary mathematical naturals fit Rust or that arbitrary Unicode
spellings denote the same identifier.

### 5.3 Split ordered scope from transition state

The model MUST separate:

```lean
structure ProfileScope where
  rootAllowed : FiniteSet Profile
  selected : Option Profile
  selectedAllowed :
    ∀ profile, selected = some profile → profile ∈ rootAllowed

structure AuthorityScope where
  profileScope : ProfileScope
  permissions : FiniteSet Permission
  validity : InclusiveWindow
  audiences : FiniteSet Audience
  actionConstraint : ActionConstraint
  budget : Option BudgetCeiling
  status : StatusPolicy
  assurance : AssurancePolicyId

structure ChainState where
  root : Principal
  subject : Principal
  scope : AuthorityScope
  remainingDepth : Nat
  lastGrant : Option GrantId
```

`AuthorityScope` contains semantic authority. `ChainState` also contains
chain position and transition data. This prevents an invalid proof that mutual
scope attenuation makes two complete states equal even when their subjects or
last-grant identifiers differ.

`FiniteSet` is conceptual in this specification. The current Lean project has
no external finite-set package. Implementation MUST either pin a Mathlib
version compatible with the project’s Lean toolchain and Aeneas runtime, then
include it in the dependency and axiom audit, or implement a small
repository-owned canonical sorted-list carrier and prove its finite-set
abstraction. This dependency choice is an explicit qualification result, not
an implicit import.

### 5.4 Relation classification

Each field MUST use its actual relation:

| Field | Relation | Required laws |
| --- | --- | --- |
| permissions | child finite set is a subset of parent | reflexive, transitive, canonical antisymmetry, membership monotonicity |
| audiences | child finite set is a subset of parent | reflexive, transitive, canonical antisymmetry, membership monotonicity |
| inclusive validity | child start is no earlier and child end no later | reflexive, transitive, canonical antisymmetry, coverage monotonicity |
| action constraint | semantic containment over target V1 `Any`, `Allowed`, and `Exact`; `Allowed({d})` and `Exact(d)` mutually attenuate | reflexive, transitive, extensional antisymmetry, normalized structural antisymmetry, `allows` monotonicity |
| optional budget | `None` is unbounded top; `Some` requires equal algebra and a non-increasing value | reflexive, transitive, canonical antisymmetry, coverage monotonicity |
| status | `ExpiryOnly` is top; snapshots require equal method and non-increasing maximum age | reflexive, transitive, canonical antisymmetry, evidence-satisfaction monotonicity |
| profile | select a member once, then preserve exact equality | transition law; no arbitrary identifier ordering |
| assurance | exact equality | invariant |
| root | exact equality | invariant |
| subject and last grant | issuer/parent linkage followed by exact state update | transition law |
| remaining depth | strict decrease | irreflexive, transitive, well-founded |

For the declared V1 transition, `rootAllowed` is invariant. An unselected
`ProfileScope` may select `p` only when `p ∈ rootAllowed`; a selected profile
may transition only to the same selected profile; both unselected values are
related only when their retained sets are equal; and unselected is never below
selected. A broader denotational containment relation may observe subset
containment between allowed sets, but the shipping V1 transition is
conservatively more restrictive. Identifier ordering is never used as profile
attenuation.

Where a relation is defined only on well-formed values, the theorem MUST carry
the invariant explicitly or use a subtype that makes malformed values
unrepresentable.

Exact assurance equality is the complete target-V1 rule, not a placeholder
for an implicit ordering. Adding a stronger/weaker assurance lattice requires
a versioned policy carrier and a separately linked proof.

Every heterogeneous bridge lemma is normative. Examples include:

```text
child_permissions ⊆ parent_permissions
and permission ∈ child_permissions
implies permission ∈ parent_permissions

child_window contained_by parent_window
and action_window contained_by child_window
implies action_window contained_by parent_window

child_constraint attenuates parent_constraint
and child_constraint allows digest
implies parent_constraint allows digest
```

Equivalent lemmas are required for audiences, budgets, profiles, status
evidence, and assurance facts. `action_coverage_downward_closed` MUST use only
the action-facing profile, permission, validity, audience, body, and budget
bridges. Evidence-requirement monotonicity MUST be proved separately from
status and assurance bridges; full-facts admission monotonicity then composes
the two. None may be assumed from component transitivity alone.

### 5.5 Exact V1 component semantics

The Lean definitions MUST mirror all current V1 cases.

For an inclusive interval:

\[
contained(child,parent) \iff
parent.start \le child.start \land child.end \le parent.end
\]

For optional budget ceilings, `None` is the unbounded grant scope:

```text
child <= None                  true
None <= Some(parent)           false
Some(child) <= Some(parent)    same algebra and child.value <= parent.value
```

An absent requested action budget is always covered. A requested budget under
an unbounded authority is covered. Two present values require the registered
V1 algebra’s coverage relation.

The formal boundary MUST distinguish:

- the built-in numeric V1 ceiling relation used by `auths-authority`;
- a registered `BudgetAlgebra` implementation used by the verifier; and
- product-level aggregate, rolling, or shared budgets.

Today the verifier can run a registry-selected budget relation and then
`auths-authority` can run its built-in numeric relation over the same edge.
Two potentially different semantic owners are not acceptable.

For target V1, the authoritative immutable grant relation SHALL be equal
algebra identifier plus non-increasing `u64` value, with `None` as unbounded
top. The V1 core registry SHALL be closed to the proved
`numeric-ceiling-v1` semantics; an arbitrary trait implementation is not proof
that a handler obeys this law. A future core algebra identifier requires its
own mechanically linked proof artifact and protocol-version review. The
duplicate V1 check SHOULD be removed or generated from the same proved kernel.
Richer evidence-relative, aggregate, rolling, or shared budgets get closed
product policy versions rather than silently changing V1 `BudgetCeiling`.
Accordingly, core `BudgetCeiling` is stateless and applies independently to one
action. It makes no cumulative-spend, reservation, or cross-action conservation
claim; those are product lifecycle properties backed by mutable state.

### 5.6 Grant transition

`delegates(parent, grantId, grant, child)` MUST include:

1. issuer equals the parent subject;
2. parent grant identifier equals the parent state’s last grant;
3. the root is preserved;
4. the first grant selects a member of the root-permitted profile set;
5. subsequent grants preserve that exact selected profile;
6. every ordered scope dimension attenuates;
7. the assurance policy is unchanged;
8. depth is positive and strictly decreases;
9. the child subject is the grant subject;
10. the child last-grant identifier is the applied grant identifier; and
11. every other child field equals the accepted grant value.

Logical acceptance and first-failure diagnostics MUST be separate definitions.
Each public caller has its own declared diagnostic contract:
`auths-authority::delegate` exposes linkage or aggregate expansion failures,
authoring may expose ordered per-dimension planning failures, and terminal
coverage has its own first-failure order. For each caller, Lean MUST prove:

```text
diagnose = Ok iff the caller’s logical predicate
diagnose = Err(code) implies the predicate is false
code is the first failing check in that caller’s declared order
```

This deterministic precedence contract is functional: equivalent
implementations return the same stable code. It does not establish constant
time, cache-obliviousness, or any broader side-channel noninterference claim.

### 5.7 Terminal action coverage

The rich action model MUST match `ActionEnvelope`. Coverage requires:

- action actor equals terminal subject;
- terminal-grant identifier equals the state’s last grant;
- action profile is permitted before selection and exact after selection;
- the action’s one permission is a member of the permission set;
- the action validity interval is contained by the authority interval;
- the action’s one audience is a member of the audience set;
- the action body digest is allowed by the action constraint; and
- the requested budget is covered.

Action membership MUST NOT be modeled as action-set subset.

This judgment intentionally covers only the authority fields consumed by
`EffectiveAuthority::authorizes`. Media type, challenge, authorization plan,
channel binding, proof references, attachments, extensions, signatures, and
other `ActionEnvelope` fields remain checked by their separately inventoried
verifier stages. `coverage_decision_ok_iff_covers` MUST NOT be presented as a
proof of complete action-envelope verification.

### 5.8 Required core theorems

At minimum, Lean MUST prove:

- every component law in the relation-classification table;
- `semantic_attenuation_preorder`;
- `structural_scope_le_decides_declared_v1_relation`;
- `structural_scope_le_implies_semantic_attenuation`;
- `scope_semantic_equivalence`;
- `scope_le_canonical_antisymmetry`;
- every component coverage/evidence bridge lemma;
- `delegate_implies_scope_le`;
- `delegate_preserves_root`;
- `delegate_updates_subject_and_parent`;
- `delegate_strict_depth`;
- `finite_delegation_chain`;
- `chain_transitive_attenuation`;
- `action_coverage_downward_closed`;
- `evidence_requirements_downward_closed`;
- `complete_admission_downward_closed`;
- `authorized_action_covered`;
- `authority_delegate_diagnostic_sound_complete`;
- `author_planning_diagnostic_sound_complete`;
- `coverage_diagnostic_sound_complete`;
- `rich_projection_accepts_iff_scope_depth_checks`;
- `apply_grant_success_iff_linked_and_projection`;
- `apply_grant_success_unique`;
- `coverage_decision_ok_iff_covers`; and
- `translated_rust_refines_rich_spec`.

The exact theorem names MAY change during implementation, but the assurance
manifest described below MUST identify the declaration satisfying each
semantic claim.

The ten-Boolean projection does not contain issuer/parent linkage or an
arbitrary child state. Its equivalence theorem therefore covers only the
declared scope/depth checks. Full grant success is proved separately as linkage
plus accepted projection plus construction of the unique next `ChainState`.

The composition claims identified by the audit require an instrumented
recursive evaluator, not definitional aliases. The strengthened model MUST
prove that its evaluation trace equals the plan’s leaf-occurrence sequence,
that a validated no-duplicate plan visits each proof reference exactly once,
that structural recursion terminates, that step count is bounded by a stated
function of validated nodes/leaves, and that arbitrary plan permutations
preserve truth and canonical diagnostics. Target V1 hard limits MUST imply that
the corresponding machine counters cannot overflow.

## 6. Mechanically connecting shipping Rust

### 6.1 Pure production kernel

The rich predicates actually called in production MUST be isolated in a small
safe `no_std` Rust authority kernel. It MUST:

- contain no networking, storage, clocks, credentials, global state, or
  application-profile I/O;
- contain no `unsafe`;
- use total functions over validated inputs;
- make malformed representation handling explicit;
- contain the actual set membership/subset, interval, constraint, budget,
  status, profile, depth, accepted next-state, delegation, and action-coverage
  decisions;
- construct the unique accepted next-state and select stable diagnostics
  inside the translated boundary, or through a mechanically proved/generated
  wrapper; and
- be called by `auths-authority`, `auths-author`, and every other shipping
  caller; production MUST NOT retain an independent second implementation of
  those comparisons.

The exact crate split will be chosen by the translation qualification spike,
but semantic conversions MUST be lossless and structural. Moving meaningful
logic into an unproved “adapter to the formal view” is prohibited.

The kernel MUST own the accepted transition result and diagnostic selection,
not merely return ten Booleans and let a wrapper independently choose the next
fields or first failure. A production wrapper may clone or commit the returned
next-state descriptor, but that operation must be a structural mapping covered
by the refinement boundary. `AttenuationChecks` MUST be emitted by this same
evaluation and MUST NOT be recomputed by a second projection implementation.

### 6.2 Preferred mechanical route

The preferred route is:

1. use Charon to lower the isolated safe Rust kernel;
2. use [Aeneas](https://github.com/AeneasVerif/aeneas) to translate that
   production code into Lean;
3. check the generated Lean into a clearly generated directory;
4. prove the generated functions equivalent to the handwritten rich Lean
   specification; and
5. make normal CI reject byte drift in the translation.

Aeneas is selected for qualification because it targets pure safe Rust through
MIR/LLBC and has a comparatively mature Lean backend. It is not accepted by
reputation alone. Auths MUST pin exact Rust, Charon, Aeneas, Lean, and library
revisions and run a repository-owned qualification corpus.

One pinned Lean environment MUST build both the handwritten Auths modules and
the Aeneas Lean runtime/generated modules. The qualification MUST inventory
every external model, monomorphization, stub, warning, and axiom introduced by
translation. The exact source must compile under the workspace’s shipping
toolchain and under Charon’s pinned extraction toolchain with identical
semantic features and `cfg` values. Extraction-only semantic forks, including
`cfg(aeneas)` alternatives, are prohibited.

Charon/Aeneas and any required nightly live in a hermetic formal job; they do
not change the workspace MSRV and are not dependencies of shipping crates.
Rust compiler/code-generation correctness remains an explicit trusted
assumption: the proof connects the extracted MIR/LLBC semantics to Lean, not
arbitrary emitted machine code.

The initial spike MUST cover representative hard cases:

- inclusive interval containment at `0` and `u64::MAX`;
- sorted unique slice membership and subset;
- action-constraint constructor pairs;
- optional budgets with algebra equality;
- status methods and freshness direction;
- profile selection/equality; and
- the complete delegation and action-coverage decision.

If a Rust construct is unsupported, the first response SHOULD be to simplify
the isolated pure kernel into the supported safe subset without changing its
public semantics. The entire verifier, codecs, cryptography, allocators, and
adapters MUST NOT be pulled into the translation boundary.

### 6.3 Fallback mechanical route

If the pinned qualification corpus shows that translation remains
unmaintainable after a bounded kernel refactor, a restricted declarative
semantic contract SHALL generate both the executable Rust predicates and Lean
definitions.

That fallback MUST:

- be a closed typed algebra, not a general-purpose policy language;
- generate the only shipping implementation of the declared predicates;
- make the generator and value-conversion layer explicit in the trusted
  computing base;
- include deterministic generated-source drift checks;
- retain a separate handwritten Lean specification and prove the generated
  Lean evaluator equivalent to it; and
- include generated-code semantic validation, rich vectors, mutation tests,
  and independent review of the generator.

Two handwritten implementations plus matching examples are not an acceptable
fallback. [Hax](https://github.com/cryspen/hax) or
[Creusot](https://creusot.rs/) may be researched for a future amendment, but
they do not replace the ADR outcome required by section 1.1. Adopting a second
proof language or backend would require a new decision with a reproducibility,
proof-composition, and trusted-computing-base comparison.

### 6.4 Defense in depth

Mechanical translation does not eliminate ordinary testing. The Rust suite
MUST add:

- genuine three-window validity transitivity;
- permission, audience, body-digest, budget, action-constraint, and status
  reflexivity/transitivity/antisymmetry properties;
- constructor tests for sorted, duplicate-free, non-empty bounded sets;
- membership-versus-subset action cases;
- zero, one, maximum-length, `0`, and `u64::MAX` boundaries;
- exact profile-selection and depth boundaries;
- lossless semantic-view tests if a view layer remains;
- rich Lean-generated semantic vectors that call shipping APIs; and
- a mutation matrix that reverses each inequality, subset direction,
  membership decision, optional-budget case, status-age direction, and
  profile/depth condition and demonstrates that the formal/refinement gate
  fails.

Pinned [Kani proof harnesses](https://model-checking.github.io/kani/)
MUST verify bounded representation invariants, fixed-width arithmetic, and the
isolated executable predicates. Function contracts MAY be used when the pinned
Kani version supports the needed contract features reproducibly. Property
tests and Kani are supplementary; neither may be described as the unbounded
Rust–Lean refinement proof.

## 7. Bounded authorization formalization

### 7.1 Sequencing

Work proceeds on two parallel tracks:

```text
Track A: core assurance             Track B: bounded-domain evidence
claim audit                         OpenTofu end-to-end vertical
rich Lean authority model           PostgreSQL end-to-end vertical
pure Rust kernel                    seven-domain comparison
mechanical Rust refinement                    |
          |                                   |
          +-----------------+-----------------+
                            v
              closed bounded-policy contracts
                            |
                            v
              reservation/execution state model
                            |
                            v
                 shared product extraction
```

Track A MAY begin immediately. Track B MUST follow the ordering in the Bounded
Authorization Abstraction Plan: complete OpenTofu and PostgreSQL with deliberate
domain-local implementations, then compare GitHub, Radicle, Stripe,
Kubernetes, OpenTofu, and PostgreSQL before extracting shared bounded-policy or
runtime code.

The comparison and later abstraction MUST keep three kinds of boundedness
separate:

1. **semantic boundedness:** which complete action and explicit-context values
   a policy admits;
2. **computational boundedness:** byte, item, depth, plan-node, work-unit,
   allocation, and index limits; and
3. **stateful boundedness:** reservations, aggregate budgets, replay,
   outcome-unknown, and reconciliation.

These concerns compose, but none is merely another coordinate in
`EffectiveAuthority`.

### 7.2 Product formal namespace

Bounded policy and mutable lifecycle proofs MUST live in a visibly separate
namespace such as:

```text
formal/Auths/Product/
  Policy.lean
  Eligibility.lean
  Reservation.lean
  Execution.lean
  Reconciliation.lean
  Theorems.lean
```

The corresponding Rust remains under `product/`. The presence of product
theorems under the repository’s `formal/` project does not authorize moving
networking, clocks, mutable ledgers, credentials, or domain adapters into
`core/`.

### 7.3 Pure policy evaluation

A bounded evaluator is a pure function of explicit inputs:

```text
evaluate(
  policy,
  exact_action,
  canonical_evidence,
  state_snapshot,
  verifier_time,
  required_configuration,
  executed_configuration
) -> Eligible(reservation_intents, obligations)
   | Denied(stable_code)
   | Indeterminate(stable_code)
```

`Eligible` is intentionally not named `Authorized`. Shared or rolling capacity
may have changed after the snapshot. Execution authorization exists only after
configuration equality and durable reservation.

Every input MUST identify:

- policy type and version;
- canonicalization version;
- canonical policy digest;
- evaluator semantic identifier and version;
- evidence schema, digest, source, observation time, and freshness rule;
- exact action digest;
- state-snapshot identity;
- explicit verifier time; and
- required and executed verifier/evaluator configuration commitments.

An optimized implementation MAY retain the same semantic evaluator identifier
only after it refines that exact evaluator version. Receipts MUST still record
which implementation/build executed. Build provenance is runtime receipt
metadata, not a pure semantic input. If local policy pins an approved build,
that pin is part of the required/executed configuration and may therefore
affect the verdict through configuration equality.

Obligations are typed as:

- pre-execution conditions that must be discharged before an execution token;
- command-construction constraints incorporated into the exact verified
  command; or
- post-execution observations that remain pending until observed or
  reconciled.

No projection may silently drop an obligation. The eligibility output,
decision receipt, execution token, verified command, and observation receipt
must account for every obligation by stable identity and state.

### 7.4 Bounded-policy laws

The generic contract MUST be extracted from the seven-domain comparison, not
invented before it. Each closed policy type MUST then prove:

- deterministic evaluation for exact inputs;
- deny/indeterminate/eligible partition;
- arithmetic representability and no wraparound;
- explicit inclusive/exclusive boundaries;
- explicit rounding and unit conversion;
- missing or stale required evidence is indeterminate or denied according to
  the versioned contract, never silently defaulted;
- every successful evidence-relative calculation is reproducible from receipt
  commitments;
- required and executed semantic/configuration commitments match before
  eligibility can become execution authorization; and
- policy tightening cannot newly accept the same exact action under the same
  evidence, state snapshot, time, and configuration.

Each closed policy’s `tightens` relation MUST be reflexive and transitive over
well-formed policies. Antisymmetry is only required modulo its declared
semantic equivalence or canonical normal form.

The fixed-context qualification is essential. Evidence and mutable state are
not generally monotone: a later refund, database write, cluster rollout, or
infrastructure change may legitimately change the decision.

There MUST NOT be one universal ordering over arbitrary domain policy. Each
versioned closed policy type defines its own `tightens` relation and proves the
common laws. Its security meaning is extensional:

```lean
def SemanticTightens (child parent : Policy) : Prop :=
  ∀ action environment childResult,
    evaluate child action environment = .eligible childResult →
    ∃ parentResult,
      evaluate parent action environment = .eligible parentResult ∧
      resultRefines childResult parentResult
```

An efficient syntactic `tightens` decider MUST be proved sound for this
relation. Antisymmetry is required only modulo semantic equivalence or after
canonical policy normalization; syntactically different policies may admit the
same actions. `environment` contains the shared evidence, state snapshot, time,
and semantic configuration; each policy carries and validates its own version
and canonical digest.

Eligibility MUST NOT be reduced to a Boolean for this proof. Each policy type
must define when one successful result safely refines another. Tightening may
add obligations, but it may not drop resource usage that must be reserved or
produce a reservation intent that undercounts the same exact action. The
definition therefore retains the required result-refinement relation as well
as acceptance.

### 7.5 Reservation and execution transition system

Lean MUST model the product lifecycle as an abstract transition system over a
linearizable durable-store interface and an explicit event trace. At minimum
it distinguishes:

```text
evaluated
    -> decision-recorded
    -> reserved
    -> execution-intent-recorded
    -> executing
         -> committed
         -> released
         -> outcome-unknown
              -> reconciled-committed
              -> reconciled-released
```

One storage transaction MAY establish several adjacent postconditions
atomically, but the abstract trace must show that each one holds before the
next security-sensitive event.

The shared state machine MUST be parameterized by a closed, versioned
`ReservationAlgebra` that defines its key, intent, state, invariant, and legal
transitions. Exact-action claims prove uniqueness, locks prove exclusivity,
numeric budgets prove additive conservation, and rolling windows prove
conservation only over usage in the applicable window. There is no universal
numeric ceiling invariant for every reservation kind.

The state machine MUST prove:

- each reservation algebra’s declared capacity or exclusivity invariant;
- numeric committed use plus reserved, executing, and outcome-unknown use
  never exceeds the applicable ceiling;
- reserve and claim operations keyed by reservation/action identity are
  idempotent;
- one logical claim issues at most one live execution authorization;
- replay returns the existing decision/result receipt and reuses the same
  claim, reservation, and idempotency or conditional-write material;
- the decision receipt, reservation, and exact execution intent are durable
  before credential acquisition or provider call;
- a verified command cannot be constructed without core authorization,
  policy eligibility, matching commitments, and a successful reservation;
- denial or indeterminate results cannot reach credential acquisition;
- the execution token binds the decision receipt, action, policy/evaluator,
  evidence/configuration, reservation-intent digest, audience, and expiry;
- an outcome-unknown reservation is never released merely because a process
  timed out or restarted;
- release occurs only after proven non-effect;
- reconciliation preserves budget conservation;
- commit and release are mutually exclusive for one reservation; and
- expiry and rolling-window transitions cannot free capacity that may already
  have produced an unobserved effect;
- revocation or expiry blocks new reservations; and
- the versioned reservation contract explicitly decides whether a reserved but
  not yet executing action can be cancelled, while executing and
  outcome-unknown actions remain held until proven non-effect.

Temporal claims such as “durable before credential acquisition” MUST be proved
over reachable traces containing store-linearization, credential-acquisition,
provider-call, response, crash, restart, and reconciliation events. They MUST
NOT be obtained merely by defining possession of a stage type to mean that the
earlier events happened.

The proof is conditional on the store contract. Lean does not prove PostgreSQL
fsync, a cloud provider, or Stripe. Each store adapter MUST provide
transaction-level conformance, concurrent histories, restart/fault injection,
isolation-level checks, and a reviewed linearizability argument. Unless an
adapter is itself mechanically verified, its status remains tested plus an
explicit store-engine assumption, not “Lean-refined.”

The store proves at most one live logical execution authorization, not at most
one external effect. One logical provider effect additionally depends on a
versioned provider contract for idempotency or conditional execution. A retry
with the same key is permitted only when that contract defines the key’s scope,
retention window, request-equality behavior, and reconciliation semantics.
Otherwise an unknown outcome must reconcile before retry. Receipts must never
misrepresent several HTTP attempts as one call.

### 7.6 Policy authority provenance

A standing bounded policy must have an explicit authority source:

1. a signer-authorized, versioned proof/grant/profile commitment to
   `policy_digest`, evaluator semantic identifier, canonicalization version,
   and executor audience; or
2. executor-local policy supplied through committed trusted configuration.

The second form is local policy enforcement. The UI, receipts, and public
claims MUST NOT describe it as a human-delegated standing policy. Before Auths
claims reusable signed standing delegation, the protocol must specify and
version how the immutable policy/evaluator commitment is carried, for example
through a critical extension or profile-bound field. This specification does
not assume that the current V1 grant already carries it.

The exact action MUST bind the same policy digest, evaluator semantic
identifier, canonicalization version, and executor audience. A core-authorized
action commitment and a separately evaluated action are not composable until
the action commitment is proved to open to those exact canonical action bytes.
Here `opens(action_commitment, exact_action)` includes equality between the
commitment and the domain-separated digest of the exact canonical action.

### 7.7 Core-to-product composition theorem

The formal seam SHOULD have this shape:

```text
core_authorized(proof, action_commitment)
and
opens(action_commitment, exact_action)
and
policy_authorized(proof_or_trusted_context,
                  policy_digest,
                  evaluator_semantic_id,
                  canonicalization_version,
                  executor_audience)
and
action_binds(exact_action,
             policy_digest,
             evaluator_semantic_id,
             canonicalization_version,
             executor_audience)
and
evaluate(evaluator, policy, exact_action, evidence, snapshot, now)
  = Eligible(reservation_intents, obligations)
and
eligibility_output_binds(exact_action_digest,
                         policy_digest,
                         evaluator_semantic_id,
                         evidence_digest,
                         snapshot_digest,
                         required,
                         executed,
                         reservation_intents,
                         obligations)
and
commitments_match(required, executed)
and
decision_recorded(decision_receipt_id,
                  exact_action_digest,
                  policy_digest,
                  evidence_digest,
                  required,
                  executed,
                  reservation_intents,
                  obligations)
and
reserve(pre_state, reservation_intents) = (reserved_state, reservation_token)
and
execution_intent_recorded(decision_receipt_id,
                          exact_action,
                          reservation_token,
                          idempotency_material)
and
execution_token_binds(exact_action_digest,
                      policy_digest,
                      evaluator_semantic_id,
                      evidence_digest,
                      required,
                      executed,
                      reservation_intents_digest,
                      decision_receipt_id,
                      executor_audience,
                      expiry)
implies
may_construct_verified_command(reachable_trace,
                               current_store_state,
                               now,
                               execution_token,
                               exact_action)
```

The inverse control-flow theorem is equally important:

```text
may_construct_verified_command(reachable_trace, state, now, token, action)
implies
there exists a matching core authorization,
opening of its commitment to this exact action,
authorized policy provenance,
policy eligibility result,
configuration match and durable decision receipt,
live reservation and execution intent at this state and time,
and token bindings for that exact action and every committed input
```

`may_construct_verified_command` MUST be defined independently of the
conjunction it is intended to imply and proved over reachable event traces and
the mechanically linked private Rust constructor. Defining possession of a
token to mean that all premises occurred would repeat the current
theorem-by-definition problem.

These theorems define the boundary enforced jointly by stage-typed Rust APIs
and the durable store. They do not claim that external evidence is truthful or
that a provider honored the command. Those facts are explicit assumptions and
later observations.

### 7.8 Domain refinement

After the common contract is based on seven working domains, each concrete
evaluator version MUST provide:

- a closed mathematical policy and evidence model;
- a mechanically linked pure Rust reference evaluator;
- canonical policy, action, evidence, and result fixtures;
- boundary, mutation, and hostile cases;
- its policy-tightening proof;
- its arithmetic and freshness proofs;
- a mapping into reservation intents and obligations; and
- an assurance-manifest entry listing unproved adapter/provider assumptions.

Stripe’s evidence-relative percentage and aggregate refund rules, Kubernetes
resource/replica scopes, OpenTofu plan/change limits, and PostgreSQL row/value
limits remain distinct semantics. Shared machinery MUST compose those closed
evaluators; it MUST NOT flatten them into a permissive expression language.

## 8. API boundaries

### 8.1 Core authority API

The isolated Rust kernel SHOULD expose semantic operations equivalent to:

```rust
pub struct DelegationEvaluation<'a> {
    pub checks: AttenuationChecks,
    pub outcome: Result<AcceptedTransition<'a>, DelegationDenial>,
}

pub fn apply_grant<'a>(
    parent: ChainStateView<'a>,
    grant_id: GrantId,
    grant: GrantView<'a>,
) -> DelegationEvaluation<'a>;

pub fn check_action_coverage(
    authority: ChainStateView<'_>,
    action: ActionView<'_>,
) -> CoverageDecision;

```

The final concrete types depend on the translation qualification. Views MUST
borrow or losslessly project validated model values. They MUST NOT parse
canonical bytes, acquire context, or hide fallible semantic normalization.

`auths-authority` owns storage of the effective state, but it MUST commit the
kernel’s returned next state and diagnostic without independently recreating
either one.

### 8.2 Product policy API

The shared product contract SHOULD distinguish eligibility from executable
authorization:

```rust
pub enum Eligibility {
    Eligible {
        reservations: ReservationIntents,
        obligations: Obligations,
    },
    Denied(StableCode),
    Indeterminate(StableCode),
}

pub struct ExecutionAuthorization {
    core_authorization: CoreAuthorizationWitness,
    exact_action: CanonicalAction,
    action_digest: Digest,
    policy: PolicyCommitment,
    evaluator: EvaluatorSemanticId,
    evidence_digest: Digest,
    state_snapshot_digest: Digest,
    required_configuration: ConfigurationCommitment,
    executed_configuration: ConfigurationCommitment,
    configuration_match: ConfigurationMatchProof,
    decision_receipt: DecisionReceiptId,
    reservation: ReservationToken,
    execution_claim: ExecutionClaim,
    effect_deduplication: EffectDeduplicationCommitment,
    executor_audience: Audience,
    expires_at: Timestamp,
    obligations: EnforcedObligations,
}
```

Only product runtime code that has validated all commitments and acquired a
durable reservation may construct `ExecutionAuthorization`. Domain executors
accept that stage type and derive `VerifiedCommand<C>` from it rather than
reconstructing commands from loose fields.

The constructor and fields MUST be private to the enforcing runtime boundary.
The capability MUST NOT implement `Clone` or serialization, and debug output
must not leak credential material. Possession alone is not the proof:
construction atomically binds to the durable claim’s
`reserved -> executing` transition, and dependency/call-graph checks plus the
mechanically linked constructor enforce that repository code cannot bypass the
stage.

## 9. Performance and representation refinement

Formal assurance must support optimization rather than freeze an inefficient
implementation.

The repository MUST retain:

1. a simple, readable, mechanically translatable reference evaluator;
2. exact canonical input and output corpora;
3. an explicit abstraction relation from optimized representations to logical
   values; and
4. a representation-refinement proof for every security-affecting optimized
   shipping path.

Exhaustive model checking may replace a universal proof only when CI actually
enumerates the entire precisely declared finite carrier. Differential fixtures,
property tests, fuzzing, and Kani over a bounded abstraction remain important
evidence but MUST be labeled tested or bounded-checked; they do not establish
equivalence over intractable sets of bounded strings, sets, or `u64` values.

Safe candidates include fixed-byte digests, prevalidated sorted slices,
precompiled immutable configuration, request-local interning or arenas,
single-pass comparisons, and lazy construction of rare diagnostic data.

An optimization MUST preserve:

- decision class, code, and stage;
- selected branches and diagnostic order;
- evaluated bounds and reservation intents;
- required/executed commitments;
- exact command derivation;
- semantic receipt contents and canonical receipt bytes when every committed
  input, including implementation provenance, is equal; and
- declared work and allocation upper bounds.

When an optimized build has different executed-build provenance, the stored
receipt MUST retain that fact. Semantic receipt equivalence may allow only the
explicitly reviewed provenance-field difference; it MUST NOT normalize
provenance away to manufacture byte identity.

Every benchmark result MUST name the exact fixture digest, repository/build
revision, evaluator semantic identifier, implementation identifier, cold or
warm mode, and phase-level allocation and work counters. Provider/network
latency must be reported separately so it cannot hide a local semantic-kernel
regression.

Canonical CBOR MUST NOT change to mirror an optimized memory layout. Verdicts,
reservations, provider outcomes, and receipts MUST NOT become asynchronous or
best-effort for latency. Unsafe layouts, custom allocators, caches of final
verdicts, or speculative SIMD require a measured bottleneck, a separate review,
and the same refinement gate.

## 10. Proof and developer UX

Formal status must be legible without reading Lean source. The repository
workflow SHOULD provide:

```text
$ cargo xtask formal audit
Claim                                      Status
core.permission-subset                     proved + Rust-refined
core.validity-containment                  proved + Rust-refined
core.action-coverage                       proved + Rust-refined
core.boolean-aggregation                   proved + generated
product.stripe.exact-refund/1              proved + Rust-refined
product.reservation.conservation           proved; store contract assumed
provider.stripe.effect                     observed; external assumption

$ cargo xtask formal case core/validity/transitivity-max
Lean rich result:       contained
Translated Rust result: contained
Shipping Rust result:   contained
Projection:             validity_attenuates=true
```

Failure output MUST name:

- the semantic claim;
- the Lean theorem and exact statement digest;
- the shipping Rust symbol and source digest;
- the linkage mechanism;
- the minimized rich counterexample or trace;
- residual assumptions; and
- one exact reproduction command.

Bounded-authorization demos MUST make the same boundary visible to users. Their
main interface and receipts must show the standing bound, agent-selected exact
action, evidence and calculation, state reservation, required and executed
configuration, credential/provider-call boundary, execution result, and later
observation. The UI must not imply that formal proof establishes external
provider truth.

## 11. CI, drift, and claim control

### 11.1 Canonical byte-to-model boundary

The proof chain is:

```text
canonical bytes
    -- codec assumptions + tests -->
validated Rust model
    -- proved structural/decision-adequate view -->
translated Rust predicate
    -- Lean refinement -->
rich semantics
```

Milestone 2 closes the validated-model-to-semantics gap. It does not by itself
prove the codec or cryptography. Core MUST retain exact canonical CBOR
fixtures, decode/re-encode identity, hostile and mutation seeds, and
byte-for-byte drift checks. Product policy, action, and evidence objects need
the same treatment using exact `.cbor` fixtures or an explicitly registered
alternate canonicalization with an immutable identifier.

Receipts and the assurance manifest MUST state where the codec remains tested
or assumed rather than proved.

### 11.2 Assurance manifest

Add a machine-readable versioned manifest for every public formal claim:

```text
claim_id
claim_text
claim_status
lean_declaration
lean_statement_digest
formal_review
rust_symbols
semantic_source_closure_digest
evidence = [
  { kind = lean-proof, artifact = ... },
  { kind = translated-rust, artifact = ... },
  { kind = bounded-kani, artifact = ... },
  { kind = test-corpus, artifact = ... }
]
scope
residual_assumptions
toolchain_lock_digest
```

The semantic source closure includes the complete crate source, semantic
dependencies, features and `cfg` values, lockfile, compiler and
Charon/Aeneas/Kani versions, external models, and extracted LLBC artifact. A
digest of a named Rust function alone is insufficient. `assumed` is a claim
status, not an evidence mechanism.

CI MUST inspect declarations from the compiled Lean environment. Source-text
substring matching is insufficient.

### 11.3 Axiom audit

For every exported claim, CI MUST report its transitive axiom dependencies and
compare them with a narrow reviewed allowlist. It MUST reject:

- `sorryAx`;
- unregistered axioms or opaque assumptions;
- a changed theorem statement under an unchanged reviewed manifest entry; and
- an unreviewed new or changed public claim.

CI cannot infer whether a Lean proposition matches an English sentence. The
initial claim audit MUST review that correspondence, record the approved
statement digest, and require formal/security review when the digest or claim
text changes.

The current source scan MAY remain as a fast preliminary check, but it is not
the security gate.

### 11.4 Generated and translated artifacts

Normal CI MUST be read-only and fail on:

- Rust/Lean semantic-contract drift;
- Aeneas/Charon translation drift;
- rich-vector drift;
- Boolean-vector drift;
- theorem-statement drift;
- assurance-manifest drift;
- toolchain-lock drift; or
- a changed closed authority/policy-dimension inventory without matching
  kernel, proof, and manifest updates.

CI can enforce drift only for dimensions declared in a closed inventory
consumed by generation or the kernel. Architecture checks and review MUST also
prevent callers from bypassing that inventory; arbitrary new Rust fields
cannot be discovered semantically by CI.

Updates require an explicit command, a reviewable generated diff, and an
assurance-manifest change where semantics or assumptions changed.

### 11.5 CI tiers

`cargo xtask formal` MUST expose:

```text
formal audit              claim statements, axioms, tools, and source mapping
formal core-rich          handwritten rich semantics and theorems
formal rust-refinement    translated production kernel and equivalence proofs
formal algebra            existing Boolean and composition boundary
formal product            bounded policy and reservation state machines
formal conformance        rich fixtures, Kani, properties, mutations, traces
```

Fast pull-request tiers MAY cache pinned tools, but a hosted formal check is
required. Release CI MUST run every tier from a clean environment and
reproduce all generated artifacts.

## 12. Implementation sequence and gates

### Milestone 0: formal baseline and translation qualification

Execute the complete first tranche in section 1.1. This milestone is not a
general formal-model rewrite.

**Gate:** every current formal claim is classified accurately, formal checks
are required in hosted and release CI, the exact qualification artifacts
reproduce from clean state, and the reviewed ADR selects exactly one mechanical
route. Milestone 1 is blocked until that ADR is merged.

### Milestone 1: rich Lean core

- add `AuthorityScope`, `ChainState`, rich component types, grant
  transition, action coverage, and ordered diagnostics;
- prove every component, chain, coverage, and projection theorem; and
- retain the generated Boolean boundary.

**Gate:** no scalar ordering stands in for a set, interval, identifier,
constraint, or transition relation.

### Milestone 2: shipping kernel and refinement

- complete the pure production Rust authority kernel, building on any
  production slice introduced during qualification;
- route production delegation and coverage through it;
- execute the ADR-selected mechanical route: translate the exact kernel with
  Aeneas or generate the only shipping implementation and Lean evaluator from
  the restricted declarative contract;
- prove the translated/generated functions refine the rich specification; and
- add rich vectors, pinned Kani harnesses, properties, and the mutation
  matrix.

**Gate:** every operator in the versioned required mutation matrix is killed by
the refinement or conformance suite. There is no independently maintained
production predicate outside the proved boundary.

### Parallel domain milestone: OpenTofu and PostgreSQL

- complete specifications 0008 and 0009 end to end;
- retain domain-local implementations while gathering evidence;
- exercise concurrency, interruption, outcome-unknown, and reconciliation; and
- produce the seven-domain semantic inventory required by the bounded plan.

**Gate:** both demos perform real local effects, pass hostile and crash cases,
and expose complete frontend and receipt experiences.

### Milestone 3: closed bounded-policy semantics

- derive the common contract from the seven-domain inventory;
- formalize each selected closed evaluator version;
- prove fixed-context policy tightening and arithmetic/freshness laws;
- mechanically link each pure reference evaluator; and
- bind semantic and implementation identities in the registry.

**Gate:** every evaluator identifier has one immutable semantic contract,
required/executed commitments are enforced, and changed semantics require a new
version.

### Milestone 4: reservation/execution semantics

- formalize the transition system and core-to-product composition seam;
- implement stage-typed product APIs;
- establish transactional-store conformance;
- run concurrent, revocation, restart, and fault-injection histories; and
- prove conservation, idempotence, fail-closed unknown outcomes, and credential
  ordering under the store contract.

**Gate:** no code path can construct a verified provider command before core
authorization, policy eligibility, exact commitment equality, durable decision
receipt, reservation, and execution intent.

### Milestone 5: extraction and migration

- extract only abstractions justified by the seven-domain comparison; an
  abstraction MAY serve a demonstrated subset while other domains compose
  smaller primitives or retain domain-specific behavior;
- migrate Stripe first while retaining its previous implementation as an
  oracle;
- migrate Kubernetes, PostgreSQL, OpenTofu, GitHub, and Radicle in reviewed
  order; and
- require exact decision, receipt, reservation, and effect-boundary
  equivalence.

**Gate:** shared code reduces duplication without erasing domain semantics or
changing observable authorization decisions.

### Milestone 6: optimized implementations

- establish the exact benchmark corpus and phase measurements;
- implement only measured optimizations;
- prove the representation refinement for security-affecting shipping paths
  and retain differential validation as defense in depth; and
- record executed build provenance in receipts.

**Gate:** a universal refinement proof, or genuine exhaustive enumeration of a
declared finite carrier, establishes semantic equivalence. Corpus-only evidence
cannot inherit the reference evaluator’s proved status.

## 13. Trusted computing base and claim language

The assurance manifest MUST make these categories explicit:

| Claim | Intended status after this specification |
| --- | --- |
| Rich authority mathematical laws | Lean-proved |
| Pure shipping Rust authority predicates | mechanically translated and proved to refine the rich model |
| Generated Boolean aggregation | Lean-proved, generated into Rust, exhaustively cross-checked |
| Pure closed bounded-policy evaluator | Lean-proved and mechanically Rust-refined per evaluator version |
| Reservation transition laws | Lean-proved under an atomic durable-store contract |
| Concrete store implementation | concurrency, transaction, restart, and fault-injection conformance; store engine assumed |
| Canonical codec and cryptography | governed by their own tests/assurance boundary unless separately proved |
| Evidence acquisition and freshness inputs | adapter verification and explicit trusted-context assumptions |
| Provider effect and observation | external system assumption plus reconciliation and observed receipts |
| Rust compiler, Lean kernel, translator, and pinned libraries | explicit toolchain trusted computing base |

Until Milestone 2 passes, Auths may say:

> Lean proves the authority aggregation and abstract ordering laws; rich
> production projections remain an explicit tested trust boundary.

After Milestone 2 passes, Auths may say:

> Lean proves the rich authority semantics and verifies that the isolated pure
> Rust authority kernel used by production refines them, subject to the
> published toolchain and representation assumptions.

It MUST NOT say that Lean proves the entire verifier, codecs, cryptography,
store engine, external evidence, credentials, or provider behavior.

## 14. Completion criteria

This specification is complete only when:

- rich Lean semantics cover every shipping attenuation and action-coverage
  dimension;
- transition fields are separated from the semantically ordered authority
  scope;
- strict depth is proved well-founded rather than mislabeled a partial order;
- action permission and audience are modeled as membership;
- production calls one isolated pure rich authority implementation;
- that implementation is mechanically represented in Lean and proved
  equivalent to the rich specification;
- the accepted next state and caller-specific diagnostic selection are inside
  the proved/generated boundary;
- the validated-model-to-semantics proof and the separately tested/assumed
  byte-to-model boundary are reported accurately;
- the existing Boolean boundary remains generated, exhaustive, and
  fail-closed;
- compiled theorem statements and transitive axiom dependencies are enforced;
- a pinned hosted formal check and the complete clean release formal gate are
  required;
- the translation qualification reproduces from clean state and its merged ADR
  selected the mechanical route before the rich rewrite began;
- every mutation in the versioned required semantic mutation matrix is killed
  by the formal/refinement gate;
- OpenTofu and PostgreSQL precede generic bounded implementation extraction;
- bounded policy uses closed versioned evaluators and fixed-context tightening
  laws that preserve reservation and obligation outputs;
- the standing policy’s authority source and the opening from the
  core-authorized commitment to exact action bytes are explicit;
- eligibility, durable decision receipt, reservation, execution intent, and
  execution authorization remain distinct proved postconditions;
- obligations are discharged, enforced in command construction, or tracked
  through observation without being dropped;
- every reservation algebra proves its applicable exclusivity or capacity
  invariant, replay, unknown-outcome, revocation, and credential-ordering laws
  under an explicit store contract;
- concrete stores pass concurrency, revocation, restart, and crash conformance
  while their residual engine assumptions remain published;
- provider-effect claims name their idempotency or conditional-write
  assumptions;
- optimized paths formally refine a simple reference evaluator, preserve wire
  semantics, and retain actual build provenance in receipts; and
- every published assurance claim names its proof mechanism and residual
  assumptions.

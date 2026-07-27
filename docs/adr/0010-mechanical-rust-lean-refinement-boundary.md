# ADR 0010: Generate the Rust–Lean Algebra Boundary from One Contract

**Status:** Accepted

**Date:** 27 July 2026

## Context

The target V1 attenuation and composition algebras are implemented in Rust and
modeled in Lean. Building both implementations is useful, but two handwritten
definitions do not establish that the shipping Rust refines the Lean model.
Example vectors reduce that risk without closing the semantic gap.

The initial formalization has three specific weaknesses:

- the Rust reference evaluator repeats the Lean composition definition;
- the Lean vector executable does not generate the checked-in vectors;
- several theorem names describe intended shipping behavior while proving only
  facts about definitions constructed to make the theorem reflexive.

Shared Rust traits and Lean typeclasses would align vocabulary, but matching
interfaces alone would not prove matching behavior.

Aeneas can translate a subset of safe Rust into Lean. Introducing it for the
whole verifier now would add an OCaml, Charon, Rust-nightly, and generated-model
toolchain around code containing dependencies and dynamic adapter boundaries
outside its best-supported subset. The pure algebra boundary is small enough to
obtain a mechanical link without making that toolchain part of the release
gate.

## Decision

Define one versioned, declarative algebra contract and generate both sides of a
small production boundary from it:

```text
formal/algebra-contract-v1.toml
                 |
          deterministic generator
          /                     \
         v                       v
Rust algebra kernel       Lean generated model
         |                       |
         | shipping callers      | refinement theorems
         v                       v
authority + composition    abstract Auths algebra
         |
         +---- Lean-generated exhaustive vectors
         |
         +---- Kani symbolic implementation checks
```

The generated Rust module owns:

- the closed three-valued truth type;
- threshold-count classification;
- the shared attenuation-projection trait;
- conjunction of every declared attenuation dimension.

The generated Lean module owns the corresponding truth type, threshold
classifier, attenuation projection, and acceptance function.

`auths-composition` and `auths-authority` MUST call the generated Rust kernel.
No second shipping implementation of these aggregate decisions is permitted.

The handwritten Lean layer MUST prove useful properties about the generated
definitions and MUST state explicit refinement theorems connecting them to the
abstract relations. A theorem inventory entry is not accepted merely because
its conclusion repeats its premise or a definition.

## Developer UX

The ordinary check is:

```text
cargo xtask formal
```

It:

1. regenerates Rust and Lean algebra modules in memory;
2. rejects any byte difference from the checked-in generated files;
3. builds the Lean project;
4. executes Lean to regenerate semantic vectors in memory;
5. rejects any byte difference from the checked-in vectors;
6. runs Rust refinement tests;
7. runs Kani against the generated shipping kernel.

An intentional contract change uses:

```text
cargo xtask formal --update
```

The update command rewrites generated modules and vectors. Reviewers can
therefore see the semantic source change and all generated consequences in one
diff.

Generated files carry a header prohibiting manual edits.

## Architecture

Add `auths-algebra-kernel` as a `no_std`, allocation-free core crate below
authority and composition:

```text
auths-model
     ^
     |
auths-algebra-kernel
     ^             ^
     |             |
auths-authority   auths-composition
```

The algebra kernel has no dependency on model, codec, adapters, verifier, or
tooling. It operates on counts and on a generated projection trait.

`auths-authority` remains responsible for projecting rich protocol objects into
dimension checks. The kernel is responsible for combining those checks. This
makes the exact proof boundary explicit:

- mechanically linked and formally modeled: aggregate attenuation acceptance
  and composition truth;
- separately tested: each rich domain projection such as set inclusion,
  interval containment, budget ordering, and status-policy ordering;
- outside this ADR: cryptography, canonical decoding, adapter evidence, and
  complete verifier control flow.

## APIs

The generated Rust surface is:

```rust
pub trait AttenuationProjection {
    fn root_preserved(&self) -> bool;
    fn depth_decreases(&self) -> bool;
    fn profile_attenuates(&self) -> bool;
    fn permissions_attenuate(&self) -> bool;
    fn validity_attenuates(&self) -> bool;
    fn audiences_attenuate(&self) -> bool;
    fn action_constraint_attenuates(&self) -> bool;
    fn budget_attenuates(&self) -> bool;
    fn status_attenuates(&self) -> bool;
    fn assurance_attenuates(&self) -> bool;
}

pub fn attenuation_accepts(
    projection: &impl AttenuationProjection,
) -> bool;

pub fn threshold_counts(
    required: u16,
    authorized: usize,
    indeterminate: usize,
) -> Truth;
```

The generated Lean surface mirrors these operations:

```lean
structure AttenuationProjection where
  rootPreserved : Bool
  depthDecreases : Bool
  profileAttenuates : Bool
  permissionsAttenuate : Bool
  validityAttenuates : Bool
  audiencesAttenuate : Bool
  actionConstraintAttenuates : Bool
  budgetAttenuates : Bool
  statusAttenuates : Bool
  assuranceAttenuates : Bool

def attenuationAccepts (projection : AttenuationProjection) : Bool
def thresholdCounts
    (required authorized indeterminate : Nat) : Truth
```

The casing difference is generated, not maintained by hand.

## Proof obligations

The accepted implementation MUST establish:

1. threshold results form a total, mutually exclusive partition;
2. increasing `required` cannot increase authority;
3. aggregate attenuation accepts exactly when every declared dimension accepts;
4. adding an attenuation dimension fails closed until both generated sides and
   the production projection implement it;
5. every threshold-count state through the declared exhaustive bound, equal to
   the target V1 default deployment leaf limit, is emitted by Lean and accepted
   by the shipping Rust kernel;
6. every Boolean attenuation projection is emitted by Lean and accepted or
   rejected identically by the shipping Rust kernel;
7. ordinary composition and delegation tests continue to pass through the
   generated kernel.

Kani checks the production Rust functions with symbolic values at the target V1
bound. Lean proves the unbounded mathematical properties. Exhaustive
Lean-generated vectors close the finite target V1 correspondence.

## Trusted computing base

This design does not claim that Lean proves the Rust compiler or the entire
verifier. The refinement trusted computing base contains:

- Lean and its kernel;
- the small deterministic contract generator;
- the Rust compiler;
- the mapping from rich authority values to Boolean projection fields.

The generator is intentionally simple, version-pinned by checked-in output, and
covered by drift checks. A future Aeneas translation of the pure kernel can
reduce trust in that generator, but is defense in depth rather than a
prerequisite for this decision.

## Consequences

### Positive

- Rust and Lean cannot silently add, remove, or rename algebra operations
  independently.
- The production code, not a duplicate reference implementation, consumes the
  generated Rust algebra.
- Semantic vectors genuinely originate in Lean.
- The finite target V1 domain is exhaustively cross-checked.
- The boundary and residual trust assumptions are reviewable.

### Negative

- Generated Rust and Lean files are checked into the repository.
- The generator becomes security-relevant code.
- Rich domain projections still require their own proofs or property tests.
- Contract changes intentionally produce broad generated diffs.

## Rejected alternatives

### Keep handwritten Lean and Rust definitions with example vectors

Rejected because agreement depends on reviewers noticing semantic drift.

### Share only traits or type names

Rejected as insufficient: structural agreement does not establish semantic
agreement.

### Call Lean from Rust through the FFI

Rejected because execution interoperability does not prove refinement and would
add Lean runtime code to the shipping kernel.

### Translate the entire verifier with Aeneas immediately

Rejected for this decision because the toolchain and supported Rust subset would
make the proof boundary larger and less reproducible than the algebra being
verified. Reconsider Aeneas for the isolated kernel after this boundary is
stable.

## Implementation plan

1. Add the versioned algebra contract and deterministic generator.
2. Add `auths-algebra-kernel` and route production composition through it.
3. Route production delegation attenuation aggregation through the generated
   trait.
4. Import the generated Lean model into the abstract proofs.
5. replace reflexive theorem placeholders with refinement statements.
6. Generate exhaustive threshold and attenuation vectors from Lean.
7. Make drift, Lean, vector, Rust, and Kani checks one `xtask` command.
8. Record the exact boundary and limitations in the formal README and spec.

## Acceptance criteria

This ADR is implemented only when:

- editing either generated file by hand makes `cargo xtask formal` fail;
- editing the contract and running without `--update` fails;
- `cargo xtask formal --update` deterministically regenerates both languages and
  both vector sets;
- `auths-authority` and `auths-composition` use `auths-algebra-kernel`;
- the Rust refinement crate contains no handwritten composition evaluator;
- Lean-generated vectors exhaust the declared target V1 domains;
- Kani verifies the generated Rust functions;
- workspace architecture, formatting, tests, and strict lint pass.

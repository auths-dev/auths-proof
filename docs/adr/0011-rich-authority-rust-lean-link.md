# ADR 0011: Translate the Production Authority Kernel with Aeneas

**Status:** Accepted

**Date:** 29 July 2026

**Decision:** `GO-AENEAS-WITH-PRODUCTION-RESHAPE`

## Context

ADR 0010 mechanically links the finite Boolean aggregation boundary, but the
shipping authority implementation still decides each Boolean by applying rich
Rust operations: sorted-set membership and subset, inclusive validity-window
containment, action constraints, optional budgets, status policies, profile
selection, chain linkage, and terminal action coverage.

Modeling equivalent sets and intervals independently in Lean would improve the
mathematical specification without proving that production Rust implements
it. The long-term design therefore needs a mechanical representation of the
exact Rust called by production, followed by refinement proofs against the
readable rich Lean specification.

The translation qualification in specification 0011 tested pinned Charon and
Aeneas revisions against exact production-source slices. The original methods
mixed pure decisions, repeated comparisons, and state mutation. They were
reshaped into total safe functions over lossless borrowed views:

- `auths-model` owns the leaf predicates;
- `auths-authority::evaluate_grant_view` owns linkage, every attenuation
  decision, ordered denial selection, and the complete accepted transition;
- `auths-authority::evaluate_action_coverage_view` owns terminal action
  coverage and ordered denial selection; and
- shipping delegation and authorization call these functions and only commit
  or map their results structurally.

The public wire format, canonical encodings, verifier decisions, stable denial
codes, and accepted state are unchanged.

## Decision

Use the preferred section 6.2 route from specification 0011:

```text
validated production Rust values
              |
              v
  exact pure production functions
              |
        Charon / LLBC
              |
           Aeneas
              |
              v
 checked-in generated Lean evaluator
              |
      refinement theorems
              |
              v
 handwritten rich Lean specification
```

The qualification outcome is `GO-AENEAS-WITH-PRODUCTION-RESHAPE`, not plain
`GO-AENEAS`, because a production reshape was needed to put the complete
decision and accepted-state boundary inside translatable safe Rust.

The generated qualification modules are evidence that the route works; they
are not yet the rich refinement proof. Milestone 1 of specification 0011 may
begin only after this ADR and its qualification artifacts are merged.

## Qualification result

The pinned environment establishes all of the following:

- Lean `v4.31.0` builds the existing Auths model and the pinned Aeneas runtime;
- Charon lowers the selected production functions with shipping features and
  no extraction-only semantic `cfg`;
- Aeneas translates all local model predicates, the generated Boolean
  conjunction, the complete grant evaluator, and the complete terminal
  coverage evaluator without an opaque local function;
- the accepted transition and stable diagnostic choice remain inside the
  translated evaluator;
- every rich external call in the authority translation links to the separately
  translated `auths-model` definition;
- the only standard-library semantic bridge is `String::as_bytes`, represented
  transparently as Aeneas' exact UTF-8 conversion on the validated Auths string
  domain and a fail result outside that domain;
- the model, algebra, and authority import closures compile with the same
  pinned Lean/Aeneas environment;
- translation templates, external links, source closure, warnings, tools, and
  cases are inventoried under `formal/qualification/aeneas`; and
- the repository command reproduces the generated output twice and requires
  byte-identical output.

The Aeneas runtime currently contains four `sorry` declarations in general
slice/string-iterator proof support. They are pinned and inventoried. None is a
transitive axiom dependency of the generated executable qualification
definitions audited here. They may not silently enter a claimed Auths theorem;
the compiled assurance audit remains fail-closed on `sorryAx`.

## Representation boundary

Aeneas erases the private Rust newtype constructors into Lean carriers. The
translation is therefore about production functions over values satisfying the
shipping model invariants, not arbitrary independently constructed Lean
strings or vectors.

That boundary is explicit:

- Auths string newtypes are non-empty and protocol-bounded;
- permission and audience collections are non-empty, bounded, sorted, and
  duplicate-free;
- validity windows and profiles are constructor-validated; and
- lossless-view tests establish that every field consumed by the evaluator is
  copied from the validated production object.

Milestone 2 must prove the validated-carrier-to-rich-semantics connection and
must not claim correctness for malformed values that safe Rust constructors
cannot create.

## CI and developer UX

The ordinary formal gate:

```text
cargo xtask formal
```

builds the checked-in Aeneas runtime and generated import closures, validates
the exact source closure and inventories, runs the qualification cases, audits
compiled Auths theorem statements and transitive axioms, runs Rust refinement
tests, and runs Kani.

The clean translation reproduction:

```text
cargo xtask formal qualify aeneas
```

requires the exact pinned Charon and Aeneas binaries, translates the production
source twice, rejects warnings and semantic `cfg` divergence, compares the two
outputs byte-for-byte, and compares them with the checked-in artifacts.

An intentional source or generator change uses:

```text
cargo xtask formal qualify aeneas --update
```

Generated output and the source-closure inventory must change together and be
reviewed together.

## Trusted computing base

This decision trusts:

- the Lean kernel and pinned Lean libraries;
- the pinned Charon/Aeneas translation toolchain and its Rust/LLBC semantics;
- the Rust compiler for the shipping binary;
- the validated Rust constructor and lossless-view boundary until its
  Milestone 2 refinement is complete;
- the reviewed `String::as_bytes` model on Auths' bounded string domain; and
- the generated-contract bridge for the ten-field Boolean conjunction.

It does not claim to prove decoding, canonical CBOR, cryptography, registries,
clocks, stores, adapters, credentials, provider effects, or the complete
verifier control flow.

## Consequences

### Positive

- The future rich Lean proofs can target the actual production evaluator,
  rather than a verification-only duplicate.
- Set, interval, constraint, budget, status, profile, linkage, transition, and
  diagnostic logic have one shipping implementation.
- A changed production source file invalidates the qualification closure even
  if ordinary examples continue to pass.
- The mechanical route remains separate from the workspace MSRV and from
  runtime dependencies.

### Negative

- Clean reproduction adds pinned Charon, Aeneas, OCaml/Nix, Rust nightly, and
  Lean tooling to the formal release environment.
- Checked-in generated Lean is intentionally verbose.
- The reviewed validated-carrier boundary remains an explicit proof obligation.
- Aeneas runtime warnings and external models must stay inventoried across
  upgrades.

## Rejected alternatives

### Independently rewrite rich Rust semantics in Lean

Rejected because equivalent-looking `Finset` and interval definitions would
not prove what the shipping Rust computes.

### Keep only the ten-Boolean boundary

Rejected because it proves aggregation after the security-relevant rich
decisions have already been made.

### Generate both languages from a new policy DSL now

Rejected for this milestone. It would move trust into a new generator before
the exact production translation route had been qualified. It remains the
specified fallback if a future pinned Aeneas route becomes unmaintainable.

### Translate the whole verifier

Rejected because codecs, cryptography, allocation-heavy parsing, registries,
and adapters are outside the pure authority-kernel proof boundary and would
increase the trusted surface without strengthening the authority theorem.

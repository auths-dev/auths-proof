# Auths-Proof formal model

This Lean 4 project proves properties of the target V1 authority ordering and
three-valued composition algebra. It deliberately excludes codecs,
cryptography, adapters, clocks, networking, storage, and complete verifier
control flow.

Every public theorem claim is listed in
[`assurance-manifest-v1.toml`](assurance-manifest-v1.toml). The compiled
[`Auths.AssuranceAudit`](Auths/AssuranceAudit.lean) target checks each exact
declaration name, statement, transitive axiom set, source closure, and required
evidence. This prevents a renamed, weakened, deleted, or `sorry`-backed theorem
from satisfying the repository gate through a textual look-alike.

## Mechanical Rust–Lean boundary

[`algebra-contract-v1.toml`](algebra-contract-v1.toml) is the single source for
the finite production algebra boundary. The repository generator derives:

- `core/crates/auths-algebra-kernel/src/generated.rs`, consumed by shipping
  authority and composition code;
- `Auths/Generated/Algebra.lean`, imported by the proofs.

Lean generates every threshold-count state through the target V1 default
deployment limit and every Boolean attenuation projection. Rust tests consume
those exact vectors, while Kani symbolically checks the generated Rust
functions. The Lean threshold theorems themselves are unbounded.

The production-translation qualification in
[`qualification/aeneas/qualification.toml`](qualification/aeneas/qualification.toml)
pins the shipping and extraction toolchains, translates the exact pure
production predicates with Charon and Aeneas, builds executable Lean cases,
inventories every external model and upstream warning, checks the complete
translation source closure, and reproduces the generated artifacts twice
byte-for-byte. The reviewed decision is recorded in
[`ADR 0011`](../docs/adr/0011-rich-authority-rust-lean-link.md).

That qualification establishes a mechanical route and moves the shipping path
behind extractable pure predicates. It does **not** yet close the rich
projection gap. Until AP-SPEC-011 Milestones 1 and 2 are complete, the rich
permission, interval, audience, constraint, budget, status, profile, assurance,
and transition relations remain a tested and explicitly disclosed trust
boundary. The generated Boolean aggregation is still the part proved in Lean.

## Commands

Run the complete read-only check from the repository root:

```text
cargo xtask formal
```

For an intentional contract change:

```text
cargo xtask formal --update
```

The update regenerates both language modules and both vector sets. A normal
check rejects any byte drift.

To reproduce the qualified shipping-Rust translation with the exact pinned
Aeneas and Charon binaries:

```text
AUTHS_AENEAS_BIN=/absolute/path/to/aeneas \
AUTHS_CHARON_BIN=/absolute/path/to/charon \
cargo xtask formal qualify aeneas
```

`--update` is allowed only for an intentional, reviewed production-source or
translator-output change. Qualification performs two clean translations and
rejects nondeterministic or committed-output drift. The ordinary formal gate
validates the committed qualification without requiring translators on every
developer machine.

`lake build` checks Lean alone. The repository-level command additionally checks
the compiled theorem inventory and transitive axioms, the qualified production
translation, generated-source drift, generated-vector drift, Rust refinement
tests, domain property tests, and Kani harnesses.

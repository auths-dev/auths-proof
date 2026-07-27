# Auths-Proof formal model

This Lean 4 project proves properties of the target V1 authority product order
and three-valued composition algebra. It deliberately excludes codecs,
cryptography, adapters, clocks, networking, storage, and complete verifier
control flow.

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

The remaining trusted mapping is explicit: `auths-authority` projects rich
protocol values such as permission sets and validity windows into the generated
attenuation trait. Those individual projections remain covered by Rust domain
tests rather than by this Lean model.

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

`lake build` checks Lean alone. The repository-level command additionally checks
the theorem inventory, generated-source drift, generated-vector drift, Rust
refinement tests, and Kani harnesses.

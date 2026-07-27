# Auths-Proof formal model

This Lean 4 project models the authority product ordering and three-valued
composition algebra used by target V1. It deliberately excludes codecs,
cryptography, adapters, clocks, networking, and storage.

Run `lake build` in this directory to check every theorem. The repository-level
`cargo xtask formal` command additionally validates theorem inventory, semantic
vectors, Rust refinement tests, and Kani harnesses.

The Rust shipping crates never depend on this project.

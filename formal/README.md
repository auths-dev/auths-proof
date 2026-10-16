# Auths-Proof formal model

This Lean 4 project proves properties of target V1 authority ordering,
three-valued composition, and selected shipping codec and enforcement functions.
The complete verifier, complete protocol-object codecs, cryptographic
integration, backend implementations, adapters, physical clocks and networking
remain outside the completed proof surface. Each component's exact scope is
recorded below and in the assurance manifest.

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

That qualification translates selected shipping codec, identifier, authority,
attenuation, lifecycle and bounded-policy functions to Lean and refines them under stated
representation and external-model assumptions. The rich authority and
transition relations are no longer only a disclosed trust boundary around a
proved Boolean aggregation: their scoped refinement claims are listed in
[`assurance-manifest-v1.toml`](assurance-manifest-v1.toml), each with its scope
and residual assumptions. This is **not** a formally verified end-to-end
verifier. Complete codec totality/completeness, cryptographic integration,
backend behavior, clocks, networking, adapters and the complete verifier control
flow remain open obligations. Selected codec and enforcement claims must not
be presented as completion of those larger boundaries.

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

## Proof coverage and mutation adequacy

How much of the decision logic the proofs reach is measured, not stated:

```text
cargo xtask formal coverage            # check the committed measurement
cargo xtask formal coverage --update   # regenerate it after an intentional change
```

The tool ports study 006's scanner and first reproduces the study's figures
byte for byte from the vendored inputs of commit `8bf2970c`
(`coverage/pin-8bf2970c.tar.zst`). It reads the scope and file roles from
`coverage-scope-v1.toml`, theorem kinds from `theorem-kinds-v1.toml`, the
check-site map from `check-site-functions-v1.toml`, and the compiled theorem
statements from `lean-assurance-audit-v1.json`, which `cargo xtask formal`
keeps equal to the compiled audit. It writes `proof-coverage-v1.json`,
`proof-coverage-functions-v1.tsv`, and
[`docs/assurance/PROOF_COVERAGE.md`](../docs/assurance/PROOF_COVERAGE.md); the
authoritative and formal gates reject drift.

```text
cargo xtask formal mutations all --update --jobs 3
```

runs the three mutation campaigns over a built `formal/` and records every
outcome in `model-mutations-v1.json`. A survivor needs a fix or an entry in
its `explanations` before a release; `cargo xtask release-check` refuses stale
results. The scheduled `Formal mutations` workflow re-runs them weekly.

## Hosted CI feedback and qualification

The pull-request check named **formal proof fast (feedback, not qualification)**
compiles the committed Lean sources first. It does not install Aeneas, Charon,
or Kani, and its success is not formal assurance evidence. After it passes,
translation and Kani run in parallel; a separate clean Lean build and an
exact-revision evidence gate make the final decision.

A proof-only follow-up may reuse a successful earlier translation job when
the translation, toolchain, source, and evidence inputs still match. Changes
to those inputs require two fresh, byte-identical reproductions. The complete
qualified path remains in hosted CI; contributors do not need to install the
formal toolchains locally to receive proof diagnostics.

## Canonical-action byte binding

The complete shipping canonical-action decoder and encoder, including their
Auths constructors, are now in the extraction closure. No Auths function in
that closure is opaque. `Auths.Codec.Action.decode_encode_exact` states that
every successful decode re-encodes to the accepted bytes;
`accepted_encoding_unique` derives one accepted encoding per decoded action.
Neither theorem assumes injective hashes.

The parser folds a bounded owned attachment state, and the encoder folds its
owned writer. Named error converters and explicit borrowed-result matches keep
those transitions visible to translation and source coverage. Native tests
compare against the former implementation, retained only as a test oracle,
including valid randomized actions, mutations, truncation, duplicate and
aggregate attachment bounds, and optional budgets.

Reviewed transparent standard-library models supply checked conversions,
Option/Result, UTF-8 validation, copying, collection projections and the sole
pure digest-key sorting call. The exact stateless callback has a source proof.
The string representation bridge derives the Unicode stream from validated
strings; it does not assume arbitrary byte carriers are UTF-8. Cases include
valid strings, overlong UTF-8 and surrogate encodings.

`Auths.Codec.Examples` additionally proves acceptance and exact encoding of a
complete nonempty action. The same shipping decoder refuses duplicate keys,
nonminimal integers, invalid UTF-8, truncation, trailing input and a byte limit
one below the accepted input; it accepts the exact byte boundary. Evaluation
uses kernel-proved portable scalar/vector equalities, with the original checked
behavior retained outside each conservative branch. It adds no native axiom.
The action is opaque codec data, not an application authorization witness.

`Auths.Codec.Constructors` gives exact decisions for the five string constructors
on validated bounded UTF-8 carriers and the complete action body constructor.
`Auths.Codec.ActionValidity` connects successful decoding to a nonempty body
within both the 8 MiB protocol ceiling and the declared deployment body limit.
These accepted-result implications do not establish parser totality.

These are scoped component results. Full constructor validity, action inverse
completeness and work bounds, every other protocol object, and AP-SPEC-069's
remaining verifier, driver, history and cryptographic obligations are still
required. See the [implementation ledger](../docs/assurance/AP_SPEC_069_STATUS.md).

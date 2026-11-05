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

That qualification translates selected shipping authority, attenuation,
lifecycle, and bounded-policy predicates to Lean and refines them under stated
representation and external-model assumptions. The rich authority and
transition relations are no longer only a disclosed trust boundary around a
proved Boolean aggregation: their scoped refinement claims are listed in
[`assurance-manifest-v1.toml`](assurance-manifest-v1.toml), each with its scope
and residual assumptions. This is **not** a formally verified end-to-end
verifier. Canonical decoding, cryptography, storage, clocks, networking,
adapter behavior, and the complete verifier control flow remain outside this
proof surface.

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

## AP074 gateway correspondence review

The AP074 repair replaces the earlier implicit-read submission model with the
shipping `order::next_step` machine. A successful deadline check names durable
grant creation; only `Granted(true)` names `Send`. A replay stops with `Stored`,
and recording a response stops with `Response`. The ordering proofs retain
native verification, durable reservation, credential checks, pre-entry reads,
relative ceilings, and at most one send. A post-send path cannot produce a
refunding `NotEntered` result.

The attempt projection now includes its protocol, bounded revision, entry grant,
and recipient acknowledgement. `translated_valid_transition_refines_model`
proves exact correspondence for every pair of translated views, including
revision-overflow refusal. The natural model proves protocol retention,
revision advancement, grant retention, and terminal-stage finality. Its unknown
exit table distinguishes three evidence routes:

- A late source response retains the original grant and records response facts,
  without asserting provider observation.
- A late recipient acknowledgement is restricted to disclosure, retains the
  original grant, and cannot claim a provider response or observation.
- An independently authorized linked observation can establish
  `ObservedByProvider` from unknown only with the retained verified-locator link
  and recorded provider evidence.

The first two routes have separate `late_response_retains_source` and
`late_acknowledgement_retains_source` theorems. The qualified unknown-observation
claim is deliberately conditional on the target being `ObservedByProvider`;
`unknown_exits_with_bound_evidence` proves the complete exit table. The old
statement that *every* unknown exit must be provider observation is no longer
true of the shipping contract and is not advertised as such.

These are proofs about the decision leaves and canonical byte projections.
They do not prove signature verification, exact recipient/challenge binding,
source provenance, store atomicity, or external I/O. The runtime must establish
those facts before constructing the projection and must authorize recovery as a
separate operation. Nonempty acknowledgement bytes in the model are not a
substitute for the runtime's authentication checks. Process, store, transport,
and cryptographic tests remain required alongside these proofs.

The reviewed gateway translation inventory is 126 local functions with zero
external or opaque local functions. AP074 adds `acknowledgement_kept`,
`acknowledgement_stage`, `entry_kept`, `protocol_consistent`, `requires_entry`,
and `same_protocol`; all are closed transition checks covered by refinement.
It removes `after_credentials`, `after_read_back`, and `lease_failed`, which
implemented the obsolete mode-dependent implicit-read route. Regeneration uses
the unchanged pinned Charon/Aeneas/Lean toolchains and two clean translations;
the inventory change is not an exception to the translation or axiom gates.

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


## Shared signing-frame refinement

`Auths.Crypto.Refinement` connects the actual `hash::signing_preimage` to the
independent `Auths.Crypto.Framing` byte grammar. Successful calls supply their
own validated length/tag premises. Equal returned bytes bind every framed
input; different registered object kinds have different preimages. Output
length and oversized-profile refusal are proved, with ordinary and multibyte
positive examples. These are preimage properties, without a hash-injectivity
assumption.

The shared helper is in the qualified codec extraction, with no opaque Auths
algorithm. Its checked capacity and error transitions have one shipping path;
the previous helper is a test-only parity oracle. Public caller encodings,
signature descriptors, cryptographic suite/dispatch behavior and commitment
preimages remain outside this slice. AP-SPEC-069 E5 and the complete composed
claim remain open.


## Finite child-summary refinement

The shipping composition engine now accumulates child outcomes in constant
space. Its translated update and finalizers refine an independent finite-list
specification of counts, minimum diagnostics, conjunctions and thresholds.
Every bounded sequence of actual updates has the exact specified summary;
threshold classification includes saturating unsigned arithmetic. Independent
byte tables establish lexical precedence for every denial/requirement pair,
with exhaustive native catalog/string parity and nine Lean/native witnesses.

At the child-summary checkpoint, the source had four local and five imported
composition functions, with no opaque Auths functions. Its 418-declaration audit
kept every prior 387 record unchanged, with only the existing foundational
axioms. Qualification passed all 11 modules, native cases and two identical
translations.
The inventory records a naming-only discriminant normalization that reuses the
pinned generator and changes only anonymous instance namespaces.

The following slice extends this child-sequence result to recursive traversal.
Public plan validation, callback implementations, the complete staged verifier
and sealed result projection remain AP-SPEC-069 E2 obligations.

## Recursive inner-plan refinement

`Auths.Composition.Traversal.evaluator_refines` compares the actual shipping
inner evaluator with an independently recursive all/any/k specification for
all finite represented plans. Its explicit contracts relate each stateful
leaf callback and observer call to their model operations. The equality fixes
the outcome and both final states, including every child and post-order event.
Separate corollaries prove exact event count and leaf order. Nonempty plans
have at most depth times leaf-count events; explicit depth-16 and 128-leaf
premises give 2,048 events. This is a semantic-event bound, not a bound on the
complete verifier, callback cost, allocation or host stack.

The extraction uses the pinned official `-loops-to-rec` pass for composition
and a strictly positive bounded-vector carrier. The carrier has exactly the
pinned Vec's usize bound, both conversion round trips and injectivity are
proved, and deref delegates to the pinned model. No generated Auths function
body is rewritten. The reviewed external inventory additionally gives exact
Option-default and existing numeric/Result links; external axiom templates
are retained as uncompiled inventory artifacts.

The source witnesses cover successful two-leaf conjunction, denial without
short-circuiting, authorization without short-circuiting, and indeterminate
and denied thresholds with exact event sequences. Native cases mirror them
through the public validating wrapper and exercise 128 leaves at depth 16.
The constructor rejects oversized member counts before sorting, preserving
invalid-threshold/empty-input error precedence and the accepted canonical form.

The expanded qualification passes all 435 compiled statements, all 11 modules,
native cases and two byte-identical translations. All prior 418 records are
unchanged, and only the existing foundational axioms occur. The exact pushed
revision requires its hosted authoritative gates. The inner evaluator theorem does not prove public validation,
leaf cryptography, closed registry/stage behavior, or sealed-result projection;
it does not complete E2 or the composed AP-SPEC-069 claim.


### Public observed-composition refinement

The production `evaluate_observed` entry point now refines independent
structural validation followed by the recursive plan semantics. Its validator
accepts exactly an independently valid plan under explicit protocol-sized
limits; valid means well-formed nonempty operators and thresholds, per-node
width, bounded depth and distinct bounded leaves. A validation result is not
assumed. Invalid structure leaves both callback states unchanged without
callback contracts. Successful evaluation fixes the result and both states
under the displayed exact stateful branch/observer contracts.

The source validator's set accumulation and consuming collection preserve the
ordered reference set and computed depth state. Reviewed bounded set/iterator
models expose that standard-library boundary and its lawful byte-order
premise; the Rust tree and allocation implementation is not proved. Native
positive and rejection cases mirror the kernel-checked public witnesses.
The actual source child loop is shared, and the public result conversion is
an explicit match. No generated Auths function body is rewritten.

The expanded qualification passes 471 statements with all prior 435 records
unchanged, all 11 cases, native parity and two identical clean translations.
The only foundations remain `propext`, `Classical.choice` and `Quot.sound`;
there are ten reviewed library models and zero compiled external axioms.
Split-line axiom declarations are both counted in uncompiled templates and
refused in compiled bridges. The full E2/M3 verifier and AP-SPEC-069 composed
claim remain open; callback implementations, facade/getter coverage,
registered stages, crypto, projection and complete work bounds are separate
obligations. Hosted evidence is still required on the exact pushed revision.


### Shipping signature encoding guards

`Auths.Crypto.Encoding` connects the actual Ed25519 field/sign and P-256
compressed-form guards to independent numeric/length specifications. Both
source refinements are total on their displayed carriers. The finite byte
scan is proved equal to the base-256 coordinate condition; no curve arithmetic
or signature equation is implemented in the proof bridge. This additional
extraction has three local functions, no external functions and no opaque
Auths algorithm. It adds no primitive axiom or custom library model.

The 490-statement construction audit preserves all 471 previous full records.
Accepted/refused kernel witnesses are encoding examples, including canonical
weak-key encodings whose signatures the native strict verifier still refuses.
The exact-source qualification passes 12/12 cases, native parity, two
byte-identical fresh translations and all 490 audited statements. Complete
suite glue, caller preimages, principal binding, dispatch and commitment
integration remain separate AP-SPEC-069 E5 obligations. Hosted evidence is
still required on this exact revision.


### Public composition facade

`Auths.Composition.Facade` refines the shipping `evaluate` wrapper against
independent validation/evaluation and proves the exact event accessor. It
discharges the actual stateless observer, preserves the exact branch state,
and refuses structurally invalid plans without callback premises. The 500
compiled statements preserve all 490 previous full records. All ten
handwritten composition functions now lie in the audited closure; registered
branch/stage implementations and full verifier assurance remain open.

One explicit, single-site FnMut dictionary binding restores an erased unit
output. The Result adapter has both general round-trip proofs and no axioms;
no translated Rust function body is rewritten. Compiler-generated closure
call shims remain in the call graph and are reported separately from
handwritten Rust functions. Eleven reviewed library/representation models
introduce zero compiled external axioms. Exact-source qualification passes
12/12 cases, native parity, two identical fresh translations and the compiled
500-statement audit. Hosted verification remains required on this revision.


### Concrete strict signature glue

`Auths.Crypto.Strict` proves the shipping parameterized Ed25519 and P-256
algorithms against independent accepted-input relations under explicit exact
total primitive contracts. Canonical key form, width, weak-coordinate/R form,
numeric low-S, error order and exact message forwarding are concrete source
properties. P-256's low-S decision is an extracted bounded byte comparison;
it is not a primitive premise. Both accepted-input equivalences include
useful acceptance as well as soundness.

The 14-function signature extraction has no external function record, opaque
Auths algorithm or custom crypto model. The construction audit has 536
statements with all prior 500 full records unchanged and only the existing
foundations. Eight kernel examples are form/guard witnesses, not claims of
signature authenticity. Concrete native-library/default-wrapper binding,
suite/principal dispatch, caller preimages and complete commitments remain
E5 obligations. Fresh qualification passes all 12 cases, native parity and two byte-identical translations with all 536 audited statements and no additional axioms. Hosted evidence remains required on the exact pushed revision.


### Public Ed25519 binding

`Auths.Crypto.NativeContract` proves the actual public verify/key-validation
wrappers and selected library adapters, including exact results and independent
acceptance iff. An explicit `Ed25519Primitives` parameter has three foreign
calls; `Ed25519Contract` supplies their exact total contracts as theorem premises.
There is no global instance or new axiom. A section-only codegen normalization
threads this parameter through dependent generated definitions and preserves
all Rust function bodies. Its strict regression checks byte-for-byte recovery.
The construction inventory has 545 claims, all previous 536 records unchanged.
`NativeExamples` supplies explicit mock call-binding and primitive-independent
malformed-key witnesses; mock success is not signature authenticity.
The 23-local/five-external extraction retains four anonymous closure shims.
Fresh qualification passes all 12 cases, native parity, two byte-identical
translations and the 545-statement audit, with thirteen reviewed external
models and zero compiled external axioms. Exact-revision hosted gates remain
required.
The pinned tools still cannot qualify the P-256 public library-wrapper closure;
its generic algorithm and concrete low-S proof remain the smaller earned claim.


### One-shot SHA-256 and commitment framing

The locally qualified inventory has 567 statements. New source results cover the
signed-capacity allocation guard, exact successful application/identifier
preimages, and the native one-shot hash wrapper under explicit foreign digest
and output-conversion contracts. Independent frame relations prove lengths,
unambiguity and domain separation; kernel witnesses supply useful admitted
frames and early refusals. All previous 545 statement records are unchanged.

The extra monomorphic codec unit keeps its actual Rust crate identity. A
strict foreign-name adapter works around the pinned emitter's inability to
print Instantiated paths. It retains original names in a generated ledger and
checks every Auths name, body, signature, generic, layout, source span and
call/type ID unchanged. The two explicit foreign operations add no global
instance or crypto axiom. Local qualification passes two byte-identical fresh
translations, 13/13 cases and the complete statement/axiom audit. Exact-revision
hosted gates remain required.
Successful-output exactness is a component claim: general framing totality,
all admitted-input completeness, callers' unsigned-object encoding, every
commitment and complete E5 remain separate obligations.

### Complete shared-framer bounds

`Auths.Crypto.FramingTotality` relates every represented input of the actual
signing/application/identifier framers to independent numeric domains. Its
nine source claims establish termination in the qualified Result semantics,
acceptance iff the domain holds, and exactly `LimitExceeded` otherwise.
Previous exact-byte, validity, length and input-binding results remain in the
same closure. Local qualification passes 582 audited statements, all prior
573 complete records unchanged, with only the permitted foundations, 13/13
cases and two byte-identical fresh translations. Exact-revision hosted gates
remain required. Physical allocation, caller object
construction, every commitment and the complete E5 claim remain separate.

### Native P-256 wrapper construction

`Auths.Crypto.P256Native` proves the actual public native P-256 verification and
key-validation results and independent acceptance equivalence under explicit
point-decoder, scalar-parser and P-256/SHA-256 equation contracts. The native
low-S and key-form algorithms have concrete total source refinements. No
primitive law or implementation instance is installed globally. Forwarding
mocks bind exact inputs and changed-input refusals without asserting signature
authenticity. The monomorphic source unit contains 14 local functions, ten
explicit foreign/standard interfaces and zero opaque Auths functions.

Local exact-source qualification passes 599 statements: 17 new and three
explicitly reviewed P-256 primitive-interface statement changes; all other 579
records are unchanged. All 14 cases and two byte-identical fresh translations
pass, with 19 reviewed models and zero compiled external axioms. Exact-revision
hosted gates remain required. This does not complete dispatch, caller construction, commitment
integration, full verification or the whole AP-SPEC-069 program.

### Linked suite verification adapters

The shipping Ed25519 and P-256 suite verification methods refine the independent
suite result and acceptance models through exact field forwarding and error
conversion. Each imported core call has a checked link to its transparent
qualified native owner and a compiled delegation equality. Kernel statement
constants, including implicit implementation instances, are now included in
the reviewed audit digest. The construction audit has 613 claims; all 599
previous readable statement texts and axiom sets are unchanged. Positive and
changed-message witnesses use explicit forwarding mocks without authenticity
claims. Focused qualification rejection tests pass. Fresh qualification passes
613 claims, 15/15 cases, 21 reviewed models, zero compiled external axioms and
two byte-identical translations. Exact-revision hosted gates remain required. Constructors, registry dispatch,
principal binding, caller preimages and complete E5 remain separate obligations.

### Shared independent P-256 vectors

The complete pinned Wycheproof P1363/SHA-256 input is vendored under
`core/fixtures/crypto`, with an offline hash-pinned adapter that retains every
upstream case and makes Auths low-S policy explicit. A shared 653-case corpus
checks 173 accepted signatures across 98 distinct keys, scalar/point/width
errors, high-S twins and exact-message refusal. Rust checks the native and
suite-port results; Go and TypeScript supply independent verdicts. The source
and release inventories bind the corpus and adapters. Fresh qualification
passes 613 unchanged complete audit records, 15/15 cases, 21 reviewed models
and two byte-identical translations. Native tests, lint and both independent
implementations pass; exact-revision hosted evidence remains required.
This is conformance evidence for the displayed primitive contracts, not a
proof of cryptographic arithmetic/security or completion of M2.

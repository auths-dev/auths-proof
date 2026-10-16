# AP-SPEC-069 implementation status

This is the implementation ledger for
[AP-SPEC-069](../specs/0069-authorization-to-execution-formal-assurance.md).
It is not an assurance claim. Completion requires the specification's exact
shipping-source refinement and hosted evidence gates.

| Milestone | State | Evidence / remaining work |
| --- | --- | --- |
| M0: claims and extraction slices | In progress | Shipping head reading/writing and identifier lookahead/scanning refine explicit grammars, with positive/refusal cases and compiled statement/axiom audits. Full protocol-object refinement and hosted qualification remain required. |
| M1: complete codec | In progress | The head codec has a source-to-source round trip and a one-to-nine-byte output bound. Successful canonical-action decoding has exact re-encoding and accepted-encoding uniqueness proofs. The shared identifier validator has exact scan/bounds refinements and a validated-string representation bridge. Complete object/carrier, work/allocation, constructor and codec refinements and hosted corpus/property evidence remain required. |
| M2: crypto integration | In progress | The shipping shared signing framer refines an independent byte grammar, supplies its validated frame premises, and proves input binding, object-domain separation, exact length and oversized-profile refusal. The shipping Ed25519 field/sign and P-256 compressed-form guards now have total exact refinements. Caller unsigned-object construction, complete suite glue/dispatch and commitments remain E5.1–E5.4 obligations. |
| M3: complete verifier | In progress | The public observed evaluator now refines independent structural validation followed by all/any/k semantics. The source validator accepts iff the independent structural contract holds; invalid plans preserve both callback states without callback premises. The ordinary facade and event accessor are now also refined. Callback implementations, registry/stage composition, sealed projection and the full E2.1–E2.5 claim remain. Exact-revision hosted gates are pending for this expansion. |
| M4: mapping and driver | Pending | E3.1–E3.5. |
| M5: history and storage | In progress | Both backends fence slot admission against a durable monotone collection cutoff. The native verifier now retains the selected witness's temporal horizon, which the final driver intersects with installed gates and the operational cap. Exact endpoint and cutoff leaves refine independent models. Complete temporal-witness, backend, admission and driver-history correspondence remain to be qualified. |
| M6: composed assurance | Pending | Final history theorem, adequacy review, and exact-release evidence. |

No E1–E5 workstream is complete yet. Existing component claims retain their
current scope; new source or a successful model proof alone does not expand
the public assurance claim.

## First exact-source slice

`Auths.Codec.Refinement.read_head_refines` covers the translated production
`read_head` and `read_tail`. Every result is a typed CBOR success or refusal;
success agrees with the independent grammar and advances one through nine
bytes without exceeding the input. `read_tail_bounded` fixes both verdict and
value for widths zero through eight. `read_head_accepts_encoding` supplies
completeness on valid independent head encodings with arbitrary following
bytes. The shipping head encoder now also refines the independent grammar:
it refuses invalid major tags, emits the shortest head for valid tags, and
produces one through nine bytes. Its actual output round-trips through the
shipping reader with arbitrary following bytes. These are head-codec claims;
they do not yet establish a complete protocol-object codec.

The qualification corpus includes an accepted unsigned head, a missing-byte
refusal at an outlying cursor, and a truncated four-byte argument. The
compiled axiom check reports only `propext`, `Classical.choice`, and
`Quot.sound`, within the existing allowlist. Existing audited theorem
statements were compared with their previous statement hashes and are
unchanged. Authoritative Lean now additionally replays the public theorem
closure into a fresh kernel environment with the pinned `leanchecker`.

The local qualification construction passed two byte-identical clean
translations, all ten qualification cases, and the compiled audit of 338
claims. A separate fresh-environment replay of `Auths.Codec.Refinement`
passed. These are development results; the exact pushed revision still
requires the hosted authoritative gates.

The canonical-action path now uses a bounded owned attachment transition and
an owned encoder fold. Named error converters and explicit borrowed-result
matches keep the actual source visible to both translation and coverage. Its
complete Auths constructor closure is extracted; no Auths algorithm in that
closure is opaque. The accepted-byte and uniqueness theorems are component
properties; totality, inverse completeness, resource bounds, full carrier
validity and every other protocol object remain open.

## Collection-fence slice

The file store persists and synchronizes `.collection.json` before deleting
slots. PostgreSQL schema `/7` (transactional-store contract `/5`) orders
admissions with a shared row lock and collection with an exclusive row lock;
the cutoff and deletions commit together. Both backends check every slot's
actual expiry in the atomic claim/slot batch. A closed window records a
terminal refusal without reserving slots or granting an execution handle.
Collection with a zero deletion limit still closes the window conservatively.

File stores reject obsolete unmarked state and missing, corrupt, oversized,
or obsolete collection metadata. Missing locks are not silently recreated for
an initialized store. File reads check size before allocation and cap the
read even if the file changes. Key uniqueness and wrong-kind reads now agree
with PostgreSQL across all five record kinds.

The independent cutoff model permits arbitrary finite interleavings and any
number of workers, including crashes, recovery, lost acknowledgements, and
partial sweeps. The shipping cutoff comparison and monotone-advance functions
refine that model. These statements do **not** yet establish the actual
backend/driver-to-history correspondence, aggregate counter derivation, the
complete admission algorithm, or E4 as a whole. The shared backend suite adds
collection/admission races, restart and old-clock attempts, lost commit
acknowledgements, marker/lock corruption, and refusal before any lease/write.
Hosted conformance remains required evidence.

The collection-fence qualification includes the ninth production extraction
crate, four accepted/refused boundary examples, six additional audited
claims, and two byte-identical clean translations. The source comparisons
remain narrower than the backend transaction and crash-recovery contracts.

## Entry-deadline slice

The sealed native result retains the successful anchors and grants/actions'
expiry, counted approvals and their anchors/status, selected observation
freshness and observer anchors, and selected assurance freshness. Status
methods return a typed horizon with their decision; the native method uses
only the relevant latest in-scope statements. Missing revocation-list entries
retain the snapshot window, without inventing a statement-age requirement.
Failed branches and ignored approvals do not contribute temporal bounds.

The production command intersects that witness with the 60-second maximum.
Preparation retains the accepted qualification or commissioning endpoint;
the final gate intersects it with the current installed gate and refuses
clock rollback. Inclusive native/qualification bounds and exclusive
commissioning bounds keep their endpoint modes, without adding one to a
timestamp. Expiry refuses entry and retains consumed claim/slot capacity.
The monotonic deadline and final secret-lease check remain required.

The new Lean endpoint model covers arbitrary finite intersections, including
equality, and the translated shipping intersection and time predicate refine
it. The complete verifier-to-temporal-witness and driver-to-I/O proofs remain
open; the endpoint refinements alone do not establish those correspondences.
Native quorum, status-age, exclusive/inclusive boundary, rollback, and retained
capacity cases are added for hosted validation.

The deadline slice passed the local qualification construction: two
byte-identical translations, ten qualification cases, and the compiled
338-claim audit. The previous 332 statements are unchanged. The new claims
use only the existing foundational axiom allowlist. Hosted end-to-end and
backend evidence is still required for this revision.

## Head-encoder slice

The actual `encode_head` and bounded `append_tail` now refine the independent
big-endian grammar. Invalid major tags receive a typed refusal, successful
output has one through nine bytes, and every valid encoding round-trips
through the actual head reader with arbitrary following bytes. Positive
qualification cases cover the inline boundary and maximum u64 argument;
an invalid major tag is refused. This does not prove complete-object
canonicality or physical allocator behavior.

Local qualification passed two byte-identical clean translations, ten
qualification cases, and the compiled audit of 342 claims. Existing theorem
statements are unchanged. The hosted lint failure was reproduced on affected
packages and fixed without weakening the gate; the exact pushed revision
still requires authoritative hosted tests.

An isolated action-decoder experiment with owned attachment state now passes
strict translation with the constructor bodies included. The candidate uses
bounded byte validation for identifier control/whitespace rules and owned
attachment transitions. Exhaustive native comparison covers every Unicode
scalar and allowed-scalar concatenations. Constructor and object refinement
proofs are still required; the experiment remains outside the production
qualification inventory.

## Verification checkpoint: 15 October 2026

Hosted run `38808755694` passed repository preflight, generated-artifact
freshness, fast Lean feedback, Kani, compliance, secret scanning, and the
OpenTofu, PostgreSQL, and records API live jobs. The full authoritative job
found a stale gateway semantic-closure fixture and an incorrect new test
expectation: replay recovery may lease a credential for its read-only
observation. The corrected test checks exactly one read and no provider
writes; the focused file-store conformance case passes locally. The closure
fixture was regenerated from its real production inputs.

The dependency gate also reported four Rustls advisories fixed upstream in
0.23.46. The workspace requirement and lockfile now select that release,
without advisory exceptions. The patched closure passes local qualification
construction: 342 audited claims, all ten qualification cases, and two
byte-identical translations. The patched revision still needs hosted gates;
none of these results completes an E1–E5 workstream.

## Identifier-validation slice

The shipping model now uses one bounded byte validator before copying an
identifier into its owned string. Its fixed UTF-8 prefix set agrees with the
pinned character rule for control and whitespace characters. URI-scheme
validation and every identifier-specific bound remain in their existing
constructors. There is one production path.

The independent scalar model proves correctness for any finite stream through
U+10FFFF, including arbitrary following bytes and the absence of false matches
across scalar boundaries. The exact shipping lookahead is total on every byte
slice/cursor; the full scan terminates with a decreasing remaining-byte
measure. The bounded validator fixes acceptance for every translated carrier
and maximum. Its Unicode-policy composition retains an explicit UTF-8 byte
representation premise; this does not by itself prove UTF-8 decoding or every
constructor/carrier invariant.

The qualification now extracts 141 local model function records and seven
standard-library externals, with zero opaque local functions. The additional
externals are transparent borrowed-string length, emptiness, and byte access;
they introduce no axiom or assumed Auths predicate. Positive/refusal cases
cover exact byte bounds, empty input, U+2028, and the nearby permitted U+200B.
Native qualification includes every Unicode scalar in isolation and an ASCII
frame, the concatenation of all allowed scalars, and randomized comparison
with the previous character predicate.

Local qualification passed two byte-identical translations, ten qualification
cases, and 347 compiled claims. The previous 342 statement hashes are unchanged;
the five additions use only the existing foundational axiom allowlist. The
hosted authoritative implementation job for the preceding `f97d7e7f` checkpoint
passed, including the storage and deadline tests. This identifier checkpoint
still requires its own hosted gates. No E1–E5 workstream is complete yet.

The preceding hosted translation job found a seven/eight-character tool-version
reporting mismatch in the two newly extracted crates. Normalization now derives
every report path from the authoritative artifact mapping and records the full
pinned commit; a regression test covers all nine reports and rejects an
unrelated tool identity. This changes reporting, not the translated algorithm
or accepted toolchain. Local qualification of this repair again passes all
347 claims, ten cases, and byte-identical reproduction.

The PostgreSQL fixture now creates its host output directory before Docker,
preserving runner ownership of `target/`. Source qualification plans were
regenerated with the current schema-7 store descriptor; all six focused plan
and commissioning tests pass. The hosted PostgreSQL qualification for `62f859c5` passed, including multi-host
capacity checks, hostile gateway/store conformance and physical backup/restore
([run](https://github.com/auths-dev/auths-proof/actions/runs/38822086710)).
This backend evidence does not complete the E4 driver/history correspondence.

## Canonical-action and string bridge construction

The expanded codec has accepted-byte and encoding-uniqueness proofs, together
with exact validated-string representation, copying, borrowing and UTF-8 model
acceptance. The compiled audit contains 353 declarations; the preceding 347
statements are unchanged and the transitive axioms remain `propext`,
`Classical.choice` and `Quot.sound`. Qualification passes all ten modules,
native codec/model/authority/author tests and two byte-identical translations.
The expanded codec has 73 local and 75 imported function records, including
its actual constructors, with zero opaque Auths functions. Its six reviewed
external models introduce no compiled axiom. The exact production source
closure is `f67c463f9f8e7d4e8c9674f86f385da7e4144edbd38f9ceede3b8f93263e463e`.
The hosted gates for the expanded checkpoint remain required.

Native tests retain the former action codec and attachment checks only as
refactor-equivalence oracles. They cover successful random actions, optional
budgets, truncation, byte mutations, duplicate attachments, collection bounds
and aggregate-byte bounds. The qualification now includes native codec tests.
The reviewed sorting model is restricted to the actual stateless digest-key
callback and lawful digest order; arbitrary stateful callbacks are not modeled.

This does not complete E1. Full constructor validity, inverse completeness, resource accounting and the
remaining protocol objects still require work. The positive whole-decoder
witness is supplied by the following slice.

## Whole-action witnesses and constructor validity

The complete translated action decoder now has a kernel-checked positive
witness: a 26-byte nonempty canonical action with every required field, under
explicit valid limits. Its encoder returns those exact bytes. The same source
refuses duplicate keys and nonminimal integers as `NonCanonical`, and invalid
UTF-8, truncation and trailing bytes as `Malformed`. A 25-byte action limit
refuses the input; the exact 26-byte limit accepts it. These are codec witnesses;
the opaque profile and body do not claim application authorization.

Five typed string constructors now have exact decisions on every validated
UTF-8 string within the standard-library byte-carrier bound, against an
independent nonempty/byte-length/Unicode predicate. The action constructor
also has an exact nonempty/8 MiB body decision, preserving its other incoming
typed fields. For every successful complete action decode, the actual returned
body is nonempty and fits both the protocol ceiling and the deployment's
canonical-body-byte limit. These are accepted-result guarantees; totality,
full decoded-carrier validity, inverse completeness and aggregate work and
allocation bounds remain open.

The proof evaluation rules are equalities proved for all their inputs. They
use a conservative 32-bit branch that works on either supported machine width
and retain the original operation elsewhere. No platform-width assumption,
`native_decide`, opaque Auths algorithm or new axiom is introduced. Native
integration cases mirror the exact positive/refusal inputs for hosted parity.

The compiled construction audit has 374 declarations. All preceding 353
statements are unchanged, and every transitive axiom remains in the existing
three-name allowlist. The new full qualification passes: two byte-identical clean translations, all
ten qualification modules and the native codec/model/authority/author tests,
including the new positive/refusal integration cases. The bound production
source closure is `f67c463f9f8e7d4e8c9674f86f385da7e4144edbd38f9ceede3b8f93263e463e`.
The exact-revision hosted gates remain required; no E1–E5 workstream is complete.

The preceding checkpoint `39c0cfd8` passed hosted PostgreSQL lifecycle
qualification, recipe qualification, gateway isolation, both customer demos
and Python/TypeScript package checks. Main CI passed preflight, fast Lean,
compliance, dependency/secrets and live-provider jobs. Its authoritative
workspace job exposed a valid base64url public key beginning with `-` being
misparsed as an option in the release CLI. Both certificate commands now
accept that argument, with a deterministic parser regression and the exact
previously failing commissioning journey passing locally. The patched revision
still requires the hosted authoritative gate.

Coverage continues to use the declared local-translation measurement. Imported
constructor bodies are present in the extraction and compiled proof closure,
but are not newly counted as local functions to inflate the headline metric.

## Shared signing-frame slice

The actual `hash::signing_preimage` is now extracted with its complete Auths
closure. It emits exactly the independent protocol grammar: `AUTHS`, protocol
V1, registered object tag, profile byte length and bytes, profile version,
unsigned-statement byte length and bytes. The qualified source supports the
six existing tags, including observation 9 and approval 10. The source's own
successful checked conversions establish every frame-validity premise.

For every successful source call, equal preimage bytes imply equal object
kind, profile bytes, profile version and unsigned statement bytes. Different
object kinds cannot share preimage bytes. Exact output length is
`21 + profile_bytes + statement_bytes`; a profile longer than 65,535 bytes is
refused with `LimitExceeded`. These are syntactic byte-binding statements,
without any assertion of collision-free hashes. Kernel examples cover an
ordinary Grant frame and an Approval frame with a multibyte profile and the
maximum u16 profile version.

The shipping implementation now uses the existing named typed-error converter
and three explicit checked capacity additions. This preserves the prior
preimage bytes and errors and exposes the real source to translation and
coverage. The former helper exists only inside the test module as a parity
oracle. Native qualification compares arbitrary strings, versions and bodies
across all six tags, plus exact ASCII/UTF-8 length boundaries.

Full local qualification passes: 387 audited declarations, all ten modules,
native model/codec/authority/author cases, and two byte-identical clean
translations. The prior 374 statement records are unchanged; all transitive
axioms remain in the original three-name allowlist. The codec closure has
74 local and 76 imported function records and zero opaque Auths functions.
The additional reviewed usize-to-u16 adapter is a transparent checked
conversion, with no compiled axiom. Production source closure:
`60a181a4bac97f3663b5ac49b6663924fac04d94b635525cd44827b3631dc899`.

This does not complete E5. The public signing wrappers' construction of the
canonical unsigned object and signature descriptor, suite/key decoding and
dispatch, commitment preimages, primitive contracts and composed authorization
still require their own source-bound proofs. The exact pushed revision must
also pass hosted qualification. At the preceding `d386aec2` checkpoint,
authoritative implementation, Kani, fast Lean, compliance, dependencies,
secrets and the live-provider jobs passed; translation remained in progress
when this slice was prepared.


## Finite child-summary slice

The shipping composition evaluator now uses one constant-space summary of
immediate-child outcomes. It retains the authorized and indeterminate counts
and the minimum denial/requirement directly, replacing the prior diagnostic
vectors. All child evaluations and observer calls remain in their previous
order. The former evaluator exists only as a native test oracle. Property tests
compare nested conjunctions, alternatives and thresholds with callbacks that
share mutable test state, checking the exact result, visited leaves, observer
events and final callback state.

The actual accumulator update, conjunction finalizer and threshold finalizer
are translated without opaque Auths functions. Their source proofs give exact
natural-number updates and final decisions, including saturating addition on
either supported machine width. Every bounded finite sequence of actual source
updates matches the independent folded summary. The model proves both counts
and minimum diagnostics for every child sequence, conjunction acceptance iff
every child authorizes, and threshold acceptance iff its count is sufficient.
Structural invalidity contributes a denial to its parent; a successful
alternative can still authorize, as the protocol specifies.

A single source catalog owns each stable diagnostic string and its comparison
rank. Kernel proofs cover every pair of the 46 denial and 21 requirement
variants against independent published-code byte tables. Native tests separately
check each public string getter, parser round trip and pairwise ordering.
The borrowed-string getter itself is not in this extraction. Nine positive,
denied and indeterminate Lean witnesses have matching native operation cases.

Qualification passes with 418 compiled declarations, the prior 387 statement
records unchanged, all 11 modules, native model/codec/composition/authority/
author cases, and two byte-identical clean translations. The composition slice
has four local and five imported function records and zero opaque Auths
functions. The six existing external models remain unchanged in number and
introduce no compiled axiom. A separately inventoried, metadata-only naming
normalization reuses the pinned Aeneas discriminant generator and scopes its
anonymous instance names; it changes no datatype or discriminant match body.
The compiled multi-import cases check distinct explicit tags on enums with the
same short name. Bound production source closure:
`003df1917fd715485d8f7fa0cb69a4c7cff4854a39069fa5d9d0fa34b4310adb`.

This does not complete E2. The qualified slice does not establish that the
recursive plan evaluator supplies exactly this child sequence, validates the
plan, invokes callbacks/observers with the expected state, or composes every
verifier stage and sealed projection. The private full-evaluator prototype is
not a qualified claim. Exact-revision hosted gates remain required. The preceding
`d386aec2` checkpoint passed every main CI gate, including authoritative Lean
replay and final evidence. At `fead08c4`, hosted PostgreSQL lifecycle, recipe
qualification, gateway isolation, both customer demos, operator package and
Python/TypeScript package checks pass; the main formal gates are still running.
All E1–E5 workstreams remain open.

## Recursive inner-plan refinement

The complete extracted inner evaluator now has a source equality with an
independently recursive plan model for every represented finite plan. Native
and model branch/observer contracts are explicit quantified premises; the
statement fixes the result and both states, so a different visit order or
missing post-order event cannot satisfy it. Source corollaries establish node
event count and exact leaf order. The structural model proves node count is
at most depth times leaf count for nonempty plans; explicit depth-16 and
128-leaf bounds yield at most 2,048 source observer calls. Public validation
correspondence, callback cost and the complete verifier bound remain open.

A positive length-indexed bounded vector solves the recursive-carrier issue
without changing the Rust plan type. Both conversions with the pinned Aeneas
Vec round-trip, their map is injective, and deref is exact delegation. Only
this standard container representation and discriminant instance naming are
normalized. The official recursive-loop extraction switch leaves Auths
function bodies untouched. The expanded report has nine local and nine
imported function records, including the generated loop record, with zero
opaque Auths functions and two additional transparent standard-library models.

Kernel-checked two-/three-leaf witnesses cover accepted, denied and
indeterminate outcomes and exact post-order events. Native mirrors use the
public validating wrapper, and a joint 128-leaf/depth-16 witness checks all
1,921 events. Constructors now reject excessive member counts before sorting,
preserving threshold/empty-input error precedence and canonical accepted plans.
This runtime bounds correction is source-reviewed and natively tested; no
constructor-refinement theorem is inferred from the inner evaluator proof.

Qualification passes all 435 compiled statements, all 11 modules, native
parity cases (including the joint hard boundary), and two byte-identical
translations. Every prior 418 declaration record is unchanged; the only
transitive axioms remain `propext`, `Classical.choice` and `Quot.sound`.
The exact source closure is
`64d845b2d6cebe06e27879dbaccda54b8425fbb29e7733e1a5f5e5c4a5737ede`.
The exact pushed revision still requires its hosted authoritative gates.
No E1–E5 workstream or M6 is complete on the strength of this slice.


## Public structural validation and observed evaluation

`ValidationContract.source_accepts_iff_valid` connects the actual shipping
validator to an independent structural relation: nonempty well-formed
operators, valid thresholds, per-node width, total depth, distinct references
and total leaf count. Both acceptance and refusal are proved; validity is not
defined by a successful checker call. The public source equality in
`ValidationPublic.public_evaluator_refines` includes the actual validator and
then the independent three-valued evaluator. Success fixes the result and both
callback states under explicit exact callback contracts. Every structurally
invalid plan is refused with both states unchanged, without any premise about
the callback implementations.

The returned shape retains the independently computed reference set in strict
order and the checker's maximum-depth state. The consuming set iterator and
vector collection loop preserve every reference. The public event bound
requires no trusted validation-success flag: independent validity and the
explicit protocol caps imply at most 2,048 events. It remains an event bound,
not a claim about callback cost, physical allocations, host stack or full
verifier work.

A shared source child-validation loop removes duplicate control flow. Explicit
collection and an explicit public error match keep the whole path visible to
the pinned extractor and coverage scanner. The only representation changes
remain standard-container models: the positive bounded vector delegates its
operations to the pinned Vec, and a reviewed ordered-set contract is scoped
to Global allocation and copied ProofRef values. The actual derived ProofRef
comparison is proved equal to lawful lexical byte order. The library's tree
implementation and physical allocation remain external boundaries. The
trait-default maximum adapter follows the pinned Rust second-argument tie
rule. No Auths validation algorithm is opaque or replaced by a model.

Qualification passes 471 audited statements, all prior 435 complete records
unchanged, all 11 qualification cases, native parity cases and two
byte-identical clean translations. There are ten reviewed standard-library
models, no unreviewed model and zero compiled external axioms. The only
transitive axioms remain `propext`, `Classical.choice` and `Quot.sound`.
The composition report has ten local and 27 imported function records; every
Auths function in its closure is transparent. The exact source closure is
`4040407246158f925ab3e1ca2569573196977d706975f4b8a05a785528ea7dd1`.

Kernel witnesses cover useful two-leaf authorization, a three-leaf
indeterminate threshold, duplicate references, a zero threshold, and reduced
width/depth limits. Native cases additionally check sorted shape output,
lower-limit refusal before callbacks and the joint hard limit. The template
inventory now detects both same-line and split-line axiom names; a regression
also proves that a split-line declaration is refused in a compiled bridge.

The measured decision denominator remains explicit: 122/1,044 functions and
1,478/11,535 lines, including 8/10 composition functions. Imported source
validator refinements are audited even though the coverage definition counts
only local translation functions; no denominator was removed to improve these
figures. The facade and event getter still need their own extraction bridge.
The staged verifier, registered handlers, leaf cryptography, sealed projection
and complete resource bound remain E2 obligations. All E1–E5 workstreams and
M6 remain open.

The preceding `9c810f75` checkpoint passed every main hosted gate, including
authoritative Lean and final formal evidence:
[CI 38852805698](https://github.com/auths-dev/auths-proof/actions/runs/38852805698).
This public-validation expansion still requires hosted verification on its
exact pushed revision.


## Canonical signature-key encoding

The public Ed25519 key contract requires canonical RFC 8032 field/sign form.
The pinned library's decoder follows ZIP-215 and accepts additional encodings,
including some non-weak points with a noncanonical field representative.
`auths-signature-core` now checks the RFC form before library point recovery;
key validation and signature verification share that one decoding path.
The existing strict signature verification and P-256 low-S rules remain.
This is a rejection-boundary correction, not evidence of a signature forgery.
The native suite retains canonical low-order *encodings* at key validation;
strict signature verification refuses weak keys and weak R points.

`Auths.Crypto.Encoding.Ed25519.guard_refines` proves the actual source guard
returns precisely the independent decoded-coordinate criterion for every
32-byte array: y below 2^255-19, with the forbidden negative-zero sign choices
excluded. The independent model uses base-256 numeric decoding; the shipping
code scans bounded bytes. Their equivalence includes totality and in-bounds
reads for that guard. `P256.guard_refines` proves the actual compressed-form
check is total on every represented slice and accepts exactly length 33 with
tag 2 or 3. Form acceptance alone makes no curve-membership claim.

The guard extraction has three local function records, zero external
function records, and zero opaque Auths functions. It requires no custom
crypto model or axiom. Published RFC public signature data supplies native
positive and changed-message cases. Tests distinguish the library's broader
point decoder from Auths canonical validation, and a valid high-S P-256
signature from the low-S form Auths accepts. Go and TypeScript independently
implement the settled field/sign rule using integer coordinates. Their
strict-verification filters also exclude all eight canonical low-order points;
the crypto libraries remain responsible for point recovery and the equation.

The construction build audits 490 statements, with every previous 471 full
record unchanged and only the three allowed foundations. Seven new kernel
witnesses cover accepted and refused encoding forms, including a canonical
identity encoding that still grants no signature authority. The exact-source qualification passes all 12 cases, native parity and two
byte-identical fresh translations. It audits all 490 statements with only the
three allowed foundations, ten reviewed library models, zero unreviewed models
and zero compiled external axioms. Its source closure is
`dc9b524b6ba84d63d55346b0e9053fe0b489a604703b5017151d3a3f7ca81503`.
Hosted verification remains required on the exact pushed revision. Whole-suite decoding, principal binding, dispatch, exact
caller unsigned bytes, commitments, and composed E5 remain open.

Primary contracts: [RFC 8032 section 5.1.3](https://www.rfc-editor.org/rfc/rfc8032#section-5.1.3)
and the pinned [dalek decoder contract](https://docs.rs/ed25519-dalek/2.2.0/ed25519_dalek/struct.VerifyingKey.html#method.from_bytes).


## Public composition facade and event projection

The ordinary public `evaluate` facade now has its own exact source refinement.
It agrees with independent structural validation and three-valued evaluation,
including the exact final branch state. Its actual stateless observer is
proved rather than assumed. Independently invalid structure is refused before
any branch call, without a callback correctness or termination premise.
The event accessor returns exactly the independent proof/aggregate outcome.
Native callback implementations and the staged verifier remain E2 obligations.

The additional extraction contains 14 local and 27 imported function records.
Two local records are compiler-generated closure call shims. They remain in
the refinement dependency graph and in the explicit translation inventory;
the handwritten-function metric treats them separately, just as it already
distinguishes compiler-generated loop and derived-method records. This does
not remove any handwritten Rust function from the denominator. All 10
composition functions now reach the audited closure; decision coverage is
124/1,044 functions and 1,490/11,535 lines. The staged verifier and callback
implementations remain outside this component claim.

The pinned backend erases the concrete unit output of the empty observer's
call, while the generic FnMut dictionary retains a Unit-times-state result.
One exact dictionary-field adapter restores that component. Both Result round
trips hold for arbitrary state, success, failure and divergence, with **zero
axioms**. Generated Rust function bodies and constructors are preserved. The
normalizer refuses missing, repeated or already-adapted dictionary sites;
focused regressions also prevent ordinary handwritten functions from being
classified as closure shims. The current inventory contains eleven reviewed
library/representation models and no compiled external axiom.

The construction audit passes 500 statements, with all previous 490 full
records unchanged and only the existing foundations. Kernel executions cover
a useful two-leaf conjunction, structural duplicate refusal before callbacks,
and a three-leaf indeterminate threshold through the actual facade. Exact
source qualification passes all 12 cases, native parity and two byte-identical
fresh translations, with the 500-statement compiled audit. Its source closure
is `c73c2fce779537862d90aa9ba9d35c651d53c76ba81a131a83597f7cbf9fced2`.
Hosted gates remain required on the exact pushed revision.
The current encoding checkpoint's hosted preflight found an iterator-style
lint on the already-qualified explicit fixed range. A single-site lint
expectation records the source-linked proof reason; focused Clippy passes.
No index check, resource limit, predicate or CI job is disabled.


## Concrete signature glue under primitive contracts

The native entry points now call one shared parameterized source algorithm
per suite. The vetted libraries retain point recovery, scalar parsing and the
signature equations. Canonicality, exact widths, Ed25519 weak-coordinate and
R-form restrictions, P-256 low-S, refusal precedence, and exact byte forwarding
are visible in the shipping Auths glue and its extraction. Native key-format
validation still permits a canonical weak encoding; verification refuses it
after the signature-width check, preserving the existing error precedence.
The Ed25519 library's own strict checks remain in the selected primitive.

`LowContract.guard_refines` proves the concrete 64-byte P-256 scalar guard is
total and returns exactly `s <= floor(n/2)` in big-endian numeric meaning.
The constant is proved equal to half the secp256r1 order. A separate theorem
shows the first 32 bytes cannot influence that decision. The source no longer
uses an assumed low-S callback or a library-normalization decision for the
Auths rule. Parser errors still precede low-S refusal.

The Ed25519 coordinate comparator is proved equal to the decoded unsigned
255-bit ordinate, preserving every coordinate bit and ignoring only the sign.
The source weak-coordinate filter matches the independent numeric set. Its
combination with the canonical point-form guard excludes the eight canonical
weak encodings. The R checker recovers exactly the first 32 signature bytes
and checks their canonical non-weak form. These results do not prove curve
arithmetic or cryptographic security.

`Strict.SuiteRefinement` proves both complete parameterized source algorithms
return exactly the independent models, including each error class and its
precedence. `Strict.SourceAcceptance` proves success iff independent accepted-
input relations hold. The only primitive premises are the displayed exact
total point-decoder, scalar-parser and equation contracts. No source success,
trusted Auths guard flag, opaque Auths algorithm, custom crypto model or global
crypto axiom is introduced. The extraction has 14 local function records and
zero external function records.

Nine native tests pass, including the published RFC public signature tuple,
changed messages, noncanonical/non-weak keys, all eight canonical weak points,
P-256 boundary/normalizer parity and a mathematically valid high-S tuple.
Call-order witnesses use explicit mocks that would accept everything: weak
Ed25519 input and high-S P-256 input never reach that equation, while admitted
form forwards the exact key, message and signature/parser result. Mock success
is not evidence of signature authenticity. Focused Clippy passes.

The construction audit passes 536 statements with all previous 500 full
records unchanged. Eight kernel guard examples include exact half-order,
just-above-half, maximum scalar, canonical weak coordinate and accepted/refused
R forms. An allowed form (including zero s) alone grants no authority.
Exact-source qualification passes all 12 cases, native parity and two byte-identical fresh translations, with all 536 compiled claims and eleven reviewed models, zero unreviewed models and zero compiled external axioms. The source closure is `c9c3f9ef750e8cce0f39656f549dd1e8d351354434bf0416c87a9e45bfe98e35`. Hosted gates remain required on the exact pushed revision.
The concrete library-leaf/default-wrapper correspondence, suite/principal
dispatch, caller unsigned-object construction, complete commitment integration
and E5 as a whole remain open, along with the other AP-SPEC-069 workstreams.

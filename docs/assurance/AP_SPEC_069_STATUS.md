# AP-SPEC-069 implementation status

This is the implementation ledger for
[AP-SPEC-069](../specs/0069-authorization-to-execution-formal-assurance.md).
It is not an assurance claim. Completion requires the specification's exact
shipping-source refinement and hosted evidence gates.

## Qualified record-validator and cursor checkpoint — 17 October 2026

**902 compiled/audited claims** qualify, with all 886 previous full declaration
records unchanged and no new axioms. The complete 3,531-job Lean build, 18/18
qualification cases, two byte-identical full translations, all 173 xtask tests
and affected-target linting pass. There are 25 reviewed external models and zero
compiled external axioms. Two transparent String methods extend the existing
ordering model's interface; the logical interface change is explicitly reviewed.

The shipping complete record validator now earns nonempty bounded collections,
global ordering, text validity, duplicate absence and temporal shape from actual
acceptance, with exact typed refusal precedence. Concrete native String/profile
comparison dictionaries close the prior generic premises. Frozen native parity
covers 43,200 complete records; 43 connection and 232 active gateway tests pass,
with 26 existing gateway tests still ignored.

The source-exact cursor batch covers construction, head/integer/null reads,
first-byte classification and completion. It preserves refusal cursor semantics
and exposes two caller limits: peeking is not payload validation and a completion
length check does not establish input identity. The harness inventory now safely
excludes flat explicit-path test modules and checks all 48 real harnesses without
counting test helpers as shipping targets. It still fails closed on unresolved
module/include constructs.

Source: `b5aa6810c742d3ee53b37b18d2d7a9b5a3f25c5cf5f2af83cf398ede95e33814`.
Review: `ap-spec-069-record-and-cursor-2026-10-17`; inventory:
`9ca7caa5ab864d0bcc5936fd696f7beeefdbf1b34a51599357d558e2ca7a5d69`;
boundary: `33fbd99ec34b7e232db2b65d19c55419a4ff5c82b1d7e371a0ed6bb35d96ea18`.

Next: payload/UTF-8/collection and full object-codec source proofs. The private
payload prototype is not included in this checkpoint. Full E1–E5/M6 and
exact-release hosted gates remain open. See spec §§13.36–13.39; keep coding
without waiting on CI.

## Qualified strict-order checkpoint — 17 October 2026

**886 compiled/audited claims** qualify, preserving all 882 preceding full
records and the existing axiom basis. The 3,524-job Lean build, 18/18 cases,
two byte-identical full translations, 42 connection tests, 232 active gateway
tests, affected-target linting and nine coverage/historical regressions pass.
The existing 26 ignored gateway tests and 25 reviewed model basis are unchanged.

Both real allowlist consumers now call the source-proved allocation-free
ordering scan. Its exact result and earned duplicate absence expose the
comparator contract and strict-order laws. Frozen parity covers 5,461 sequences
per integer/String/profile comparator and 688 complete allowlist/decoder cases.
The temporal oracle retains its own frozen ordering helper.

Source: `1a15772736daa1ab26f69e4859691cb0316e5232cdb2f54925142ff68ca79255`.
Review: `ap-spec-069-strict-allowlist-order-2026-10-17`; inventory:
`dc748ef710367d4817f350f08dc1fccba042d454fa20af73eef1136d6a536cfe`;
boundary: `e3c0b057f86b94b84182655b8cd8b4b923a5f54b50ba7031923891976758c375`.

Next: close the actual String/profile comparator instances and compose the
complete record validator; its private construction prototype is not qualified.
Full E1–E5/M6 and exact-release hosted gates remain open. See spec §§13.34–13.35.

## Qualified complete record-time checkpoint — 17 October 2026

The latest batch qualifies **882 compiled claims**, all 877 preceding full
records unchanged and no new axioms. The full 3,523-job Lean build, 18/18 cases
and two byte-identical clean translations pass; there remain 25 reviewed models,
none unreviewed and zero compiled external axioms. Source closure:
`10abedf6c85d16e017b07b4177983a0e58db46a099995b01c8a7b56f6c4e26ec`.

Actual constructor/decoder validation consumes the complete proved temporal
shape: ordered creation/update, revocation timestamp exactly for revoked state,
and inclusive lifetime bounds on every present revocation timestamp. Two
independent model laws preserve that shape through the existing administrative
conditions and field updates. Neither claims a whole native I/O caller proof.

All 40 connection tests, 232 active gateway tests and affected-target/xtask linting
pass; 26 ignored gateway tests stay unchanged. A frozen complete validator and the
real canonical decoder agree on 450 combinations: 65 accepted complete records
and 385 typed refusals. Source cases cover useful success and malformed shapes.
Coverage v4 and historical reproduction retain the primary 134/1047 function,
1833/11563 line and 23/82 check-site scope.

Review: `ap-spec-069-complete-record-times-2026-10-17`; inventory:
`b4353da77341c99dd42adde58ed8777272ca301797322aa29978145f7e796bca`;
boundary: `fc09192a131ddba7b342418e42f24f58e141d0a740c2a73b0ed01ad4af1c7256`.

Full record/resource/caller closure, physical-clock correspondence and the rest
of §13.5/E1–E5/M6 remain open, including hosted exact-revision evidence. Strict
allowlist ordering is prepared privately with a source-exact generic loop and
independent pairwise/no-duplicate laws under explicit comparator contracts.
Continue that cutover without waiting on CI. See spec §§13.32–13.33.

## Qualified actual String-constructor checkpoint — 17 October 2026

The latest checkpoint qualifies **877 compiled claims**, all 871 preceding full
declaration records unchanged, with no new axioms. The 3,522-job Lean build,
18/18 qualification cases and two byte-identical clean full translations pass.
There remain 25 reviewed models, none unreviewed and zero compiled external
axioms. Source closure:
`00e36a422d77f9710709d41550f7fe4c7918d5173b4552bafcd023e4168b88d9`.

The actual ProviderKind, ConnectionAlias and SemanticId owned-String constructors
now have exact source language/error proofs and success-earned payload validity.
Their explicit portable U32 representation bound belongs to the existing reviewed
String/UTF-8 interface. It assumes no valid identifier or desired parser result.
The three standard projections are direct aliases to existing reviewed models;
all Auths constructors/helpers are transparent. Positive/Unicode-refusal witnesses
are kernel-checked without native axioms.

All 39 connection tests and affected-target/xtask linting pass. Character-language
oracles check 116,608 UTF-8 cases, with 7,618 provider, 7,618 alias and 20,026 semantic
successes, exact payloads/errors, additional Unicode/NUL and size boundaries.
Selector checksum/path regressions pass. The expanded unit contains four
non-shipping selectors, 17 imported function records and three uncompiled standard
interface template stubs; the artifact inventory has 99 files. Coverage v4 and
historical reproduction retain 134/1047 functions, 1833/11563 lines and 23/82 sites.

Review: `ap-spec-069-actual-string-constructors-2026-10-17`; inventory:
`9450e7c2b425e8691d8eb74bafe494b3863715961aea74549ff7ed4b59892ef2`;
boundary: `730bcc49302621155bf0ed66b4a3eb493b43b0595a69a17584f6017df083a040`.

Other Into<String> paths, complete record/codec/caller closure and the remaining
§13.5/E1–E5/M6 program stay open, including exact-revision hosted evidence. The
complete durable-record timestamp predicate and preservation proofs are prepared
privately, outside this checkpoint. Continue with that cutover without waiting
for hosted CI. See spec §§13.30–13.31.

## Qualified recovery and administration checkpoint — 17 October 2026

The latest batch qualifies **871 compiled claims**, with all 861 previous full
declaration records unchanged and no new axioms. Two clean full translations
are byte-identical; all 18 qualification cases pass. There remain 25 reviewed
external models, none unreviewed and no compiled external axioms. Source closure:
`016c236971e9cd58ab0d6fd762ac7febf2e86919bda2a376e95802a80d10c8aa`.

Five actual record methods consume source-proved recovery/administration guards.
Revocation always refuses recovery first. Successful recovery earns a positive
operation generation bounded by the durable record; binding selection earns the
exact current pair or a valid older recorded pair. The actual constant-time
commitment check is preserved. State changes, rotation and authorization
replacement earn terminal revocation and nondecreasing timestamps.

The 3,520-job full Lean build, 38 connection tests, 232 active gateway tests and
affected-target/xtask linting pass; 26 existing ignored gateway tests stay unchanged.
Frozen full-record/native parity covers 2,250 bindings (210 successes), 450 state
transitions, 450 rotations and 600 authorization replacements. Rotation and
replacement each have 30 useful successes. Source qualification also exercises
success, zero/future generation refusal, terminal revocation, commitment selection,
no-op state changes and time regression. The enum-context regression preserves
all native enum bodies and rejects inventory drift.

Review: `ap-spec-069-connection-recovery-administration-2026-10-17`; inventory:
`978677ea2fd11b7b04029f70566e6b7711650b907006a5057ac21de7b9349e6d`;
boundary: `e47a70caeb2efe34fdbd8936cbf4091c81d191de15000389ba457434c699df5d`.

Complete record/caller projection, operation authentication, primitive comparison
correspondence, actual credential-store lease and reload/write histories remain
open under §13.5/E1–E5/M6, as does exact-revision hosted evidence. Direct String
constructor proofs are being prepared privately using the existing reviewed
standard-interface models. See spec §§13.28–13.29; continue without waiting on CI.

## Qualified constructor and connection-key checkpoint — 17 October 2026

The latest batch qualifies **861 compiled claims**, with all 838 previously
pushed complete declaration records unchanged. Two clean full translations are
byte-identical; all 18 qualification cases pass, with 25 reviewed external
models, none unreviewed and no compiled external axioms. Source closure:
`390c119b23d2172f15bc6b026236af76a28d9f0f3d13e705b770de7914e9ee0c`.

Shipping constructors consume proved full-buffer provider/alias, workload and
semantic-identifier grammars. Acceptance earns the stated size bounds and NUL
absence; semantic identifiers also earn whole-buffer ASCII. The actual unchanged
profile constructor has a direct transparent source proof of its version refusal
and exact field preservation. The gateway hashes a source-proved domain/provider/
separator/alias preimage whose independent framing proof binds both fields under
the earned provider grammar. No hash-injectivity axiom is added.

The complete 3,519-job Lean build, 35 connection tests, 40 kernel tests, 232 active
gateway tests and affected-target/xtask linting pass. Existing ignored gateway
tests remain 26. Native tests compare every byte pair and size boundaries,
589,824 binary preimages and 64 typed gateway keys with frozen preceding behavior.
Coverage v4 inventories the actual transparent constructor selected by a
non-shipping entrypoint, preserves full local spans and validates its imported
declaration span separately. Historical coverage reproduction stays byte-identical;
headline scope remains 134/1047 decision functions, 1833/11563 lines and 23/82 sites.

Review: `ap-spec-069-connection-byte-framing-2026-10-17`; inventory:
`1b4a2587677994a404e5f8808c10d0f1fbc2288e10d1b8c13d3e42fffbf1beb2`;
boundary: `94d0a3fefdb75a3344bb2822641bdefff372d261deef3ebd81a2a55c1abeca49`.

The complete String/record decoder, actual reload/lease/write association, backend
history and whole §13.5/E1–E5/M6 program remain open, including exact-revision
hosted evidence. A recovery-lease component is being prepared privately; it is
not part of this qualified checkpoint. Continue implementation without waiting
on hosted CI. See spec §§13.25–13.27.

## Qualified connection-entry checkpoint — 17 October 2026

The latest batch qualifies **838 compiled claims**, preserving all 832 previous
complete declaration records. Two clean full translations reproduce
byte-identically; all 18 qualification cases pass, with 25 reviewed models,
none unreviewed, and no compiled external axioms. Shipping source closure:
`dbdeafb8829de25fd97cdee75384bf275314efc725134b4fb388e1681a72a141`.

The runtime consumes exact source-proved active-state, workload-membership and
full profile identifier/version checks, plus the existing proved exact-byte
primitive for reload comparison. Native parity checks 1,728 constructor-valid
record queries (126 permitted, 1,602 refused) and every canonical byte mutation.
The full Lean build, 231 active gateway tests, 39 kernel tests and affected-target/
xtask linting pass. Existing ignored gateway tests remain 26. Source qualification
checks useful acceptance, disablement and profile-version mismatch witnesses.

Complete record decoding, record-to-projection correspondence, reload/lease/write
association and full E4.6 runtime composition remain open, as does the rest of
§13.5/E1–E5/M6 and exact-revision hosted evidence. Constructor byte predicates
are the next privately prepared component. See spec §13.24.

## Qualified reservation checkpoint — 17 October 2026

The latest batch qualifies **832 compiled claims**, with all 798 complete
records from the previous pushed checkpoint unchanged. Both clean full
translations reproduce byte-identically; all 18 qualification cases pass.
There are 25 reviewed external models, none unreviewed, and no compiled
external axioms. Production source closure:
`1a07b71048278076845fd283106a674087d05a89d4bd2dd3560c2f17dd99dce5`.

Shipping code now consumes the proved complete claim/count/sum builder, exact
decoded cumulative-record validator, shared count-to-sum slot lookup and complete
ordered reservation decision. Successful admission earns every count/slot/sum
bound, all parallel-vector lengths and overflow-safe sums. Native tests cover
all 289 aligned batch layouts, 486 decoded record combinations with independent
success/refusal counts, and 139,968 ordered admission combinations.

The full Lean build and 229 active gateway, 38 kernel and 24 bounded-policy
library tests pass, as do affected-target/xtask linting and final store aggregate
scenarios. Existing ignored gateway tests remain 26. Coverage v3 reports
134/1047 decision functions, 1833/11563 code lines and 23/82 check sites;
the historical study still reproduces byte-identically.

Full authenticated caller mapping, backend linearization and runtime/history
correspondence remain open, as do the rest of E1–E5/M6 and exact-revision hosted
evidence. The next connection-entry membership component is a private prototype,
not qualified shipping code. See spec §§13.20–13.23 and the remaining-program
table in §13.5.

## Qualified complete slot-batch checkpoint — 16 October 2026

The latest batch qualifies **809 compiled claims**, with all 798 previous
complete declaration records unchanged. Both clean full translations reproduce
byte-identically; all 18 qualification cases pass, with 25 reviewed external
models, none unreviewed, and no compiled external axioms. Source closure:
`339d80930b9e3b5cb85900bd15713284f49802820a7225c7d44afa5792a43d9e`.

Shipping reservation assembly consumes the proved complete builder: exactly one
claim first, every count and sum slot, and at most 33 entries on success.
Mismatched vectors, excessive cardinalities and cumulative overflow fail closed.
All 227 active gateway tests, 35 kernel tests and affected-target clippy pass.
A frozen shipping constructor oracle checks canonical bytes, keys and expiries
for all 289 aligned layouts. Coverage version 3 fixes numbered-loop
classification using explicit translation metadata; all seven regression checks
pass and the historical study remains byte-identical.

The next component validates decoded cumulative records. JSON parsing, backend
linearization, authenticated caller mapping, count/sum coupling and full
runtime/history composition remain separate obligations. Whole E1–E5/M6
completion and exact-revision hosted evidence remain open. See spec §13.20.

## Qualified aggregation/retry checkpoint — 16 October 2026

The latest batch qualifies **798 compiled claims**, with all 757 previous
complete declaration records unchanged. Both clean full translations reproduce
byte-identically; all 18 qualification cases pass. The inventory has 25 reviewed
external models, none unreviewed, and no compiled external axioms. Source closure:
`d75d2be54aeef9a943fb35736ead1ff024ffe838c11565c10f9ef647b99193c4`.

Shipping count/sum counter derivation consumes the actual proved aggregators.
The source loops earn unique IDs and minimum per-ID capacities on the admitted
16-link domain; sum updates retain the first count-slot bound. Reservation retries
consume a total checked interpreter for claim/count/sum conflicts, including
malformed indices, parallel-array bounds and word overflow. The slot-availability
guard now uses the already proved length-checking count predicate.

The complete Lean build, 225 active gateway tests, 33 kernel tests and affected
Rust clippy pass. Native parity compares complete sorted count/sum/slot results
to the preceding implementation. The decision-scope coverage measurement remains
133/1046 functions, 1814/11544 lines and 23/82 check sites; gateway additions are
recorded in its separate translation inventory. Exact-revision hosted evidence
remains required; no whole E1–E5/M6 milestone is complete.

The subsequent complete slot-batch checkpoint above supersedes the prepared
prototype status recorded at this aggregation/retry checkpoint. Full authenticated caller mapping,
count/sum coupling, backend linearization, cumulative-record decoding and
runtime/history composition remain open. See spec §§13.18–13.20.

## Qualified counter/slot checkpoint — 16 October 2026

The current batch qualifies **757 compiled claims**. All 741 previous complete
declaration records are unchanged. Both clean full translations reproduce
byte-identically; all 18 qualification cases pass, with 25 reviewed external
models, none unreviewed, and no compiled external axioms. The source closure is
`8701bdf464825fa990591db6833a3b35dc58806769a80520651dcade26968222`.

Production counter/slot hashing now consumes the translated exact preimage
builders. The new proofs cover the component lengths and bytes, all four
domains, window coordinates, typed counter IDs and slot words; count/sum
source-output identity binding; framing injectivity; and 774/844-byte counter
frame bounds. SHA-256 security remains a separate primitive contract. The
actual hashing callers match their frozen previous implementation in native
parity tests. The complete Lean build, 224 gateway tests, 26 kernel tests and
affected-target clippy pass. Hosted exact-revision evidence remains required.

Counter aggregation, full runtime/backend correspondence and the remaining
E1–E5/M6 obligations remain open. A separate keyed-minimum prototype is prepared
for the next batch. See spec §13.17.

## Qualified checkpoint — 16 October 2026

The current local batch qualifies **741 compiled claims**, including all 671
previous complete statement/constant/axiom records unchanged. Two clean full
translations reproduce byte-identically; all 18 qualification cases pass, with
24 reviewed external models, none unreviewed, and no compiled external axioms.
The shipping source closure is
`f9041056a71f53030c45a3a9e0c4208da53fc5a56d26b03466ef119e54104549`.

New components cover the complete principal-ID constructor, constructor-earned
scope ordering through trust decoding and status selection, exact schema-name
lookup, logical-operation token/framing, and the actual frontier search methods
with a composed 64-read bound. The shipping compiler rejects duplicate JSON
members before source/lock decoding. Independent history models combine
chain/count/sum bounds with durable claims, crashes, lost acknowledgements and
one-use ownership; actual backend/driver correspondence remains separate.

The affected native crates pass 327 library tests (26 existing gateway tests
remain ignored). Coverage's six checks include byte-identical historical
reproduction and compiled-constant handling of method notation. Coverage v2
reports 133/1046 decision functions and 1814/11544 decision code lines in the
refined closure, and 23/82 check sites. Exact-revision hosted gates remain
pending; no complete E1–E5 or M6 milestone is claimed.

| Milestone | State | Evidence / remaining work |
| --- | --- | --- |
| M0: claims and extraction slices | In progress | Shipping head reading/writing and identifier lookahead/scanning refine explicit grammars, with positive/refusal cases and compiled statement/axiom audits. Full protocol-object refinement and hosted qualification remain required. |
| M1: complete codec | In progress | The head codec has a source-to-source round trip and a one-to-nine-byte output bound. Successful canonical-action decoding has exact re-encoding and accepted-encoding uniqueness proofs. The shared identifier validator has exact scan/bounds refinements and a validated-string representation bridge. Complete object/carrier, work/allocation, constructor and codec refinements and hosted corpus/property evidence remain required. |
| M2: crypto integration | In progress | The shipping shared signing framer refines an independent byte grammar, supplies its validated frame premises, and proves input binding, object-domain separation, exact length and oversized-profile refusal. The shipping Ed25519 field/sign and P-256 compressed-form guards now have total exact refinements. Caller unsigned-object construction, complete suite glue/dispatch and commitments remain E5.1–E5.4 obligations. |
| M3: complete verifier | In progress | The public observed evaluator now refines independent structural validation followed by all/any/k semantics. The source validator accepts iff the independent structural contract holds; invalid plans preserve both callback states without callback premises. The ordinary facade and event accessor are now also refined. Callback implementations, registry/stage composition, sealed projection and the full E2.1–E2.5 claim remain. Exact-revision hosted gates are pending for this expansion. |
| M4: mapping and driver | In progress | Exact source field-name lookup and an independent named/positional projection relation are proved; duplicate source/lock JSON members are refused. Full source compiler, sealed projection and driver-to-I/O correspondence remain E3.1–E3.5. |
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


## Public Ed25519 API and explicit foreign implementation

The shipping public Ed25519 verify and key-validation entry points now have
exact source refinements, including their selected callback dictionaries,
library adapters and result projections. `Native.public_verify_refines`
covers the complete result and stable refusal precedence for arbitrary
represented byte slices. `Native.public_verify_accepts_iff` connects success
to the independent canonical/non-weak exact-message suite relation.
The decoded-key validator has its own exact Unit/error projection theorem.

Three foreign library calls are fields of an explicit implementation parameter:
point recovery, fixed-width signature construction and the strict equation.
Their exact total contracts are displayed theorem premises. There is no
default/global implementation instance, global crypto axiom, opaque Auths
helper or rewritten Rust function body. A reviewed section declaration threads
only that parameter through dependent generated declarations. Missing, repeated
and already-generalized normalization inputs are rejected, and a regression
checks exact recovery of every generated body by removing only that declaration.
Transparent Result-to-Option and existing Result-map models handle projections.

The construction audit passes 545 claims with all previous 536 full records
unchanged and only the existing three foundations. Concrete kernel witnesses
check exact message/signature forwarding, changed-message refusal and malformed
key refusal before any primitive call. The explicit forwarding mock is an
inhabited contract and call-binding witness; it establishes no cryptographic
authenticity. Existing published native signature tuples remain separate evidence.

The extraction has 23 local and five external function records. Four local
records are compiler-generated non-generic closure call shims. They remain in
the complete dependency/report inventory and are classified separately from
handwritten functions, as the generic composition shims already were.
A focused regression rejects unrelated methods, receiver mismatches and malformed
closure names. No handwritten function is removed from a coverage denominator.
The complete fresh qualification passes all 12 cases, native parity and two
byte-identical translations, with all 545 compiled claims, thirteen reviewed
external models, zero unreviewed models and zero compiled external axioms.
Its exact source closure is
`bc6f231fa8c0594a57748ba5a52e34bdc743f15cf965cb4b19c1bb955041fbd1`.
Hosted evidence remains required on the exact new revision.

P-256's parameterized source algorithm and concrete numeric low-S guard remain
proved. Its public native-wrapper extraction hits a pinned Charon associated-
type normalization failure even on the isolated library point-decoding call;
monomorphization gets past that stage but fails in the pinned Aeneas translator.
No failed or partially translated artifact is in the qualification inventory.
That public binding, suite/principal dispatch, caller unsigned-object closure,
all commitments and whole E5 remain open, as do the other full AP-SPEC-069 gates.

The preceding 500-claim facade checkpoint passed every hosted main CI gate,
including authoritative Lean, clean checking and final formal evidence:
[CI 38875070290](https://github.com/auths-dev/auths-proof/actions/runs/38875070290).


The assurance source resolver now uses the pinned Lean header parser and module
resolver in one process, rather than launching Lean once per source. The
resolved set was compared exactly against the prior 145-source result. The
resolver implementation itself is included in the hashed source inputs, and
the Rust caller rejects foreign/duplicate paths and a missing audit root.
Invalid-header and outside-root construction cases fail closed. Each claim
must still name the exact independently resolved closure and its digest; the
audit hashes the common snapshot once and rehashes it before publishing, so a
source change during the audit is refused. No theorem statement, source input,
axiom check, evidence digest, or hosted gate is removed by this cost reduction.


## One-shot hashing, exact commitment frames and signed capacity

The production codec now uses the selected one-shot SHA-256 call. Application
commitments and identifier hashes first build explicit, checked preimages;
the streaming implementations remain only as independent native test oracles.
The wire transcripts and digests are unchanged for admitted inputs. Five
focused native tests pass, including randomized old-transcript comparison,
all nine identifier tags, UTF-8 byte limits and unrepresentable allocation
requests. The gateway semantic-closure fixture is regenerated from the source.

The new buffer guard checks signed pointer-size representability before Vec
allocation. Checked usize addition alone did not establish that requirement.
`BufferAllocation.buffer_refines` characterizes its complete abstract result;
success implies an empty buffer and the signed-capacity bound. Physical memory
availability and allocator behavior remain the declared standard-library/host
boundary. The source check does not promise allocation success under exhaustion.

`CommitmentFrames` independently defines the exact application and identifier
transcripts. It proves their lengths, framing injectivity on the stated valid
relations, and separation from each other and the signing domain. The shipping
preimage functions have successful-output byte-exact refinements, including all
nine identifier tags. Those conditional results do not establish all-input
framing totality, the complete valid-carrier bridge or general admissible-input
acceptance. Concrete kernel witnesses accept a useful application frame and
every identifier tag, and reject empty/oversized domains before payload work.
The previous signing statements are preserved with proofs for the new guard.

A second compilation unit for the same actual codec crate monomorphizes the
native SHA-256 leaf. The pinned name-pattern emitter cannot print foreign
`Instantiated` names. Eleven exact foreign name paths receive export aliases;
a checked ledger retains their original concrete identities and source spans.
The adapter checks every Auths name and every body, signature, generic, layout,
source span and call/type ID unchanged. Tests reject an Auths declaration,
missing/unreviewed names and name substitution inside executable data, and
reject repeated primitive-context generalization. Charon reparses the resulting
hash-consed AST before translation. No failed/partial translation earns a claim.

The two selected foreign operations, digest and Into<[u8;32]>, are explicit
`Sha256Primitives` fields. `Sha256Native.raw_hash_refines` proves exact input
forwarding and output construction under their displayed total functional
contract. It asserts no primitive correctness, hash injectivity, collision
resistance, preimage resistance or global implementation instance. Explicit
byte-echo mocks witness forwarding only; they are not SHA-256 implementations.
The foreign aliases in that unit's report are linked to actual declarations by
the normalization ledger and do not represent new Rust source symbols.

Local exact-source qualification passes 567 claims, with all previous 545 full
records unchanged and only the existing three foundations: two byte-identical
fresh translations, 13/13 qualification cases, and 16 reviewed external models
with no unreviewed model or compiled external axiom. The source closure is
`c84be514413fea52bd330d905ac5d2b3e23c93d8695215bf0e86dc27c2553ba4`.
The exact revision still requires hosted gates. Complete caller
unsigned-object/descriptor construction, hash-call integration for every
commitment, the P-256 public binding and whole E5 remain open, along with the
other full AP-SPEC-069 milestones.

Hosted CI for the preceding 545-claim checkpoint reported the generic key rule
on a public upstream function type in an immutable, uncompiled Aeneas template.
The reviewed exception names only that historical commit/path/rule/line. The
pinned 8.28.0 scanner passes both the exact staged remediation and full local
history. No credential, generated byte, broad rule, path or scanner gate was
changed; the correction is committed for the next hosted revision.

## Accepted commitment-frame validity and input binding

The shipping application and identifier framing now supply the independent
valid-frame premises directly from acceptance. Equal accepted preimage bytes
therefore imply equality of the original domain/tag and payload, without a
caller-supplied validity premise. Exact successful output lengths are also
proved for every represented input and all registered identifier tags.

Local exact-source qualification passes 573 claims; every previous 567 full
statement record is unchanged, and the six additions use only the permitted
foundations. Two fresh translations match byte-for-byte, all 13 qualification
cases pass, and 16 external models are reviewed with zero compiled external
axioms. Source closure:
`57d8e7d80c72736d88c803642ef4bae8833974d6d5fc4844379d30f748669c43`.
Exact-revision hosted gates remain required. These are
preimage-byte properties. They assert no SHA-256 injectivity or cryptographic
security, and do not yet establish all-input totality, general acceptance,
caller unsigned-object construction, every commitment or complete E5.

## Complete bounds classification for the three shared framers

The actual signing, application-commitment and content-identifier framers now
have all-input totality in the qualified Result semantics. Each accepts iff
its independent numeric domain holds, and returns exactly `LimitExceeded`
iff that domain does not hold. The domains retain exact UTF-8 byte lengths,
protocol word widths, checked unsigned capacity and the actual signed
pointer-size allocation ceiling. Empty signing profiles remain admitted;
application commitment domains must be nonempty and at most 128 bytes.

Together with the previous successful-byte, valid-frame, exact-length and
input-binding results, this closes the shared framer's complete bounds/result
classification. The proofs inspect every translated branch and append bound.
They introduce no implementation premise that assumes successful framing.
Physical allocator behavior and memory availability remain explicit standard
library/host contracts, rather than a claim that arbitrary memory exists.

Local exact-source qualification passes 582 claims. All prior 573 complete
statement records are unchanged; the nine additions use only the existing
foundations. Two fresh translations are byte-identical, all 13 qualification
cases pass, and 16 external models are reviewed with zero compiled external
axioms. Source closure:
`0daa0c0f1cb323def162abff2add05fbcb94433b88aee7ef5804082ec58ae087`.
Exact-revision hosted gates remain required.
Caller unsigned-object and descriptor construction, all commitment call sites,
P-256 public native-library integration, the remaining complete-object codec
and complete E5 remain open. No whole AP-SPEC-069 milestone is declared done.

## Native P-256 public API and explicit primitive interface

The production P-256 verifier now shares one explicit private primitive
interface for point recovery, scalar parsing and the exact-message equation.
Its fixed-width signature conversion owns exactly 64 copied bytes, avoiding
region-erased borrowed array types in monomorphic extraction. The public key
validator uses a direct result match. Public Rust APIs and stable decisions
are preserved; no second production verifier or compatibility route is added.

The actual native public verification and key-validation APIs now refine the
independent suite models under displayed foreign functional contracts. The
accepted-input equivalence requires compressed form, a decoded point, exact
signature width, a parsed scalar, numeric low-S and the exact-message equation.
Concrete guards and the actual native adapters are translated. Library
correctness and elliptic-curve arithmetic/security are not proved or assumed
as global axioms. Explicit forwarding mocks demonstrate key, message and
signature binding and changed-input refusal; they assert no authenticity.

The native unit translates 14 local functions and ten explicit foreign/standard
interfaces, with no opaque Auths function. The reviewed name adapter preserves
every body, signature, generic, layout, source span and call/type ID. Thirty-one
foreign export paths receive aliases. Two unique Auths helper specializations
lose only their final name-only instantiation suffix; their original complete
identities remain in the ledger and their base source names are retained.
Exactly dependent types/functions receive an explicit primitive parameter.
The standard monomorphic Result/Option/Try and array/slice operations are
transparent; three foreign calls are implementation projections with no
installed instance. The explicit key-validation match removes the erased
unit-callback issue without a callback model or callback premise.

Local exact-source qualification passes 599 claims: 17 additions and exactly
three reviewed statement changes from FnOnce callback arguments to the explicit
P256Primitive dictionary, retaining the same independent functional contracts.
The other 579 complete records are unchanged, and only the permitted foundations
occur. Two fresh translations are byte-identical, all 14 qualification cases
pass, and 19 external models are reviewed with zero compiled external axioms.
Native signature tests, focused lint, name-adapter rejection tests and gateway
semantic-closure regeneration also pass. Qualified source closure:
`494fbe483fbf5aa946ccc33f87b1d122bb1b1c697757551866118ae02b7244e7`.
Exact-revision hosted gates remain required. Suite/principal
dispatch, caller unsigned-object/descriptor construction, every commitment,
the complete verifier and whole E5/M6 remain open.

## Qualified suite verification adapters

The actual Ed25519 and P-256 SignatureSuite verification methods now refine
the independent suite results and acceptance predicates, including all three
input fields and exhaustive port-error mapping. Their two imported core calls
delegate directly to the previously qualified public native implementations.
A closed owner-link inventory requires exact Rust/Lean identities, transparent
local owners, and compiled delegation theorems mentioning both exact constants.
The compiled statement audit now records kernel constant references, including
implicit implementation instances, and binds these to the reviewed digest.
Readable statement text cannot substitute for a missing owner reference.

Four explicit-mock witnesses cover exact input acceptance and changed-message
refusal; these demonstrate forwarding, not authentic cryptographic signatures.
All previous 599 readable statement texts, modules, kinds and axiom sets are
unchanged; the new constant-reference metadata is added to every audit record.
The construction audit has 613 claims, with only the permitted foundations.
Focused owner-link, digest-rejection and nested closure-scanner tests pass.
Fresh exact-source qualification passes all 613 audited claims, 15/15 cases,
21 reviewed models and zero compiled external axioms. Two clean translations
are byte-identical. Qualified source closure:
`17a0056b33dcb6769fe574e62f8cf3a6422e208b56c6b9a041b94e946827c7cc`.
Exact-revision hosted evidence remains required for this expansion. Suite
constructors, IDs, registry selection, key/principal binding, caller object
construction, remaining commitments, and complete E5/M6 remain open.

## Independent P-256 conformance corpus

The pinned public Wycheproof P-256/SHA-256 P1363 corpus is now vendored and
adapted deterministically to the registered Auths compressed-point/low-S
policy. All 262 upstream cases are retained. The shared corpus has 653 cases,
including 173 admitted signatures over 98 distinct public keys, high-S twins,
changed messages, malformed points/scalars/widths and refusal-priority checks.
The original source hash is required by the offline byte-for-byte generator.
Rust checks the actual native API, key validation and suite-adapter error
mapping. The independent Go and TypeScript implementations consume the same
corpus. Native qualification and hosted bindings conformance include these
checks; the corpus and adapters are bound into the exact source/release
inventories. Native tests, focused Rust lint and independent Go/TypeScript cases pass.
Fresh source qualification passes 613 unchanged complete audit records,
15/15 cases, 21 reviewed models, zero compiled external axioms and two
byte-identical translations. Qualified source closure:
`231fa58fa3a0200c0d5914a35d613e5672096992199df9b56c33f64f20275c03`.
Exact-revision hosted evidence remains required. These tests support the explicit primitive
contracts and do not prove them or complete E5/M2.

## Actual selected-witness expiry helpers

The shipping verifier's status-decision, status-horizon and selected-assurance
horizon helpers now refine independently defined status/expiry semantics. The
actual loop terminates for every represented finite input. Missing requirement
references and required observation timestamps fail closed; unbounded rules
need no timestamp; selected deadlines use exact saturating 64-bit addition
and their minimum. A successful native horizon admits exactly the maximum
word bound and all selected expiries. Status endpoints are inclusive and
principal/grant failures preserve their distinct stable classes.

The native unit has four local declarations (three Rust functions and one
loop), 14 transparent imported Auths helpers and one standard Option import.
No Auths algorithm is opaque. A scoped, unconditional standard comparison
adapter projects only partial_cmp; no generated function body is rewritten.
The pure model imports no generated Rust. Nine Lean witnesses separate actual
status calls from pure expiry examples. Five native tests use actual validated
Rust constructors; focused lint, context rejection tests and gateway semantic
closure regeneration pass. The construction audit has 634 claims, all 613
previous complete records unchanged and only the permitted foundations.
Fresh exact-source qualification passes 634 compiled claims, all 613 prior
complete records unchanged, 16/16 cases, 22 reviewed models and zero compiled
external axioms. Two clean translations are byte-identical. Qualified closure:
`d0e1dba843ae5f0bba50a2b00cf8f779721756069e3bc1481feaab81d1b836d5`.
Exact-revision hosted evidence remains required.

These are expiry-only claims. Authenticity, selection by the actual assurance
evaluator, observation-time ordering, satisfaction of every required policy,
complete verification, other horizon intersections and the actual runtime
consumer remain separate E2/E4/M6 obligations. No whole milestone is closed.


## Approval-view status-selection source refinement

The actual principal and grant selectors now use one indexed scan each,
without temporary collections. Shipping first-rule lookup and approval-view
visibility refine independent list rules. Both actual public port methods
have total Result refinements against an operational accumulator, including
all policies, snapshot refusal order and complete decision/horizon results.
Nine kernel-checked witnesses exercise the actual principal port. The pure
filter/max/tie-set specification is separate; its equivalence to the scan is
still an open obligation, as are anchor-view refinement, evidence authenticity
and complete verifier composition.

The prior algorithms remain test-only independent references. More than
19,000 constructor-valid snapshot pairs compare both selectors in three views,
with dedicated word-limit, saturation, rollback and latest-tie cases. Focused
native parity, lint and generated-context rejection checks pass. The standard
binary-search model follows the pinned standard library's size/base/half
transitions; sorted-scope membership is not yet claimed.

Fresh source qualification passes 658 compiled claims, all 634 preceding
complete records unchanged, 17/17 cases, 23 reviewed models, zero unreviewed
models, zero compiled external axioms and two byte-identical clean translations.
Qualified production closure:
`597b19ee0354614b37b9f048c7248e5684e69cf2c0d05a92a8b224a0b1172c7f`.
The preceding 634-claim revision `e4770a2b` passed all ten hosted workflows,
including [main CI](https://github.com/auths-dev/auths-proof/actions/runs/38931405294).
The new source slice requires exact-revision hosted gates. E1–E5/M6 remain open.


## Independent status-selection adequacy

The operational accumulator now equals the independent filter/max/tie-set
specification for every finite input, subject equality operation, view and
policy, without an input-validity or source-success premise. The proof earns
an attained maximum, preserves every highest-sequence tie, treats rollback
as absorbing, and connects exact minimum horizons to the independent fold.
Its semantic modules import no generated Rust.

Both actual principal and grant approval-view port methods now refine that
independent specification, returning the exact decision and horizon. This
closes the scan-versus-specification gap recorded in the preceding checkpoint.
Anchor-view source refinement, evidence authentication, closed dispatch and
complete verifier/runtime consumption remain open. No whole E2/E4/M6
milestone is complete.

Fresh qualification passes 661 compiled claims, all 658 preceding complete
records unchanged, 17/17 cases, 23 reviewed models, zero unreviewed models,
zero compiled external axioms and two byte-identical fresh translations.
Qualified production closure:
`678c19c1155869c45fed1cb7e849c147bca5bde0e07df567f413487335ab6669`.
Only the permitted foundational axioms occur. Exact-revision hosted gates
remain required.

Hosted implementation checking of `85bc1e0f` found that the gateway checksum
still described the differential test file before its final lint cleanup.
The generated artifact is refreshed in this checkpoint; its focused native
check must pass again. No gate or checksum input is excluded to accommodate
the change. Other hosted results for that revision remain separately recorded.


## All-view status source refinement on ordered scopes

The actual principal and grant ports now refine the independent status
specification in every view. The proof includes the existing binary-search
lookup: its reviewed pinned-standard model terminates, preserves membership
through each interval reduction, and returns a bounded index; the actual Auths
contains wrapper returns exact list membership. Actual visibility then agrees
with the per-issuer OwnAnchor, listed-anchor and AnyAnchor rules.

The all-view statements require ordered listed-anchor scopes. This is a
legitimate representation invariant, not a desired-result premise; derivation
from the actual sorting/validation constructor remains open. Approval-view
statements retain their earlier unrestricted represented-input contracts.
Five new cases check first/last listed anchors, an absent anchor, active status
through the issuer own anchor and hidden status through another anchor. The
last two quantify over unrelated anchor fields and assert selection only;
their synthetic evidence is not an authentication witness.

Fresh exact-source qualification passes 671 claims, all 661 preceding complete
records unchanged, 17/17 cases, 23 reviewed models, zero unreviewed models and
zero compiled external axioms. Two clean translations are byte-identical.
Production closure:
`0e96ae702036cbe01af7fe60060ac560482b17fc4f473bb24e653ca35a6b5b60`.
Only the three permitted foundational axioms occur. Exact-revision hosted
verification remains required. Constructor validity, evidence authenticity,
closed dispatch, full verifier composition and runtime/history consumption
remain separate E1/E2/E4/M6 obligations.

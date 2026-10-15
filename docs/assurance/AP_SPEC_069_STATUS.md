# AP-SPEC-069 implementation status

This is the implementation ledger for
[AP-SPEC-069](../specs/0069-authorization-to-execution-formal-assurance.md).
It is not an assurance claim. Completion requires the specification's exact
shipping-source refinement and hosted evidence gates.

| Milestone | State | Evidence / remaining work |
| --- | --- | --- |
| M0: claims and extraction slices | In progress | The shipping head reader now refines the independent grammar for every byte slice and cursor, including reserved tags and truncated arguments. Four audited claims, positive/refusal cases, and the codec extraction inventory are connected. Full protocol-object extraction and hosted qualification remain required. |
| M1: complete codec | In progress | The object codecs now use the in-repository CBOR reader/encoder; the previous dependency is a test oracle. Differential hostile-input properties and existing corpus/fixture checks need hosted validation. Object/carrier, work/allocation bounds, and complete codec refinements remain required. |
| M2: crypto integration | Pending | E5.1–E5.4. |
| M3: complete verifier | Pending | E2.1–E2.5. |
| M4: mapping and driver | Pending | E3.1–E3.5. |
| M5: history and storage | In progress | Both backends now fence slot admission against a durable monotone collection cutoff. Exact scalar-decision refinements and arbitrary finite cutoff-history invariants are implemented; backend conformance and the complete admission/driver-history bridge remain to be qualified. Authority-derived entry expiry is still required. |
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
bytes. The independent encoder's round trip does **not** yet establish a
refinement of the Rust encoder.

The qualification corpus includes an accepted unsigned head, a missing-byte
refusal at an outlying cursor, and a truncated four-byte argument. The
compiled axiom check reports only `propext`, `Classical.choice`, and
`Quot.sound`, within the existing allowlist. Existing audited theorem
statements were compared with their previous statement hashes and are
unchanged. Authoritative Lean now additionally replays the public theorem
closure into a fresh kernel environment with the pinned `leanchecker`.

The local qualification construction passed two byte-identical clean
translations, all ten qualification cases, and the compiled audit of 332
claims. A separate fresh-environment replay of `Auths.Codec.Refinement`
passed. These are development results; the exact pushed revision still
requires the hosted authoritative gates.

The next object-level prototype extracted `decode_canonical_action` through
Charon. Strict Aeneas translation rejected its fallible attachment iteration.
Removing borrowed encoder returns eliminated the encoder arrow-type errors;
factoring the attachment loop still exposed an Aeneas context-match failure.
The unsuccessful loop rewrites were removed. This is a concrete need for an
owned, bounded decoder-state transition before claiming whole-object
refinement. The prototype's partial output is not in the qualification
inventory and cannot support an assurance claim.

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

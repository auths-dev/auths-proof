# AP074 follow-up Lean verification reuse

The owner identified repeated expensive Lean work on every PR push. The CI
planner compares the entire PR to its protected base, so a follow-up native or
documentation commit continues to require formal gates. Previously both Lean
jobs rebuilt unconditionally; authoritative Lean explicitly deletes repository
outputs. Only Aeneas translation had validated reuse.

The combined repair retains all required gates and adds reuse of a successful
clean same-repository/same-PR authoritative Lean record to both jobs. The full
provenance and complete-input contract is in [.github/ci/README.md](../../.github/ci/README.md).
Native code recomputes the complete digest and reruns current Rust/source checks;
GitHub metadata, exact producer attempt and archive integrity are independently
validated before that call. Fallback is always fresh verification. No build cache,
unsigned local fixture or old record without complete inputs proves anything.

The first rollout is deliberately cold: source977's existing phase schema has no
complete-input attestation, and the reuse executor/control plane itself changed.
The running977 Lean job is preserved while authoring this batch but cannot seed
the new optimization. Future native/docs-only edits leave the proof key unchanged;
proof/generated/import/toolchain/assurance/executor changes invalidate it.

Validation is batched after all implementation and negative controls are written.
It covers exact key sensitivity and native/docs stability, transitive local data
closure, every native phase/input/provenance field, failed/wrong-attempt jobs,
foreign repository/PR/workflow, expired/missing/oversized/tampered archives,
duplicate JSON and archive paths, legacy/chained evidence, current-check refusal,
and mandatory fresh-workflow fallback. Synthetic controls are unit-test evidence,
not an observed hosted reuse hit. The repaired head must bootstrap with real
hosted clean Lean evidence; a later legitimate unchanged-input follow-up will
establish an actual hosted hit. The required final evidence/acceptance-ledger documentation commit is the planned warm-hit verification; no speculative code publication is added.

The actual977 run also exposed a second source of redundant pushes: source-closure
regeneration left59 existing assurance citations stale. The bounded updater
published `ee7975be` automatically while manual publication was held, changing only
those source-closure evidence hashes. That commit is preserved in the combined
ancestry. `semantic-freeze --update` now asks the native assurance owner to refresh
only existing citations of `formal/qualification/aeneas/source-closure.json` after
regenerating that file. This is metadata construction, not proof qualification.
Typed negative controls preserve the complete statement/axiom/claim/review/semantic
binding structure and every other evidence item, reject kind/path substitutions,
and require the unchanged fresh compiled audit before qualification.


The final affected verification passed: Python9 provenance tests; planner35 tests;
21 native phase/assurance tests;25 qualification-policy tests; strict xtask/planner
Clippy; phase ownership and production source-closure checks. Actual logs are in
`/tmp/ap074-ci-lean-reuse-final`. The metadata constructor refreshed exactly59
source citations and preserved the entire remaining typed assurance structure.
Release inventory requires freeze432, assurance bytes62, source-closure bytes107,
evolution85 and public surface432; other identities remain unchanged. Hosted
fresh bootstrap and a subsequent genuine warm hit remain required evidence.

A post-publication read of actual GitHub discovery metadata exposed a bounded
lookup defect: each push creates14 workflows, so the first ten repository-wide
runs contained only the current head. This safely fell back to fresh Lean but
could prevent every warm hit. Discovery now queries the current CI workflow ID
before applying the ten-candidate limit. Regression controls reproduce the14
unrelated runs, prove the exact endpoint, and preserve the tenth/eleventh
candidate boundary. This controller correction invalidates the initial proof key;
the corrected head, rather than f5e9, must establish the fresh bootstrap.

The complete lookup correction passed all10 offline provenance tests; the native
metadata constructor passed with zero citation changes and byte-identical release
inventory. The actual workflow-scoped GitHub endpoint returns current f5e9,
previous ee797 and original977 CI runs, unlike the repository-wide first ten.
No early f5e9 failed check was observed before this correction. Real bootstrap
and warm-hit results remain pending; no hosted proof success is inferred.

The requested audit against actual retained GitHub metadata found that a run's
associated PR object updates its head SHA when the PR advances. Successfulce9
run40899439849 and original977 now show the current20b PR snapshot. Historical
identity instead matches across the immutable run, successful exact-attempt
job123552204257, artifact12910849462 and its single lean.json member. Its verified
ZIP SHA-256 is94562f1057bddcaae2aae0be22adc645c39830f498a72cf9a62c1057fb629cd1.
The PR association still validates the number and both repository identities;
only its mutable snapshot is excluded from historical source comparison. Tests
accept this observed shape while refusing any mismatched immutable source field.
The oldce9 record still lacks complete attestation and cannot qualify reuse.

The complete metadata correction passed all11 provenance tests and the metadata
constructor with no generated changes. Running the corrected transport against
the retained actualce9 run accepts its same-PR association, then explicitly rejects
its old phase for missing complete-input attestation. No native validator or
qualified result was invoked or synthesized for that legacy artifact. No early20b
failed check was observed before this correction.

## Verified cold producer and pending consumer

The corrected controller's real bootstrap is source `eb44d8f7`, CI run41924977969,
attempt1. Fast Lean126908887765 passed; translation126913912807 reproduced twice;
Kani126913912984 verified49harnesses. Authoritative Lean126929527493 completed its
clean build and329-statement compiled audit successfully at23:38:21UTC. Final
formal evidence126942117729 also passed; the three old CI failures all derive
from the known corpus root (85success/3failure/8conditional skips). The
[producer evidence report](0074-hosted-evidence-eb44d8f7.md) records immutable
source/merge identities and authenticated artifact hashes. The old overall CI
retains its separate, repaired corpus failure; a successful clean producer job
is the reuse predicate, not a false claim that the entire old CI passed.

Clean Lean artifact13373617020 contains only `lean.json`, with ZIP SHA-256
`f2a256d1be842c86af7cf057b0e46e989e2029f5a4504ca18b2ecf093fd6818c`.
It attests `executed-clean`, no reuse chain, source eb44/run41924977969/attempt1,
and complete inputs
`c523f465540e306ac9eaaf49ef460365b467be4bccaafd2160552ce23dc83432`.
The actual native digest function returns this same key for the held corpus
repair and final documentation. No producer result was synthesized locally.

At publication of this report, real warm hits in both consumer Lean jobs and
complete final-head qualification are still pending. The legitimate follow-up
combines the required corpus repair with final evidence documentation. Both jobs
must independently validate the retained producer, rerun current Rust/source
checks and retain current-head provenance before skipping only the expensive
Lean rebuild. Missing/mismatched evidence must still fall back to fresh work.
Final results belong to the exact head in [PR213 checks](https://github.com/auths-dev/auths-proof/pull/213/checks)
and its immutable validation records; no recursive docs-only publication is
needed merely to record the outcome of the commit containing this report.

## Actual first-consumer dependency-order correction

The b54 consumer exposed a real warm-path miss: fast Lean completed reuse
validation and then entered fresh setup. The native current-head validator audits
`formal/.lake/packages/aeneas` for the exact pinned commit, clean status and
reviewed warning inventory, but the workflow previously created that dependency
checkout only after a reuse miss. A fresh hosted checkout therefore could not
satisfy the intended audit. Both jobs now prepare pinned dependencies before
validation; the expensive repository proof build remains conditional. No warning,
commit, signature, provenance, current-source or refinement check is removed.
Fresh-checkout and both-job order regressions reject omitted, late, conditional
or ignored setup. The complete executor fingerprint is retained: this correction
changes proof inputs and requires a new successful clean producer before another
real warm verification. The eb44 successful proof remains valid for its exact
inputs; it is not silently reinterpreted under this corrected executor.

The retained b54 fast-job log confirms the refusal at00:03:19UTC: `git rev-parse
HEAD` could not run in the absent Aeneas package directory. The affected batch
passes27 native qualification tests, workflow ownership and strict xtask Clippy;
metadata construction/non-update verification and formal source-closure check
pass after advancing only the generator-reported counters. Freeze433 advances
assurance bytes63, source-closure bytes108, evolution86 and public surface433;
runtime protocol/SDK identities are unchanged. Exactly59 existing source-citation
hashes changed, with all remaining manifest bytes identical.

Corrected formal source closure is
`09fb135d91c47ff1b2a873b583564db3467e76973c9763090bac2affd73b6837`;
the actual complete native proof-input key is
`9b5a7049779384207399e43d927cef5ccd856dce925ba80242c1bc0a25f929aa`.
No local Lean/Kani run or corrected hosted warm success is claimed. The healthy
old fallback may be superseded after remaining current implementation results
are collected: its old executor key cannot qualify this correction.

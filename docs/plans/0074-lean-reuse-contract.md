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

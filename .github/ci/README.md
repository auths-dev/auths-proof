# CI planning contract

`phase-ownership.toml` is the checked-in source of truth for deciding which
expensive CI phases a change can affect. The `auths-ci-plan` package validates
the manifest against every tracked path, every Cargo workspace package, and
every stable workflow gate before producing `target/ci/plan.json`.

The planner is fail closed:

- an unknown path, malformed diff, missing package, deleted package, incomplete
  dependency graph, or invalid manifest schedules every phase in the active
  workflow;
- renames classify both the old and new path;
- Cargo changes use package identities and dependency graphs rather than raw
  `Cargo.lock` hashes;
- pushes to `main`, scheduled runs, and manual runs execute the comprehensive
  set for the selected workflow.

The jobs named `authoritative`, `formal-translation`, `compliance`,
`dependencies`, `secrets`, `opentofu-live`, `postgresql-live`,
`records-api-live`, and `fuzz` are stable gate jobs. Branch protection should
require those names, not the implementation jobs ending in `-run`. A gate
passes only when the planner safely skipped its implementation or the required
implementation succeeded.

The release workflow is intentionally comprehensive rather than selective. Its
preparation and promotion jobs are mapped individually; `compare-and-stage`
and `promote-github-prerelease` are the final gates for their respective
operations.

Cargo downloads and installed Cargo tools are cached, while complete `target/`
directories are deliberately not cached. Authoritative, compliance, and
records API compilation share `sccache`. The formal path is decomposed into an
early Lean feedback job, translation reproduction or verified reuse, a
clean authoritative Lean build, an independent Kani job, and one exact-revision
evidence aggregator. Only the stable `formal-translation` gate reports the
final decision.

The pinned Lean toolchain and third-party Lake packages are cached by exact
toolchain/manifest identity. Repository-owned Lean build outputs are never
accepted as authoritative evidence: the authoritative job deletes them before
its full build. Proof-only pull requests may reuse a successful byte-identical
translation record from the exact protected base SHA. A follow-up proof-only
commit on the same pull request may also reuse a successful prior translation
job, even if that workflow later failed in Lean, only when the prior phase
result and committed generated files match the current translation, toolchain,
source, and evidence closures. Changed inputs since that producer, missing
artifacts, or invalid provenance fall back to two clean reproductions.

`baseline.json` records the pre-optimization runner-minute evidence from issue
#24. Planner artifacts include projected savings and monthly scheduled cost.
Each phase summary reports actual wall time, local artifact size, and compiler
cache statistics, and emits a non-blocking warning after the checked-in
regression threshold is exceeded.

Formal source-closure checking runs before that expensive toolchain is
installed. The closure normalizes the root Cargo manifest and lockfile to the
actual translated dependency graph, so unrelated workspace packages cannot
invalidate the formal translation. To refresh only this cheap artifact:

```console
cargo run --locked -p auths-ci-plan -- formal-source-closure update
```

This command does not run Nix, Aeneas, Lean, or Kani.

When adding a path, package, domain workflow, or phase:

1. update `phase-ownership.toml`;
2. add or preserve a stable gate job;
3. run `cargo run --locked -p auths-ci-plan -- check`;
4. add a planner test proving unrelated domains remain excluded;
5. keep scheduled fuzz targets synchronized with `cargo xtask fuzz-inventory`.

### Reusing clean Lean evidence across follow-up commits

The base-relative planner still schedules required formal gates. Both the early
feedback job and authoritative Lean job may avoid recompilation by independently
locating a successful **clean** authoritative Lean producer on the same repository,
workflow and pull request. This reuses a completed proof attestation, never cached
`.olean` outputs. Main/release/scheduled or forked executions remain cold.

`.github/scripts/reuse-formal-lean.py` checks bounded GitHub metadata, the exact
successful job attempt, source revision, repository/PR identity, artifact identity
and the API-reported ZIP SHA-256. It accepts only one bounded `lean.json` member.
The native `cargo xtask ci formal-lean-reuse` owner separately requires matching
proof, toolchain, execution-policy, translation-source and toolchain-lock hashes,
plus a complete `proof_inputs_sha256` from the original clean run. Reused records
cannot seed another reuse chain. Missing, expired, malformed, oversized, failed,
untrusted or different-input evidence selects the existing full fresh build.

The complete hash includes all tracked authored/generated Lean, Lake manifests,
imports, assurance/axiom policies and vectors; root Cargo/config/toolchain inputs;
workflow/setup/reuse controllers; the full xtask/control-plane packages; and every
local package and data file transitively reachable from `auths-formal-refinement`
according to locked Cargo metadata. The separate validated production closure
binds all translated Rust roots and their dependencies. New local dependencies
are traversed rather than selected by a fixed crate allowlist. Unrelated native
gateway/tests, demos and repository documentation do not enter this proof hash;
proof/compiler/generated/import/toolchain/assurance/controller changes do.
Conservative Cargo or controller changes may cause an additional cold run.

A hit still validates the current Rust toolchain, source closure, algebra/bridges,
translation inventory/reports, workflow and warning policies, runs current
`auths-formal-refinement` tests and checks the current Kani harness inventory.
Input hashes are checked again after these current-head checks. It then emits a
new current-head/current-run phase record linked to the original run, attempt,
job, source revision, artifact ID and ZIP digest. The final aggregator still
requires successful translation, Lean and Kani phases with exact current input
bindings. The feedback job's hit remains feedback, not independent qualification.
Kani remains a separate current-head gate; it is not skipped by Lean reuse.

Legacy records lack the complete-input field and are intentionally ineligible.
The initial rollout therefore requires fresh verification. Later unchanged-input
follow-ups can use that successful producer. The search is bounded to ten of the
latest fifty same-branch PR runs and one hundred artifacts/jobs per candidate;
no eligible retained producer means another fresh run. This availability limit
never converts missing proof evidence into a passing skipped gate.

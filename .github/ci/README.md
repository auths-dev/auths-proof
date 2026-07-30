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

The release workflow is intentionally comprehensive rather than selective; its
single `release` job is also mapped in the manifest and remains a stable gate.

Cargo downloads and installed Cargo tools are cached, while complete `target/`
directories are deliberately not cached. Authoritative, compliance, and
records API compilation share `sccache`. Formal extraction remains isolated
behind the pinned Nix/Aeneas/Lean/Kani toolchain and uses the public Cachix
substitute configured in the workflow.

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

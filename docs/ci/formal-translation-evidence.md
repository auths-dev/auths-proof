# Formal translation evidence

## How the job chooses its evidence

The `formal translation` job qualifies the Aeneas translation of the exact head
commit in one of three ways.

| Path | When | Evidence |
| --- | --- | --- |
| Two clean reproductions | The plan requires a cold run: every push, schedule, and dispatch event, and every pull request that changes the translation, toolchain, or evidence closure. Also whenever no reusable evidence was located. | Aeneas and Charon run twice from source; the outputs must be byte-identical and match the committed generated files. |
| Same pull request, earlier run | A pull request with a cold plan whose earlier run's `formal translation` job succeeded with the same closure digests. | That run's result, bound to this checkout. |
| Protected base | A pull request that changes none of those closures, when a successful `CI` push run on `main` for the base commit published translation evidence. | The base run's evidence, bound to this checkout by `cargo xtask ci formal-translation-reuse`. |

Reuse saves time; it is never required. The ci-plan summary line "reuse
protected-base evidence" states the plan. The translation job decides at run
time whether evidence exists.

## Missing protected-base evidence

The base commit often has no successful run. Its run may have failed in another
job, been cancelled by a newer push to `main`, still be running, or have
expired. The job then runs the two clean reproductions itself, and its summary
says why:

```text
Translation: no protected-base evidence for base <sha> (no successful CI push run on main); executing two clean reproductions.
```

The phase timing records the execution as `executed-cold-without-base-evidence`.
The fallback checks nothing less than a cold plan does. A pull-request
reproduction runs in update mode: output that differs from the committed files
is packaged for the [formal artifact updater](formal-artifact-regeneration.md)
and the job fails until the regenerated files are committed.

Evidence that is found but does not bind to this checkout fails the job. There
is no fallback for that case. It means the committed generated artifacts or the
translation source closure differ from what the base run qualified, although
the plan saw no closure change. Look for hand-edited generated files or a file
missing from the planner's closures.

## Manual recovery

Dispatch `ci.yml` on the pull request's branch:

```bash
gh workflow run ci.yml --repo auths-dev/auths-proof --ref <branch>
```

`workflow_dispatch` is a comprehensive event in
`.github/ci/phase-ownership.toml`. The dispatched run plans every phase, runs
two clean reproductions, and qualifies the branch head. Its checks are recorded
on the same head commit as the pull-request run. The formal artifact updater
starts CI the same way after it pushes regenerated artifacts. A dispatched run
is not a pull-request event, so it never packages generated updates: drift makes
it fail.

A missing base run no longer needs this. Use it when:

- found base evidence failed to bind, and the head should be qualified from
  source instead of from the base run; or
- a pull-request head needs a complete cold qualification without a new
  commit.

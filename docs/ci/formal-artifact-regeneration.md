# Formal artifact regeneration

## UX

For a same-repository pull request, the ordinary read-only CI job reproduces the
formal qualification output. If generated files drift, CI publishes a bounded
artifact and keeps the stable `formal-translation` check red. A separate trusted
workflow validates that artifact and adds one ordinary bot commit to the PR branch.
The new commit runs the normal read-only checks again and can pass once the tree is
reproducible.

Fork pull requests get the same downloadable artifact and diagnostic summary, but
never receive automatic writeback. A rejected artifact names the violated boundary
(for example, an unexpected path, symlink, deletion, stale SHA, or size limit).

## Architecture

```text
PR code + pinned formal tools (contents: read)
                |
                v
    manifest + hashed regular-file blobs
                |
                v
default-branch updater (contents: write)
  - authorizes open same-repository PR
  - requires unchanged, unprotected head
  - builds validator only from default branch
  - checks provenance, policy hash, paths,
    modes, counts, sizes, and blob hashes
                |
                v
      non-force bot push to PR branch
                |
                v
       ordinary read-only CI verification
```

The write-enabled workflow never runs scripts or binaries from the PR checkout.
It treats both the checkout and downloaded artifact as untrusted data. Its validator
comes from the default branch, and its allowlist comes from
`.github/ci/formal-generated-paths.json` on that same trusted checkout. Changing the
policy in a PR therefore cannot expand the bot's authority.

The updater refuses forks, closed or moved PRs, protected/default branches,
untrusted author associations, duplicate artifacts, unsuccessful
generator jobs, provenance mismatches, traversal, symlinks, executable modes,
renames, deletions, unexpected files, and bounded-count or bounded-size violations.
Runs without an update artifact are clean no-ops.
The final push is never forced, so a concurrent branch update fails closed. A clean
follow-up run publishes no update artifact, which terminates the loop.

The formal job uses the existing pinned Nix/Cachix and Lean caches plus the bounded
Rust compiler cache. Correctness does not depend on a cache: every candidate is
still reproduced and the committed result is checked by the follow-up run.

## APIs

The internal command-line contract is:

```text
auths-ci-plan formal-update-artifact create <provenance flags>
auths-ci-plan formal-update-artifact apply <same provenance flags>
```

`create` emits `update_required` to `GITHUB_OUTPUT` and writes
`target/formal-update/manifest.json` plus content-addressed file blobs. `apply`
requires the exact repository, workflow, run, attempt, base SHA, head SHA, and
trusted-policy digest, then stages only the manifest's validated paths. This is CI
plumbing only; it does not alter the Auths protocol, Lean theorem sources, or public
product APIs.

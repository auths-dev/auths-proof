# Auths 1.0.0-rc.1 candidate-closure record

## Scope

This record closes the repository-local portion of AP32-PR5. The initial
candidate revision completed two isolated preparations successfully in
[run 30849197798](https://github.com/auths-dev/auths-proof/actions/runs/30849197798).
That run exposed no remaining reproducibility defect and supplied the runtime
evidence for the builder assessment. The commit that merges the assessment is
the new proposed candidate revision and must complete the same preparation
again because its release metadata changed.

The change intentionally contains no semantic refactor. It advances release
metadata to the first approved RC coordinate, regenerates the semantic-freeze
inventory, and adds conservative release-candidate notes. Provider and domain
behavior remain unchanged and domain-owned.

## Frozen candidate inputs

- Rust workspace and maintained crates: `1.0.0-rc.1`.
- TypeScript distribution `@auths-dev/sdk`: `1.0.0-rc.1`.
- Python distribution `auths`: `1.0.0rc1`, the PEP 440 spelling equivalent to
  the SemVer RC.
- Candidate tag contract: `auths-v1.0.0-rc.1`.
- Release public-surface semantic identity: version 14.
- Semantic-freeze inventory: version 14.

The release manifest, rather than this prose, owns the eventual full commit and
artifact digests.

## Evidence required after merge

The following are hard gates and are not represented as passed by this PR:

1. every required GitHub check is terminal and successful on the exact merged
   revision;
2. the repository uses immutable GitHub OIDC subjects and a pre-existing,
   branch-protected `release-candidate` environment;
3. two fresh hosted preparation jobs build the exact merged revision;
4. their deterministic subjects match according to the frozen reproducibility
   classes;
5. every manifest subject has verified signed provenance and SPDX coverage;
6. the checked-in SLSA 1.2 Build Level 3 assessment remains valid for the exact
   reusable-builder bytes; and
7. offline verification succeeds from the staged, digest-bound bundle.

If a hosted preparation exposes any defect or drift, this proposed candidate
is rejected. The fix belongs in another bounded candidate-closure PR, and the
two preparations must start again from its new merged revision.

## Explicit exclusions

This repository change does not configure GitHub settings, upload a secret,
run a preparation, approve a manifest, create or move a tag, create a GitHub
prerelease, publish a registry package, engage an external reviewer, or make a
public assurance claim. The SLSA build assessment has passed, but the exact
candidate must be prepared again; owner promotion authorization and the Phase
9 independent security review remain pending. Issue #50 continues to govern
separately authorized publication.

## Rollback and withdrawal

Before tag creation, reject the proposed candidate and revert this
repository-only change or replace it in a new reviewed closure PR. After an RC
tag exists, never move or delete it: mark the candidate withdrawn, correct the
defect at a new commit, increment the RC ordinal, and prepare again.

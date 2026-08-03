# Auths 1.0.0-rc.1 candidate-closure record

## Scope

This record closes the repository-local portion of AP32-PR5. The commit that
merges this bounded change is the proposed candidate revision. It becomes the
final candidate revision only after all required hosted checks and the two
isolated release preparations complete successfully against that exact commit.

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
- Release public-surface semantic identity: version 4.
- Semantic-freeze inventory: version 4.

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
6. an evidence-backed assessment establishes every applicable SLSA 1.2 Build
   Level 3 producer and build-platform requirement; and
7. offline verification succeeds from the staged, digest-bound bundle.

If a hosted preparation exposes any defect or drift, this proposed candidate
is rejected. The fix belongs in another bounded candidate-closure PR, and the
two preparations must start again from its new merged revision.

## Explicit exclusions

This repository change does not configure GitHub settings, upload a secret,
run a preparation, approve a manifest, create or move a tag, create a GitHub
prerelease, publish a registry package, engage an external reviewer, or make a
public assurance claim. The SLSA runtime assessment and independent security
review remain pending. Issue #50 continues to govern separately authorized
publication.

## Rollback and withdrawal

Before tag creation, reject the proposed candidate and revert this
repository-only change or replace it in a new reviewed closure PR. After an RC
tag exists, never move or delete it: mark the candidate withdrawn, correct the
defect at a new commit, increment the RC ordinal, and prepare again.

# Auths release control

This directory defines preparation and promotion controls for an Auths release
candidate. The controls do not authorize a release. Preparation, approval,
tagging, GitHub publication, and registry publication are separate events.

## Preparation

The `Auths release control` workflow accepts a full commit and an exact
`auths-v<version>-rc.<ordinal>` tag. Before invoking a builder it requires:

- the commit to be the current `main` revision;
- a pre-existing `release-candidate` environment restricted by branch policy;
- repository OIDC configuration with immutable subject claims enabled; and
- the immutable repository subject prefix recorded in the owner decisions.

The workflow invokes the same digest-pinned reusable builder twice on separate
GitHub-hosted runners. Each run starts from a clean checkout and empty output
directories, builds the complete subject catalogue, emits SPDX evidence,
creates a Sigstore-backed GitHub provenance attestation, preserves current
trusted roots, and verifies every subject against the reusable workflow and
candidate digest.

Python wheel production derives `SOURCE_DATE_EPOCH` from the exact candidate
commit timestamp. Maintained-bindings CI builds the wheel twice with that epoch
and requires byte-identical SHA-256 digests before performing its install and
test smoke check. The isolated release comparison remains the authoritative
cross-runner check.

The assurance archive contains deterministic formal, fixture, conformance,
architecture, compliance, and benchmark evidence. Its own SPDX entry, signed
provenance, trusted root, final manifest, and comparison report remain detached
beside it. Putting those files inside the archive they digest would create a
self-referential checksum cycle.

`cargo xtask release-control compare` compares the two manifests by their
declared reproducibility classes. A mismatch in a `byte-identical`,
`deterministic-evidence`, or same-platform `platform-reproducible` subject is
terminal. A `provenance-only` subject is never relabeled as reproducible.

The exact official bytes are then stored in a new, non-overwriting Actions
artifact whose name contains the candidate commit and release-manifest digest.
The comparison report travels with those bytes. Actions artifacts are staging,
not long-term public distribution.

## Promotion

Promotion requires a second workflow dispatch naming:

- the original preparation run;
- candidate commit and immutable tag;
- exact release-manifest digest; and
- SHA-256 digest of the repository owner's separate authorization record.

The unprivileged entry job downloads and validates the staged artifact. The
protected `release-promotion` job receives only verified staged bytes. Static
repository policy rejects checkout, compilation, packaging, evidence
generation, or overwriting in that job. It may create the tag only when the tag
is absent, or resume when the existing tag already targets the exact candidate.
It then creates a GitHub prerelease from the staged subjects and evidence.

The first-RC manifest deliberately records the SLSA 1.2 Build Level 3 runtime
assessment as pending. Promotion remains terminally blocked until an
independent assessment of the implemented builder and an actual preparation
run changes that exact manifest field to `passed` through the candidate-closure
process. No label or ordinary successful workflow is treated as that evidence.

Publication to crates.io, npm, and PyPI remains separately gated by
[issue #50](https://github.com/auths-dev/auths-proof/issues/50). This workflow
does not upload registry credentials or publish registry packages.

## Offline verification

The staged evidence preserves the Sigstore bundle and contemporaneous trusted
root. For every subject, consumers can run:

```console
gh attestation verify <subject-path> \
  --repo auths-dev/auths-proof \
  --bundle target/release-evidence/provenance.sigstore.json \
  --custom-trusted-root target/release-evidence/trusted-root.jsonl \
  --signer-workflow auths-dev/auths-proof/.github/workflows/release-builder.yml \
  --signer-digest <candidate-commit> \
  --source-digest <candidate-commit> \
  --deny-self-hosted-runners
```

Then verify `release-manifest.json`, every referenced SHA-256 digest, the
semantic freeze, SPDX subject coverage, and `preparation-comparison.json`.
Verification requires neither repository write access nor an Auths-hosted
service.

## Withdrawal

Never move or delete an issued candidate tag. Mark a defective candidate as
withdrawn, publish bounded guidance, fix it at a new commit, increment the RC
ordinal, and prepare again. Do not overwrite staged or public bytes.

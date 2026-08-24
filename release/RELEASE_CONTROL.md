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

The dispatch also carries the exact canonical authorization record as one-line
base64. The entry gate decodes it, requires the immutable repository-owner
identity, rejects unknown or non-canonical fields, verifies its digest, and
requires every candidate, run, manifest, destination, and statement field to
match the promotion request. The protected job receives and rechecks that
record. Both the authorization and promotion request are preserved with the
GitHub prerelease evidence. The schema is
[`owner-authorization.schema.json`](owner-authorization.schema.json); the
operator procedure is [`RELEASE_RUNBOOK.md`](RELEASE_RUNBOOK.md).

The unprivileged entry job downloads and validates the staged artifact. The
protected `release-promotion` job receives only verified staged bytes. Static
repository policy rejects checkout, compilation, packaging, evidence
generation, or overwriting in that job. It may create the tag only when the tag
is absent, or resume when the existing tag already targets the exact candidate.
It then creates a GitHub prerelease from the staged subjects and evidence. The
prerelease description comes from the digest-bound staged copy of
[`RELEASE_CANDIDATE_NOTES.md`](RELEASE_CANDIDATE_NOTES.md), not mutable or
hardcoded workflow prose.

Before the protected promotion boundary opens, the entry gate runs the strict
Rust-owned qualification release check. It requires the exact five-profile
linux-x86_64 launch set, three distinct family attestations, and exact agreement
among the signed records, qualification index, roster, and launch projection.
An empty or merely well-formed unqualified index cannot authorize promotion.

The SLSA 1.2 Build Level 3 assessment is recorded in
[`SLSA_BUILD_LEVEL_3_ASSESSMENT.md`](SLSA_BUILD_LEVEL_3_ASSESSMENT.md) and its
machine-readable companion. It is bound to an observed successful preparation
and the exact reusable-builder SHA-256. Finalization and offline promotion
verification reject a stale workflow digest, an incomplete requirement set,
or a status other than `passed`. The assessment is not an independent security
audit and does not itself authorize promotion.

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

After promotion, also verify that `promotion-request.json` names the same
manifest, run, tag, and authorization SHA-256, and that the published canonical
`owner-authorization.json` hashes to that value. These two post-preparation
records authorize distribution; they do not retroactively become build inputs.

## Withdrawal

Never move or delete an issued candidate tag. Mark a defective candidate as
withdrawn, publish bounded guidance, fix it at a new commit, increment the RC
ordinal, and prepare again. Do not overwrite staged or public bytes.

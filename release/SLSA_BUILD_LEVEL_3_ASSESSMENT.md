# SLSA 1.2 Build Level 3 assessment

## Result and boundary

The Auths reusable release builder passes the applicable SLSA 1.2 Build Level
3 requirements for the workflow bytes whose SHA-256 is
`e2762ffe4ee2aa2c76c79f7382b2ac4913582a21630907c27fa0a517a1c7c25d`.
The machine-readable authority is
[`slsa-build-level-3-assessment.json`](slsa-build-level-3-assessment.json).

This is a repository-owner-delegated technical assessment of the build
platform and an observed successful execution. It is not the Phase 9
independent security review, and it does not claim that the source, its
dependencies, external providers, or the GitHub control plane are free of
vulnerabilities.

The assessment uses the [SLSA 1.2 requirements](https://slsa.dev/spec/v1.2/requirements)
and [Build track basics](https://slsa.dev/spec/v1.2/build-track-basics).
GitHub documents that artifact attestations provide SLSA Build Level 2 and
that a reusable workflow using attestations can establish the isolation needed
for Build Level 3 in
[Increasing the security rating of your artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/increase-security-rating).

## Assessed runtime

- Preparation run: [30849197798](https://github.com/auths-dev/auths-proof/actions/runs/30849197798)
- Source commit: `a6e7f99a151b641b94837504749404109f7a59e2`
- Proposed tag: `auths-v1.0.0-rc.1`
- Release-manifest SHA-256:
  `2c9f38a7c2190e4d531af6f5bc3bb318bde18a599da459bc25802958eeefdd3a`
- Official build attestation:
  [38657617](https://github.com/auths-dev/auths-proof/attestations/38657617)
- Independent-reproduction attestation:
  [38657752](https://github.com/auths-dev/auths-proof/attestations/38657752)

Both reusable-builder invocations completed on separate GitHub-hosted jobs.
Their provenance verified against the exact repository, reusable workflow,
source commit, and subjects, with self-hosted runners denied. Their
deterministic release subjects matched, and the offline staging verification
completed. GitHub states that standard hosted jobs run on a new virtual
machine and are decommissioned after the job in
[GitHub-hosted runners](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).

## Requirement assessment

| Requirement | Result | Concrete evidence |
| --- | --- | --- |
| L1: consistent build process | Pass | One digest-bound reusable workflow performs both isolated preparations with pinned action revisions and tool versions. |
| L1: provenance exists and identifies the build | Pass | GitHub artifact attestations use SLSA provenance v1 and bind every declared subject, the builder workflow, source repository, and source commit. |
| L1: provenance is distributed | Pass | Both signed attestations are retrievable through GitHub's attestation store, and the complete Sigstore bundle and trust root are included in the staged release evidence. |
| L2: hosted build platform | Pass | Both preparations ran on GitHub-hosted `ubuntu-latest` runners; the verifier rejects self-hosted provenance. |
| L2: platform-generated, signed provenance | Pass | `actions/attest` requests GitHub artifact attestations using job-scoped `attestations: write` and `id-token: write`; no repository signing key is supplied to the build. |
| L2: provenance authenticity is verified | Pass | The builder preserves the trust root and verifies every subject with exact repository, workflow, signer digest, source digest, and the self-hosted denial. |
| L3: build isolation | Pass | The build is encapsulated in a reusable workflow and the two invocations use separately provisioned hosted VMs. Neither preparation consumes output from the other before comparison. |
| L3: provenance signing secret is inaccessible to user build steps | Pass | Signing is performed by GitHub's artifact-attestation service from an ephemeral OIDC identity. The workflow contains no long-lived provenance key or signing secret for build commands to read. |

The L3 conclusion is about the producer and build-platform controls, not the
truth of the program's security properties. SLSA explicitly leaves the build
platform and verification roots within the consumer's trust analysis.

## Staleness and enforcement

The result is valid only for the exact reusable-builder bytes named above and
the documented GitHub-hosted execution boundary. Release finalization reads
the machine-readable assessment, requires every enumerated requirement to be
`passed`, verifies the assessed workflow SHA-256 against the checked-out
workflow, and embeds a digest reference to the assessment in the release
manifest. Offline promotion verification repeats those checks against the
staged files.

Changing the builder workflow therefore makes the assessment stale and blocks
the release. A successful CI label, an edited prose claim, or a manifest field
alone cannot preserve the result.

## Exclusions

This assessment does not:

- authorize tag creation, a GitHub prerelease, or registry publication;
- replace the exact repository-owner promotion authorization;
- claim an independent security audit, certification, compliance, or
  production readiness;
- establish that source code, dependencies, providers, or generated artifacts
  are vulnerability-free; or
- cover compromise of GitHub, Sigstore trust roots, or a consumer's verifier.

The Phase 9 independent review remains a separate post-RC gate.

# Auths release-candidate operator runbook

This runbook is the exact operational sequence for an Auths release candidate.
It does not grant authority to skip a gate. The repository owner must authorize
promotion of one exact prepared manifest; crates.io, npm, and PyPI publication
remain separately authorized operations.

## State sequence

```text
candidate PR merged
        |
        v
required CI passes on exact main commit
        |
        v
prepare twice -> verify provenance -> compare -> stage official bytes
        |
        v
bind, qualify, independently review, and sign exact staged candidate
        |
        v
owner creates exact canonical authorization record
        |
        v
protected promotion verifies staged bytes and authorization
        |
        v
immutable tag + GitHub prerelease
        |
        +----> Phase 8 exact claims -> Phase 9 independent review
        |
        +----> separately authorized registry publication
```

## 1. Establish the candidate

Merge the final bounded candidate-closure PR. Wait for every required check on
the resulting `main` commit to finish successfully. Record:

- the full 40-character `main` commit;
- the exact tag coordinate, such as `auths-v1.0.0-rc.1`; and
- the successful required-check run URLs.

Do not prepare a branch head, local commit, dirty worktree, shortened commit,
or tag that differs from the workspace version.

## 2. Prepare twice

Open **Actions → Auths release control → Run workflow** from `main` and enter:

| Input | Value |
| --- | --- |
| `operation` | `prepare` |
| `candidate_commit` | Exact 40-character `main` commit |
| `candidate_tag` | Exact immutable RC tag |
| promotion-only inputs | Leave empty |

The workflow verifies the protected `release-candidate` environment and
immutable OIDC configuration, then invokes the same reusable builder on two
separately provisioned GitHub-hosted runners. It verifies provenance, compares
the declared reproducibility classes, and stages the official bytes without
overwriting an existing artifact.

The preparation is successful only when every job is terminal and successful.
From the run summary, record:

- the numeric preparation run ID from the run URL;
- the exact candidate commit and tag; and
- the 64-character release-manifest SHA-256.

The staged artifact is named
`auths-staged-<commit>-<manifest-sha256>` and is retained for 90 days. Its
existence is not publication authorization.

## 3. Inspect the prepared evidence

Before authorization, confirm that:

- the official and reproduction builders both succeeded;
- the preparation comparison passed;
- every subject has verified signed provenance and SPDX coverage;
- the manifest names the expected commit, tag, semantic freeze, subjects, and
  SLSA assessment;
- `RELEASE_CANDIDATE_NOTES.md` is digest-bound in the manifest; and
- offline verification succeeds from the staged artifact.

Do not authorize a run with a warning, skipped required job, mismatched digest,
expired artifact, or unresolved question about the exact bytes.

## 4. Create the exact owner authorization

Before creating release authorization, the candidate's assurance manifest must
name the exact prepared image, packages, provenance, configuration, schema, and
semantic freeze. Record all required test evidence, the completed qualification
window, and independent reviews, then sign with a key listed in
`release/assurance/trusted-signers.json`. This command must succeed offline:

```console
cargo xtask assurance verify \
  release/assurance/open-production-candidate-1/manifest.json
```

The verifier rejects a shorter or internally inconsistent window, undisclosed
or overlapping gaps, missing and non-passing evidence, modified reports,
unresolved critical or high findings, untrusted signers, and stale candidate
digests. Do not create owner authorization when it fails.

Create the record only after Step 3 passes. The canonical representation is
UTF-8 compact JSON in the field order below with exactly one trailing newline.
The workflow rejects unknown fields, reordered or pretty-printed bytes, a
different owner, and any mismatch with the staged candidate.

```console
jq -cn \
  --arg issued_at "<UTC-RFC3339-TIMESTAMP>" \
  --arg commit "<CANDIDATE-COMMIT>" \
  --arg tag "<CANDIDATE-TAG>" \
  --arg manifest "<MANIFEST-SHA256>" \
  --arg run "<PREPARATION-RUN-ID>" \
  '{schema:"auths.owner-release-authorization/1",operation:"promote-prepared-candidate",repository:"auths-dev/auths-proof",authorizedBy:"bordumb",authorizedById:"3743841",issuedAt:$issued_at,candidateCommit:$commit,tag:$tag,manifestSha256:$manifest,preparationRunId:$run,destinations:["github-prerelease"],statement:"I authorize promotion of these exact prepared bytes to a GitHub prerelease."}' \
  > owner-authorization.json
```

Inspect the record, then calculate its digest and one-line base64 value:

```console
shasum -a 256 owner-authorization.json
base64 < owner-authorization.json | tr -d '\n'
```

The record is not a secret. It is an auditable authorization artifact. Do not
reuse it for another commit, manifest, run, tag, destination, or RC ordinal.

## 5. Promote the prepared bytes

Run **Auths release control** again from `main` with:

| Input | Value |
| --- | --- |
| `operation` | `promote-github-prerelease` |
| `candidate_commit` | Authorized 40-character commit |
| `candidate_tag` | Authorized RC tag |
| `preparation_run_id` | Numeric ID recorded in Step 2 |
| `manifest_sha256` | Authorized manifest digest |
| `owner_authorization_sha256` | Digest from Step 4 |
| `owner_authorization_base64` | One-line base64 from Step 4 |

Only the immutable repository owner identity may dispatch this operation. The
entry gate decodes and validates the canonical authorization, downloads the
exact staged artifact from the named run, and verifies the complete promotion
request without rebuilding. The protected `release-promotion` environment
then requires its configured approval.

The protected job may create the tag only if it is absent. If the tag already
exists, it must point to the exact authorized commit. The prerelease is created
from staged subjects and evidence, uses the digest-bound candidate notes, and
publishes the owner authorization and promotion request as evidence.

## 6. Verify promotion

After the workflow succeeds:

1. confirm the tag points to the authorized full commit;
2. confirm the GitHub release is marked **prerelease**;
3. confirm its description matches the staged
   `RELEASE_CANDIDATE_NOTES.md`;
4. download the manifest, subjects, evidence, owner authorization, and
   promotion request;
5. verify their SHA-256 relationships and every manifest digest reference;
6. verify every subject's attestation using the command in
   [`RELEASE_CONTROL.md`](RELEASE_CONTROL.md); and
7. record the release URL and verification result for Phase 8.

Do not describe the RC as independently audited, certified, compliant,
production-ready, or stable v1.

## 7. Registry publication and later phases

GitHub prerelease promotion does not publish crates.io, npm, or PyPI packages.
Those uploads remain separately gated by
[issue #50](https://github.com/auths-dev/auths-proof/issues/50), including
registry-specific identity, provenance, package-order, and rollback checks.

After an immutable, verified RC exists, Phase 8 may bind exact public claims to
its subjects. Phase 9 independent review remains required before making any
external-review claim.

## Failure and retry rules

| Failure point | Required response |
| --- | --- |
| Candidate CI, preparation, or assurance fails | Fix through a bounded PR, merge a new commit, and restart candidate qualification whenever executable meaning changed. |
| Builder workflow bytes change | Treat the SLSA assessment as stale; reassess an observed successful run before promotion. |
| Reproduction or digest comparison fails | Reject the candidate; never relabel the differing subject as reproducible. |
| Authorization content or digest fails | Create a new canonical record for the exact unchanged candidate; do not weaken validation. |
| Promotion fails before tag creation | Correct only the external gate or exact input and retry against the same staged bytes. |
| Existing tag points elsewhere | Stop. Never move or delete the tag. Use a new RC ordinal after remediation. |
| Prerelease exists with incomplete assets | Stop and investigate; do not overwrite evidence casually. Resume only when the exact tag and staged bytes remain provable. |
| Defect found after publication | Mark the RC withdrawn, publish bounded guidance, fix at a new commit, increment the RC ordinal, and prepare again. |

Never rebuild during promotion, overwrite a staged artifact, move an issued
tag, reuse an authorization for different bytes, or claim an external gate
passed without retrievable evidence.

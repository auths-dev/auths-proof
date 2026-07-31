# Phase 7 owner decision guide

> **Historical decision aid:** this guide predates the owner's issue 54 naming
> decision. Package and tag alternatives recorded here are not current
> recommendations. `P7-OD-012`, AP-SPEC-034, and
> [`release/public-naming.toml`](../../release/public-naming.toml) govern the
> Auths coordinates.

## Purpose

This guide explains the choices in the
[Phase 7 owner decision register](PHASE_7_RELEASE_OWNER_DECISIONS.md). It does
not make or approve them.

The recommendations optimize for a first independently reviewable RC, not a
general-availability launch. Legal, regulatory, contribution-rights, and
trademark questions require qualified advice where applicable.

## Decision bundles

The 11 decisions fall into four bundles:

| Bundle | Decisions | Why they belong together |
| --- | --- | --- |
| Legal and contribution boundary | `P7-OD-001`, `P7-OD-002`, `P7-OD-011` | Determines distribution rights, inbound rights, vulnerability ownership, and external-release obligations |
| Artifact and distribution boundary | `P7-OD-003`, `P7-OD-004`, `P7-OD-007` | Determines what is built, where it may be published, and how the immutable candidate is named |
| Supply-chain evidence | `P7-OD-005`, `P7-OD-006`, `P7-OD-009` | Determines provenance strength, SBOM representation, signing identity, and consumer verification |
| Human authority | `P7-OD-008`, `P7-OD-010` | Separates build identity from release approval and names the owner of public claim wording |

An owner may decide bundles separately. Implementation still remains blocked
until every decision needed by the affected release surface is approved.

## `P7-OD-001`: release license

### Current fact

All workspace packages currently declare `MIT OR Apache-2.0`, and both license
texts are present.

### Options

1. Keep `MIT OR Apache-2.0` through v1.
2. Move future release artifacts to Apache-2.0 only after rights and
   contribution review.
3. Defer external distribution and prepare a private candidate while counsel
   evaluates a different boundary.

### Recommended default

Keep the existing dual license through v1. It avoids an unnecessary
relicensing event and preserves the repository's current open-source boundary.

### Owner must state

- exact SPDX expression for source and packages;
- whether all approved subjects use the same expression;
- whether any artifact is excluded pending review; and
- who owns future license changes.

## `P7-OD-002`: inbound contribution policy

### Options

- **DCO:** lightweight contributor attestation tied to commits.
- **CLA:** explicit contributor agreement that may cover broader copyright,
  patent, and relicensing terms.
- **No external contributions yet:** keep contribution intake closed until
  counsel and ownership records are ready.

### Tradeoff

A DCO usually has less contributor friction. A CLA can provide a more explicit
rights record but adds legal and operational complexity. The correct choice
depends on the intended commercial and governance model, not release tooling.

### Owner must state

- DCO, CLA, or temporarily closed intake;
- policy text owner and storage location;
- effective date; and
- handling of contributions already present.

## `P7-OD-003`: artifact catalogue

### Current fact

The workspace contains 95 packages. Current metadata treats 60 Rust packages
as publishable and 35 as private. The release checks also build npm, Python,
WASM, formal, compliance, fixture, benchmark, and documentation artifacts, but
they are not yet one approved subject catalogue.

### Options

1. **Complete current publishable set:** treat all 60 Rust crates plus every
   maintained binding and evidence bundle as RC subjects.
2. **Maintained consumer surface:** approve only packages intended for external
   consumption and explicitly mark other packages `publish = false` before the
   candidate.
3. **Evidence-only candidate:** publish source and assurance subjects first,
   while preparing but not distributing package subjects.

### Tradeoff

Publishing every technically publishable crate creates immediate compatibility
and support expectations across a large surface. Selecting only the maintained
consumer surface requires an explicit dependency-closure and exclusion review.

### Owner must state

- every approved subject family;
- every explicit exclusion and reason;
- which subjects are prepared but not published;
- supported platforms for native subjects; and
- which packages carry preview versus release-candidate labeling.

## `P7-OD-004`: registry publication

### Candidate locations

- GitHub prerelease and release attachments;
- crates.io for approved Rust crates;
- npm for `@auths-dev/proof`;
- PyPI for the approved Python package;
- GHCR or another OCI registry for images or assurance bundles; and
- preparation-only content-addressed staging with no public publication.

### Recommended default

Prepare every approved subject, but publish only to registries explicitly named
by the owner. Use prerelease semantics everywhere. A registry not named in the
decision receives no publication credential or workflow permission.

### Owner must state

- registry-by-subject matrix;
- public, private, staged, or not-published state;
- trusted-publishing identity per registry;
- withdrawal behavior; and
- whether the first RC is an external distribution event.

## `P7-OD-005`: supply-chain target

### Options

- signed hosted-build provenance meeting SLSA Build L2;
- a stronger approved target after assessing runner hardening; or
- preparation-only evidence with an explicit limitation and no public RC.

### Recommended target

Target SLSA 1.2 Build Level 3 from the first RC. Level 3 requires a hardened
builder that protects provenance generation and isolates build runs; it is not
achieved merely by adding a signature to an ordinary workflow. Treat failure
to establish the target as an RC blocker rather than silently relabeling Level
2 evidence as sufficient. Provenance identifies how an artifact was built; it
does not claim that the artifact is secure or defect-free.

### Owner must state

- target level and specification version;
- approved hosted builder and workflow identity;
- accepted limitations; and
- consumer verification policy.

## `P7-OD-006`: SBOM baseline

### Current fact

The repository emits and validates CycloneDX 1.5 for Cargo metadata. It does
not yet emit the required SPDX release baseline or cover every possible subject
unambiguously.

### Options

1. SPDX JSON as the normative release SBOM, retaining CycloneDX as additional
   evidence.
2. SPDX JSON only after the owner selects the exact supported SPDX version and
   profile.
3. Defer external distribution until tooling can cover all approved subjects.

### Recommended default

Use SPDX JSON as the normative baseline and retain CycloneDX where it adds
consumer value. Generate evidence inside the release build and bind it to exact
subject digests.

### Owner must state

- exact SPDX version/profile;
- per-subject versus aggregate document model;
- whether CycloneDX is retained; and
- validation and consumer-tool expectations.

## `P7-OD-007`: tag convention

### Existing constraint

The current release check accepts a `v*` tag only when it exactly equals
`v<Cargo workspace version>`. It does not accept the target-state example
`auths-proof-v1.0.0-rc.1` without implementation changes.

### Candidate conventions

- `auths-proof-v1.0.0-rc.1`, which names the product explicitly;
- `v1.0.0-rc.1`, which is conventional and compatible with many registry
  tools; or
- another semver-compatible immutable pattern recorded before tooling changes.

### Owner must state

- exact grammar;
- relationship to workspace and package versions;
- ordinal increment and withdrawal policy; and
- whether one tag covers every subject family.

## `P7-OD-008`: release approvers

### Requirement

At least one named human approver must be distinct from the build identity.
The approval protects promotion of already prepared bytes; it must not trigger
a hidden rebuild.

### Owner must state

- person or repository role allowed to approve;
- minimum approver count;
- protected GitHub environment or equivalent control;
- approval-record retention; and
- emergency withdrawal authority.

## `P7-OD-009`: signing identity

### Options

- GitHub artifact attestations bound to repository, workflow, commit, and
  subject digest;
- an approved Sigstore identity and bundle;
- registry-native trusted-publishing provenance plus an additional release
  attestation; or
- no external publication until an identity is approved.

### Recommended default

Use GitHub-hosted OIDC as the keyless identity for the first GitHub-built RC
and produce Sigstore attestations for exact release-subject digests, provided
the reusable builder and verification policy satisfy the approved
supply-chain target. Preserve the signed attestation bundle and trust material
inside the evidence bundle so consumers can verify offline.

This is release-infrastructure identity, not an Auths identity method. The
protocol, verifier, SDK, runtime, and proof exchange MUST NOT require GitHub,
OIDC, Sigstore services, or network access. Independent reproducible
preparation remains a separate evidence path. A hosted release builder is a
declared trusted component, not centralized plumbing imposed on Auths users.

### Owner must state

- issuer and identity subject;
- allowed workflow and reusable-workflow chain;
- repository and ref restrictions;
- verification command and trust roots; and
- rotation or compromise response.

### Auths is a complementary authorization layer

An Auths proof can authorize the exact promotion action: a named owner permits
one candidate commit and release-manifest digest to be promoted under one tag
to one registry set before an expiry. The resulting receipt can travel with
the release evidence and makes a denial terminal for the same inputs.

That is different from build provenance. Auths answers whether an actor had
authority for the promotion. SLSA and Sigstore provide evidence about which
builder produced which bytes and under which workload identity. SPDX describes
the subject's software components. Reproducibility compares independent
outputs. None should be relabeled as another.

Candidate-built code must not be the first RC's sole judge of its own release
authority. The first candidate may emit an Auths receipt as defense-in-depth.
A later candidate can make it a mandatory gate using a previously reviewed,
digest-pinned Auths verifier or another independently qualified bootstrap.

## `P7-OD-010`: public claim approver

### Requirement

Phase 8 needs a named technical owner who approves exact wording and scope. The
approver cannot turn missing evidence into a stronger claim.

### Owner must state

- named person or repository role;
- approval-record location;
- whether a second formal/security reviewer is required;
- who may suspend a claim after a finding; and
- reapproval conditions after an RC or claim change.

## `P7-OD-011`: vulnerability and CRA ownership

### Required separation

The owner must distinguish:

- security contact and coordinated-disclosure operations;
- release withdrawal authority;
- external distribution scope;
- manufacturer or steward questions for each artifact; and
- counsel's legal conclusions.

### Owner must state

- security contact or role;
- protected report channel;
- disclosure and embargo owner;
- whether the first RC is externally distributed in the EU or elsewhere;
- counsel-reviewed CRA role when applicable; and
- explicit deferral if external distribution is not yet in scope.

This guide does not determine legal scope.

## Fast response template

The owner may answer in one block:

```yaml
phase7_release_decisions:
  P7-OD-001: {status: approved, decision: "...", owner: "..."}
  P7-OD-002: {status: approved, decision: "...", owner: "..."}
  P7-OD-003: {status: approved, decision: "...", owner: "..."}
  P7-OD-004: {status: approved, decision: "...", owner: "..."}
  P7-OD-005: {status: approved, decision: "...", owner: "..."}
  P7-OD-006: {status: approved, decision: "...", owner: "..."}
  P7-OD-007: {status: approved, decision: "...", owner: "..."}
  P7-OD-008: {status: approved, decision: "...", owner: "..."}
  P7-OD-009: {status: approved, decision: "...", owner: "..."}
  P7-OD-010: {status: approved, decision: "...", owner: "..."}
  P7-OD-011: {status: approved, decision: "...", owner: "..."}
```

Conditions and evidence references may be added per decision. Missing entries
remain unresolved and continue to block their affected release surfaces.

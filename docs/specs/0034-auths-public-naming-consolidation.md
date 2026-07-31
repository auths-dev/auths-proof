# AP-SPEC-034: Auths public naming consolidation

**Status:** Specified — the owner-approved target map in issue 54 blocks all
remaining AP-SPEC-032 artifact and metadata freeze work until the repository,
registry, predecessor, and external-content gates below are satisfied

**Governs:** The naming prerequisite inserted before the remaining Phase 7
release-candidate work in AP-SPEC-032

**Authority:** [Issue 54](https://github.com/auths-dev/auths-proof/issues/54)
and the checked-in
[`release/public-naming.toml`](../../release/public-naming.toml) inventory

**Depends on:** The merged AP-SPEC-032 semantic-freeze implementation, the
Phase 7 owner decision register, registry custody evidence, and the current
prelaunch workspace

**Scope:** One coherent Auths product identity across public packages,
documentation, examples, workflows, release artifacts, provenance, generated
documentation, deployment references, and predecessor-project disposition

**Normative language:** **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are
requirements on conforming repository and release work.

## 1. Decision

The public project and product are **Auths**. “Proof” names the bounded proof
protocol and related implementation components where that is technically
accurate; it is not the umbrella product name.

The first-RC public coordinates are:

| Surface | Coordinate |
| --- | --- |
| Product | **Auths** |
| Website | `https://auths.dev` |
| Rust core facade | `auths` |
| Rust SDK | `auths-sdk` |
| JavaScript/TypeScript SDK | `@auths-dev/sdk` |
| Python distribution and import root | `auths` |
| Proof-protocol component | `auths-proof` |
| First RC tag | `auths-v1.0.0-rc.1` |

The current `auths-dev/auths-proof` repository coordinate MAY remain until a
separate repository-rename migration is approved. A literal repository name
inside a GitHub attestation subject is identity evidence, not permission to
present “Auths Proof” as the product.

This decision supersedes the public-coordinate portions of `P7-OD-003` and all
of `P7-OD-007`. It does not change the lean SDK-first catalogue, the
prepare-before-publish decision, or any publication authorization boundary.

## 2. Why this blocks release evidence

AP-SPEC-032 binds package names, subjects, artifact filenames, tags,
attestations, SBOM relationships, checksums, and documentation to one release
manifest. Freezing those fields under the abandoned coordinates would turn a
prelaunch correction into a compatibility migration across every registry and
assurance artifact.

Therefore:

```text
merged semantic freeze
        |
        v
AP-SPEC-034 naming inventory and custody evidence
        |
        v
Rust facade + SDK coordinates
        |
        v
npm/Python/docs + predecessor notice
        |
        v
release identity + stale-name enforcement
        |
        v
resume AP-SPEC-032 release-evidence work
```

No remaining release manifest, SBOM, provenance subject set, source archive,
assurance bundle, prepare/promote workflow, or exact public claim may be
frozen before the AP-SPEC-034 exit gate passes.

## 3. Authoritative inventory

`release/public-naming.toml` is the sole machine-readable authority for:

- current and target public names;
- compatibility consequences and bounded owner PRs;
- the exact first-RC package publication tiers;
- every crates.io package published from the predecessor project;
- current registry owner, version, download, and reverse-dependency evidence;
- Continue, Retire, or Replace disposition;
- deletion eligibility; and
- destructive-action authorization state.

Human-readable plans and generated reports MUST agree with that file. They
MUST NOT become competing naming sources. A change to a target public
coordinate, predecessor disposition, or publication tier requires:

1. a focused inventory change;
2. an explicit compatibility explanation;
3. registry evidence refreshed on the change date;
4. repository-owner approval; and
5. release and stale-name checks updated in the same PR or an earlier blocking
   PR.

Registry download totals are weak operational evidence. They include
automation and dependent-package resolution and MUST NOT be represented as
independent users. crates.io reverse-dependency results cover published
registry relationships only; absence there does not prove the absence of Git,
path, vendored, or copied use.

## 4. Rust package architecture

### 4.1 `auths`

The `auths` crate is the supported consumer-facing core facade. The first
implementation SHOULD remain thin: it re-exports the stable embedded proof
verification surface from `auths-proof` without moving provider, profile,
custody, transport, or stateful runtime behavior into core.

This preserves two different statements:

- users install and import **Auths** through `auths`; and
- the bounded proof-protocol implementation remains `auths-proof`.

The facade MUST NOT become a generic executor or a dumping ground for every
workspace crate merely to justify the product name.

### 4.2 `auths-sdk`

The product SDK package is `auths-sdk`. The temporary local package name
`auths-proof-sdk`, introduced before issue 54, has never been published by this
implementation and receives no compatibility shim.

The predecessor published `auths-sdk` `0.1.x`. Reuse of that owned coordinate
is an intentional major-version transition. Package documentation MUST state
that the new SDK is a semantic and architectural replacement and MUST NOT
imply source compatibility with the experimental `0.1.x` line.

### 4.3 Supporting closure

The public roots are `auths` and `auths-sdk`. Their crates.io normal-dependency
closure is supporting implementation surface, not a promise that every crate
is a separate product.

The publication tiers in `release/public-naming.toml` are normative. Packages
within one tier MAY be packaged in parallel; tier `N+1` MUST NOT be published
or dry-run resolved against a registry until all of its tier-`N` dependencies
are available in the isolated staging model. CI MUST derive the dependency
graph from manifests and reject an inventory tier that violates an edge.

Adding `auths` changes the previously frozen 27-crate closure to an expected
28-crate closure. Any further expansion blocks the candidate pending focused
review.

## 5. Language SDKs

### 5.1 npm

The public package is `@auths-dev/sdk`. The internal Rust/WASM build package
MAY remain `auths-proof-wasm` because it implements the proof boundary. Public
imports, package metadata, README examples, tarball names, provenance
subjects, SBOM package identities, and clean-consumer tests MUST use
`@auths-dev/sdk`.

The npm registry currently contains predecessor version `0.1.16` at the target
coordinate. No new version may be published without the separate exact-
manifest authorization required by `P7-OD-004`.

### 5.2 Python

The public distribution and import root are both `auths`. The internal native
binding crate MAY remain `auths-proof-python` where it accurately describes
the proof binding.

The PyPI registry currently contains predecessor version `0.1.16` at the
target coordinate. The new package MUST document the major transition and
MUST pass isolated wheel installation and import tests in hosted CI before
publication is considered. No publication is authorized here.

## 6. Predecessor registry policy

Every predecessor crate has at least one published version. Cargo's official
publishing contract treats publication as permanent: published code cannot be
deleted or overwritten, and yanking does not delete the bytes or free the
name. Consequently, no predecessor crate is eligible for **Delete and
reclaim**.

The dispositions mean:

- **Continue:** the public responsibility remains recognizable. The current
  implementation may use the owned coordinate only through an explicit major
  transition and separately authorized publication.
- **Retire:** no first-RC package adopts the coordinate. Ownership is retained
  and the predecessor package is marked superseded through a future
  non-destructive metadata release only if separately authorized.
- **Replace:** the predecessor boundary encoded an architecture the current
  project rejected. The inventory names its narrower replacement coordinates;
  no compatibility package is implied.
- **Delete and reclaim:** prohibited for this inventory.

No issue, spec, or documentation PR authorizes a yank, owner change, package
upload, or deprecation release.

## 7. Documentation, URLs, and deployments

User-facing current documentation MUST call the project Auths and SHOULD link
to `auths.dev` and `docs.auths.dev`. It MAY say “Auths proof,” “Auths proof
protocol,” or use an `auths-proof*` package name when the sentence points to
the bounded proof mechanism.

Historical plans and ADRs MAY retain “Auths Proof” when rewriting would falsify
the record. Each retained historical document MUST carry a visible historical
or supersession note and be listed in the stale-name check allowlist with a
reason. An unbounded directory exclusion is forbidden.

Existing Fly, Vercel, and GHCR demo names beginning with `auths-` already
conform. The `auths-proof-site.vercel.app` and
`auths-proof-docs.vercel.app` preview aliases MAY remain as infrastructure
coordinates, but current user-facing links must use the canonical Auths URLs
once the destinations are verified. This spec authorizes no deployment rename
or DNS change.

Generated Rust documentation must lead consumers to `docs.rs/auths` and
`docs.rs/auths-sdk`; proof-component API references may use
`docs.rs/auths-proof`.

## 8. Release identity and provenance

The first RC identity is `auths-v1.0.0-rc.1`. All release parsers,
documentation, artifact catalogues, source archives, assurance bundles,
checksums, SBOM names, attestation subject paths, and claim registries MUST use
the same `auths` product/version identity.

The immutable GitHub repository subject remains:

```text
repo:auths-dev@260513770/auths-proof@1310728509:environment:release-candidate
```

while the repository retains its current name and ID. Validators MUST compare
that value literally. They MUST also distinguish it from public artifact
names, which use `auths-*`.

No RC tag may be created by any AP-SPEC-034 PR. AP-SPEC-032 promotion remains a
separate owner-authorized event for one exact manifest digest.

## 9. Stale-name enforcement

Hosted CI MUST add one authoritative check that:

- loads `release/public-naming.toml`;
- validates unique surface and predecessor-package entries;
- validates the complete predecessor inventory and non-destructive policy;
- derives Rust dependency edges and rejects invalid publication tiers;
- rejects `auths-proof-sdk`, `@auths-dev/proof`, `pypi:auths-proof`, and
  `auths-proof-v` outside explicitly identified historical records;
- rejects “Auths Proof” as a current product heading or package-installation
  instruction;
- permits `auths-proof` only for inventory-declared bounded components,
  temporary repository/provenance coordinates, and exact historical records;
- verifies package metadata, release workflow names, and the semantic-freeze
  public surface against the inventory; and
- fails on an allowlist entry whose path or reason is absent.

The check MUST include negative fixtures proving that each stale public name
fails. A grep-only check without semantic exceptions is insufficient because
`auths-proof` remains a valid component name.

## 10. Predecessor repository

Before archival, `auths-dev/auths` MUST receive a concise, prominent notice
that truthfully says:

- it was an experimental predecessor and was not released as the supported
  Auths v1 product;
- experimental `0.1.x` packages were published from it;
- the current Auths implementation supersedes it;
- it remains available as research history and prior art; and
- new adopters should use `auths.dev` and the current repository.

The notice MUST NOT call the repository wholly “unpublished,” because the
registry inventory proves that packages were published.

Before the notice PR declares the codebase ready to archive, the Secure
Enclave bridge, custody/keychain concepts, storage work, and signing workflow
must each point to either:

- a migrated current implementation or specification; or
- an explicit deferral issue with scope, rationale, and future trigger.

Merging the notice does not authorize GitHub archival, repository renaming,
package yanking, or owner changes.

## 11. Bounded PR units

AP-SPEC-034 is implemented through these independently reviewable units:

1. **`AP34-PR1` — naming authority and governing amendments.** Add this spec,
   the authoritative inventory, registry evidence, predecessor dispositions,
   publication tiers, and AP-SPEC-032/033 owner-decision amendments. No package
   or workflow behavior changes.
2. **`AP34-PR2` — Rust facade and SDK coordinates.** Add the thin `auths`
   facade; restore `auths-sdk`; update Cargo manifests, lockfile, Rust imports,
   package metadata, architecture inventories, and clean-consumer examples.
3. **`AP34-PR3` — npm, Python, and current documentation.** Rename public
   language packages and imports, update current READMEs/examples/generated-doc
   inputs, and retain proof-specific internal build names.
4. **`AP34-PR4` — release identity and enforcement.** Update semantic-freeze
   release metadata, tag parser, artifact names, package catalogue,
   provenance/SBOM subjects, publication-order validation, and adversarial
   stale-name CI.
5. **`AP34-PR5` — predecessor notice and archival-readiness ledger.** In the
   predecessor repository, add the accurate notice and migrated/deferred
   ledger. Do not archive or rename it.
6. **`AP34-PR6` — external Auths content alignment.** In the repository that
   owns `auths.dev`, replace predecessor-era package/repository instructions
   with the current inventory. Do not change DNS or deploy without separate
   authorization.

Every PR must identify tests/evidence, affected release claims, exclusions,
and remaining gates. Documentation-only PRs do not establish code or external
gate completion.

## 12. Entry and exit gates

### Entry gate

Implementation begins only when:

- issue 54 is open and its target map has not been superseded;
- the release-evidence draft is not merged or frozen under old names;
- registry queries show the target coordinates remain under intended custody;
- no publication, tag, deletion, yank, rename, archive, deployment, or DNS
  action is bundled into the migration; and
- the repository owner has approved the target map.

### Exit gate

AP-SPEC-034 is complete only when:

- `release/public-naming.toml` validates and covers every listed public
  surface;
- current product documentation consistently presents Auths;
- Rust, npm, and Python package metadata use `auths-sdk`, `@auths-dev/sdk`, and
  `auths` respectively;
- `auths` is the supported Rust core facade and `auths-proof` is confined to
  accurate proof-component or temporary repository contexts;
- all predecessor crates have current registry evidence and a disposition;
- the 28-crate publication order is derived and verified in hosted CI;
- the old repository notice and migration/deferral ledger are merged;
- `auths.dev` current content no longer directs new users to the predecessor
  package line as the supported implementation;
- release specifications, semantic freeze, artifacts, and tag checks agree on
  `auths-v1.0.0-rc.1`;
- stale-name adversarial checks pass in hosted CI; and
- package builds, examples, documentation links, and release dry runs pass in
  hosted CI.

Only then may the stashed AP-SPEC-032 release-evidence work be reconciled to
the new inventory and resumed. Passing this gate still does not authorize
publication, tag creation, external review, repository archival, repository
renaming, deployment, or DNS changes.

## 13. Explicit exclusions

This specification does not authorize:

- deleting or yanking a registry package or version;
- publishing any crate, npm package, wheel, deprecation release, or metadata
  release;
- changing package ownership;
- creating or promoting any RC tag;
- renaming or archiving either GitHub repository;
- deploying a website or changing DNS;
- engaging reviewers or design partners;
- accepting compatibility or security risk; or
- claiming AP-SPEC-032, Phase 7, or any external gate has passed.

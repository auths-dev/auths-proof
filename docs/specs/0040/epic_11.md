# Epic 11 — Enforce Cross-Repository Qualification and Release

**Parent:** [AP-SPEC-040](../0040-stripe-quality-documentation-platform.md)

**Repositories:** `auths-proof` and `auths-proof-docs`

**Depends on:** Epics 1–10

**Blocks:** Public documentation launch

## Outcome

Make documentation consistency a required property of the product change that
causes it. Public API, endpoint, profile, error, limit, fixture, evidence, or
source-documentation changes must automatically build the correct docs preview
from an immutable artifact and fail before merge when coverage drifts.

Then qualify and deploy one exact pair of product and docs revisions with an
immutable rollback bundle.

## Zero-context starting point

Read:

- the parent specification and all prior epics;
- `.github/workflows/` in both repositories;
- `xtask/ci-plan/`, `xtask/src/evolution_policy.rs`, `release.rs`,
  `release_control.rs`, and `docs_contract.rs`;
- `release/release-subjects.toml` and release builder/promotion workflows;
- the docs repository build, test, and deployment scripts;
- GitHub required-check configuration documentation; and
- the intended Vercel/Cloudflare/object-storage deployment configuration.

Do not reuse stale workflow runs or mutable branch artifacts. The repository
has already experienced stale-head and late semantic-drift failures; docs CI
must identify the current head and run early classification.

## Pull-request architecture

```text
auths-proof PR @ head SHA
      |
      v
build affected installed artifacts
      |
      v
docs contract fingerprint vs base
      |
      +-- unchanged --> record explicit no-change result
      |
      +-- changed ----> build immutable PR docs bundle
                             |
                             v
                 invoke docs workflow by pinned SHA
                             |
                   isolated auths-proof-docs checkout
                             |
        contract + examples + reference + content + browser tests
                             |
                             v
                 immutable preview + result attestation
                             |
                             v
          required check on the same auths-proof head SHA
```

The invocation passes bundle digest, artifact locator, source head/base SHAs,
docs workflow SHA, and expiration. It never passes a sibling path, mutable
branch as artifact identity, or unchecked URL.

## Change classification

Run the contract fingerprint and semantic diff immediately after the smallest
required public artifacts build. Automatically require docs qualification when
any of these change:

- public Rust item/signature/docs;
- npm export/signature/TSDoc/package subpath;
- Python export/signature/docstring/module;
- operation/projection/page/scenario identity;
- runtime route, wire content, trust boundary, or limit;
- profile, stable error, lifecycle state, configuration, receipt, or evidence;
- executable fixture or normalized outcome;
- supported runtime/package/version policy; or
- public source provenance.

There is no `docs-not-required` label. A code-path heuristic may skip expensive
artifact builds only when the contract classifier proves the public fingerprint
cannot change.

## Docs workflow gates

For a changed bundle, require:

- bundle signature/checksum, provenance, schema, and source-head validation;
- exact locked toolchain and dependency installation;
- MDX/frontmatter/component policy;
- stable identity and projection completeness;
- installed-artifact/source-doc completeness;
- route/profile/error/limit/evidence completeness;
- executable Rust/TypeScript/Python scenario qualification;
- normalized semantic parity;
- reference and affected-page dependency generation;
- HTML/Markdown/search/manifest parity;
- internal, anchor, source, and stable-identity links;
- secret/sensitive-content scanning;
- HTML validation, browser behavior, and responsive layout;
- WCAG 2.2 AA automated checks and keyboard/no-JavaScript flows;
- deterministic critical-template screenshots;
- maintained desktop, tablet, narrow-mobile, and 200-percent-zoom screenshots
  for home, guide, SDK reference, and runtime API reference templates;
- two-row header/search alignment, expanded/collapsed contextual navigation,
  sticky-offset/anchor behavior, and dead-gutter checks;
- page-wide Rust/TypeScript/Python switching, Bash grammar override, JSON
  result grammar, and page/section Markdown action checks;
- Lighthouse accessibility at least 95 and performance at least 90 under the
  maintained profile;
- static production deployment smoke; and
- a bounded result attestation tied to both repository SHAs and bundle digest.

External network links run nightly; canonical internal and pinned source links
remain PR gates.

## Human review routing

The contract diff separates:

1. **Automatically regenerated facts** — signatures, parameters, routes,
   errors, versions, profiles, limits, and manifests.
2. **Broken executable coverage** — must be fixed in the originating PR.
3. **Affected authored pages** — determined by declared semantic dependencies.
4. **Security-sensitive review** — trust, custody, receipts, disclosure,
   provider-unknown, retry, and assurance changes require named owners.

An affected page may be acknowledged as still correct only by an owner review
record tied to the exact contract diff. CI cannot auto-rewrite explanatory or
security prose.

## Release architecture

```text
qualified product release candidate + docs bundle
                  |
                  v
automation opens/updates docs release PR pinned by digest
                  |
                  v
full docs qualification + preview + usability sign-off
                  |
         +--------+--------+
         v                 v
package promotion     immutable docs bundle
         |                 |
         +--------+--------+
                  v
          docs.auths.dev stable
```

The deployment manifest records:

- product release and commit;
- docs commit;
- docs-contract and bundle versions/digests;
- Rust/npm/Python package coordinates and digests;
- reference runtime image digest;
- build workflow identity;
- static output digest;
- deploy target and time; and
- prior deploy digest for rollback.

Stable deployment must not precede package promotion to unavailable
coordinates. Package promotion must not advertise docs qualification that did
not pass for the same candidate. Use a staged release with one final promotion
decision rather than mutable post-release patching.

## Deployment and rollback

- Deploy only immutable static files.
- Use atomic alias/pointer promotion after smoke tests.
- Retain at least the supported-version bundles and the immediately prior
  stable deployment.
- Rollback changes the serving pointer to an already-qualified bundle; it does
  not rebuild old source.
- Preview URLs are unguessable or access-controlled before public release and
  expire automatically.
- The site has no production database, credentials, or dependency on GitHub
  availability after deployment.

## Implementation steps

- [ ] Add the early contract fingerprint and automatic change classifier to
  `auths-proof` CI planning.
- [ ] Build and upload the immutable current-head PR docs bundle.
- [ ] Add a reusable, pinned `auths-proof-docs` qualification workflow.
- [ ] Validate head SHA before starting expensive work and again before
  returning status.
- [ ] Publish a static preview and bounded change report.
- [ ] Add deterministic visual/interaction fixtures for the global shell,
  navigation states, SDK/runtime reference layouts, and shared code components.
- [ ] Return one required check associated with the exact source head.
- [ ] Configure human review routing from semantic dependencies and code
  ownership.
- [ ] Add nightly full-version, external-link, dependency, and example checks.
- [ ] Integrate docs qualification into release subjects and promotion.
- [ ] Build immutable deployment manifest, atomic promotion, and rollback.
- [ ] Run the Epic 6 unfamiliar-developer study against production-equivalent
  preview.
- [ ] Exercise rollback and prove old pages, Markdown, search, and manifests
  remain internally consistent.

## Failure and adversarial tests

Test:

- stale candidate head before and after the docs build;
- a superseded workflow trying to set current-head success;
- changed public signature classified as internal;
- a label attempting to suppress required docs;
- artifact digest or source commit mismatch;
- mutable branch artifact substituted after invocation;
- docs workflow reference changed without review;
- package coordinate unavailable at preview or promotion;
- reference page generated from one release and example from another;
- an SDK reference preview labelled as a generic API reference;
- a header-height change leaving stale sidebar, code-rail, outline, or anchor
  offsets;
- one language panel, Bash command, result block, or section Markdown action
  disagreeing with the current verified page model;
- an icon-library root import passing despite breaching the client budget;
- a security-sensitive page auto-acknowledged without owner review;
- preview secret leakage or non-expiring preview;
- partial deploy and CDN cache inconsistency;
- GitHub outage after static deployment;
- rollback to an incomplete or mismatched bundle;
- flaky test quarantine without owner/issue/expiry; and
- current-head CI green while any required job remains queued or running.

## Validation commands

In `auths-proof`:

```text
cargo xtask docs-contract
cargo xtask docs-bundle <artifact-dir>
cargo xtask ci
```

In `auths-proof-docs`:

```text
pnpm install --frozen-lockfile
pnpm qualify --bundle <immutable-bundle>
pnpm build
pnpm deploy:smoke
pnpm deploy:rollback-test
```

Exercise the cross-repository workflow from a real pull request before making
the check required.

## Exit gate

This epic is complete when a public product change cannot merge without a
current-head, digest-pinned docs preview; generated facts update automatically;
affected prose receives deliberate review; every launch gate and usability
target passes; `docs.auths.dev` serves one exact qualified release across HTML,
Markdown, search, examples, and reference; and rollback restores a previously
qualified immutable bundle without rebuilding it.

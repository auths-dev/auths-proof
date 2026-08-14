# Epic 8 — Generate the Deep Reference from Stable Identities

**Parent:** [AP-SPEC-040](../0040-stripe-quality-documentation-platform.md)

**Repository:** `auths-proof-docs`

**Depends on:** Epics 4, 5, and 7

**Blocks:** Epics 9–11

## Outcome

Generate concept-oriented operation pages and exact Rust, TypeScript, Python,
runtime API, profile, error, configuration, limits, lifecycle, receipt,
protocol, and assurance reference from the verified release bundle.

No generated reference page is hand-edited or committed. A changed function
argument or new endpoint updates the proper page through stable identities and
fails the originating change if required coverage is missing.

## Zero-context starting point

Read:

- parent sections 8, 9, 13–15, and 19–20;
- Epics 1–5 and 7;
- the release bundle schemas and one verified bundle;
- the Auths page frontmatter and page-graph schemas;
- generated-reference template tests from Epic 5; and
- installed surface models from Epic 4.

Do not infer joins from similarly named functions. Inspect the operation and
projection identities first.

## Reference hierarchy

Generate:

```text
/reference/
├── operations/<operation-slug>
├── sdk/
│   ├── rust/<symbol>
│   ├── typescript/<symbol>
│   └── python/<symbol>
├── runtime-api/<endpoint>
├── profiles/<profile>
├── errors/<stable-code>
├── configuration/<section>
├── limits
├── lifecycle
├── receipts
├── protocol/
└── assurance/
```

The operation page is the primary cross-language reference. Language-specific
symbol URLs exist for search, direct linking, and language detail but point
back to the same operation meaning.

Surface kind is closed and visible. `sdk-operation` pages describe installed
Rust, TypeScript, or Python symbols; `runtime-api-operation` pages describe
HTTP method/path and wire behavior. Generated titles, breadcrumbs, navigation,
search records, Markdown metadata, canonical URLs, and install panels derive
from that kind. An SDK page cannot inherit the generic label “API reference,”
and a runtime API page cannot present an SDK function signature as its primary
contract.

## Page model

Parse release facts into a closed model equivalent to:

```ts
interface ReferencePageModel {
  pageId: PageId;
  operation?: OperationId;
  release: ReleaseIdentity;
  title: string;
  summary: SourceOwnedDocumentation;
  projections: readonly SdkSymbolProjection[];
  endpoints: readonly EndpointProjection[];
  profiles: readonly ProfileProjection[];
  outcomes: readonly OutcomeProjection[];
  errors: readonly ErrorProjection[];
  scenarios: readonly ScenarioProjection[];
  trust: readonly TrustBoundaryFact[];
  provenance: readonly ProvenanceLink[];
  authoredLinks: readonly PageId[];
}
```

All fields are bounded and schema-parsed. Rendering templates accept only the
verified model, never raw contract JSON.

## Operation page UX

```text
Create authority                                      Stable · 1.0
Create exact, bounded authority for one actor and action.

[Rust] [TypeScript] [Python]
+---------------------------------------------------------------+
| createAuthority(input: CreateAuthorityInput): AuthorityResult |
+---------------------------------------------------------------+

Parameters                 Outcomes                 Related
actor ...                  completed ...            REST guide
action ...                 denied ...               Delegation

Security boundary
Untrusted action bytes are parsed and committed before authority exists.

Examples · Errors · Runtime endpoint · Source at release
```

Parameter/member sections come from the installed declaration model. Product
meaning and trust facts come from source docs and Rust-owned facts. Templates
must make provenance visible without overwhelming the default view.

The desktop template uses left contextual navigation, middle semantic content,
and a right language-aware code rail. The middle and right regions share the
same background plane with no heavy vertical divider. Each source or
source-plus-result unit is bounded by the shared dark code component. The rail
may remain sticky within the active semantic section, but its offset consumes
the global header-height token. Section-level Copy/View Markdown actions render
beside the section heading and resolve only that section's verified projection.

## Automatic change mapping

### Changed SDK argument

1. Epic 4 extracts the new installed signature under the same operation ID.
2. The signature fingerprint changes.
3. The operation page model receives the new parameter automatically.
4. Epic 7 examples compile and identify broken call sites.
5. The page dependency graph lists authored pages using that operation.
6. The preview shows generated reference changes and required prose reviews.
7. Merge fails on an unmapped parameter, broken example, missing source docs,
   incompatible version classification, or unresolved page review.

There is no parameter table to update in MDX.

### New runtime endpoint

1. Epic 3 requires a route descriptor at registration.
2. The descriptor enters the release bundle with operation/page identities.
3. The endpoint template creates HTML, Markdown, navigation, search, and
   manifest entries.
4. An effectful endpoint without outcome/error/trust/limit/scenario coverage
   fails the bundle and never reaches deployment.

### Renamed or removed surface

Stale projections, scenario calls, `ReferenceLink` components, frontmatter
dependencies, and search aliases fail. Before public launch, cut over directly
without compatibility aliases. After 1.0, the older release contract continues
to render under its versioned path.

## Search and linking

Build one stable resolver:

```ts
resolvePage(pageId, release): CanonicalUrl
resolveOperation(operationId, release, language?): CanonicalUrl
resolveSymbol(language, packageName, symbol, release): CanonicalUrl
resolveError(code, release): CanonicalUrl
```

Authored MDX uses `ReferenceLink`, `ReferenceSignature`, and semantic
frontmatter dependencies. It cannot hardcode generated reference paths.

Search records include title, operation identity, SDK spellings, endpoint,
profile, error codes, product synonyms, language, release, availability, and
bounded excerpt. Do not index private types, internal source names, draft
pages, or unsupported claims.

## Template implementation

Create shared templates for:

- operation and SDK symbol pages;
- runtime endpoints;
- profiles and exact effects;
- stable errors and recommended action;
- configuration and limits;
- lifecycle states and transitions;
- receipts and disclosure;
- protocol/wire subjects; and
- assurance claims, evidence, and limitations.

Templates render HTML and canonical Markdown from the same model. Do not emit
MDX files and then parse them back.

## Implementation steps

- [ ] Implement strict bundle-to-page-model parsing.
- [ ] Build the stable page and operation resolvers.
- [ ] Join language projections, endpoints, profiles, errors, scenarios, and
  evidence by semantic identity.
- [ ] Implement each reference template and Markdown projection.
- [ ] Implement distinct SDK/runtime-API surface templates and reject generic
  or conflicting reference labels.
- [ ] Build the three-column reference shell, sticky code rail, global language
  synchronization, and section-scoped actions over the verified page model.
- [ ] Generate navigation, search records, sitemap members, and reference
  manifest from the page graph.
- [ ] Add authored-guide backlinks from declared semantic dependencies.
- [ ] Add contract-diff output grouped into automatic fact changes, broken
  coverage, and human review required.
- [ ] Add source-at-release links from provenance.
- [ ] Bound reference page size and split oversized type/member trees without
  changing identity.
- [ ] Verify a fresh build leaves the Git worktree clean.

## Adversarial tests

Reject:

- a join by display name, slug, or function spelling;
- missing, duplicate, or conflicting operation projections;
- an undocumented argument or field in a P0/P1 symbol;
- a reference template inventing a default, limit, error, or security claim;
- an endpoint missing from navigation or Markdown;
- an unsupported language displayed as supported;
- an SDK operation labelled as a runtime API or a runtime endpoint labelled as
  an SDK/API client function;
- a sticky code rail using a copied numeric header offset;
- a page-wide language change leaving one code/result panel stale;
- a section Markdown action including a neighboring operation or code step;
- a stale `ReferenceLink` or semantic dependency;
- a source link to a mutable branch;
- private/internal symbols in search;
- unsafe full receipt material in a default reference example;
- an assurance claim without evidence and limitations;
- a page whose HTML and Markdown represent different outcomes; and
- generated output becoming a checked-in or extractor input.

Golden tests must cover one operation with all languages, one language-specific
operation, one endpoint, one profile, one error, one unsupported projection,
and one versioned removal.

## Validation commands

```text
pnpm reference:build --bundle <verified-bundle>
pnpm reference:check
pnpm test:contract
pnpm test:reference
pnpm test:search
pnpm test:markdown
pnpm build
git diff --exit-code
```

## Exit gate

This epic is complete when every supported public operation, symbol, endpoint,
profile, error, limit, lifecycle state, receipt form, protocol subject, and
assurance claim is discoverable through one exact release; unsupported states
and SDK/runtime-API surface kinds are explicit; the qualified reference shell,
code rail, and section actions consume the same verified page model;
HTML/Markdown/search agree; and an SDK argument or endpoint change reaches the
correct page without human routing or copied reference content.

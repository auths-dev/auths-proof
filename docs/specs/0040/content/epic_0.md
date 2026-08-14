# Content Epic 0 — Establish Platform and Editorial Ownership

**Status:** Complete in `auths-docs` commit `4576625`.

**Parent:** [AP-SPEC-040](../../0040-stripe-quality-documentation-platform.md)

**Repositories:** `auths-proof` and `auths-docs`

**Depends on:** AP-SPEC-040 Platform Epics 1 and 5 contracts; implementation
may begin against their checked fixture schemas.

**Blocks:** Content Epics 1–9 and public content implementation in Platform
Epics 6, 9, 10, and 11.

## Outcome

Establish one enforceable boundary between generated product truth, tested
examples, and human-authored teaching before either workflow creates public
pages. Both lanes compile into one verified page graph and cannot silently
create competing signatures, endpoints, code samples, navigation, Markdown,
or assurance inventories.

## Current problem

AP-SPEC-040 originally combined documentation plumbing with representative
public content. The later content program added detailed editorial epics. That
created overlapping claims of ownership:

- Platform Epic 6 and Content Epics 1–4 both described the product journey;
- Platform Epic 9 and Content Epics 6, 8, and 9 both described deep content;
- Platform Epics 10–11 and Content Epic 9 both described machine surfaces and
  qualification; and
- route inventories could be interpreted as either generated structure or
  manually authored navigation.

Without an explicit compiler boundary, a product change could require edits in
source docs, generated reference templates, MDX prose, code fences, navigation,
Markdown renderers, and search metadata independently.

## Three provenance classes

Every public semantic block has exactly one provenance class:

| Class | Owner | Examples | Editorial treatment |
|---|---|---|---|
| Generated fact | `auths-proof` release bundle | Signatures, routes, fields, errors, limits, profiles, versions, evidence status | Reference by stable identity |
| Tested scenario | Qualified scenario artifact | Rust, TypeScript, Python source, commands, normalized results, failure fixtures | Select scenario and display step |
| Editorial narrative | `auths-docs` MDX | Explanation, recommendation, conceptual diagram, transition, landing-card order | Author and review directly |

If released behavior can make prose false, convert the disputed value into a
generated fact or scenario projection. Editorial prose may explain what a fact
means but cannot restate mutable values as its own source of truth.

## Ownership matrix

| Concern | Platform lane | Editorial lane |
|---|---:|---:|
| Stable operation, scenario, page, and section identities | Defines and validates | References |
| SDK signatures and docstrings | Extracts | Never copies |
| Runtime endpoints, profiles, errors, limits, evidence | Extracts | Explains through components |
| Executable code and expected output | Builds and qualifies | Selects and contextualizes |
| MDX schema and registered components | Implements | Uses |
| Reader journeys and recommended paths | Provides typed model | Chooses and authors |
| Landing-card selection and order | Validates identities | Owns |
| Architecture and lifecycle explanations | Provides fact-backed components | Owns prose and conceptual views |
| HTML, Markdown, search, navigation, and LLM rendering | Implements once | Supplies page models |
| Content requirements | Enforces declared policy | Defines editorial acceptance |
| CI orchestration, exact-head checks, release, rollback | Owns | Does not reimplement |

## Composition contract

```text
AuthsDocsReleaseBundleV1      AuthoredPageSourceV1
facts + scenarios             prose + stable references
             \                    /
              \                  /
               v                v
                DocsPageCompiler
                       |
                       v
              VerifiedPageGraphV1
             /       |       |       \
          HTML   Markdown  Search   Agent surfaces
```

The compiler parses both inputs into closed types and fails when:

- an authored page references an unknown or incompatible identity;
- a mutable product fact appears in a manually authored fact slot;
- an executable example is not backed by a qualified scenario;
- two pages claim the same page or route identity;
- navigation references a route absent from the graph;
- HTML and Markdown select different semantic blocks;
- an assurance claim lacks current evidence or a limitation; or
- content uses a release fact from a different bundle identity.

## Authored source contract

Every authored page declares dependencies rather than copying facts:

```yaml
id: auths.page.get-started.local/1
uses:
  operations:
    - auths.operation.authority.execute/1
  scenarios:
    - auths.scenario.rest-authorize/1
  profiles:
    - auths.profile.application.rest-effect/1
  claims:
    - auths.claim.exact-effect-commitment/1
```

MDX embeds registered components such as:

```mdx
<OperationSummary id="auths.operation.authority.execute/1" />
<ScenarioStep id="auths.scenario.rest-authorize/1" step="execute" />
<OutcomeMatrix operation="auths.operation.authority.execute/1" />
```

The content repository does not maintain parallel JSON files containing those
facts. It may keep bounded editorial configuration such as card order,
audience, reader depth, and related-page selection.

## Change workflows

### Product fact changes

An installed API, endpoint, error, profile, limit, version, or evidence change
updates the immutable bundle. Generated reference and scenarios rebuild. The
dependency graph identifies affected editorial pages and requires review only
where the semantic dependency changed.

### Editorial changes

Prose, card ordering, recommendations, and conceptual diagrams rebuild only the
documentation repository. They cannot modify the selected product bundle or
generated facts.

### Semantic changes

The changed operation receives a new semantic identity or version. References
to the previous identity remain release-pinned or fail explicitly; the compiler
never rejoins pages by similar function names.

### New public surfaces

A new surface creates generated reference automatically. Closed discoverability
policy determines whether it also requires a catalog entry, landing-card
decision, tested scenario, or authored guide.

## Repository and naming rules

- Refer to platform epics as `P1`–`P11` and content epics as `C0`–`C9`.
- Keep product facts and immutable bundle construction in `auths-proof`.
- Keep public `.mdx`, editorial navigation configuration, and visual composition
  in `auths-docs`.
- Do not add mutable `../auths-proof` dependencies to `auths-docs`.
- Use immutable local fixture bundles during development and immutable release
  bundles in qualification.
- Build navigation, canonical Markdown, search, sitemap, and agent surfaces
  from `VerifiedPageGraphV1`; none receives a separate source corpus.

## Implementation steps

- [ ] Add the two-lane execution map to `docs/specs/0040/README.md`.
- [ ] Freeze the three provenance classes in the page-model schema.
- [ ] Add stable dependency references to authored page frontmatter.
- [ ] Implement strict product-fact and scenario-reference components.
- [ ] Implement duplicate page, route, navigation, and fact ownership checks.
- [ ] Reject raw executable code fences on public pages unless a component
  resolves them to a qualified scenario artifact.
- [ ] Reject manually authored generated-reference inventories and tables.
- [ ] Generate an affected-page report from semantic dependencies.
- [ ] Display block provenance and release identity in preview diagnostics.
- [ ] Update P6, P9, P10, P11, and C1–C9 to reference this ownership contract.
- [ ] Add CODEOWNERS or equivalent review routing for generated facts,
  scenarios, editorial narrative, security claims, and operations procedures.

## Acceptance criteria

- Every public block can report one and only one provenance class.
- A changed SDK argument updates reference without editing MDX.
- A changed editorial paragraph does not rebuild or alter product artifacts.
- A copied signature, endpoint inventory, version table, or executable snippet
  in editorial MDX fails qualification.
- One page graph produces HTML, Markdown, navigation, search, and agent output.
- The affected-page report is based on stable identities, not path or symbol
  string similarity.
- Platform and content epics contain no conflicting ownership statements.

## Validation

```text
npm run test:content-ownership
npm run test:dependencies
npm run test:provenance
npm run test:examples
npm run test:markdown
npm run test:navigation
npm run build
```

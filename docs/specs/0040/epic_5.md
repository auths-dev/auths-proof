# Epic 5 — Build the Static Docs Foundation and MDX Contract

**Parent:** [AP-SPEC-040](../0040-stripe-quality-documentation-platform.md)

**Repository:** `auths-proof-docs`

**Depends on:** Epic 4's fixture bundle schema. Implementation may use a
checked fixture bundle before the first release bundle exists.

**Blocks:** Epics 6–11

## Outcome

Create the separate static documentation application, constrained MDX content
system, Auths design system, navigation shell, version/language state, local
search foundation, and deterministic HTML/Markdown rendering architecture.

This epic produces representative pages and components. It does not yet write
the complete quickstarts or generate the deep reference.

## Zero-context starting point

Before editing `auths-proof-docs`, read from `auths-proof`:

- `AGENTS.md`;
- `docs/specs/0040-stripe-quality-documentation-platform.md`;
- Epics 1–4 in `docs/specs/0040/`;
- `docs/target-state/PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md`;
- the fixture docs bundle schema and sample artifact; and
- `bindings/public-topology-v1.json`.

Then read every existing file in `auths-proof-docs`. Preserve its independent
Git history and package boundary. Never add a mutable `../auths-proof` path
dependency.

## Fixed toolchain

Use:

- Node 22;
- npm with a committed lockfile and deterministic `npm ci` installs;
- Vinext on Vite, React server components, and `@mdx-js/rollup`;
- strict TypeScript;
- strict typed page models and parse-at-the-boundary contract loaders;
- Shiki;
- the official checked Auths SVG and one pinned, tree-shakable icon family;
- Pagefind;
- pinned `remark`/`rehype` plugins;
- Mermaid rendered to SVG at build time;
- Playwright, `axe-core`, and Lighthouse CI; and
- immutable static deployment.

Use small client components for language selection, search, navigation, and
copy actions; keep documentation content server-rendered. Do not add a database,
runtime CMS, hosted search, or authentication without a later measured
requirement.

## Content model

All human-authored public pages are `.mdx`. Plans and internal repository docs
remain ordinary `.md` outside the public content collection.

MDX may use only globally registered components. Add a policy plugin that
rejects:

- arbitrary imports and exports;
- inline scripts and event handlers;
- network or filesystem side effects;
- raw HTML outside a small audited allowlist;
- unregistered component names;
- copied signatures, hand-written endpoint inventories, package-version
  tables, and executable example fences; and
- frontmatter values outside the closed content schema.

Typed frontmatter:

```ts
interface AuthsPageFrontmatter {
  id: PageId;
  title: BoundedTitle;
  description: BoundedDescription;
  audience: readonly Audience[];
  depth: "understand" | "start" | "build" | "operate" | "inspect" | "verify";
  status: "draft" | "preview" | "stable";
  languages: readonly SdkLanguage[];
  products: readonly ProductArea[];
  reviewers: readonly OwnershipArea[];
  uses: SemanticDependencies;
}
```

Unknown keys fail. `uses` contains operation, profile, error, and scenario
identities, not URLs.

## Architecture

```text
verified release/fixture bundle       authored .mdx
             |                            |
      strict contract parse         strict content parse
             |                            |
             +-------------+--------------+
                           v
                    VerifiedPageGraph
                  /        |         \
                 v         v          v
               HTML    canonical MD   Pagefind/indexes
                 |
                 v
          immutable static bundle
```

Only schema-parsed data enters page components. The HTML renderer and Markdown
renderer consume the same page graph, so `.md` output is not a second content
source.

## UX shell

```text
+----------------------------------------------------------------------------+
| [Auths logo] Auths Docs             Search docs...             GitHub [↗] |
| Start   SDK   Concepts   Architecture                                    |
|----------------------------------------------------------------------------|
| Start       | Protect one REST effect                         | On this page |
| Development |                                                | Outcome      |
| SDKs        | Give one caller exact authority ...             | Build        |
| API         |                                                | Failure      |
| Architecture| [Rust] [TypeScript] [Python]                    | Next         |
| Operate     | +--------------------------------------------+  |              |
| Reference   | | tested code                               |  |              |
|             | +--------------------------------------------+  |              |
|----------------------------------------------------------------------------|
| Copy for LLM | View Markdown | Open source | Ask an agent                  |
+----------------------------------------------------------------------------+
```

The page remains readable without JavaScript. Language tabs render all panels
in HTML, with CSS/default selection and an enhanced persisted choice when
JavaScript is available. The URL may accept `?lang=python` for shareable
selection but canonical content does not fork by query.

Promote the proven local prototype into the qualified product while preserving
these UX contracts:

- a two-row global header with official Auths mark/title upper-left, functional
  search centered, GitHub icon/external indicator upper-right, and `Start`,
  `SDKs`, `Runtime API`, `Concepts`, `Architecture`, and `Operations`
  lower-left, plus a bounded `More` menu for `Integrations` and `Assurance`;
- contextual navigation flush to the left viewport edge, collapsible on
  desktop and a drawer on narrow screens;
- one CSS design token for header height, consumed by every sticky offset,
  anchor margin, and viewport calculation;
- page actions immediately below title/description;
- a three-column reference shell with middle content and right code rail on
  the same visual plane; and
- one icon language with individual imports and no Unicode stand-ins.

The search control must open the Pagefind-backed interface with `Command + K`
and `Control + K`, correct dialog/focus behavior, and no header reflow. A
decorative search button does not satisfy this epic.

## Components

Implement typed components listed in the parent specification, beginning with:

- `GlobalHeader`, `ContextNavigation`, `PageOutline`, and `ReferenceShell`;
- `OutcomeHero`;
- `LanguageGroup`;
- `CodeBlock` and `CodeBlockWithResult` with the parent section 8.2 prop
  contract;
- `TestedExample` placeholder over fixture scenarios;
- `ReferenceLink` and `ReferenceSignature` placeholders;
- `FiveVerbFlow` and `FiveNounMap`;
- `OutcomeMatrix`;
- `TrustBoundary`;
- `Lifecycle`;
- `ReceiptView`;
- `SecurityCallout` and `FailurePath`;
- `Diagram` with text equivalent;
- `VersionBadge` and `AvailabilityBadge`; and
- `PageActions` and a section-scoped `SectionActions` foundation.

Every component needs HTML, no-JavaScript, narrow-screen, and Markdown
behavior. Components may standardize presentation but cannot invent semantics.

## Repository layout

Create the exact foundation described in parent section 13.3, including:

- `site/src/content/docs/` for public `.mdx`;
- `site/src/components/` and `site/src/layouts/`;
- `site/src/pages/reference/` for later generated templates;
- `site/public/images/auths_logo.svg` as the canonical copied brand mark;
- `schemas/` for contract, page graph, and scenario types;
- `tools/fetch-release/` with checksum verification;
- `tools/build-page-model/`;
- `tools/render-markdown/`;
- `examples/` placeholders by scenario and language; and
- browser, contract, and visual test directories.

Generated output lives under ignored build directories and is never hand
edited or committed.

## Implementation steps

- [ ] Pin the toolchain and lock every dependency.
- [ ] Add the strict release-bundle parser and fixture bundle.
- [ ] Add the typed content collection and MDX policy.
- [ ] Build the page graph and stable page-ID resolver.
- [ ] Implement the responsive shell, navigation, outline, theme, typography,
  status colors, version selector, language state, and footer actions.
- [ ] Wire the official SVG, single icon family, two-row header, real centered
  search, edge-aligned contextual navigation, and shared header-offset token.
- [ ] Implement the shared syntax renderer, `CodeBlock`, and
  `CodeBlockWithResult`, including Bash override and JSON-default result
  grammar without duplicating toolbar/copy behavior.
- [ ] Implement representative content, generated-reference, error, and
  operations page templates.
- [ ] Add Pagefind over final rendered content.
- [ ] Add deterministic Mermaid-to-SVG with accessible text alternatives.
- [ ] Add canonical Markdown renderer interfaces, even if full coverage lands
  in Epic 10.
- [ ] Add CSP, security headers, and a no-third-party-script assertion.
- [ ] Establish bundle-size, accessibility, and performance budgets.

## Adversarial and UX tests

Test:

- malformed and unknown bundle schema versions;
- checksum mismatch and archive traversal;
- unknown frontmatter and semantic dependencies;
- MDX import, script, raw HTML, and unregistered components;
- reference links that use URLs instead of stable identity;
- language preference unavailable on the next page;
- JavaScript disabled;
- keyboard-only navigation, search, tabs, and page actions;
- keyboard opening/closing of search, focus return, and no header reflow;
- stale numeric sticky offsets after the header height changes;
- contextual navigation collapse that leaves a dead gutter;
- whole-library icon imports or replacement of official icons with text glyphs;
- Bash commands highlighted as the selected SDK language;
- JSON results rendered as untyped plain text;
- 320-pixel layout and 200-percent zoom;
- reduced motion, high contrast, and screen-reader landmarks;
- a diagram without a text equivalent;
- Pagefind accidentally indexing navigation chrome or unpublished pages; and
- production output containing source plans, fixture secrets, or build paths.

## Validation commands

Define stable scripts equivalent to:

```text
pnpm install --frozen-lockfile
pnpm typecheck
pnpm lint:content
pnpm test:contract
pnpm build
pnpm test:browser
pnpm test:a11y
pnpm test:performance
```

## Exit gate

This epic is complete when the separate repository builds a polished static
site from one verified fixture bundle and constrained MDX; HTML and Markdown
share one parsed model; stable language/version state works without hiding
content; the exact global/header/navigation/code component contracts above pass
desktop and narrow-screen qualification; representative pages meet
accessibility/performance budgets; and no page can execute arbitrary MDX code
or duplicate generated facts.

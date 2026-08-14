# AP-SPEC-040: Stripe-Quality Documentation and Developer Portal

**Status:** Specified across `auths-proof` and the separate `auths-proof-docs`
repository. This repository owns source documentation, product facts, semantic
mapping, and immutable release metadata. `auths-proof-docs` owns authored public
content, rendering, reference generation, qualification, and deployment.
Neither repository acquires a mutable sibling dependency.

**Depends on:** [AP-SPEC-034 public naming
consolidation](0034-auths-public-naming-consolidation.md), [AP-SPEC-038 open
production substrate](0038-production-runtime-custody-observability-and-assurance.md),
the published Rust, TypeScript, and Python package contracts, and the canonical
release and semantic identities

**Related:** [AP-SPEC-039 enterprise coordination and
operations](0039-enterprise-coordination-and-operations-plane.md). Enterprise
documentation may be added later, but it must not obscure or gate the complete
open, self-hosted path.

## 1. Product decision

Auths will have one beautiful, fast, public documentation experience that
makes exact authority feel simple before revealing its depth. A new developer
must be able to protect one REST effect in fifteen minutes using five verbs:
`create`, `delegate`, `execute`, `resume`, and `verify`. The same site must let
an experienced security or infrastructure engineer descend into lifecycle
state, custody, profiles, wire formats, threat boundaries, differential
evidence, and formal assurance without encountering a second vocabulary.

The documentation is a product surface, not a generated appendix. It has four
equal responsibilities:

1. explain why Auths exists in ordinary language;
2. produce a safe first success quickly;
3. provide exact, tested reference material for every supported public
   surface; and
4. remain directly usable by humans, terminals, coding agents, and other
   machines.

The north star is Stripe-quality comprehension, not a visual clone of Stripe.
Auths should adopt the structural lessons that make Stripe's documentation
effective while developing its own authority-specific visual and conceptual
grammar.

## 2. Evidence from Stripe's documentation

This specification is informed by the following current, public Stripe
patterns:

- Stripe's [documentation landing page](https://docs.stripe.com/) starts from
  outcomes and products instead of presenting the API reference as the whole
  product.
- Its [developer resources](https://docs.stripe.com/development) group CLI,
  SDKs, APIs, agents, MCP, testing, versioning, security, and extension tools
  into a coherent developer platform.
- Its [SDK landing page](https://docs.stripe.com/sdks) makes official language
  libraries, versioning, support policy, OpenAPI, and adjacent tools easy to
  discover.
- Its [API overview](https://docs.stripe.com/apis) teaches authentication,
  request behavior, testing, limits, and errors before sending readers into
  individual operations.
- Its [API reference](https://docs.stripe.com/api) and individual operation
  pages, such as [Create a
  customer](https://docs.stripe.com/api/customers/create), keep request,
  response, return behavior, and parameter details together.
- Stripe's [quickstart catalog](https://docs.stripe.com/quickstarts) describes
  end-to-end examples with multiple languages and frameworks, scroll-linked
  implementation steps, and downloadable or agent-assisted starting points.
- Stripe explicitly publishes [machine-readable documentation
  surfaces](https://docs.stripe.com/agents): appending `.md` to a documentation
  URL returns Markdown, and the same developer area points agents toward
  indexed skills and tools.
- Its [MCP documentation](https://docs.stripe.com/mcp) separates documentation
  search and API-detail tools from broad write tools, allowing a client to
  retrieve only the context it needs.

Auths will adopt the outcome-first hierarchy, deep reference, tested
multi-language examples, and machine-readable delivery. It will improve on the
pattern for Auths' domain by making trust boundaries, authorization versus
execution, and denial versus indeterminate versus provider-unknown outcomes
visible throughout the site.

## 3. Success criteria

The initial public release is complete only when all of the following are true:

- An unfamiliar developer can install one maintained SDK, run the local
  reference path, and authorize one exact REST effect in under fifteen minutes.
- A reader can answer “what is Auths?”, “why is this not OAuth?”, and “what is
  the smallest thing I can build?” from the home page without protocol terms.
- Every maintained Rust, TypeScript, and Python public operation has an exact
  reference page or an explicit, machine-checked `not supported` state.
- Language selection is consistent across a page and persists while navigating.
- Every displayed code sample comes from a file that CI compiles or executes
  against published artifacts.
- Equivalent Rust, TypeScript, and Python examples produce the same normalized
  outcomes against the same fixtures and reference runtime.
- Every public HTML content page has a canonical Markdown representation.
- Search can resolve product vocabulary, SDK symbols, stable error codes,
  profiles, concepts, and common synonyms.
- The site remains useful without client-side JavaScript; JavaScript enhances
  tabs, search, and diagrams but does not contain the documentation.
- The public site meets WCAG 2.2 AA, scores at least 95 for accessibility and
  90 for performance in the maintained Lighthouse profile, and has no serious
  automated accessibility violation.
- No draft plan, scratch document, secret, internal release note, or
  unsupported claim is published accidentally.

Usability qualification must include at least five developers who have never
worked in this repository. At least four must complete the REST quickstart
without verbal help. Every hesitation longer than two minutes becomes a docs
issue even if the user eventually succeeds.

## 4. Audience and primary jobs

The site serves six audiences through one information architecture:

| Audience | First question | Primary destination |
| --- | --- | --- |
| Application developer | How do I protect one endpoint? | REST quickstart |
| Agent developer | How do I give an agent narrow authority? | Agent authority guide |
| SDK consumer | What does this function accept and return? | Language-aware SDK reference |
| Security architect | What is trusted, signed, stateful, and fail-closed? | Architecture and threat boundaries |
| Platform operator | How do I deploy, observe, recover, and rotate custody? | Operations guides |
| Auditor or implementer | What are the exact semantics and evidence? | Protocol and assurance reference |

The home page must not force these users through the same depth. It offers a
single recommended start and then clear routes by job.

## 5. Progressive-disclosure contract

Progressive disclosure is structural, not merely a collection of collapsed
sections. Every concept has one name and appears at increasing levels of depth:

| Level | Reader intent | Content |
| --- | --- | --- |
| 0 — Understand | “Why should I care?” | One concrete story, outcomes, five nouns and five verbs |
| 1 — Start | “Show me the safe path.” | Install, local sandbox, one complete effect, one receipt |
| 2 — Build | “Adapt this to my application.” | Guides, profiles, approvals, recovery, framework recipes |
| 3 — Operate | “Run this reliably.” | Deployment, custody, stores, observability, backup, reconciliation |
| 4 — Inspect | “Explain exactly what happened.” | Outcomes, receipts, disclosure, error codes, state transitions |
| 5 — Verify | “Show me the contract and evidence.” | Protocol, wire formats, fixtures, formal and differential assurance |

A page may link downward but must not duplicate the deeper explanation. The
simple path uses concrete defaults and names the next decision only when the
reader reaches it.

Security-critical facts are exempt from concealment. A warning that changes
whether an effect is safe, repeatable, private, or authorized must appear at
the point of action; it cannot exist only in an “advanced” accordion.

Every guide follows this order:

1. **Outcome:** what the reader will have working.
2. **Before you begin:** the smallest real prerequisite set.
3. **Build:** executable steps with a visible progress rail.
4. **What Auths proved:** a plain-language explanation of the resulting
   authority and receipt.
5. **Failure paths:** denial, indeterminate, replay, expiry, mutation, and
   unknown provider outcome where relevant.
6. **Take it further:** links to operations, architecture, and exact reference.

## 6. Information architecture

The public navigation is organized around user intent rather than repository
layers or crate names.

```text
/
├── start/
│   ├── what-is-auths
│   ├── rest-api
│   ├── delegate-to-an-agent
│   └── verify-a-receipt
├── development/
│   ├── sdks
│   ├── runtime-api
│   ├── cli
│   ├── agents-and-mcp
│   ├── testing
│   └── versioning
├── guides/
│   ├── identity-and-trust
│   ├── approvals
│   ├── delegation
│   ├── recoverable-execution
│   ├── receipts-and-disclosure
│   └── cross-company-authority
├── profiles/
│   ├── application
│   ├── mcp
│   ├── opentofu
│   ├── postgresql
│   └── github
├── architecture/
│   ├── system-map
│   ├── identity-versus-authority
│   ├── trust-boundaries
│   ├── lifecycle-and-recovery
│   ├── custody
│   ├── transport-and-exchange
│   └── threat-model
├── operations/
│   ├── deploy
│   ├── postgresql
│   ├── kms-and-pkcs11
│   ├── observability
│   ├── backup-and-restore
│   └── incident-runbooks
├── integrations/
│   ├── oauth-oidc
│   ├── spiffe
│   ├── cedar-opa-rebac
│   ├── cloud-iam
│   └── ucan-biscuit-http-signatures
├── reference/
│   ├── sdk/{rust,typescript,python}/...
│   ├── runtime-api/...
│   ├── profiles/...
│   ├── errors/...
│   ├── configuration
│   ├── limits
│   └── protocol/...
├── assurance/
│   ├── claims
│   ├── fixtures
│   ├── differential-evidence
│   ├── formal-evidence
│   └── release-evidence
└── releases/
    ├── changelog
    ├── support-matrix
    └── upgrade-guides
```

Crate and package names remain searchable and appear on reference pages, but
they do not determine the top-level navigation.

The default home-page journey is:

```text
"I need to authorize one effect"
              |
              v
      REST API quickstart
              |
              v
 create -> delegate -> execute -> verify
              |
              v
     human-readable receipt
              |
       +------+-------+
       |              |
       v              v
 adapt a profile   understand architecture
```

## 7. UX

### 7.1 Visual character

The visual system should feel calm, exact, and capable. It must avoid the
“cybersecurity dashboard” cliché of neon colors, constant warning states, and
decorative network graphics. Authority and lifecycle state should be legible
through typography, spacing, restrained color, and consistent diagrams.

The design system provides semantic colors for:

- verified or completed;
- denied or rejected;
- indeterminate or unavailable;
- recoverable or outcome unknown; and
- explanatory, non-status information.

Color is never the only carrier of meaning. Outcome components always include
an icon, label, and short text.

The checked Auths SVG is the canonical brand mark for the header, footer,
metadata, and generated social assets. Do not recreate it with CSS geometry,
text glyphs, or an approximate icon. The site uses one restrained, open icon
family for navigation and actions. GitHub, search, clipboard, Markdown, and
external-link actions use real icons from that family, with accessible labels;
production imports must be per icon or equivalently tree-shaken.

### 7.2 Global shell and home page

The desktop header has two deliberate rows: the official Auths mark and
“Auths Docs” at the upper left, search centered independently, and the GitHub
icon plus external-link indicator at the upper right. `Start`, `SDK`,
`Concepts`, and `Architecture` occupy the lower-left row.

Contextual documentation or reference navigation begins at the left viewport
edge below the header. It is collapsible on desktop and becomes a drawer on
narrow screens; collapsing it widens the reading surface rather than leaving
an empty centered gutter.

One design token owns the full header height. Sticky contextual navigation,
page outlines, reference code rails, restored-navigation controls, anchor
scroll margins, and viewport-height calculations consume that token. No
component may copy a numeric header offset.

The centered search control opens real local search with `Command + K` and
`Control + K`, keyboard focus management, and an accessible dialog. It must
not be decorative or resize the header when open. On narrow screens the brand
and GitHub icon remain in the first row, search occupies its own row, and the
four global links remain horizontally available.

```text
+--------------------------------------------------------------------------------+
| [Auths logo] Auths Docs       Search docs, symbols, errors...       GitHub [↗] |
| Start   SDK   Concepts   Architecture                                      |
+--------------------------------------------------------------------------------+
| Give people and agents exact authority—without giving away the account.         |
|                                                                                |
| [Protect a REST effect in 15 minutes]   [Understand Auths]                     |
|                                                                                |
| create  ->  delegate  ->  execute  ->  resume  ->  verify                     |
+--------------------------------------------------------------------------------+
| Start with an outcome                                                          |
| [REST API] [Agent delegation] [Cross-company] [Infrastructure] [Approvals]     |
+--------------------------------------------------------------------------------+
| Build with Auths                                                               |
| [Rust] [TypeScript] [Python] [Runtime API] [CLI] [MCP]                         |
+--------------------------------------------------------------------------------+
| Why Auths                                                                      |
| Identity says who. Auths proves the exact action they may perform.              |
| [See the architecture] [Compare alternatives]                                  |
+--------------------------------------------------------------------------------+
```

The hero must not lead with “capabilities,” “CBOR,” “attenuation algebra,” or
crate names. The first screen contains one promise, one primary quickstart,
the five verbs, search, and language access.

### 7.3 Guide page

```text
+----------------------+--------------------------------------+------------------+
| Guide navigation     | Protect a REST effect                | On this page     |
|                      |                                      |                  |
| 1 Install       ✓    | [Rust] [TypeScript] [Python]         | Outcome          |
| 2 Define action ✓    | +----------------------------------+ | Build            |
| 3 Create        ●    | | exact runnable code              | | What was proved |
| 4 Execute            | +----------------------------------+ | Failure paths    |
| 5 Verify             |                                      | Next steps       |
|                      | The authority permits only...        |                  |
+----------------------+--------------------------------------+------------------+
| Copy for LLM · View Markdown · Edit · Report an issue                         |
+--------------------------------------------------------------------------------+
```

On narrow screens, the left navigation becomes a drawer, the progress rail
becomes a compact header, and the table of contents becomes an inline outline.
Code never requires horizontal page scrolling beyond its own container.
The guide navigation is flush with the left viewport edge rather than placed
inside the centered prose shell. A desktop collapse control remains available,
and restoring navigation does not change the reader's semantic scroll position.

### 7.4 Reference page

```text
+----------------------+--------------------------------------+------------------+
| Reference            | create                               | Rust TS Python   |
| Search symbols       | Create bounded root authority        |                  |
|                      |                                      | Install          |
| Authority            | Signature                            | Request          |
|  create              | create(request) -> AuthorityResult   | Response         |
|  delegate            |                                      | Errors           |
| Execution            | Parameters                           | Related guides   |
|  execute             | Returns                              |                  |
|  resume              | Outcomes                             |                  |
+----------------------+--------------------------------------+------------------+
```

Reference pages remain concept-first. A Rust trait name, TypeScript interface,
and Python class can be different projections of the same semantic operation;
the page begins with the shared meaning and then shows language-specific names,
types, and examples.

The reference shell has three distinct responsibilities: left contextual
navigation, middle meaning/reference content, and a right language-aware code
rail that may remain sticky within the current section. The middle and right
columns share one visual plane and are not separated by a heavy vertical rule;
the dark bounded code component supplies its own edge. The code rail may pair
tested source with a typed normalized-result block. Selecting a language in the
rail updates every applicable source and symbol panel on the page.

An **SDK reference** documents installed Rust, TypeScript, and Python
operations and types. A **runtime API reference** documents HTTP methods,
paths, carriers, trust context, outcomes, and retry behavior. Titles,
navigation, installation text, URLs, and search records use those exact
surface names and never label an SDK page merely “API reference.”

### 7.5 Page tools

Every content page exposes the following actions in a consistent location:

- **Copy for LLM**, which copies the canonical page Markdown;
- view the canonical `.md` URL;
- copy the current section link;
- copy the smallest relevant code example;
- copy a bounded “implement this with Auths” prompt containing the page URL,
  selected language, package version, and explicit task—but no secrets or page
  analytics;
- edit the human-authored source on GitHub where permitted;
- report an issue with page identity and release version prefilled; and
- switch the documentation version.

Page-level Copy/View Markdown actions appear directly beneath the page title
and description. Long reference pages additionally expose section-level
**Copy for LLM** and **View as Markdown** actions beside the section heading.
The section projection contains that heading, its relevant prose, all declared
language examples, generated facts, warnings, semantic identity, and release
identity. It excludes neighboring sections, code from another semantic step,
and navigation chrome.

The copy-as-Markdown result must be useful independently. It includes title,
summary, prerequisites, all language examples under explicit headings,
security callouts, reference links, page identity, and release identity. It
excludes navigation chrome, cookie text, hidden UI labels, and analytics.

## 8. Multi-language SDK experience

Rust, TypeScript, and Python are equal maintained SDKs. The site must never
describe one as canonical implementation documentation and the others as
secondary wrappers, even though Rust owns protocol semantics internally.

### 8.1 Language state

- The selector offers `Rust`, `TypeScript`, and `Python` in that order only
  when all are relevant. A page may offer a documented subset.
- Selection applies to all code groups and symbol panels on the page.
- Selection persists across navigation in local storage and is represented in
  `?lang=rust|typescript|python` so a link is shareable.
- The query value is parsed into a closed language type. Unknown values are
  ignored rather than reflected into the page.
- Server-rendered HTML contains every language example. CSS and minimal
  JavaScript select the visible panel; content does not arrive through a later
  API request.
- Keyboard users can move between tabs with standard tab-list behavior, and
  screen readers receive the language and panel relationship.
- A desktop-only “Compare languages” action may show two implementations side
  by side. It is an enhancement, not a separate content source.

### 8.2 Code and result rendering

All source presentation composes two closed components:

```ts
interface CodeBlockProps {
  language: "rust" | "typescript" | "python";
  code: string;
  isBash?: boolean;
  label?: string;
}

interface CodeBlockWithResultProps extends CodeBlockProps {
  result: string;
  resultLanguage?: "json" | "text" | "bash" | "rust" | "typescript" | "python";
  resultLabel?: string;
}
```

`isBash` means the source is a shell command associated with the selected SDK,
so Bash grammar overrides the SDK language grammar without changing global
language state. Result grammar defaults to JSON and must be declared when the
normalized result is text, Bash, or another maintained language. Both
components share one theme, toolbar, copy behavior, spacing system, overflow
policy, accessibility contract, and syntax renderer. A result is visually
distinct inside the same bounded block rather than an unrelated second card.

The component receives verified source and result text from scenario or
reference page models. MDX cannot use it to smuggle a second untested
executable example. Canonical Markdown emits explicit language-labelled fences
for source and result.

### 8.3 One scenario, three idiomatic implementations

Examples are not generated by transliterating Rust. Each language remains
idiomatic, while a shared scenario manifest owns:

- the purpose and profile;
- fixture identities;
- exact application bytes;
- clock and lifecycle inputs;
- expected normalized outcomes;
- stable error codes;
- receipt commitments; and
- security assertions.

The three source files execute against the same immutable reference release.
CI captures their normalized results and compares them with the Rust-owned
fixture. The documentation build reads the exact tested source files. It must
never copy code from prose or maintain a second hidden snippet.

If an SDK does not support a capability, the capability registry renders a
clear unavailable state and links to the owning issue. Documentation must not
simulate parity with language-local helper code that changes Auths meaning.

### 8.4 Reference generation

The SDK reference combines generated facts with human explanation:

- Rust public items and signatures come from release-scoped Rustdoc JSON or a
  purpose-built bounded export.
- TypeScript exports and declarations come from the installed package's
  frozen public API snapshot.
- Python symbols, signatures, typing, and doc summaries come from the installed
  wheel's public API contract.
- Cross-language semantic operation identities come from one release manifest.
- Human-authored introductions, examples, guidance, and security notes are
  joined by stable operation identity, never by display name matching.

A missing join, duplicate identity, undocumented public symbol, or stale
symbol reference fails the build.

## 9. Architecture and conceptual documentation

Architecture pages must explain relationships visually and then provide an
equivalent text description. The default system map is horizontal and compact:

```text
identity evidence      exact authority       sealed command       receipt
      |                      |                      |                  |
      v                      v                      v                  v
+-----------+         +-------------+       +--------------+    +-----------+
| identity  | ------> | Auths verify| ----> | closed       | -> | durable   |
| provider  | context | + lifecycle | claim | gateway      |    | evidence  |
+-----------+         +------+------+       +--------------+    +-----------+
                            |
                            v
                     replay / budget /
                     recovery state

Transport carries bytes. Custody signs commitments. Neither grants authority.
```

The architecture section must cover:

- identity versus authority;
- the five nouns and five verbs;
- exact application-byte commitment;
- delegation and attenuation;
- approvals bound to exact transactions;
- offline verification versus stateful enforcement;
- replay, budget, expiry, revocation, and recovery state;
- authorization, provider delivery, observed effect, and receipts as distinct
  facts;
- sealed commands and closed gateways;
- cryptographic, identity, custody, transport, store, and provider agility;
- Rust ownership of semantics and thin language projections;
- open-core versus optional enterprise boundaries; and
- the scope and limits of formal, differential, and operational evidence.

Mermaid diagrams are allowed as authored source, but the build must render
them deterministically to accessible SVG with pinned tooling. Each diagram has
a text alternative and remains understandable in Markdown-only output. Motion
is optional and disabled under reduced-motion preferences.

## 10. API and reference surfaces

“API reference” is divided into explicit surfaces so readers do not confuse a
language method, runtime route, profile, and wire object.

### 10.1 SDK reference

Organized by semantic operation, with language-specific symbols, types,
examples, errors, limits, and availability. It includes the simple five-verb
surface first, followed by deliberate deeper groups for identity, trust,
approvals, custody, runtime, inspection, diagnostics, profiles, and testkit.
Installation panels use the SDK package coordinates and Bash-highlighted
commands while the operation examples remain highlighted as the selected SDK
language. The page title, navigation, search kind, and canonical URL identify
this surface as an SDK reference, never a generic API reference.

### 10.2 Runtime API reference

Documents the HTTPS production boundary, content types, limits, authentication
context, exact routes, status handling, and binary request and response
contract. Every operation page contains:

- purpose and trust boundary;
- method and path;
- required profile;
- request carrier and byte limit;
- successful and non-success outcome families;
- retry meaning;
- stable codes;
- executable curl or SDK examples where safe; and
- related lifecycle and security guidance.

The reference must not imply that a successful HTTP response alone means an
effect was authorized or completed.
Its code rail may expose safe `curl` or SDK alternatives, but the middle
contract remains method/path and wire behavior rather than an SDK function
signature.

### 10.3 Profile reference

Every maintained profile page owns its exact action, policy inputs, trusted
evidence, required and executed configuration, denial and indeterminate
outcomes, provider boundary, credential timing, recovery behavior, receipt
claims, hard limits, and qualification evidence. Profile pages link to their
domain guide and runnable example.

### 10.4 Protocol and assurance reference

Documents canonical objects, version identities, algorithms, limits, stable
result codes, fixture manifests, and assurance claims. Raw byte layouts belong
here, not in the quickstart. Every claim links to the exact release evidence
that supports it and names what the evidence does not prove.

## 11. Search, discovery, and glossary

The first release uses a static, build-scoped search index so documentation
remains self-hostable and does not leak queries to a third party. Search ranks:

1. exact SDK symbols, route names, profile identities, and stable error codes;
2. page titles and aliases;
3. headings;
4. summaries and body text; and
5. historical names only when an explicit synonym exists.

The index stores document version, language applicability, audience, content
kind, support status, and release identity. Search results display these facts
and never mix `next` documentation into a stable-release result without a
visible label.

A checked glossary owns preferred terms and synonyms. For example, searches
for “permission,” “scope,” “role,” or “token” may lead to authority pages while
preserving the distinction between those concepts. Unknown synonyms are not
silently inferred during the build.

## 12. Machine-readable and agent-first delivery

Every canonical HTML route has a Markdown twin:

```text
GET /architecture/trust-boundaries
GET /architecture/trust-boundaries.md
GET /architecture/trust-boundaries/sections/evidence.md
```

The Markdown response has content type `text/markdown; charset=utf-8`, a
canonical link header, release identity, and cache validators. A missing `.md`
route for a public content page fails deployment qualification.

Templates may also publish bounded section Markdown at
`/<page>/sections/<stable-section-id>.md`. Section routes are generated from
closed page-model identities, not mutable heading text, and include their
parent canonical URL and release identity.

The site also publishes:

- `/llms.txt`: a concise index of the product model and important page URLs;
- `/llms-full.txt`: a bounded, release-scoped compilation of the essential
  public documentation, excluding generated exhaustive symbol reference;
- `/.well-known/auths-docs.json`: documentation version, release identity,
  languages, package versions, sitemap, search index, Markdown convention, and
  integrity metadata;
- `/sitemap.xml`: canonical human routes;
- `/search-index.json`: a bounded public search catalog without analytics; and
- `/reference/manifest.json`: operation, SDK symbol, profile, error, and
  evidence identities for the selected release.

Phase two may add a read-only documentation MCP server with only:

```text
search_auths_docs(query, version?, language?)
read_auths_doc(page_id, version?, section?)
resolve_auths_symbol(symbol, language, version?)
explain_auths_error(code, version?)
```

These tools return bounded excerpts plus canonical URLs. They never execute an
Auths operation, accept credentials, mutate a resource, or blur documentation
access with the product's authority MCP surfaces.

## 13. Architecture

The documentation implementation remains in the separate `auths-proof-docs`
repository, as required by the monorepo contract. It consumes published,
immutable artifacts from `auths-proof`; it never imports this checkout through
a sibling path.

```text
auths-proof release
  packages + docs contract + fixtures + evidence
                      |
                      v
             immutable artifact fetch
                      |
                      v
+---------------- auths-proof-docs ----------------+
| authored MD/MDX                                    |
| generated reference join                          |
| tested example sources                            |
| Astro build + custom Auths design system          |
| static search + Markdown renderer                 |
+-------------------------+-------------------------+
                          |
                          v
                 immutable static output
                          |
             +------------+-------------+
             |                          |
             v                          v
       CDN / docs.auths.dev      release artifact archive
```

### 13.1 Tooling decisions

Use the following concrete stack. These choices are part of the specification,
not suggestions to revisit during implementation:

- **Runtime and package manager:** Node 22, Corepack, and `pnpm`, with an exact
  `packageManager` value and committed lockfile. CI rejects lockfile drift.
- **Site generator:** Astro with `@astrojs/starlight` and `@astrojs/mdx`.
  Starlight supplies the accessible documentation shell; a custom Auths theme
  owns navigation, reference layouts, language state, and visual identity.
- **Authoring:** `.mdx` for every human-authored public page. Plain Markdown is
  valid MDX, so prose stays simple while typed components remain available.
- **Types and parsing:** strict TypeScript, Astro content collections, and Zod
  schemas that parse untrusted files and release artifacts into closed types.
- **Client behavior:** Astro and small vanilla-TypeScript islands. Do not add
  React, Vue, or another client framework unless a measured requirement cannot
  be met with native browser APIs.
- **Code rendering:** Shiki with pinned grammars and themes.
- **Icons and brand assets:** the checked official Auths SVG plus one pinned,
  open icon family. Load icons individually or through a build-proven
  tree-shakable path; root imports that pull an entire icon catalog fail the
  client bundle budget. Text glyphs do not substitute for product-action icons.
- **Search:** Pagefind, built from the final static output and served without a
  hosted search dependency.
- **Diagrams:** pinned Mermaid tooling rendered to accessible SVG during the
  build. Production pages do not execute Mermaid in the browser.
- **Content transforms:** pinned `remark` and `rehype` plugins, including an
  Auths-owned MDX policy plugin.
- **Browser and accessibility tests:** Playwright and `axe-core`.
- **Performance and visual tests:** Lighthouse CI and Playwright screenshot
  comparisons on a bounded set of stable page templates.
- **Links:** a pinned, cross-platform link checker that validates HTML,
  Markdown twins, anchors, and release-pinned source links.
- **Deployment:** immutable static output compatible with Vercel, Cloudflare
  Pages, or ordinary object storage plus CDN.

Exact patch versions are locked in the docs repository. Major upgrades are
ordinary reviewed changes with a rendered preview and complete qualification;
no build dependency floats in CI.

Do not introduce a database, runtime CMS, account system, server-rendered
dependency, or production-time dependency on GitHub for the first release.

UX prototypes may use a different local framework to settle interaction and
visual contracts. They are evidence for component behavior, not permission to
replace this production stack, copy framework-specific runtime code, or add a
mutable dependency on the prototype repository. Promote the proven contracts
through the typed Astro components described here.

### 13.2 Authoring format and MDX policy

There are three deliberately different representations:

1. **Human-authored `.mdx`:** concepts, quickstarts, architecture, integration,
   security, and operations guidance.
2. **Generated page models:** signatures, parameters, returns, routes, errors,
   profiles, limits, versions, and evidence. These are typed data rendered by
   shared Astro templates; they are not generated or hand-edited MDX files.
3. **Executable example files:** real `.rs`, `.ts`, and `.py` sources compiled
   or run in clean consumers. MDX embeds them by scenario identity rather than
   duplicating them in fenced code blocks.

MDX is constrained so documentation remains content rather than an unbounded
application framework:

- pages may use only globally registered, allowlisted documentation
  components;
- arbitrary component imports, inline scripts, network access, and build-time
  side effects in MDX are rejected;
- authored pages never contain hand-written parameter tables, endpoint lists,
  support matrices, package versions, or copied executable examples;
- raw HTML is rejected except for an explicitly audited allowlist;
- each component receives schema-parsed props and renders in both HTML and
  canonical Markdown; and
- plans, research, private notes, and repository READMEs may remain `.md`
  because they are outside the public content collection.

The deployed `/<page>.md` representation is generated from the same parsed
page model as HTML. It is an output, never a second authored source.

### 13.3 Repository layout

```text
auths-proof-docs/
├── README.md
├── package.json
├── pnpm-lock.yaml
├── astro.config.ts
├── tsconfig.json
├── docs/
│   ├── plans/
│   ├── content-contract.md
│   └── authoring.md
├── site/
│   ├── src/content/docs/        # human-authored public .mdx
│   ├── src/components/          # allowlisted documentation components
│   ├── src/layouts/
│   ├── src/pages/reference/     # templates over typed page models
│   ├── src/generated/           # ignored build output; never committed
│   ├── src/styles/
│   ├── public/
│   └── tests/
├── examples/
│   ├── scenarios/               # typed expected-outcome manifests
│   ├── rust/
│   ├── typescript/
│   └── python/
├── schemas/
│   ├── docs-contract/
│   ├── page-model/
│   └── scenario/
├── tools/
│   ├── fetch-release/
│   ├── extract-rust/
│   ├── extract-typescript/
│   ├── extract-python/
│   ├── build-page-model/
│   ├── render-markdown/
│   └── check-links/
└── tests/
    ├── contract/
    ├── browser/
    └── visual/
```

Plans and internal research are never placed inside the public content
collection. Generated reference pages are materialized only in a temporary
build directory. The repository commits schemas, templates, mapping manifests,
authored MDX, and executable examples—not thousands of generated pages.

### 13.4 Release documentation contract

`auths-proof` publishes one checksummed documentation-contract artifact per
release candidate. It contains or references:

- release, semantic, protocol, ABI, and package identities;
- supported runtimes and SDK versions;
- the cross-language capability matrix;
- Rust, TypeScript, and Python public symbol exports;
- runtime route and content-type contracts;
- profile identities, limits, and stable outcomes;
- stable error registry;
- canonical example and adversarial fixtures;
- assurance-claim and evidence indexes; and
- source repository links pinned to the release commit.

The artifact contains facts, not marketing prose. A typed parser in the docs
repository rejects unknown contract versions, missing required sections,
duplicate semantic identities, malformed limits, and integrity mismatch before
content generation begins.

The top-level artifact is `auths-docs-contract-v1.json`. Its records use stable
semantic identities rather than presentation names or URLs. The central join
key is an operation identity such as:

```text
auths.operation.authority.create/1
```

An operation record may project to a Rust item, TypeScript export, Python
symbol, runtime endpoint, profile operation, errors, examples, and evidence.
The join never depends on a display label, function name, URL slug, source line,
or documentation heading.

Each SDK owns a small checked projection manifest:

```yaml
operation: auths.operation.authority.create/1
language: typescript
package: "@auths-dev/sdk"
symbol: createAuthority
entrypoint: auths
```

The manifest maps semantic identity to a public symbol. It does not repeat the
symbol's arguments, return type, documentation, or availability; those facts
come from the compiled public artifact. Missing symbols, duplicate mappings,
unmapped public operations, and mappings to private symbols fail CI.

### 13.5 Public-surface extraction

Reference facts are extracted from what users actually install, not inferred
from source layout:

- **Rust:** a pinned docs-only nightly emits rustdoc JSON for the released
  public crates. A pinned parser using the matching `rustdoc-types` schema
  converts it to the documentation contract. This nightly is build tooling
  only; it does not change the product's stable toolchain or MSRV.
- **TypeScript:** packed npm artifacts are installed into an empty consumer.
  `@microsoft/api-extractor` reads their emitted `.d.ts` files and produces a
  normalized API model.
- **Python:** built wheels are installed into an empty virtual environment.
  Griffe reads the installed runtime package and its `.pyi` typing contract;
  the extractor rejects disagreement between runtime exports and typed public
  exports.
- **Runtime API:** endpoints are not scraped from Axum source. Every public
  route is declared through a typed, Rust-owned `RuntimeEndpointSpec` beside
  the concrete handler. The route registry and docs exporter consume the same
  descriptor, and a completeness test rejects a public route without a spec or
  a spec without a registered route.
- **Profiles, errors, limits, and evidence:** existing typed registries,
  semantic-freeze identities, fixtures, and assurance manifests export their
  data into the same contract.

`RuntimeEndpointSpec` contains only public contract metadata: stable operation
and page identities, method, path, request and response schemas, outcomes,
stable error identities, authentication and trust-boundary requirements,
profile, maturity, and limits. It does not introduce a generic runtime router
or weaken the repository's concrete profile boundary.

The generation pipeline is one-way:

```text
installed packages + runtime/profile registries + fixtures
                              |
                              v
                    surface-specific extractors
                              |
                              v
             parsed AuthsDocsContract (stable identities)
                              |
                              v
              completeness + cross-language joins
                              |
                              v
                    typed ReferencePageModel
                 /            |             \
                v             v              v
              HTML       canonical .md   search/manifest
```

No generated output may become an input to another extractor. Every fact has a
single provenance record back to an installed artifact, Rust-owned registry,
or fixture.

### 13.6 Stable page mapping and content dependencies

Every public page has a stable `page_id`. Generated operation pages normally
derive it from the operation identity, while human pages declare it in
frontmatter. URLs are presentation and may change; page identities do not.

Human MDX links to generated facts with typed components:

```mdx
<ReferenceLink operation="auths.operation.authority.create/1" />
<ReferenceSignature operation="auths.operation.authority.create/1" />
<TestedExample scenario="rest-authorize-v1" />
```

The build resolves these identities to release-specific URLs and content.
Authors do not hardcode reference slugs, copy signatures, or paste examples.

Frontmatter also declares semantic dependencies:

```yaml
uses:
  operations: [auths.operation.authority.create/1]
  profiles: [auths.profile.rest-effect/1]
  errors: [auths.error.replay_detected/1]
  scenarios: [rest-authorize-v1]
```

The dependency graph makes a contract diff actionable. If an operation,
profile, error, or scenario changes, the originating pull request lists every
human page whose meaning may need review. The generated facts update
automatically; security or explanatory prose remains human-reviewed.

### 13.7 Exact change propagation

When a function argument changes:

1. the SDK is built and installed into an empty consumer;
2. its extractor observes the new compiled signature and changes the contract
   fingerprint for the same stable operation identity;
3. existing public-API and semantic-version gates classify the change;
4. the reference page renders the new argument automatically—there is no
   parameter table to edit;
5. every executable scenario using the function is compiled or run and fails
   at its real call site if it needs an update;
6. the dependency graph identifies authored pages that use the operation;
7. a docs preview shows the exact reference and guide diff; and
8. the code pull request cannot merge until the contract, examples, affected
   page review, and preview are consistent.

When an API endpoint is added:

1. the concrete handler is added with a `RuntimeEndpointSpec` containing stable
   operation and page identities;
2. the route-completeness test fails if either the handler or descriptor is
   absent;
3. the release contract exports the endpoint;
4. the runtime API page, navigation entry, search record, Markdown twin, and
   reference manifest are generated automatically;
5. stable or launch endpoints must declare schemas, outcomes, errors, trust
   boundary, limits, and at least one executable scenario; and
6. CI fails until all required coverage exists.

When a surface is removed or renamed before launch, Auths performs a direct
cutover. Stale mappings, links, examples, and semantic dependencies fail in the
same pull request. Compatibility aliases, redirects, and deprecation pages are
not created for unpublished surfaces. After 1.0, versioned release contracts
preserve the old reference under its supported release path.

### 13.8 Cross-repository preview and release flow

Separate repositories must not turn documentation into an eventually
consistent afterthought. A public-surface pull request in `auths-proof` runs:

```text
auths-proof PR
  -> build packed SDKs, wheels, crates, fixtures, and runtime metadata
  -> cargo xtask docs-contract
  -> sign/checksum one immutable PR artifact
  -> invoke the auths-proof-docs reusable preview workflow by pinned SHA
  -> install the artifact in an isolated checkout
  -> build reference, execute examples, render site, publish preview
  -> return one required "Documentation contract and preview" check
```

The invocation passes an immutable artifact digest and source commit, never a
mutable sibling checkout or branch name. Automatic contract-diff
classification decides whether the check is required; a label cannot suppress
it.

After merge, the release candidate publishes the same versioned contract
bundle. An automation opens or updates a docs-repository release pull request
pinned to its digest. Final package promotion and the stable docs deployment
require the docs qualification result for that exact digest. The deployed site
records the product commit, docs commit, package versions, contract version,
and artifact digest, so a previous static bundle can be restored exactly.

## 14. Content and component contracts

Every human-authored page has typed frontmatter:

```yaml
id: start.rest-api
title: Protect a REST effect
description: Give one caller authority for one exact application action.
audience: application-developer
depth: start
status: stable
languages: [rust, typescript, python]
products: [sdk, runtime]
release: inherited
reviewers: [sdk, security]
uses:
  operations: [auths.operation.authority.create/1]
  profiles: [auths.profile.rest-effect/1]
  errors: []
  scenarios: [rest-authorize-v1]
```

The parser accepts a closed set of identifiers. Unknown audience, depth,
status, language, product, or semantic dependency values fail the build.

The component system includes:

- `GlobalHeader`, `ContextNavigation`, `PageOutline`, and `ReferenceShell` for
  the two-row header and edge-aligned, collapsible documentation geometry;
- `OutcomeHero` for a concrete reader result;
- `LanguageGroup` for synchronized language panels;
- `CodeBlock` and `CodeBlockWithResult` for language-aware source, Bash
  overrides, and typed normalized results;
- `TestedExample` for source-linked executable code;
- `FiveVerbFlow` and `FiveNounMap` for the simple model;
- `OutcomeMatrix` for completed, denied, indeterminate, recoverable, verified,
  and rejected results;
- `TrustBoundary` for trusted and untrusted inputs;
- `Lifecycle` for state transitions without implying false success;
- `ReceiptView` for safe summary, authorized detail, and opaque views;
- `ProfileContract` for exact-effect documentation;
- `ReferenceSymbol` for generated signatures and types;
- `ReferenceLink` and `ReferenceSignature` for stable identity-based reference
  resolution without hardcoded URLs or copied declarations;
- `SecurityCallout`, `FailurePath`, and `OperationalCallout`;
- `VersionBadge` and `AvailabilityBadge`;
- `Diagram` with accessible text equivalent; and
- `PageActions` and `SectionActions` for page/section Markdown, source, prompt,
  and issue actions.

Components may standardize presentation. They must not generate profile
semantics, infer retry behavior, or convert denial into indeterminate.

## 15. Versioning and release behavior

Before launch, the site follows direct cutovers and does not preserve obsolete
prelaunch surfaces with deprecation pages or compatibility aliases. At public
1.0:

- `/` and unversioned paths describe the latest stable release;
- `/v/<major.minor>/...` preserves supported release documentation;
- `/next/...` documents the main-branch candidate with a permanent warning;
- every page shows its selected release and SDK package versions;
- code examples install exact compatible major/minor versions while allowing
  patch selection according to the support policy; and
- links between versions never silently cross from stable to `next`.

A release cannot publish until its documentation-contract artifact, generated
reference, examples, links, Markdown twins, and support matrix pass together.

## 16. Security, privacy, and accessibility

- Examples use obvious placeholders or deterministic public fixture material.
  Secret scanners run against authored content, generated output, build logs,
  and deployment bundles.
- Copy actions never include environment values, cookies, account identifiers,
  or analytics context.
- The site uses a restrictive content security policy and does not execute
  third-party scripts by default.
- Search is local for the first release. If hosted search is introduced later,
  query collection requires an explicit privacy decision.
- Code examples must distinguish public identity material, opaque authority,
  secret custody material, and authorized disclosure.
- Receipt examples default to bounded summaries. Sensitive detail appears only
  in pages explicitly teaching authorized disclosure.
- Focus, heading order, landmarks, tab semantics, contrast, reduced motion,
  zoom, and code scrolling are tested automatically and manually.
- Diagrams have text equivalents in HTML and Markdown.
- No essential instruction depends only on hover, animation, color, or a
  desktop-sized viewport.

## 17. APIs

The first release is statically served and exposes no mutable application API.
Its public read contract is:

```text
GET /<page>                         canonical HTML
GET /<page>.md                      canonical Markdown
GET /<page>/sections/<section>.md   bounded canonical section Markdown
GET /llms.txt                       concise machine index
GET /llms-full.txt                  bounded essential corpus
GET /.well-known/auths-docs.json    release and discovery metadata
GET /search-index.json              static search catalog
GET /reference/manifest.json        release-scoped reference identities
GET /sitemap.xml                    canonical route catalog
```

Build tools operate through typed local interfaces:

```text
fetchRelease(release_or_digest) -> VerifiedReleaseBundle
extractRust(bundle) -> RustSurface
extractTypeScript(bundle) -> TypeScriptSurface
extractPython(bundle) -> PythonSurface
parseDocsContract(bundle, surfaces) -> VerifiedDocsContract
buildPageModel(contract, authored_pages) -> VerifiedPageGraph
buildReference(page_graph) -> GeneratedReference
loadScenario(id) -> Scenario
verifyExample(language, scenario, release) -> NormalizedOutcome
renderHtml(page_graph) -> StaticHtml
renderMarkdown(page_graph) -> CanonicalMarkdown
buildSearch(page_graph) -> SearchIndex
```

Only `VerifiedDocsContract` may feed generated reference. Integrity checking,
contract-version parsing, and schema parsing occur before generation.

## 18. Implementation epics

Implement the following detailed epics in order. Each file follows the
implementation-spec house style used by AP-SPEC-038: zero-context starting
point, architecture, APIs, files, task checklist, adversarial tests, validation
commands, and an objective exit gate.

```text
auths-proof foundations
  Epic 1 contract/identities
       |
  Epic 2 source docs --------+
       |                      |
  Epic 3 product facts ------+
       |                      |
  Epic 4 installed bundle <--+
       |
auths-proof-docs product
  Epic 5 site/MDX foundation
       |
  Epic 6 progressive journey
       |
  Epic 7 executable examples
       |
  Epic 8 generated reference
       |
  Epic 9 deep guidance
       |
  Epic 10 machine surfaces
       |
  Epic 11 cross-repo qualification and release
```

1. [Freeze the documentation surface contract](0040/epic_1.md): establish
   stable operation, page, scenario, and SDK projection identities.
2. [Make the public API self-documenting at source](0040/epic_2.md): document
   public Rust, TypeScript, and Python surfaces by product priority and enforce
   installed documentation quality without incentivizing private-comment
   noise.
3. [Export runtime, profile, error, and assurance facts](0040/epic_3.md): make
   non-SDK product facts Rust-owned and machine-readable from the same sources
   that build the runtime.
4. [Extract installed SDK surfaces and publish the docs
   bundle](0040/epic_4.md): extract packaged crates, npm declarations, and
   wheel runtime/stub surfaces and join them through stable identities.
5. [Build the static docs foundation and MDX contract](0040/epic_5.md): create
   the constrained Astro/Starlight/MDX product and shared HTML/Markdown model.
6. [Ship the progressive product journey](0040/epic_6.md): deliver the five-
   verb fifteen-minute path and outcome-first information architecture.
7. [Build executable cross-language examples](0040/epic_7.md): run and compare
   every displayed Rust, TypeScript, and Python launch scenario.
8. [Generate the deep reference from stable identities](0040/epic_8.md): build
   operation, symbol, endpoint, profile, error, lifecycle, receipt, protocol,
   and assurance reference without checked-in generated MDX.
9. [Publish architecture, operations, integrations, and
   assurance](0040/epic_9.md): complete the deep human guidance and open-core
   runbooks.
10. [Deliver machine-readable and agent-first
    documentation](0040/epic_10.md): ship canonical Markdown, indexes,
    discovery, and an optional isolated read-only docs MCP.
11. [Enforce cross-repository qualification and release](0040/epic_11.md):
    make current-head documentation previews and immutable deployment part of
    the originating product change and release gate.

## 19. CI and quality gates

The maintainability guarantee begins in the repository that changes the public
surface. Every `auths-proof` pull request runs a lightweight contract-diff job
after its public artifacts build. If the fingerprint is unchanged, the docs
preview is optional. If it changes, CI automatically requires:

- installed-artifact extraction for each affected language;
- runtime route/spec completeness where runtime code changed;
- semantic operation and SDK projection completeness;
- public-API and version classification;
- regeneration and validation of the PR documentation contract;
- compilation or execution of affected examples;
- an affected-page report from semantic dependencies; and
- the digest-pinned `auths-proof-docs` preview result.

There is no manually applied `docs-not-required` label. A pull request cannot
claim that a public change is internal while the compiled contract says
otherwise.

Every pull request or invoked preview in `auths-proof-docs` runs:

- exact toolchain, lockfile, and immutable artifact checks;
- strict TypeScript, content-schema parsing, and MDX policy validation;
- release-artifact integrity, provenance, and contract-version checks;
- missing, duplicate, stale, or unmapped operation/page/symbol/route checks;
- generated reference and semantic-dependency graph checks;
- Rust, TypeScript, and Python executable example tests for affected scenarios;
- cross-language normalized-outcome comparison;
- rejection of copied signatures, parameter tables, endpoint inventories, and
  executable example fences in authored MDX;
- internal, external, anchor, stable-identity, source, and Markdown-twin link
  checks;
- secret and sensitive-fixture scanning;
- spelling and preferred-vocabulary checks;
- static-search and synonym-index checks;
- HTML validation;
- Playwright interaction and responsive tests;
- axe accessibility checks;
- deterministic screenshot comparisons for the home, guide, SDK reference,
  and runtime API reference templates at maintained desktop, tablet, narrow
  mobile, and 200-percent-zoom viewports;
- expanded/collapsed contextual navigation, two-row header alignment, centered
  search, sticky code-rail, and anchor-offset tests;
- synchronized Rust/TypeScript/Python selection plus Bash-override and JSON
  result-highlighting tests;
- Lighthouse budgets;
- sitemap, `llms.txt`, discovery, and reference-manifest checks; and
- a production-equivalent static deployment smoke test.

Generated reference output is not committed, so "drift" means disagreement
between schemas, mappings, installed artifacts, and rendered outputs—not a bot
rewriting thousands of checked-in pages. A compact contract fingerprint and
public-surface snapshot may remain in `auths-proof` for semantic diffing.

Nightly CI checks external links, all supported documentation versions, all
examples, and dependency vulnerabilities. Release CI runs the complete matrix
against the exact candidate packages and reference service, then records both
repository commits and the contract digest in the deploy manifest.

Flaky docs tests are defects. They may be quarantined only with an owner,
issue, expiration date, and no reduction in security or example-parity
coverage.

## 20. Content governance

Each public page has one owning area and required reviewers. Security claims,
protocol reference, profile semantics, and operational instructions require a
reviewer from the corresponding code ownership area.

Three source classes are allowed:

1. **Authored:** `.mdx` narrative, guides, architecture, and operations
   content using only allowlisted components.
2. **Generated:** signatures, routes, profiles, errors, limits, versions, and
   evidence facts from the release contract.
3. **Executable:** examples whose source is run in CI and embedded directly.

Generated facts must not be hand-edited. Authored prose must not restate exact
signatures, limits, or support matrices that the release contract can supply.
Executable code must not be copied into authored fences.

An automated freshness report lists pages whose owning public contract changed
since their last review. Freshness is a review signal, not permission for an
LLM to rewrite security claims automatically.

## 21. Explicit non-goals

The first release does not include:

- an authenticated customer dashboard;
- enterprise organization or fleet administration;
- a writable documentation MCP server;
- a general-purpose AI chat widget;
- a runtime CMS or documentation database;
- arbitrary in-browser execution against customer infrastructure;
- hidden compatibility pages for superseded prelaunch APIs;
- separate TypeScript or Python definitions of Auths semantics;
- automatic publication of every file under `docs/`; or
- claims that are not linked to release-scoped evidence.

## 22. Completion condition

AP-SPEC-040 is complete when Auths has one public documentation experience in
which:

- a newcomer reaches a safe first effect in fifteen minutes;
- the five-verb surface remains simple and prominent;
- Rust, TypeScript, and Python examples are idiomatic, switchable, executable,
  and semantically equal;
- architecture, operations, profiles, protocol, and assurance depth are easy
  to find without burdening the quickstart;
- every public surface is release-scoped and generated from verified facts;
- HTML and Markdown deliver the same meaning;
- search works for human language and exact technical identities;
- the site is accessible, fast, private by default, and statically
  self-hostable; and
- no website convenience can change, widen, or ambiguously describe Auths
  authorization semantics.

The desired result is not merely attractive documentation. It is an interface
that makes a new authority layer legible enough to adopt, precise enough to
trust, and structured enough for humans and agents to use without inventing
their own interpretation.

# Auths Documentation Site Plan

## Purpose

Build an exemplary documentation site that helps an engineer move from
understanding Auths to integrating and operating it without requiring them to
reverse-engineer the repository.

The site must:

- explain proof-carrying authorization clearly before introducing protocol
  detail;
- provide short, runnable integration paths for the supported surfaces;
- distinguish normative protocol requirements from explanatory guidance;
- make the offline-kernel boundary unmistakable;
- generate reference material from code, specifications, registries, and the
  canonical corpus wherever possible;
- detect documentation drift in CI instead of relying on maintainers to notice
  it;
- support custom diagrams, interactive inspectors, annotations, and other
  components through MDX;
- make version, stability, and provenance visible on every reference page; and
- remain useful when copied, printed, indexed, or read without JavaScript.

This plan covers the documentation system for the three-repository Auths
ecosystem. The site may live in a dedicated repository, but source-of-truth
material remains in the repository that owns it:

| Repository | Documentation ownership |
| --- | --- |
| `auths-proof` | Protocol, offline verification, canonical model and codec, authoring, ports, adapters, WASM, core corpus, errors, assurance, and security |
| `auths-proof-exchange` | Exchange protocol and transport implementations |
| `auths-proof-apps` | Application profiles, runtime behavior, custody integrations, replay/budget state, MCP, deployment, receipts, configuration, reference applications, and independent verifiers |

The documentation build may aggregate all three repositories. It must never
blur their dependency direction or imply that transport, live resolution,
runtime state, or application-profile logic belongs in `auths-proof`.

---

## 1. Technology Stack

### 1.1 Recommended framework: Astro Starlight

Use **Astro with Starlight**, TypeScript, and MDX.

Starlight is a better fit than a general application framework because the
primary artifact is a versioned, content-heavy, mostly static documentation
site. It provides the expected documentation primitives—navigation, table of
contents, search integration, internationalization readiness, code examples,
accessibility, and responsive layouts—without requiring the team to build a
docs shell from scratch.

Astro also allows React components for the few experiences that benefit from
client-side interaction while shipping ordinary documentation pages with
minimal JavaScript.

Recommended baseline:

| Concern | Choice | Reason |
| --- | --- | --- |
| Framework | Astro + Starlight | Static-first, docs-focused, accessible, MDX-native |
| Language | TypeScript, strict mode | Typed configuration and generated-content tooling |
| Content | MDX | Markdown ergonomics with controlled custom components |
| Package manager | Bun | Matches the website toolchain and provides fast scripts |
| Styling | Starlight tokens + small authored CSS layer | Preserve accessible defaults while carrying the Auths design language |
| Search | Pagefind initially | Static, private-deployment friendly, no hosted search dependency |
| Diagrams | Mermaid plus authored MDX components | Mermaid for maintainable flows; components for protocol-specific visuals |
| Syntax highlighting | Expressive Code | Annotations, line markers, titles, copy controls, and language tabs |
| API extraction | `cargo doc` JSON/rustdoc JSON pipeline | Rust items remain sourced from code |
| Schema extraction | CDDL parser/generator | Wire reference remains sourced from `auths-proof.cddl` |
| Testing | Vitest + Playwright + axe-core | Content transforms, navigation, examples, and accessibility |
| Link checking | Lychee | Checks repository and built-site links |
| Deployment | Vercel preview + production deployments | Fits the existing public site and supports preview URLs |
| Analytics | Privacy-preserving and optional | Do not make documentation depend on tracking |

### 1.2 Why not use the marketing-site application directly?

The landing site and documentation site should share visual tokens, header
language, and deployment infrastructure, but should not share an application
runtime. Documentation has different requirements:

- structured content collections;
- deep sidebar navigation;
- local search;
- versioned and generated reference pages;
- code-group and callout primitives;
- edit/provenance links;
- stale-content detection; and
- hundreds of static routes.

The public experience can still use one domain:

```text
auths.dev/                marketing site
auths.dev/docs/           documentation site
```

If independent Vercel projects make path routing awkward, use
`docs.auths.dev` initially and retain a prominent shared product navigation.

### 1.3 Repository layout

Prefer a dedicated `auths-proof-docs` repository for the site application. It
should fetch pinned revisions of the three source repositories during the
build. Do not place the Astro application inside the offline kernel.

```text
auths-proof-docs/
├── astro.config.mjs
├── package.json
├── bun.lock
├── src/
│   ├── content/
│   │   └── docs/                 # Authored MDX
│   ├── components/               # Purpose-built documentation components
│   ├── data/generated/           # Generated JSON; never edited manually
│   ├── layouts/
│   └── styles/
├── scripts/
│   ├── sync-sources.ts
│   ├── generate-all.ts
│   ├── check-generated.ts
│   ├── verify-snippets.ts
│   └── check-frontmatter.ts
├── vendor/
│   ├── auths-proof/              # Pinned source checkout
│   ├── auths-proof-exchange/
│   └── auths-proof-apps/
├── generated/
│   ├── api/
│   ├── errors/
│   ├── registry/
│   ├── schema/
│   └── corpus/
└── tests/
```

The source repositories should also expose stable documentation-export
commands through their own `xtask` or equivalent tooling. The docs repository
coordinates those commands but does not duplicate domain parsing.

### 1.4 MDX component policy

MDX components should explain Auths-specific concepts that plain Markdown
cannot express as clearly:

- `<AuthorityPath />` — trust root, grant, action, and narrowing constraints;
- `<ProofAnatomy />` — selectable proof-bundle objects and relationships;
- `<VerificationPipeline />` — bounded decode through sealed action;
- `<DecisionBadge />` — authorized, denied, or indeterminate semantics;
- `<ErrorCode />` and `<ErrorTable />` — generated error data with source links;
- `<RegistryEntry />` — status, identifier, implementation, and stability;
- `<FixtureExplorer />` — decoded canonical corpus vectors and expected result;
- `<ByteInspector />` — annotated CBOR bytes and CDDL fields;
- `<CompatibilityMatrix />` — generated crates, targets, features, and versions;
- `<CodeGroup />` — Rust, WebAssembly/TypeScript, and future independent
  implementations;
- `<Normative />`, `<SecurityNote />`, and `<BoundaryNote />` — visually and
  semantically distinct callouts; and
- `<SourceProvenance />` — source file, revision, and generation timestamp.

Components must render a meaningful static fallback. Core explanations,
examples, and reference tables must not require client-side JavaScript.

### 1.5 Visual design contract

The documentation site must look and feel like a deeper, more technical surface
of the main Auths landing page—not a separately branded Starlight template.
Starlight supplies accessible documentation behavior and structure, while the
Auths visual system controls its presentation.

The relationship should be:

```text
Landing page                         Documentation
────────────                         ─────────────
Editorial product story       ->     Structured technical explanation
Illustrative proof artifact   ->     Inspectable proof and fixture data
Numbered narrative sections   ->     Numbered guides and protocol stages
Dark integration panel        ->     Code examples and API reference
Authority-path diagrams       ->     Interactive protocol diagrams
```

#### Shared foundations

The docs site must reuse or derive the landing page's actual design tokens
rather than approximating them independently:

| Foundation | Required Auths treatment |
| --- | --- |
| Canvas | Warm off-white background |
| Surfaces | White cards and panels separated primarily by thin rules |
| Primary text | Near-black with high contrast |
| Secondary text | Restrained warm gray |
| Brand accent | Auths blue for links, active states, paths, and emphasis |
| Verification | Restrained green reserved for verified or successful states |
| Typography | Geist-style sans for prose and display; monospace for protocol metadata, identifiers, bytes, and labels |
| Shape | Compact radii; avoid soft, oversized “SaaS card” styling |
| Depth | Minimal shadows used only when they communicate layering or focus |
| Spacing | Generous section whitespace with denser spacing inside reference material |
| Rules | Thin borders and dividers as the primary organizational device |

The source of truth should be a small shared design-token package or generated
CSS contract consumed by both the landing-page and documentation repositories.
It should include color, typography, spacing, radius, shadow, border, motion,
and breakpoint tokens. CI should detect incompatible or missing token changes.
Sharing tokens must not require the two sites to share an application runtime.

#### Shared site chrome

The documentation site must use:

- the same `auths/` wordmark treatment;
- the same header height, horizontal proportions, and restrained sticky-header
  behavior;
- the same button hierarchy and external-link treatment;
- a shared product navigation model;
- a footer that uses the same typography, rule, and spacing language; and
- consistent focus, hover, selection, and reduced-motion behavior.

The docs-specific sidebar, search, version selector, breadcrumbs, and
table-of-contents rail should appear as natural extensions of that chrome. They
must not inherit Starlight's default colors, radii, or component styling
unchanged.

#### Documentation motifs

Reuse the landing page's characteristic visual vocabulary throughout the docs:

- numbered sections and steps;
- uppercase monospace kickers and technical labels;
- structured key/value records;
- proof cards and verification-state indicators;
- authority paths composed of nodes, lines, and narrowing transitions;
- dark code and integration panels;
- canonical byte, digest, audience, constraint, and resource metadata; and
- sparse blue emphasis instead of decorative gradients or illustration.

Custom diagrams should look like Auths protocol artifacts: precise lines,
bounded nodes, explicit direction, and inspectable labels. Avoid generic stock
illustrations, glossy three-dimensional graphics, oversized icon grids, and
visual effects unrelated to the authority model.

#### Information density

The landing page is intentionally editorial and spacious. Documentation pages
must retain that calm character while supporting more information:

- concept and guide introductions may use the landing page's wide editorial
  layouts;
- API, error, registry, schema, and corpus pages may become denser below the
  page introduction;
- prose line length should remain approximately 65–75 characters;
- tables must favor rules and alignment over heavy containers;
- the active navigation state should use blue text or a narrow blue rule rather
  than a large filled pill; and
- cards should be used for distinct artifacts or choices, not as the default
  wrapper around every paragraph.

#### Motion and interaction

Motion should be sparse, functional, and consistent with the landing page:

- short transitions for navigation, disclosure, selection, and copied states;
- subtle entry motion only for explanatory artifacts when it materially helps
  orientation;
- no continuous decorative animation;
- no movement that obscures stable byte, proof, or error comparisons; and
- full support for `prefers-reduced-motion`.

Interactive proof, byte, and fixture components should preserve the visual
structure when JavaScript is unavailable. Hover must never be the only way to
discover information, and every interaction must work by keyboard and touch.

#### Responsive behavior

On smaller screens:

- the shared product navigation collapses using the landing-page pattern;
- the documentation sidebar becomes an explicit contents drawer;
- the table of contents moves inline or into a disclosure;
- structured records stack without losing key/value association;
- diagrams switch to vertical authority paths;
- wide byte and code views scroll inside clearly bounded panels; and
- primary reading content remains visually dominant.

#### Visual acceptance criteria

Before public launch:

- a landing page and documentation page viewed side by side must unmistakably
  belong to one product;
- the docs shell must contain no visibly uncustomized Starlight components;
- shared tokens and chrome must render consistently across both repositories;
- light-theme contrast must meet WCAG 2.2 AA;
- dark code panels must match the landing site's integration-panel language;
- representative concept, guide, API, error, and corpus pages must pass desktop
  and mobile visual review; and
- screenshots of the shared header, buttons, proof artifact, code panel, and
  footer should be covered by targeted visual-regression tests.

---

## 2. Information Architecture

### 2.1 Top-level navigation

```text
+-----------------------------------------------------------------------+
| auths / docs      Learn  Build  Reference  Security  Conformance  [/] |
+-------------------+---------------------------------------------------+
| Sidebar           | Breadcrumbs                         On this page   |
|                   |                                                   |
| Introduction      | Page title                                        |
| Quickstart        | One-sentence purpose                              |
| Core concepts     |                                                   |
| Integrate         | Main content                                      |
| Protocol          | diagrams / code / fixtures                        |
| Reference         |                                                   |
| Security          |                                                   |
| Conformance       |                                                   |
+-------------------+---------------------------------------------------+
| Was this useful?  Edit page  Source revision  Report an issue         |
+-----------------------------------------------------------------------+
```

Primary topic groups:

1. **Start** — orientation, mental model, and first successful verification.
2. **Concepts** — authority, delegation, proof, evidence, action binding, trust,
   and decisions.
3. **Build** — authoring and verification guides for supported developer
   surfaces.
4. **Adapters** — principal-control methods and their assurance boundaries.
5. **Protocol** — normative V1 specification and wire-format material.
6. **Reference** — generated API, errors, registry, schema, limits, and
   compatibility.
7. **Security** — threat model, assurance, deployment guidance, and reporting.
8. **Conformance** — canonical corpus, fixtures, implementation requirements,
   and fuzzing.
9. **Contribute** — repository topology, development, specification changes,
   and releases.

### 2.2 User journeys

The site should support these paths without forcing every reader through the
entire protocol:

```text
New evaluator
  Start here -> Why Auths -> Mental model -> Quickstart -> Architecture

Rust integrator
  Quickstart -> Verify a proof -> Configure trust -> Handle decisions
  -> Rust API

Browser/edge integrator
  WASM quickstart -> Portable ABI -> Bundling/security notes -> API reference

Protocol implementer
  Protocol overview -> CDDL -> Verification algorithm -> Registries
  -> Error codes -> Canonical corpus -> Conformance checklist

Security reviewer
  Security model -> Trust assumptions -> Threat model -> Bounded verification
  -> Adapter assurance -> Corpus/fuzzing -> Architecture decisions

Auths ecosystem developer
  Repository map -> Correct extension point -> Ports and registries
  -> Specification change process -> CI and release checks
```

### 2.3 Content labels

Every page must declare one content class:

- **Guide** — goal-oriented instructions;
- **Concept** — explanatory mental model;
- **Reference** — exact lookup material;
- **Specification** — normative requirements;
- **Security** — security assumptions or operational controls; or
- **Generated** — derived from a machine-readable source.

Normative statements must appear only in specification sources. Guides may
summarize them but must link to the controlling section and avoid creating a
second normative definition.

---

## 3. Complete Page and File Map

Paths below are relative to `src/content/docs/` in the docs-site repository.
Files marked **generated** are build outputs and must not be edited manually.
Files marked **source mount** are rendered from the owning Auths repository with
site frontmatter supplied by the aggregation layer.

### 3.1 Start

```text
start/
├── index.mdx
├── why-auths.mdx
├── mental-model.mdx
├── quickstart-rust.mdx
├── quickstart-wasm.mdx
├── decisions-and-failures.mdx
└── where-auths-fits.mdx
```

- `index.mdx` — audience routing, the one-minute explanation, and next steps.
- `why-auths.mdx` — problems with ambient credentials and centralized,
  request-time authorization dependencies.
- `mental-model.mdx` — trust root → delegation → exact action → local
  verification, with `<AuthorityPath />`.
- `quickstart-rust.mdx` — the smallest compile-tested verifier integration.
- `quickstart-wasm.mdx` — browser/edge verification through
  `auths-proof-wasm`.
- `decisions-and-failures.mdx` — authorized versus denied versus indeterminate,
  including safe handling.
- `where-auths-fits.mdx` — Auths versus authentication, identity, policy
  authoring, exchange, runtime enforcement, and application profiles.

### 3.2 Concepts

```text
concepts/
├── index.mdx
├── trust-and-principals.mdx
├── grants-and-delegation.mdx
├── permissions-and-audiences.mdx
├── action-binding.mdx
├── authorization-plans.mdx
├── evidence-and-control.mdx
├── status-and-freshness.mdx
├── assurance.mdx
├── composition.mdx
├── canonical-encoding.mdx
├── deterministic-verification.mdx
├── bounded-verification.mdx
└── sealed-execution.mdx
```

Important distinctions:

- `trust-and-principals.mdx` must state that Auths is principal-system agnostic;
- `evidence-and-control.mdx` must distinguish carried static evidence from live
  acquisition, which belongs downstream;
- `sealed-execution.mdx` must emphasize executing decoded verified action bytes
  rather than the original caller request; and
- `bounded-verification.mdx` must expose default and hard limits from code.

### 3.3 Build with Auths

```text
build/
├── index.mdx
├── rust/
│   ├── install.mdx
│   ├── verify.mdx
│   ├── author-grants.mdx
│   ├── author-actions.mdx
│   ├── external-signing.mdx
│   ├── configure-registries.mdx
│   ├── configure-trust.mdx
│   ├── set-verifier-limits.mdx
│   ├── handle-results.mdx
│   └── no-std.mdx
├── wasm/
│   ├── install.mdx
│   ├── verify.mdx
│   ├── portable-abi.mdx
│   ├── bundlers.mdx
│   └── security-boundary.mdx
├── extension-points/
│   ├── index.mdx
│   ├── principal-method.mdx
│   ├── signature-suite.mdx
│   ├── resource-matcher.mdx
│   ├── profile-policy.mdx
│   ├── budget-algebra.mdx
│   ├── status-method.mdx
│   ├── assurance-rule.mdx
│   └── critical-extension.mdx
└── recipes/
    ├── threshold-approval.mdx
    ├── offline-environment.mdx
    ├── constrained-delegation.mdx
    ├── detached-attachments.mdx
    ├── status-snapshots.mdx
    ├── diagnose-indeterminate.mdx
    └── inspect-a-proof.mdx
```

All code in `build/` must be compiled or executed in CI. Snippets should be
extracted from complete examples where practical, using named regions rather
than maintaining partial copies.

### 3.4 Principal adapters

```text
adapters/
├── index.mdx
├── choosing-an-adapter.mdx
├── raw-key.mdx
├── did-key.mdx
├── did-keri.mdx
├── did-web.mdx
├── webauthn.mdx
├── hsm-attested.mdx
├── spiffe-x509.mdx
└── assurance-comparison.mdx
```

Each adapter page follows the same template:

1. what principal-control claim it proves;
2. which static evidence and explicit trust context are required;
3. supported subset and registry identifiers;
4. assurance properties and limitations;
5. offline-kernel versus upstream acquisition responsibilities;
6. runnable integration example;
7. relevant canonical fixtures;
8. errors specific to the adapter; and
9. links to the normative profile and Rust API.

`assurance-comparison.mdx` is generated from adapter metadata plus reviewed
human-authored descriptions. Generated fields include registry identifier,
crate, feature support, required evidence, status support, and implementation
state. Assurance judgments remain reviewed prose and must not be inferred by a
script.

### 3.5 Protocol V1

```text
protocol/
├── index.mdx
├── status-and-scope.mdx
├── four-planes.mdx
├── authority-objects.mdx
├── evidence-and-status.mdx
├── decisions.mdx
├── encoding.mdx
├── limits.mdx
├── conformance.mdx
├── verification-algorithm.mdx
├── domain-separation.mdx
├── registry.mdx
├── error-codes.mdx
├── schema.mdx
└── profiles/
    ├── did-key.mdx
    ├── did-keri.mdx
    ├── did-web.mdx
    ├── webauthn.mdx
    ├── hsm-attested.mdx
    └── spiffe-x509.mdx
```

The normative source remains `auths-proof/spec/v1/`. The site must not create a
forked MDX copy of those files. Use one of these approaches, in preference
order:

1. teach the content loader to render the source Markdown directly and attach
   site metadata;
2. generate MDX wrappers that import or embed the pinned source; or
3. copy during build into a generated directory with a source hash and a
   mandatory drift check.

`schema.mdx`, `registry.mdx`, and `error-codes.mdx` combine readable
explanation with generated reference tables. The underlying CDDL, registry
identifiers, and stable result codes remain authoritative.

### 3.6 Reference

```text
reference/
├── index.mdx
├── rust/
│   ├── index.mdx
│   ├── auths-proof.mdx
│   ├── auths-model.mdx
│   ├── auths-codec.mdx
│   ├── auths-verifier.mdx
│   ├── auths-author.mdx
│   ├── auths-ports.mdx
│   ├── auths-registries.mdx
│   ├── auths-authority.mdx
│   ├── auths-composition.mdx
│   ├── auths-assurance.mdx
│   ├── auths-status.mdx
│   └── auths-multikey.mdx
├── wasm/
│   ├── index.mdx
│   ├── verify-v1.mdx
│   ├── verify-self-contained-v1.mdx
│   └── engine-errors.mdx
├── errors/
│   ├── index.mdx
│   ├── verification-codes.mdx
│   ├── codec-errors.mdx
│   ├── model-errors.mdx
│   ├── author-errors.mdx
│   ├── port-errors.mdx
│   └── adapter-errors.mdx
├── data-model/
│   ├── index.mdx
│   ├── authority.mdx
│   ├── proof-bundle.mdx
│   ├── verifier-context.mdx
│   ├── verification-result.mdx
│   └── identifiers-and-digests.mdx
├── registries.mdx
├── verifier-limits.mdx
├── feature-flags.mdx
├── platform-support.mdx
├── compatibility.mdx
└── glossary.mdx
```

Rust API pages should be generated summaries optimized for discovery and link
to full rustdoc for item-level detail. Avoid building a second hand-authored
API reference. Each crate page includes:

- purpose and position in the dependency graph;
- feature flags and `no_std` status;
- public modules, types, traits, functions, and errors;
- selected rustdoc examples;
- minimum supported Rust version;
- source links pinned to the documented revision; and
- related guides and protocol sections.

### 3.7 Security

```text
security/
├── index.mdx
├── security-model.mdx
├── trust-assumptions.mdx
├── threat-model.mdx
├── verification-boundary.mdx
├── untrusted-input-and-limits.mdx
├── canonical-cbor-security.mdx
├── cryptographic-suites.mdx
├── adapter-assurance.mdx
├── operational-checklist.mdx
├── audit-readiness.mdx
└── report-a-vulnerability.mdx
```

`threat-model.mdx` and adapter assurance material should render from the
existing reviewed sources in `auths-proof/docs/`. Security pages show the source
revision and last substantive review date. CI should fail once a configured
review window expires rather than silently displaying stale security guidance.

### 3.8 Conformance and implementation

```text
conformance/
├── index.mdx
├── requirements.mdx
├── canonical-corpus.mdx
├── fixture-explorer.mdx
├── manifest-reference.mdx
├── semantic-digests.mdx
├── implementation-checklist.mdx
├── independent-implementations.mdx
├── fuzzing.mdx
└── release-gates.mdx
```

- `fixture-explorer.mdx` is generated from `fixtures/v1/manifest.json` and
  decoded `.cbor` files;
- every fixture page displays category, expected decision/code, involved
  objects, human-readable decoded form, canonical bytes, and source link;
- valid, denied, indeterminate, and malformed cases are filterable;
- `fuzzing.mdx` is generated in part from `fuzz/fuzz_targets/` so every target
  lists its entry point, seed corpus, covered boundary, and latest CI smoke
  status; and
- `release-gates.mdx` documents the exact `cargo xtask release-check` pipeline
  from code rather than a hand-maintained command list.

### 3.9 Architecture and contribution

```text
contribute/
├── index.mdx
├── repository-topology.mdx
├── kernel-architecture.mdx
├── crate-dependency-graph.mdx
├── development-setup.mdx
├── testing.mdx
├── xtask-reference.mdx
├── change-the-protocol.mdx
├── add-a-registry-entry.mdx
├── add-an-adapter.mdx
├── add-a-corpus-vector.mdx
├── fuzz-a-boundary.mdx
├── specification-style.mdx
├── documentation-style.mdx
├── release-process.mdx
└── decisions/
    ├── index.mdx
    └── [adr].mdx
```

The ADR index and individual ADR pages are generated from `docs/adr/*.md`.
Crate dependency diagrams are generated from Cargo metadata and checked against
the repository-boundary rules.

### 3.10 Ecosystem pages

The aggregate site may include sections sourced from downstream repositories:

```text
exchange/
├── index.mdx
├── protocol.mdx
├── memory.mdx
└── iroh.mdx

applications/
├── index.mdx
├── mcp/
├── deploy/
├── runtime/
├── receipts/
└── auths-lab/
```

These sections must visibly identify their owning repository. Links from kernel
pages should say “provided by Auths Exchange” or “provided by Auths Apps” rather
than presenting downstream behavior as part of the offline verifier.

---

## 4. Automation and Source-of-Truth Architecture

### 4.1 Generation pipeline

```text
+----------------------- auths-proof ------------------------+
| Rust source | spec/*.md | CDDL | fixture manifest | ADRs  |
+------+------------+--------+----------+--------------+------+
       |            |        |          |              |
       v            v        v          v              v
+----------------------------------------------------------------+
| Repository-owned exporters                                     |
| cargo xtask docs-export --out <dir>                             |
| - rustdoc/API JSON       - errors and stable codes              |
| - registries             - schema model                         |
| - limits/features        - corpus and fuzz metadata             |
+-------------------------------+--------------------------------+
                                |
                                v
+---------------------- auths-proof-docs -------------------------+
| sync pinned sources -> validate schemas -> generate MDX/data    |
| -> compile snippets -> build Astro -> link/a11y/search checks   |
+-------------------------------+--------------------------------+
                                |
                     +----------+----------+
                     v                     v
               Preview deploy        Production deploy
```

### 4.2 Add a repository-owned `xtask docs-export`

Extend `auths-proof/xtask` with:

```text
cargo xtask docs-export --out <directory>
cargo xtask docs-check
```

`docs-export` emits a versioned, deterministic bundle:

```text
docs-export/
├── manifest.json
├── workspace.json
├── api.json
├── errors.json
├── verification-codes.json
├── registries.json
├── limits.json
├── features.json
├── corpus.json
├── fuzz-targets.json
├── adrs.json
└── source-map.json
```

Requirements:

- stable, explicitly versioned JSON schemas;
- deterministic ordering and no wall-clock timestamps in content digests;
- source file and line anchors for every exported item where possible;
- Git revision recorded separately as build provenance;
- no networking;
- `--check` mode that compares regenerated output with committed snapshots when
  snapshots are retained; and
- tests that fail if public error types, verification codes, registry entries,
  xtask commands, or fixture classes are absent from the export.

The exporter should use domain APIs rather than regex-parsing Rust source
wherever possible. Rustdoc JSON is appropriate for API shape and documentation.
Small compile-time metadata tables are appropriate for registry/error fields
that need stable descriptions and remediation text.

### 4.3 SDK/API documentation

Generate API data from Rust code in two layers:

1. `cargo doc --workspace --no-deps` produces the canonical full Rust API
   documentation.
2. rustdoc JSON or a dedicated extractor creates site navigation, crate
   summaries, signatures, examples, stability, feature gates, and source links.

The docs site renders the summary pages and links each item to full rustdoc.
Public items without rustdoc should already fail the kernel quality gate.
Examples in rustdoc must compile as doctests.

When Go and TypeScript independent implementations exist in
`auths-proof-apps`, their API references should use language-native generators:

- Go doc comments and package metadata through `go doc`/a structured extractor;
- TypeScript declarations and TSDoc through API Extractor or TypeDoc.

Do not translate Rust API docs into other languages. Each implementation owns
its native API and exports a common set of cross-language concept identifiers
for linking.

### 4.4 Error and decision documentation

The error system needs a structured documentation contract. Each stable
verification code should expose:

```text
code
decision                  authorized | denied | indeterminate
stage
summary
security meaning
common causes
safe response
related requirement
protocol anchor
canonical fixture IDs
introduced version
```

Typed Rust errors additionally expose:

```text
crate
error type
variant
display message template
source link
conversion boundary
```

Generate the error pages and searchable error index from those structures.
Never scrape terminal output. The spec’s stable failure taxonomy, code enums,
and canonical corpus must cross-check one another:

- implemented stable code has a spec entry;
- non-reserved code has at least one fixture;
- fixture expected code exists in the model;
- documented remediation exists for every public stable code; and
- removed or renumbered V1 codes fail CI.

### 4.5 Registries, schemas, and wire format

Generate:

- registry tables from the executable registry declarations and
  `spec/v1/registry.md`;
- schema field reference from `spec/v1/auths-proof.cddl`;
- default/hard limits from `VerifierLimits` and related constants;
- domain-separation identifiers from codec constants;
- feature matrices from Cargo metadata;
- platform/MSRV data from `Cargo.toml`, `rust-toolchain.toml`, and CI; and
- canonical byte examples from committed `.cbor` fixtures.

The generated schema reference should always link back to the relevant
normative CDDL and protocol prose. A generated field list is a navigation aid,
not a replacement for normative semantics.

### 4.6 Canonical corpus explorer

Add a deterministic exporter that decodes every fixture into safe,
human-readable JSON plus byte annotations. The docs site consumes only
committed corpus files and exporter output.

For each fixture:

- show its manifest description and expected outcome;
- display the proof/action/context/result object relationship;
- offer hexadecimal and diagnostic views of CBOR;
- highlight bytes selected in the structured view;
- link to related error, registry, adapter, and protocol pages;
- show the command that verifies the corpus; and
- provide a download link to the exact committed bytes.

The browser component is an inspector, not an alternate verifier. Any
interactive verification demo must use the published WASM verifier and clearly
distinguish local experimentation from normative corpus results.

### 4.7 Executable examples and snippets

Store complete examples in compilable projects, not only MDX fences:

```text
examples/docs/
├── verify-minimal/
├── author-and-verify/
├── external-signing/
├── custom-principal-method/
├── wasm-browser/
└── no-std-verifier/
```

Use named source regions:

```rust
// docs:start:verify-minimal
// example code
// docs:end:verify-minimal
```

`scripts/verify-snippets.ts` extracts regions into MDX at build time and checks:

- referenced region exists exactly once;
- source compiles/tests in its native project;
- MDX does not contain a stale copied equivalent;
- dependency versions match the documented release; and
- expected output is generated by the example, normalized, and compared.

Security-sensitive examples must use conspicuously non-production key material
and include a generated warning. No example may encourage executing the
caller’s original bytes after verification.

### 4.8 CI workflow

Every pull request affecting code, specs, fixtures, examples, or docs runs:

```text
1. cargo xtask docs-export --out generated
2. fail if generated output differs
3. compile and test all referenced examples/doctests
4. validate MDX/frontmatter/content schemas
5. verify internal source anchors and external links
6. build Astro in strict mode
7. build Pagefind index
8. run unit tests for generators/components
9. run Playwright smoke tests for critical journeys
10. run axe accessibility checks
11. enforce performance and bundle-size budgets
12. deploy a preview and attach its URL to the pull request
```

Nightly jobs:

- external-link check;
- supported-toolchain and platform matrix validation;
- security-page review-age audit;
- Pagefind/search quality checks against a fixed query set;
- fuzz target/corpus inventory sync;
- broken source-line anchor detection; and
- screenshot checks for the small number of critical visual components.

Release jobs:

- pin the source revisions for all three repositories;
- run their release and docs-export gates;
- publish immutable versioned docs;
- update the `latest` alias only after all checks pass;
- emit a content manifest with hashes and provenance; and
- preserve the previous documentation version.

### 4.9 Local authoring commands

Expose a small, predictable command surface:

```text
bun run dev                 # sync if needed, then start the docs site
bun run generate            # regenerate all derived data and MDX
bun run generate:check      # fail on drift
bun run snippets:check      # compile and verify referenced examples
bun run links:check
bun run test
bun run check               # complete local pre-push gate
```

In `auths-proof`:

```text
cargo xtask docs-export --out <path>
cargo xtask docs-check
```

`cargo xtask ci` should include `docs-check` once the exporter exists.

---

## 5. Content and UX Standards

### 5.1 Every guide

Each guide contains:

- a specific outcome in the title;
- prerequisites and supported versions;
- a time estimate only when tested and defensible;
- one primary path before alternatives;
- complete copyable code backed by a compiled example;
- expected result;
- security implications;
- common failures linked to generated error entries; and
- next steps.

### 5.2 Every reference page

Each reference page contains:

- stability and protocol version;
- source repository and pinned revision;
- machine-generated fields clearly labeled;
- exact signatures or wire forms;
- valid and invalid examples where relevant;
- links to conceptual guidance;
- links to the normative source; and
- an edit/source link that targets the true owner, not generated output.

### 5.3 Writing style

- Lead with the developer outcome.
- Use “must” only for normative or security requirements.
- Separate identity/control from authority.
- Say “offline verification,” not “offline system,” when acquisition or
  runtime state may still occur upstream.
- Use “principal method” rather than making one identity technology sound
  required.
- Name the repository boundary when a workflow crosses it.
- Prefer concrete actions and decoded objects over abstract token language.
- Never claim production maturity, audits, or compatibility not evidenced by
  the repository.

### 5.4 Search

Index:

- titles, headings, summaries, aliases, and glossary terms;
- stable error codes and Rust error variants;
- registry identifiers;
- crate/module/type/function names;
- protocol field names;
- fixture IDs; and
- common synonyms such as “token,” “capability,” “delegation,” “MCP,” and
  “deployment approval.”

Provide scoped filters for Guides, API, Protocol, Errors, and Fixtures. Maintain
a fixed set of high-value queries and assert that an expected page appears in
the first results.

### 5.5 Accessibility

- WCAG 2.2 AA target;
- complete keyboard access for navigation, tabs, diagrams, and inspectors;
- no meaning conveyed by color alone;
- diagrams include an adjacent text description or data table;
- copy controls announce success;
- motion respects reduced-motion settings;
- code lines remain readable at browser zoom;
- focus is never trapped in interactive inspectors; and
- generated content passes the same checks as authored MDX.

### 5.6 Performance and resilience

- static HTML for all essential content;
- JavaScript only for search and explicitly interactive components;
- no client-side framework hydration for ordinary prose pages;
- documented per-route JavaScript and image budgets;
- self-hosted, subset fonts or system fonts;
- no third-party scripts required for reading, search, or navigation;
- print stylesheet for specifications and security material; and
- useful 404 page with search, top destinations, and error-code detection.

---

## 6. Exemplary Features

These features would make the site materially better than a standard docs
template:

### 6.1 Proof anatomy explorer

An interactive but progressively enhanced view that connects:

- authorization plan leaves;
- grants and parent references;
- principal-control evidence;
- action envelope;
- trust context;
- verification stages; and
- final decision.

Selecting an object highlights the canonical fixture bytes and the relevant
CDDL and protocol sections.

### 6.2 Decision explainer

Paste a portable verification result or select a canonical fixture to see:

- decision and code;
- stage;
- consumed resources;
- safe operational response;
- related protocol requirement;
- relevant source implementation; and
- whether the result is denied or indeterminate and why the distinction
  matters.

This consumes static result data or runs the official WASM verifier locally. It
must not accept secrets, send proof material to a server, or imply that it
replaces application enforcement.

### 6.3 Boundary map

Every architecture page can invoke a shared diagram showing ownership:

```text
acquire evidence       exchange proof        verify proof       execute action
      |                      |                    |                    |
      v                      v                    v                    v
auths-proof-apps    auths-proof-exchange     auths-proof      auths-proof-apps
```

Selecting a stage shows allowed dependencies and the correct extension point.
This directly prevents integrations from placing network or application logic
inside the kernel.

### 6.4 “Show me the bytes”

Examples can toggle among:

- domain object;
- diagnostic notation;
- hexadecimal canonical CBOR;
- signing preimage;
- content identifier; and
- verification result.

All views are generated from canonical code and fixtures, preventing prose from
drifting away from wire behavior.

### 6.5 Documentation provenance

Generated and normative pages display:

- source repository;
- Git revision;
- source file;
- protocol version;
- generation schema version; and
- last reviewed date for human security analysis.

The footer should link to the precise source rather than a repository root.

### 6.6 Downloadable conformance kit

Offer a release-pinned bundle containing:

- CDDL;
- registry and error metadata;
- canonical corpus and manifest;
- semantic digests;
- implementation checklist; and
- verifier output schema.

Publish a checksum and content manifest. Generate the bundle from the same
release inputs as the docs.

---

## 7. Versioning and Release Policy

Prelaunch status means there is no migration documentation requirement and no
need to invent V1-to-V2 upgrade pages.

The site should still distinguish:

- `main` or `next` documentation for active development;
- immutable docs for published protocol releases once they exist; and
- API stability labels such as experimental, pre-release, or stable.

Protocol versions, crate versions, docs revisions, and corpus revisions are
related but not interchangeable. A version selector must communicate which one
it changes.

Until the first supported release, publish one clearly labeled
**pre-release/current** site. Do not build empty version archives.

---

## 8. Delivery Sequence

### Phase 1: Foundation

- create the dedicated Astro/Starlight repository;
- establish Auths tokens, navigation, MDX component policy, and content schema;
- implement source pinning and provenance;
- mount existing specs, architecture, threat model, assurance model, and ADRs;
- ship Start, Concepts, Security, and Protocol entry pages;
- add Pagefind, link checking, accessibility checks, previews, and production
  deployment.

### Phase 2: Generated reference

- implement `cargo xtask docs-export` and its schema;
- generate Rust API summaries, stable error pages, registries, limits, features,
  and schema reference;
- add drift checks to `cargo xtask ci`;
- add source links and generated-content labels.

### Phase 3: Integration guides

- create the compile-tested `examples/docs/` workspace;
- write Rust verification and authoring guides;
- write WASM verification guides;
- add extension-point guides;
- implement named-region extraction and expected-output checks.

### Phase 4: Conformance experience

- generate corpus and fuzz inventories;
- build the fixture explorer and byte inspector;
- publish the conformance kit;
- add independent-implementation checklists.

### Phase 5: Ecosystem aggregation

- pin and ingest `auths-proof-exchange` and `auths-proof-apps`;
- add exchange, MCP, deployment, runtime, and reference-application sections;
- generate native Go and TypeScript API references when those implementations
  exist;
- verify repository ownership labels and cross-repository links.

---

## 9. Definition of Done

The documentation system is ready for its first public release when:

- an unfamiliar engineer can explain the Auths authority model after the Start
  path;
- Rust and WASM quickstarts work from a clean checkout;
- all public Rust APIs are reachable from generated reference navigation;
- every stable verification code has generated causes, safe handling, protocol
  linkage, and corpus coverage;
- every registry entry, CDDL field, verifier limit, and fixture is sourced from
  authoritative repository data;
- no normative specification is hand-copied into MDX;
- code and generated documentation drift fails CI;
- all critical user journeys pass browser and accessibility checks;
- search reliably resolves concepts, API names, errors, registry IDs, and
  fixture IDs;
- every page identifies its owning repository and version;
- kernel pages never imply ownership of exchange, live acquisition, runtime, or
  application behavior; and
- the complete site is readable, navigable, and technically useful without
  client-side JavaScript.

# Epic 10 — Deliver Machine-Readable and Agent-First Documentation

**Parent:** [AP-SPEC-040](../0040-stripe-quality-documentation-platform.md)

**Repository:** `auths-proof-docs`

**Depends on:** Epics 5–9

**Blocks:** Epic 11

## Outcome

Make the same release-scoped documentation directly usable by browsers,
terminals, crawlers, coding agents, and later a read-only docs MCP server
without scraping site chrome or granting product authority.

Machine surfaces are alternate renderings and indexes over the verified page
graph. They are not independently authored corpora.

## Zero-context starting point

Read:

- parent sections 12, 13, 16, and 17;
- Epics 5, 7, 8, and 9;
- the verified page-graph and reference-manifest schemas;
- the HTML and Markdown component-rendering contracts;
- current Stripe agent/Markdown documentation patterns linked by the parent;
  and
- Auths MCP product surfaces, ensuring the docs service remains a different,
  inert boundary.

## Static public contract

Serve:

```text
GET /<page>                         canonical HTML
GET /<page>.md                      canonical Markdown
GET /<page>/sections/<section>.md   bounded canonical section Markdown
GET /llms.txt                       concise machine index
GET /llms-full.txt                  bounded essential corpus
GET /.well-known/auths-docs.json    discovery and release metadata
GET /search-index.json              bounded static search catalog
GET /reference/manifest.json        release-scoped semantic identities
GET /sitemap.xml                    canonical human routes
```

Every response is immutable for a versioned release, has a bounded size, and
declares the release/contract identity through content and headers where the
host supports them.

Section IDs are stable, closed page-model identities rather than heading-text
slugs inferred at click time. Only sections declared independently useful by
the page template receive a section Markdown route.

## Canonical Markdown

Render Markdown from `VerifiedPageGraph`, not by converting final HTML and not
from a second set of `.md` source files.

Markdown must preserve:

- title, description, release, status, and canonical URL;
- headings and prose;
- language-labelled executable examples;
- generated signatures and reference tables;
- security/failure/operations callout meaning;
- diagram text equivalents instead of inaccessible SVG alone;
- source/evidence links pinned to the release; and
- related semantic pages.

Strip navigation chrome, theme controls, copy buttons, analytics, and hidden UI
labels. Component tests compare semantic blocks rather than whitespace.

## Page actions

Every public page offers:

- **Copy for LLM** — copies canonical page Markdown only;
- **View as Markdown** — navigates to the `.md` URL;
- **Open source** — release-pinned authored source or generated provenance;
- **Report an issue** — pre-fills canonical page ID and release, not page
  contents; and
- **Ask an agent** — copies a bounded prompt with canonical URL, release,
  declared goal, and instruction to retrieve current page Markdown.

Page actions appear immediately below the title and description. Long
reference templates also provide section actions beside eligible headings:

- **Copy for LLM** copies only the canonical section Markdown; and
- **View as Markdown** opens `/<page>/sections/<section>.md`.

A section projection includes its title, relevant prose, generated facts,
security/failure callouts, all declared language examples, page/section
identities, release, and parent canonical URL. It excludes adjacent sections,
navigation, inactive local UI state, and a sticky example belonging to another
semantic step.

Copy actions never include cookies, local storage, search history, environment
values, account identifiers, credentials, or undisclosed receipt material.

## Discovery formats

`/.well-known/auths-docs.json` includes:

- schema version;
- docs release and product release;
- contract and deploy digests;
- supported documentation versions;
- canonical base URLs;
- SDK coordinates and supported runtimes;
- Markdown URL convention;
- search, sitemap, and reference manifest URLs; and
- integrity/provenance metadata.

`/reference/manifest.json` maps stable operation, page, symbol, endpoint,
profile, error, scenario, and evidence identities to release-specific URLs.

`llms.txt` is a concise curated index. `llms-full.txt` contains the bounded
essential product/start/architecture corpus and links to deep reference rather
than concatenating every generated symbol page into an enormous payload.

## Search contract

Search runs over a bounded static index. It supports product vocabulary,
language symbols, error codes, endpoints, profiles, common synonyms, and page
titles. Results expose canonical URL, page ID, release, availability, language,
and a bounded excerpt.

Do not index:

- internal/private symbols;
- draft or excluded pages;
- raw receipt/proof/action material;
- source plans and scratch files;
- unpublished release bundles; or
- navigation/footer text.

## Read-only docs MCP — phase two

Add only after all static surfaces pass qualification:

```text
search_auths_docs(query, version?, language?)
read_auths_doc(page_id, version?, section?)
resolve_auths_symbol(symbol, language, version?)
explain_auths_error(code, version?)
```

The server reads immutable static indexes and bounded Markdown excerpts. It:

- has no product credentials, signer, custody port, runtime client, lifecycle
  store, provider gateway, or mutation tool;
- cannot authorize, delegate, approve, execute, resume, disclose a private
  receipt, or inspect caller state;
- rejects unknown versions/IDs and bounds query, excerpt, and result counts;
- returns canonical URLs and release identity with every result; and
- emits privacy-safe aggregate operations metrics only if explicitly enabled.

Do not combine this server with Auths authority or agent-execution MCP tools.

## Architecture

```text
VerifiedPageGraph
   |
   +--> HTML renderer --------> /page
   +--> Markdown renderer ----> /page.md
   +--> index builders -------> llms / search / sitemap / manifest
   |
   +--> optional inert MCP ---> bounded reads of the same artifacts
```

All outputs record one page-graph digest. A parity checker ensures no output is
built from a different release or graph.

## Implementation steps

- [ ] Finish Markdown renderers for every allowed component.
- [ ] Generate and route canonical `.md` twins.
- [ ] Build page actions with bounded copy/prompt behavior.
- [ ] Generate eligible section Markdown projections and build reusable
  section actions over stable section identities.
- [ ] Generate discovery metadata, reference manifest, sitemap, `llms.txt`, and
  bounded `llms-full.txt`.
- [ ] Build the final static search index and synonym registry.
- [ ] Add semantic HTML/Markdown parity tests.
- [ ] Add content-type, cache, CSP, robots, and canonical-link behavior.
- [ ] Qualify all static surfaces before considering MCP.
- [ ] If MCP proceeds, implement it as a separate read-only deployment over
  immutable artifacts and threat-model it independently.

## Adversarial tests

Catch:

- HTML and Markdown with different outcomes or security warnings;
- Markdown generated by lossy HTML scraping;
- copied page content containing hidden UI or local state;
- a section copy containing neighboring content or the wrong sticky code rail;
- a section route derived from mutable heading text or an unknown section ID;
- a generated index pointing across releases silently;
- `llms-full.txt` exceeding its bound;
- draft/private pages appearing in search, sitemap, or manifests;
- a symbol resolver returning a similarly named private symbol;
- query or section parameters causing path traversal;
- an MCP result without release/canonical URL;
- MCP access to a runtime client, credentials, network destinations, or
  mutation path;
- prompt injection stored in search metadata altering tool behavior; and
- receipts, actions, principals, credentials, or secrets leaking through logs
  or indexes.

## Validation commands

```text
pnpm docs:render-markdown
pnpm docs:build-indexes
pnpm test:markdown
pnpm test:parity
pnpm test:search
pnpm test:machine-surfaces
pnpm build
```

If phase-two MCP exists, add its contract, fuzz, bounded-input, and no-capability
tests as a separate required job.

## Exit gate

This epic is complete when every public page has equivalent HTML and Markdown,
machine indexes resolve stable identities for one exact release, page actions
and eligible section actions copy only bounded canonical projections, no private
material enters public indexes, and any docs MCP is demonstrably read-only,
effect-free, and isolated from all Auths product authority.

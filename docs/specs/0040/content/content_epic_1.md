# Content Epic 1 — Global Information Architecture and Topic Landings

**Depends on:** [Content Epic 0](./epic_0.md) and Platform Epics P5–P6.

**Ownership:** This epic owns public taxonomy, route selection, landing-card
curation, and explanatory copy. Platform code owns the typed navigation and
landing models and validates every referenced page identity.

## Outcome

Replace the implementation-oriented global navigation with durable reader
domains and give every domain a curated landing page before its detailed tree.

## Current problem

The current header exposes `Start`, `SDKs`, `Runtime API`, `Concepts`,
`Architecture`, and `Operations`. This mixes a journey, two reference formats,
two explanatory content types, and one operating domain. It cannot scale without
turning the global bar into a sitemap, and it offers no first-class route for
identity/trust or agent builders.

Stripe's global topics lead to curated landing pages, while local sidebars carry
the exhaustive domain tree. [Research evidence](./STRIPE_CONTENT_RESEARCH.md#batch-1--global-landings-catalogs-and-depth-transitions)

## Information architecture

```text
Primary topics
├── Get started
├── Identity & trust
├── Authority
├── Agents
├── Operations
└── Developers

Utility destinations
├── APIs & SDKs
├── Search
└── GitHub

Cross-linked domain
└── Assurance
```

## Required landing routes

| Stable page identity | Route | Reader promise |
|---|---|---|
| `auths.page.start/1` | `/get-started` | Choose and complete the right first Auths path |
| `auths.page.identity-trust/1` | `/identity-trust` | Bring identity and trust without adopting a fixed provider or suite |
| `auths.page.authority/1` | `/authority` | Create, narrow, approve, execute, recover, and prove exact authority |
| `auths.page.agents/1` | `/agents` | Give agents bounded authority without granting ambient credentials |
| `auths.page.operations/1` | `/operations` | Run the open runtime safely in production |
| `auths.page.developers/1` | `/developers` | Find SDKs, tools, testing, integrations, and extension contracts |
| `auths.page.reference/1` | `/reference` | Choose SDK, Runtime API, CLI, schema, error, or evidence reference |
| `auths.page.assurance/1` | `/assurance` | Inspect claims, evidence, limitations, and reproduction |

## Landing-page contract

Every landing must contain, in order:

1. one outcome-oriented `h1` and one-sentence promise;
2. one recommended path with a primary action;
3. three to six grouped task cards with descriptions;
4. explicit audience exits where another landing is more appropriate;
5. “understand first” links to tours or design guides;
6. “build now” links to qualified quickstarts;
7. “go deeper” links to operations, reference, or assurance;
8. canonical page Markdown actions; and
9. generated contextual navigation from stable page identities.

Landing cards must not duplicate the entire sidebar. Cards are editorial and
ordered; the sidebar is exhaustive and generated.

## Implementation steps

- [ ] Declare the eight page identities and dependencies in the authored page
  manifest accepted by P6.
- [ ] Author the six-topic global navigation configuration and separate
  `APIs & SDKs` utility destination.
- [ ] Curate the contextual tree for each topic from verified page identities.
- [ ] Author the eight landing pages from the page contract above.
- [ ] Declare breadcrumb and back-to-landing relationships for every descendant
  page.
- [ ] Preserve direct aliases from `/sdk`, `/reference/sdk`, and existing
  public routes only where the prelaunch route map explicitly chooses them;
  remove accidental duplicate destinations.
- [ ] Review the P6/P10 renderings of the same page graph across HTML,
  canonical Markdown, sitemap, search, and navigation.
- [ ] Qualify navigation at wide, medium, and narrow breakpoints.

## Acceptance criteria

- Every global topic opens a useful landing, not the first child article.
- No global navigation item names a page format such as “Concepts” or
  “Architecture.”
- APIs and SDKs remain reachable in one action from every page.
- A landing never contains more than six groups or more than six cards per
  group.
- Collapsing contextual navigation widens the reading surface.
- Keyboard, screen-reader, zoom, reduced-motion, and mobile navigation tests
  pass.
- Every landing has a canonical `.md` projection and no hand-authored reference
  facts.

## Validation

```text
npm run typecheck
npm run lint
npm run test:content
npm run test:navigation
npm run test:a11y
npm run test:markdown
npm run build
```

# Auths Documentation Content and Link Audit

**Audit date:** 2026-08-14  
**Rendered target:** `http://localhost:3000`  
**Scope:** every registered public page and every internal link inside each
page's `<main>` content. Global header and footer links are assessed separately
by the site-shell qualification suite.

## Verdict

The current documentation has a credible visual prototype and a useful
content-ownership foundation, but it is not yet a coherent documentation
product. The landing pages look organized while the next click frequently
drops the reader into a shallow, context-free page. The site currently models
pages as isolated records; it does not model a reader's durable place inside a
topic.

This is a structural failure, not a copy-editing problem.

The implementation of Content Epics 1–9 must not continue as additive page
creation. The site first needs a canonical hierarchy, topic-local navigation,
route ownership, content-depth contracts, and link-intent qualification.

## Measured findings

| Measure | Result | Meaning |
|---|---:|---|
| Registered HTML pages audited | 92 | Every page in the current content registries was rendered |
| Internal `<main>` links audited | 217 | Includes navigation, Markdown, section Markdown, and downloads |
| Navigational links | 109 | HTML destinations and topic transitions |
| Markdown links | 101 | Page and section machine-readable views |
| Download links | 7 | One per generated quickstart |
| Pages without any detected left navigation | 83 | Only 9 pages expose any left-side structure |
| Pages under 80 rendered words | 55 | Most new pages are labels plus one paragraph |
| Pages with no code block | 82 | Only SDK, Runtime API, quickstarts, and one REST guide contain code |
| Pages with at most one substantive destination | 68 | Most pages are dead ends after excluding their Markdown action |
| Navigational orphans | 60 | No other rendered page links to them after excluding self Markdown links |
| Broken HTML route targets | 0 | Routing works; relevance and hierarchy do not |
| Missing Markdown targets | 1 | `/reference/cli.md` is linked but absent |

## Primary-section audit

None of the six top-level sections has a topic-local left navigation. Links are
syntactically valid but often leave the section immediately.

### Get started

Current links:

- `/get-started/choose` — related and inside the section;
- `/get-started/local` — related and inside the section;
- `/get-started/agent` — related and inside the section;
- `/get-started/verify` — related and inside the section;
- `/get-started/prerequisites` — related and inside the section;
- `/get-started/cross-company` — related and inside the section; and
- `/get-started/evaluate` — related and inside the section.

The landing is the least misleading of the six, but its children have no
shared navigation, almost no code, and frequently hand off to legacy
`/start/*` or `/guides/*` pages.

### Identity & trust

Only `/identity-trust/how-it-works` descends into the section. The remaining
cards jump to generic destinations:

- “Compose existing identity” → `/integrations`;
- “Keep adapters replaceable” → `/architecture`;
- “Turn identity into bounded action” → `/authority`;
- “Verify offline” → `/start/verify-receipt`;
- “Review agility claims” → `/assurance`; and
- “Open exact contracts” → `/reference`.

These are potentially useful related links, but they are presented as if they
were the identity documentation itself. No page exists for raw keys, OIDC,
SPIFFE, application resolvers, suite selection, trust policy, key exchange, or
rotation.

### Authority

Only the lifecycle, approval-plan, and receipt pages live under `/authority`.
The landing sends its core verbs elsewhere:

- “Create” and the recommended path → `/guides/protect-rest-effect`;
- “Delegate” → `/start/delegate-agent`; and
- “Execute and recover” → `/operations`.

This makes Authority look like a label placed over unrelated pages. It has no
topic-local pages for the authority model, authoring, constraints, delegation,
use/budget bounds, revocation, verification, or profile semantics.

### Agents

Every substantive landing card leaves `/agents`:

- “Delegate one tool” and “Delegate without widening” →
  `/start/delegate-agent`;
- “Protect an effect” → `/guides/protect-rest-effect`;
- “Verify what happened” → `/start/verify-receipt`;
- “MCP and transports” → `/integrations`;
- “Agent identity” → `/identity-trust`; and
- “Closed execution” → `/operations`.

The MCP link is materially misleading: the destination is a generic
integration overview with no MCP client or protected-server workflow. Seven
new `/agents/*` pages exist in the registry, but the landing does not link to
them; all seven are orphans and contain no code.

### Production operations

Only `/operations/execution-lifecycle` descends into the section. Other cards
jump to Runtime reference, Architecture, receipt starter content, Assurance,
or Developers. Eleven operational pages exist but ten are not linked by the
landing, most contain roughly 40–50 words, and none provides tested commands,
observations, stop conditions, or rollback steps.

### Developers

Every landing card leaves `/developers`:

- SDKs → `/reference/sdk`;
- Runtime API → `/reference/runtime-api`;
- Quickstarts → `/guides/protect-rest-effect`;
- Integrations → `/integrations`;
- Agents and MCP → `/agents`; and
- Testing and evidence → `/assurance`.

The SDK and Runtime destinations are technically useful, but the landing does
not lead through developer-owned index pages. The Quickstarts card is singular
and misleading: it promises a catalog and opens one legacy REST guide. Six
`/developers/*` pages and five secondary reference pages exist but are not
linked from the landing.

## Page and link inventory

The tables below cover every registered HTML page and every link rendered in
its main content. “MD” means the page's `View as Markdown` link to the same
route. “No topic nav” means either no left navigation or a legacy page-specific
nav that does not preserve the owning top-level section.

### Home and legacy journey pages

| Page | Main-content links | Audit |
|---|---|---|
| `/` | `/guides/protect-rest-effect` (four placements), `#model`, `/start/delegate-agent`, `/start/verify-receipt` | No topic nav; routes readers into legacy namespaces |
| `/guides/protect-rest-effect` | `/`, MD | Has code and a page-specific nav, but is a dead end outside the six-section hierarchy |
| `/start/delegate-agent` | MD, `/start/verify-receipt` | Legacy nav; zero code; not owned by Agents or Authority |
| `/start/verify-receipt` | MD, `/concepts` | Legacy nav; zero code; not owned by Identity, Authority, or Assurance |
| `/concepts` | `/concepts/index.md`, `/architecture` | Page-specific nav; dead end |
| `/concepts/auths-in-15-minutes` | MD, `/get-started/local`, `/reference/sdk` | No topic nav |
| `/architecture` | `/architecture/index.md`, `/operations` | Page-specific nav; dead end |
| `/architecture/trust-boundaries` | `/architecture/trust-boundaries/index.md` | Page-specific nav; dead end |

### Get started and adoption

| Page | Main-content links | Audit |
|---|---|---|
| `/get-started` | MD; `/get-started/choose`; `/local`; `/agent`; `/verify`; `/prerequisites`; `/cross-company`; `/evaluate` under the same prefix | No topic nav |
| `/get-started/choose` | MD, `/get-started/local` | Thin; chooser has no persistent section context |
| `/get-started/prerequisites` | MD only | Dead end; no code |
| `/get-started/local` | MD, `/guides/protect-rest-effect` | Hands off to legacy route; no code itself |
| `/get-started/runtime` | MD, `/guides/protect-rest-effect` | Wrong scenario destination; no runtime code |
| `/get-started/agent` | MD, `/start/delegate-agent` | Wrong namespace; no code |
| `/get-started/verify` | MD, `/start/verify-receipt` | Wrong namespace; no code |
| `/get-started/cross-company` | MD, `/start/delegate-agent`, `/start/verify-receipt` | Two generic handoffs; no cross-company workflow |
| `/get-started/evaluate` | MD, `/guides/protect-rest-effect`, `/start/delegate-agent`, `/start/verify-receipt` | Scenario index points only to legacy pages |
| `/get-started/adopt` | MD only | Orphan; dead end |
| `/adopt/plan` | MD only | Orphan; thin |
| `/adopt/signed-requests` | MD only | Orphan; thin |
| `/adopt/oauth-oidc` | MD only | Orphan; thin |
| `/adopt/api-keys` | MD only | Orphan; thin |
| `/adopt/cloud-iam` | MD only | Orphan; thin |
| `/adopt/policy-engines` | MD only | Orphan; thin |
| `/adopt/capabilities` | MD only | Orphan; thin |
| `/adopt/approvals` | MD, `/developers` | Orphan; tested-scenario link loses context |
| `/adopt/shadow-mode` | MD only | Orphan; thin |
| `/adopt/cutover` | MD only | Orphan; thin |

### Identity and trust

| Page | Main-content links | Audit |
|---|---|---|
| `/identity-trust` | MD, `/identity-trust/how-it-works`, `/integrations`, `/architecture`, `/authority`, `/start/verify-receipt`, `/assurance`, `/reference` | Six of seven content cards leave the section |
| `/identity-trust/how-it-works` | MD, `/identity-trust`, `/architecture/trust-boundaries` | No topic nav; conceptual only |
| `/integrations/identity-trust` | MD only | Orphan, thin, and outside Identity namespace |

### Authority

| Page | Main-content links | Audit |
|---|---|---|
| `/authority` | MD, `/guides/protect-rest-effect` twice, `/start/delegate-agent`, `/operations`, `/authority/lifecycle`, `/authority/approval-bound-plans`, `/authority/receipts-and-disclosure` | Core verbs leave the section |
| `/authority/lifecycle` | MD, `/get-started/agent`, `/authority` | No topic nav; no code |
| `/authority/approval-bound-plans` | MD, `/get-started/cross-company`, `/authority` | No topic nav; no code |
| `/authority/receipts-and-disclosure` | MD, `/get-started/verify`, `/assurance` | No topic nav; no code |

### Agents and MCP

| Page | Main-content links | Audit |
|---|---|---|
| `/agents` | MD, `/start/delegate-agent` twice, `/guides/protect-rest-effect`, `/start/verify-receipt`, `/integrations`, `/identity-trust`, `/operations` | Every card leaves the section; MCP card is misleading |
| `/agents/how-auths-works` | MD only | Orphan; 64 words; no code |
| `/agents/delegate-one-tool` | MD, `/developers` | Orphan; 43 words; no code; scenario link loses context |
| `/agents/approved-plan` | MD, `/developers` | Orphan; 50 words; no code; scenario link loses context |
| `/agents/multi-agent` | MD only | Orphan; 44 words; no code |
| `/agents/mcp-client` | MD only | Orphan; 45 words; no code |
| `/agents/protect-mcp-server` | MD only | Orphan; 46 words; no code |
| `/agents/skills` | MD only | Orphan; 52 words; no code |

### Integrations

| Page | Main-content links | Audit |
|---|---|---|
| `/integrations` | `/integrations/index.md` only | No guide links despite six child pages |
| `/integrations/capabilities` | MD only | Orphan; 48 words; no code |
| `/integrations/cloud` | MD only | Orphan; 48 words; no code |
| `/integrations/identity-trust` | MD only | Orphan; 54 words; no code |
| `/integrations/policy` | MD only | Orphan; 49 words; no code |
| `/integrations/profile-kit` | MD only | Orphan; 43 words; no code |
| `/integrations/transport` | MD only | Orphan; 52 words; no code |

### Production operations

| Page | Main-content links | Audit |
|---|---|---|
| `/operations` | MD, `/reference/runtime-api` twice, `/architecture`, `/start/verify-receipt`, `/operations/execution-lifecycle`, `/assurance`, `/developers` | Only one card descends into Operations |
| `/operations/evaluate-locally` | MD only | Orphan; 49 words; no commands |
| `/operations/deploy-runtime` | MD only | Orphan; 45 words; no commands |
| `/operations/durable-state` | MD only | Orphan; 48 words; no commands |
| `/operations/custody` | MD only | Orphan; 50 words; no commands |
| `/operations/trust-and-profiles` | MD only | Orphan; 45 words; no commands |
| `/operations/provider-gateways` | MD only | Orphan; 46 words; no commands |
| `/operations/observability` | MD only | Orphan; 47 words; no commands |
| `/operations/backup-and-restore` | MD only | Orphan; 48 words; no commands |
| `/operations/recovery-and-reconciliation` | MD, `/developers` | Orphan; 42 words; scenario link loses context |
| `/operations/upgrade-and-rollback` | MD only | Orphan; 41 words; no commands |
| `/operations/receipt-retention` | MD only | Orphan; 45 words; no procedure |
| `/operations/execution-lifecycle` | MD, `/get-started/runtime`, `/operations` | No topic nav; conceptual only |
| `/operations/incident-response` | MD only | Orphan; structured summaries but no executable runbook flow |

### Developers and reference

| Page | Main-content links | Audit |
|---|---|---|
| `/developers` | MD, `/reference/sdk` twice, `/reference/runtime-api`, `/guides/protect-rest-effect`, `/integrations`, `/agents`, `/assurance` | Every card leaves the section |
| `/developers/sdks` | MD only | Orphan; 71 words; no code |
| `/developers/runtime-api` | MD only | Orphan; 62 words; no request example |
| `/developers/cli` | MD only | Orphan; 61 words; no commands |
| `/developers/testing` | MD, `/developers` | Thin; tested-scenario link loses context |
| `/developers/errors` | MD only | Orphan; thin; no per-error pages |
| `/developers/versioning` | MD only | Orphan; thin |
| `/reference` | MD, `/reference/sdk` twice, `/reference/runtime-api`, `/developers`, `/concepts`, `/architecture/trust-boundaries`, `/assurance` | No reference-local nav |
| `/reference/sdk` | six section Markdown links | Strongest page: topic nav, synchronized code, but no onward journey |
| `/reference/runtime-api` | `/reference/sdk`, page MD, five section MD links | Strong page; reference-local nav; no broader developer journey |
| `/reference/cli` | `/reference/cli.md` | Orphan, 21 words, zero commands; Markdown target is missing |
| `/reference/profiles` | MD only | Orphan; 36 words |
| `/reference/errors` | MD only | Orphan; 42 words |
| `/reference/schemas` | MD only | Orphan; 38 words |
| `/reference/evidence` | MD only | Orphan; 37 words |

### Quickstarts

Each quickstart renders five code blocks and links to its own Markdown, exact
JSON download, `/developers/testing`, and `/operations`. The source and failure
shape are substantially better than the generic pages, but all seven are
orphans and none has topic navigation.

| Page | Exact links | Audit |
|---|---|---|
| `/quickstarts/local-rest-effect` | MD, `/downloads/quickstarts/local-rest-effect.json`, `/developers/testing`, `/operations` | Orphan; should live in Get started hierarchy |
| `/quickstarts/runtime-effect` | MD, `/downloads/quickstarts/runtime-effect.json`, `/developers/testing`, `/operations` | Orphan; should live in Get started hierarchy |
| `/quickstarts/agent-delegation` | MD, `/downloads/quickstarts/agent-delegation.json`, `/developers/testing`, `/operations` | Orphan; should be curated by Get started and Agents |
| `/quickstarts/approved-plan` | MD, `/downloads/quickstarts/approved-plan.json`, `/developers/testing`, `/operations` | Orphan; should be curated by Get started and Authority/Agents |
| `/quickstarts/offline-verification` | MD, `/downloads/quickstarts/offline-verification.json`, `/developers/testing`, `/operations` | Orphan; should be curated by Get started and Identity/Authority |
| `/quickstarts/recovery` | MD, `/downloads/quickstarts/recovery.json`, `/developers/testing`, `/operations` | Orphan; should be curated by Get started and Operations |
| `/quickstarts/identity-swap` | MD, `/downloads/quickstarts/identity-swap.json`, `/developers/testing`, `/operations` | Orphan; should be curated by Get started and Identity |

### Assurance

| Page | Main-content links | Audit |
|---|---|---|
| `/assurance` | MD, `/architecture/trust-boundaries`, `/architecture`, `/start/verify-receipt`, `/reference`, `/operations`, `/integrations`, `/developers` | No claim page is linked; every card leaves Assurance |
| `/assurance/semantics` | MD only | Orphan; thin |
| `/assurance/authority` | MD only | Orphan; thin |
| `/assurance/execution` | MD only | Orphan; thin |
| `/assurance/disclosure` | MD only | Orphan; thin |
| `/assurance/supply-chain` | MD only | Orphan; thin |
| `/assurance/limitations` | MD only | Orphan; thin |

## Root causes

1. **A page registry is being mistaken for information architecture.** It can
   prove unique IDs and paths but not that a reader remains oriented.
2. **Landing cards are curated before their destination journeys exist.** A
   plausible label is linked to the nearest vaguely related page.
3. **Generic rendering rewards one-paragraph pages.** A valid content record
   becomes a published page without meeting a job-specific content contract.
4. **Tested scenarios are linked indirectly.** Generic “Open the tested
   scenario” links often go to `/developers`, not to the scenario that produced
   the claim.
5. **Route namespaces do not express ownership.** `/start`, `/guides`,
   `/quickstarts`, `/adopt`, `/integrations`, and `/reference` compete with the
   six primary sections.
6. **Link checks prove existence, not meaning.** There are zero broken HTML
   routes and still many broken reader promises.
7. **Left navigation is treated as a special reference feature.** It must be a
   universal topic shell for every non-landing content page.

## Stop conditions

Do not resume additive editorial expansion until:

- the proposed hierarchy is approved as the canonical route graph;
- every page has exactly one primary section owner;
- every primary-section landing links first to its own index and child pages;
- every non-landing page renders its owning section's left navigation;
- legacy routes are removed or replaced cleanly (the product is prelaunch);
- guide, quickstart, reference, concept, and runbook page types have distinct
  minimum content contracts; and
- qualification detects orphan pages, misleading card intent, missing code,
  missing procedures, and missing Markdown.


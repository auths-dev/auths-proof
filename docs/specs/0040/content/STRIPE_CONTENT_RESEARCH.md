# Stripe Documentation Content Research

Status: active research notebook  
Research date: 2026-08-14  
Target: at least 40 distinct live Stripe documentation pages

## Purpose

This notebook studies how Stripe turns a large technical product into a
progressively disclosed documentation system. It records observable content
and navigation patterns that Auths can adapt without copying Stripe's prose,
visual identity, or product taxonomy.

The research asks:

1. What job does each topic landing page perform before technical detail?
2. How does global navigation hand off to contextual left navigation?
3. How do overview, tour, quickstart, concept, design, and reference pages
   differ?
4. How does a reader move from choosing an outcome to implementing it?
5. Which patterns suit Auths, and which are specific to Stripe's product?

## Method

- Inspect at least 40 distinct pages in the live Stripe documentation.
- Begin from global topic destinations, then follow contextual links into
  representative journeys.
- Record observations in batches immediately after inspection.
- Cite the exact Stripe page beside every page-specific observation.
- Separate observed behavior from recommendations for Auths.
- Finish with an evidence ledger and derive executable Auths content epics in
  sibling files.

## Page ledger

| # | Area | Page | Page role | Inspected |
|---:|---|---|---|---|
| 1 | Global | [Get started](https://docs.stripe.com/get-started) | Topic landing | Yes |
| 2 | Global | [Payments](https://docs.stripe.com/payments) | Topic landing | Yes |
| 3 | Global | [Revenue](https://docs.stripe.com/revenue) | Topic landing | Yes |
| 4 | Global | [Developer resources](https://docs.stripe.com/development) | Topic landing | Yes |
| 5 | Developer | [SDKs](https://docs.stripe.com/sdks) | Catalog landing | Yes |
| 6 | Developer | [APIs](https://docs.stripe.com/apis) | Concept catalog landing | Yes |
| 7 | Agents | [Agents and AI](https://docs.stripe.com/agents) | Audience/use-case landing | Yes |
| 8 | Get started | [Quickstarts](https://docs.stripe.com/quickstarts) | Task catalog landing | Yes |
| 9 | Migration | [Data migrations overview](https://docs.stripe.com/get-started/data-migrations/overview) | Process overview | Yes |
| 10 | Migration | [Import payment method data](https://docs.stripe.com/get-started/data-migrations/payment-method-imports) | Deep operational guide | Yes |
| 11 | Payments | [Tour of the API](https://docs.stripe.com/payments-api/tour) | Conceptual API tour | Yes |
| 12 | Payments | [Checkout Sessions API](https://docs.stripe.com/payments/checkout-sessions) | Recommended abstraction overview | Yes |
| 13 | Agents | [How agents work with Stripe](https://docs.stripe.com/agents/how-it-works) | Architecture and composition guide | Yes |
| 14 | Get started | [Stripe accounts](https://docs.stripe.com/get-started/account) | Prerequisite catalog | Yes |
| 15 | Get started | [Development environment](https://docs.stripe.com/get-started/development-environment) | Environment quickstart | Yes |
| 16 | Get started | [API keys](https://docs.stripe.com/keys) | Security concept and operations guide | Yes |
| 17 | Get started | [Testing](https://docs.stripe.com/testing) | Scenario catalog | Yes |
| 18 | Get started | [No-code integration](https://docs.stripe.com/no-code/get-started) | Audience-specific solution guide | Yes |
| 19 | Get started | [Startup payments](https://docs.stripe.com/get-started/use-cases/startup) | Outcome recipe | Yes |
| 20 | Get started | [SaaS subscriptions](https://docs.stripe.com/get-started/use-cases/saas-subscriptions) | Outcome recipe | Yes |
| 21 | Payments | [Design a payments integration](https://docs.stripe.com/payments/use-cases/get-started) | Product chooser | Yes |
| 22 | Payments | [Build a payments page](https://docs.stripe.com/payments/checkout) | Capability landing | Yes |
| 23 | Payments | [Stripe-hosted Checkout](https://docs.stripe.com/checkout/quickstart) | Interactive quickstart | Yes |
| 24 | Payments | [Embedded Checkout](https://docs.stripe.com/checkout/embedded/quickstart) | Interactive quickstart | Yes |
| 25 | Payments | [Checkout Sessions quickstart](https://docs.stripe.com/payments/quickstart) | Interactive quickstart | Yes |
| 26 | Payments | [Web Elements](https://docs.stripe.com/payments/elements) | Component landing | Yes |
| 27 | Payments | [Supported payment methods](https://docs.stripe.com/payments/payment-methods/overview) | Compatibility catalog | Yes |
| 28 | Payments | [Payment Intents API](https://docs.stripe.com/payments/payment-intents) | Lifecycle concept guide | Yes |
| 29 | Payments | [Setup Intents API](https://docs.stripe.com/payments/setup-intents) | Lifecycle concept guide | Yes |
| 30 | Developer | [Webhook quickstart](https://docs.stripe.com/webhooks/quickstart) | Interactive quickstart | Yes |
| 31 | Revenue | [Billing](https://docs.stripe.com/billing) | Product landing | Yes |
| 32 | Revenue | [Billing quickstart](https://docs.stripe.com/billing/quickstart) | Interactive quickstart | Yes |
| 33 | Revenue | [Design a subscriptions integration](https://docs.stripe.com/billing/subscriptions/design-an-integration) | Design decision guide | Yes |
| 34 | Revenue | [How subscriptions work](https://docs.stripe.com/billing/subscriptions/overview) | Lifecycle concept guide | Yes |
| 35 | Revenue | [Recurring pricing models](https://docs.stripe.com/products-prices/pricing-models) | Domain model catalog | Yes |
| 36 | Revenue | [Invoicing](https://docs.stripe.com/invoicing) | Product landing | Yes |
| 37 | Revenue | [Set up Stripe Tax](https://docs.stripe.com/tax/set-up) | Configuration procedure | Yes |
| 38 | Revenue | [Revenue Recognition](https://docs.stripe.com/revenue-recognition/get-started) | Product onboarding guide | Yes |
| 39 | Revenue | [How Sigma works](https://docs.stripe.com/data/how-sigma-works) | Boundary-first capability guide | Yes |
| 40 | Revenue | [How Data Pipeline works](https://docs.stripe.com/data/access-data-in-warehouse) | Integration capability guide | Yes |
| 41 | Revenue | [Subscriptions](https://docs.stripe.com/subscriptions) | Subdomain landing | Yes |
| 42 | Agents | [Model Context Protocol](https://docs.stripe.com/mcp) | Tool integration guide | Yes |
| 43 | Agents | [Agent skills](https://docs.stripe.com/skills) | Installation and catalog guide | Yes |
| 44 | Developer | [Stripe CLI](https://docs.stripe.com/cli) | Generated command reference | Yes |
| 45 | Developer | [Server-side SDKs](https://docs.stripe.com/sdks/server-side) | Cross-language SDK guide | Yes |
| 46 | Developer | [SDK versioning](https://docs.stripe.com/sdks/versioning) | Compatibility policy | Yes |
| 47 | Developer | [Automated testing](https://docs.stripe.com/automated-testing) | Testing strategy guide | Yes |
| 48 | Developer | [Error handling](https://docs.stripe.com/error-handling) | Cross-language failure guide | Yes |
| 49 | Assurance | [Security at Stripe](https://docs.stripe.com/security) | Assurance landing | Yes |
| 50 | Developer | [Stripe-Context header](https://docs.stripe.com/context) | Request-scope concept guide | Yes |

## Batch notes

### Batch 1 — Global landings, catalogs, and depth transitions

Pages 1–10 establish the outer information architecture and show how Stripe
hands a reader from a broad product promise into increasingly specific work.

#### Observations

1. A global topic destination is a curated decision surface, not a table of
   contents. The Get Started page first offers account setup and development
   prerequisites, then outcome-shaped common use cases, migration, testing,
   and help. Each card combines an action title with a one-sentence promise.
   [Evidence: Get started](https://docs.stripe.com/get-started)

2. Product landings use the same structural grammar but change their grouping
   logic. Payments groups the landscape by payment outcome, payment method,
   adjacent financial job, platform model, and deeper technical concepts;
   Revenue groups by the business lifecycle domains Billing, Tax, Reporting,
   and Data. [Evidence: Payments](https://docs.stripe.com/payments),
   [Revenue](https://docs.stripe.com/revenue)

3. The global navigation remains a small collection of audience-sized domains.
   The contextual left navigation becomes the complete local map. The landing
   page therefore explains and recommends; the sidebar enumerates. Stripe does
   not force the global header to carry every product or subtopic.
   [Evidence: Get started](https://docs.stripe.com/get-started),
   [Developer resources](https://docs.stripe.com/development)

4. The Developer Resources landing is an ecosystem map rather than an SDK
   page. It distinguishes CLI, SDKs, APIs, agents, MCP, testing, versioning,
   operational tools, security, extensions, and community. This prevents
   developers from assuming the client library is the whole platform.
   [Evidence: Developer resources](https://docs.stripe.com/development)

5. Catalog pages carry real explanatory value before listing destinations.
   The SDK page explains where server, web, and mobile libraries fit and
   exposes current versions; the API page explains the shared request model,
   then groups authentication, response shaping, pagination, testing, and
   errors. [Evidence: SDKs](https://docs.stripe.com/sdks),
   [APIs](https://docs.stripe.com/apis)

6. Quickstarts are treated as a content type with an explicit promise:
   end-to-end examples, framework/language choices, stepwise implementation,
   and a runnable or downloadable path. The Quickstarts landing categorizes
   them by outcome instead of presenting an undifferentiated tutorial list.
   [Evidence: Quickstarts](https://docs.stripe.com/quickstarts)

7. The Agents landing mixes a literal copyable starting prompt with a map of
   agent tooling, commerce use cases, billing, and open protocols. That page
   serves both someone using an agent to build and someone building an agentic
   product; it names the distinction without creating two disconnected docs
   sites. [Evidence: Agents and AI](https://docs.stripe.com/agents)

8. Deep operational content begins with an outcome contract. The migration
   overview tells readers what they will understand, then divides the work into
   build, learn, plan, coordinate, migrate, and update phases. It connects each
   phase to the next relevant technical or organizational surface.
   [Evidence: Data migrations overview](https://docs.stripe.com/get-started/data-migrations/overview)

9. The payment-method import guide is allowed to become dense because the
   reader has already crossed an overview boundary. It opens with method tabs,
   then covers defaults, limitations, regulatory evidence, file requirements,
   field-level details, and output review. This depth belongs below—not on—the
   migration landing page.
   [Evidence: Import payment method data](https://docs.stripe.com/get-started/data-migrations/payment-method-imports)

#### Implications for Auths

- Keep global navigation bounded to durable user domains; give each one a real
  landing page before exposing its detailed tree.
- Make landing pages recommend routes by outcome and reader job, not merely
  repeat sidebar links.
- Define distinct templates for topic landing, catalog landing, quickstart,
  process overview, and deep operational guide.
- Give Auths an ecosystem/developer landing that distinguishes SDKs, Runtime
  API, CLI, agent/MCP tooling, integrations, testing, and assurance.
- Let operational and cryptographic depth live behind overview pages that tell
  readers why and when they need it.

### Batch 2 — Tours, prerequisites, testing, and outcome recipes

Pages 11–20 show that progressive disclosure is not merely shallow-to-deep.
Stripe uses different intermediate page types to answer different questions
before the reader reaches reference material.

#### Observations

1. An API tour explains the object system and lifecycle before teaching
   individual calls. It explicitly promises to help readers move beyond copied
   tutorial code by showing common patterns and how objects fit together.
   [Evidence: Tour of the API](https://docs.stripe.com/payments-api/tour)

2. Stripe recommends a default abstraction and explains why. The Checkout
   Sessions overview describes the capabilities it bundles, identifies the UI
   forms it supports, and positions it as the default for most integrations
   before discussing its lifecycle. This reduces premature choice overload.
   [Evidence: Checkout Sessions API](https://docs.stripe.com/payments/checkout-sessions)

3. The agent architecture page begins with independent components, shows how
   each connects to the product, and then documents common combinations. It
   does not imply that adopting agent developer tooling also requires billing
   or agentic commerce.
   [Evidence: How agents work with Stripe](https://docs.stripe.com/agents/how-it-works)

4. Prerequisite pages remain scoped. The account page separates immediate
   sandbox availability from live-account activation and then routes into
   account-management tasks rather than mixing them into every quickstart.
   [Evidence: Stripe accounts](https://docs.stripe.com/get-started/account)

5. The development-environment guide states what the reader will learn, offers
   an explicit non-developer exit, introduces CLI and SDK roles, and then moves
   through installation to a first request. Audience branching happens near
   the top instead of after irrelevant setup.
   [Evidence: Development environment](https://docs.stripe.com/get-started/development-environment)

6. Security documentation combines conceptual taxonomy with operational
   handling. The API-key page explains key types, sandbox/live distinctions,
   protection, rotation, request logs, and access policy from one durable
   security landing.
   [Evidence: API keys](https://docs.stripe.com/keys)

7. Testing is organized as a scenario catalog, not a generic admonition to
   test. Readers can deliberately simulate success, brands, countries,
   declines, fraud, invalid data, disputes, refunds, authentication, webhooks,
   and other outcome classes.
   [Evidence: Testing](https://docs.stripe.com/testing)

8. No-code is a first-class audience path with its own decision guide. The
   page recommends components by business job—online payment, subscriber
   retention, invoicing, in-person payment, tips—without exposing API detail.
   [Evidence: No-code integration](https://docs.stripe.com/no-code/get-started)

9. Use-case pages are linear outcome recipes. The startup guide sequences
   account, payment link, sharing, go-live, and next steps; the SaaS guide adds
   product/price modeling, subscriptions, recommended configuration,
   monitoring, and go-live. Both choose an opinionated path for a named reader.
   [Evidence: Startup payments](https://docs.stripe.com/get-started/use-cases/startup),
   [SaaS subscriptions](https://docs.stripe.com/get-started/use-cases/saas-subscriptions)

#### Implications for Auths

- Add an Auths semantic tour that explains how actor, action, authority,
  outcome, and receipt fit together before any symbol-level reference.
- Publish a clearly recommended default integration for ordinary applications,
  then show where lower-level profiles and ports are appropriate.
- Explain that identity, policy, transport, custody, and provider integrations
  compose independently; never present the full stack as mandatory.
- Give each onboarding page an early exit to the correct audience path: local
  library, hosted runtime, agent/MCP workflow, integration author, or operator.
- Build testing documentation as adversarial scenario recipes: success,
  denial, expiry, replay, mutation, revocation, indeterminate, recoverable, and
  provider-unknown.
- Create named outcome recipes rather than one universal quickstart.

### Batch 3 — Product choice, interactive quickstarts, and lifecycle concepts

Pages 21–30 show how Stripe helps a developer choose an integration, complete
one working path, and then understand the lower-level lifecycle beneath it.

#### Observations

1. A product chooser starts from business and UX constraints, not product
   names. The payments design guide contrasts no-code, hosted, embedded, and
   custom paths and lets the reader discover which surface fits before opening
   implementation detail.
   [Evidence: Design a payments integration](https://docs.stripe.com/payments/use-cases/get-started)

2. A capability landing sits between chooser and quickstart. The Checkout page
   explains the shared API, visually distinguishes hosted, embedded, and
   element-based interfaces, then routes into customization, collection
   timing, and business management.
   [Evidence: Build a payments page](https://docs.stripe.com/payments/checkout)

3. Interactive quickstarts are a distinct application surface. They offer
   frontend and backend selectors, synchronized examples, numbered progress,
   highlighted implementation lines, complete downloadable projects, a text
   alternative, and an explicit no-code exit.
   [Evidence: Stripe-hosted Checkout](https://docs.stripe.com/checkout/quickstart),
   [Embedded Checkout](https://docs.stripe.com/checkout/embedded/quickstart),
   [Checkout Sessions quickstart](https://docs.stripe.com/payments/quickstart)

4. Closely related quickstarts reuse one interaction grammar while changing
   only the integration boundary. Hosted Checkout teaches redirect; Embedded
   Checkout teaches an embedded form; the Checkout Sessions quickstart teaches
   a custom page backed by managed session semantics. Familiar scaffolding
   makes the architectural difference easier to see.
   [Evidence: Stripe-hosted Checkout](https://docs.stripe.com/checkout/quickstart),
   [Embedded Checkout](https://docs.stripe.com/checkout/embedded/quickstart),
   [Checkout Sessions quickstart](https://docs.stripe.com/payments/quickstart)

5. Component landings state the security boundary and product value before
   setup. The Elements page explains that sensitive details are tokenized
   without touching the application server, then lists global methods,
   compliance, saved methods, and compatible APIs.
   [Evidence: Web Elements](https://docs.stripe.com/payments/elements)

6. Compatibility catalogs explain why variation matters before enumerating it.
   The payment-method page introduces regional preference and per-method
   currency, country, product, and API constraints before its category tree.
   [Evidence: Supported payment methods](https://docs.stripe.com/payments/payment-methods/overview)

7. Lifecycle concept pages justify lower-level objects with the stateful
   problem they solve. Payment Intents explains changing payment state,
   authentication, idempotency, and post-payment work; Setup Intents explains
   preparing and authenticating a payment method now for future use without a
   charge.
   [Evidence: Payment Intents API](https://docs.stripe.com/payments/payment-intents),
   [Setup Intents API](https://docs.stripe.com/payments/setup-intents)

8. The webhook quickstart attaches asynchronous infrastructure to a concrete
   post-effect job—receipts, fulfillment, database updates—rather than teaching
   event delivery in isolation. It uses the same language-selectable,
   downloadable quickstart grammar as product integrations.
   [Evidence: Webhook quickstart](https://docs.stripe.com/webhooks/quickstart)

#### Implications for Auths

- Add an integration chooser that begins with deployment and trust constraints:
  local verification, hosted runtime, agent delegation, cross-company action,
  or custom profile/adapter.
- Insert capability landings between the chooser and technical guides—for
  example “Protect an application effect,” “Delegate to an agent,” “Run an
  approval-bound plan,” and “Verify portable evidence.”
- Standardize a real interactive quickstart shell across Rust, TypeScript, and
  Python: selected language, numbered steps, tested source, expected outcome,
  downloadable project, text alternative, and explicit next steps.
- Pair high-level defaults with lifecycle tours for authority, execution,
  recovery, and receipt disclosure.
- Make every adapter/catalog page state its security boundary and compatibility
  dimensions before listing implementations.

### Batch 4 — Product landings, design decisions, and operational boundaries

Pages 31–40 show how Stripe documents a broad business domain after the reader
has entered it from a global Revenue landing.

#### Observations

1. A product landing can serve operators and developers together without
   collapsing their paths. Billing presents no-code options, subscription
   onboarding, usage billing, invoicing, quotes, a sample project, and a feature
   catalog as separate choices under one product promise.
   [Evidence: Billing](https://docs.stripe.com/billing)

2. A sophisticated quickstart can expose an explicit integration-path switch
   in addition to frontend and backend language choices. The Billing quickstart
   lets readers select customer/account modeling while retaining the same
   guided, downloadable sample experience.
   [Evidence: Billing quickstart](https://docs.stripe.com/billing/quickstart)

3. Design guides identify the small number of decisions that materially shape
   an implementation. The subscriptions design page asks how to charge, how
   customers check out, and when they pay, then routes the selected combination
   into build guides.
   [Evidence: Design a subscriptions integration](https://docs.stripe.com/billing/subscriptions/design-an-integration)

4. Lifecycle guides explain the state machine independently from setup. The
   subscriptions overview describes creation through cancellation, separates
   subscription status from payment status, and connects phases to object state.
   [Evidence: How subscriptions work](https://docs.stripe.com/billing/subscriptions/overview)

5. Domain-model catalogs map business language to product objects. The pricing
   guide explains products, prices, currency, and service period, then compares
   flat-rate, per-seat, tiered, and usage patterns.
   [Evidence: Recurring pricing models](https://docs.stripe.com/products-prices/pricing-models)

6. Product landings consistently lead with multiple operational modes. The
   Invoicing page distinguishes Dashboard/no-code workflows, accounts
   receivable automation, API integration, and adjacent product comparison
   before deep configuration.
   [Evidence: Invoicing](https://docs.stripe.com/invoicing)

7. Configuration procedures present an ordered operational checklist and name
   alternative control surfaces. Stripe Tax walks through address, tax code,
   inclusive pricing, registrations, integration/API enablement, filing, and
   disabling collection; it also separates platform-specific responsibility.
   [Evidence: Set up Stripe Tax](https://docs.stripe.com/tax/set-up)

8. Product onboarding includes evaluation before production. Revenue
   Recognition introduces imports, rules, reports, and transaction-model tests,
   and makes sandbox/trial use part of the documented path.
   [Evidence: Revenue Recognition](https://docs.stripe.com/revenue-recognition/get-started)

9. Capability guides lead with hard boundaries when misuse would be costly.
   Sigma states that queries are read-only before describing reporting and
   metrics. Data Pipeline states its one-way export purpose, supported
   destinations, schemas, multi-account model, sandbox behavior, and shutdown.
   [Evidence: How Sigma works](https://docs.stripe.com/data/how-sigma-works),
   [How Data Pipeline works](https://docs.stripe.com/data/access-data-in-warehouse)

#### Implications for Auths

- Give each major Auths domain a landing that serves builders, integrators, and
  operators with separate recommended paths.
- Build design-decision guides around the few choices that actually alter the
  architecture: local versus service runtime, identity/trust source, approval
  policy, custody, state store, transport, and provider gateway.
- Publish lifecycle/state-machine pages separately from quickstarts for grants,
  plans, executions, recovery references, and receipts.
- Translate application intent into Auths domain objects with comparison tables
  and worked examples.
- Put hard boundaries first: offline versus effectful, inert versus executable,
  public identity versus secret custody, transport versus authorization, and
  completed versus provider-unknown.
- Include sandbox/evaluation and safe shutdown paths in every operational
  integration guide.

### Batch 5 — SDKs, CLI, agents, failures, and assurance

Pages 41–50 cover the cross-cutting developer surfaces most analogous to Auths.

#### Observations

1. A subdomain landing remains useful even when a parent product landing
   exists. Subscriptions narrows Billing into sample integration, conceptual
   overview, design choices, no-code options, webhooks, integrations, and
   feature expansion. The reader does not need to rediscover this path inside
   the broader Billing page.
   [Evidence: Subscriptions](https://docs.stripe.com/subscriptions)

2. The MCP guide distinguishes using Stripe's MCP server from building an MCP
   application that accepts payments. It then gives client-specific connection
   instructions, enumerates tools, and separately covers connected-account and
   Treasury contexts.
   [Evidence: Model Context Protocol](https://docs.stripe.com/mcp)

3. Agent skills documentation recommends maintained, automatically updated
   plugins first and places manual installation behind a warning. It follows
   installation with a skills index rather than treating setup as the entire
   product.
   [Evidence: Agent skills](https://docs.stripe.com/skills)

4. CLI reference uses a purpose-built information architecture rather than the
   prose-page template. Its left navigation is grouped by getting started,
   documentation, webhooks, resources/HTTP, projects, tools, and commands; the
   content begins with purpose and installation, then exposes exhaustive
   commands, subcommands, flags, examples, credential behavior, and sandbox
   lifecycle.
   [Evidence: Stripe CLI](https://docs.stripe.com/cli)

5. A cross-language SDK guide synchronizes language selection across setup and
   core tasks. It covers installation, initialization, requests, response
   access, expansion, request IDs, per-request options, errors, escape hatches,
   source code, client construction, and preview channels—not only a package
   install command.
   [Evidence: Server-side SDKs](https://docs.stripe.com/sdks/server-side)

6. Compatibility policy is a first-class page. Stripe explains API cadence,
   SDK semantic versions, breaking-change timing, SDK support windows, runtime
   support, and preview channels in one place.
   [Evidence: SDK versioning](https://docs.stripe.com/sdks/versioning)

7. Automated-testing guidance states constraints before recommendations.
   Stripe explains why security controls and rate limits make direct automation
   unsuitable for some interfaces, then recommends simulated client and server
   outputs to test application behavior and failure recovery.
   [Evidence: Automated testing](https://docs.stripe.com/automated-testing)

8. Error documentation is cross-language and action-oriented. It first teaches
   the common error envelope, exception handling, webhook monitoring, and stored
   failure information, then separates declines, invalid requests, connection,
   API, authentication, idempotency, permission, rate-limit, and signature
   failures.
   [Evidence: Error handling](https://docs.stripe.com/error-handling)

9. Assurance has a dedicated narrative surface. Stripe separates standards and
   regulatory compliance, product security, infrastructure safeguards, and
   ongoing posture maintenance instead of mixing every assurance claim into
   product quickstarts.
   [Evidence: Security at Stripe](https://docs.stripe.com/security)

10. Request-context documentation uses a concrete organization hierarchy to
    teach scope. It explains the default scope, the explicit override, which
    related accounts are reachable, and how the requested context relates to
    the key's authority.
    [Evidence: Stripe-Context header](https://docs.stripe.com/context)

#### Implications for Auths

- Create subdomain landings for authority, agents, approvals, execution,
  recovery, receipts, integrations, and assurance beneath the bounded global
  destinations.
- Separate “use Auths with an agent/MCP client” from “build a protected MCP
  server or agent product.”
- Treat maintained agent plugins/skills as an onboarding channel with explicit
  versioning and security boundaries, not as copied prompt snippets.
- Give the CLI a generated command-reference template while retaining a short
  outcome-oriented CLI landing page.
- Expand the SDK guide into the full cross-language journey: install, compose,
  create, delegate, execute, resume, verify, inspect outcomes, handle errors,
  test, and find source.
- Publish explicit support/version policy before launch.
- Build a failure-handling hub around Auths' closed outcomes and stable error
  identities, with language-specific handling examples.
- Keep assurance evidence in its own navigable domain, and link precise claims
  from product pages rather than duplicating them.

## Synthesis

### The reusable content grammar

Stripe's pages repeatedly form this progression:

```text
global topic
    -> curated landing
        -> chooser or design guide
            -> opinionated quickstart
                -> lifecycle/concept guide
                    -> generated reference
                        -> operations, testing, and assurance
```

The progression is not a mandatory funnel. A knowledgeable reader can enter at
reference or operations, while a new reader receives progressively more detail.
The key is that each page has one recognizable job.

### Proposed Auths global information architecture

```text
+--------------------------------------------------------------------------------+
| Auths Docs          Search                              APIs & SDKs     GitHub   |
| Get started | Identity & trust | Authority | Agents | Operations | Developers  |
+--------------------------------------------------------------------------------+
| Contextual left navigation | Recommended landing or focused content | Outline   |
+--------------------------------------------------------------------------------+
```

Decisions:

- `Get started` owns prerequisites, the integration chooser, quickstarts,
  evaluation, adoption, and migration.
- `Identity & trust` explains identity agnosticism, verification methods,
  evidence, resolvers, trust roots, and authentication composition.
- `Authority` owns actions, grants, attenuation, delegation, approvals, plans,
  execution, recovery, outcomes, receipts, and disclosure.
- `Agents` owns agent delegation, MCP client/server journeys, approval-bound
  plans, skills/plugins, and multi-agent patterns.
- `Operations` owns production runtime deployment, state, custody,
  observability, recovery, incident response, and runbooks.
- `Developers` owns local tooling, CLI, testing, errors, integrations, profile
  development, versioning, changelog, contribution, and assurance entry points.
- `APIs & SDKs` is a visually distinct utility destination for generated Rust,
  TypeScript, Python, Runtime API, CLI, schema, and stable-error references.
- `Assurance` remains a first-class landing with strong cross-links from
  Authority, Operations, and Developers; it does not consume a primary tab.

### Page types Auths must support

| Page type | Reader question | Required shape |
|---|---|---|
| Topic landing | “Where do I begin in this domain?” | Promise, recommended path, grouped cards, audience exits |
| Product/capability landing | “What does this surface do?” | Boundary, value, modes, common jobs, next steps |
| Chooser | “Which integration fits?” | Decision dimensions, recommendations, comparison, route |
| Design guide | “Which decisions alter my architecture?” | Small decision set, tradeoffs, resulting path |
| Quickstart | “Can I make one thing work?” | Tested project, steps, languages, outcome, failure, download |
| Tour | “How does the model fit together?” | Nouns, lifecycle, diagrams, common combinations |
| Concept/lifecycle | “Why does this primitive exist?” | Problem, state model, invariants, failure paths, links |
| Operations procedure | “How do I run this safely?” | Preconditions, commands, checks, rollback, escalation |
| Catalog | “What is supported?” | Compatibility dimensions, generated inventory, constraints |
| Reference | “What is the exact contract?” | Generated facts, sticky examples, stable identities, errors |
| Assurance | “Why should I trust this claim?” | Claim, evidence, limitation, version, reproduction |

### Content laws

1. Every global topic has a curated landing page.
2. Landing pages recommend; sidebars enumerate.
3. Every quickstart produces one observable success and at least one safe
   failure.
4. Every effectful guide names the trust, custody, state, and provider boundary.
5. Every reference fact comes from a release artifact, never copied prose.
6. Every language switch preserves semantics and changes only idiomatic syntax.
7. Every lifecycle explains denied, indeterminate, recoverable, and unknown
   outcomes where applicable.
8. Every assurance claim links to versioned evidence and states limitations.
9. Every page has canonical Markdown and bounded section projections.
10. Every deep page links back to its overview and forward to the next likely
    task.


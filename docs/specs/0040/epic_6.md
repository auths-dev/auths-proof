# Epic 6 — Ship the Progressive Product Journey

**Parent:** [AP-SPEC-040](../0040-stripe-quality-documentation-platform.md)

**Repository:** `auths-proof-docs`

**Depends on:** Epic 5

**Blocks:** Epics 9–11

## Outcome

Deliver the outcome-first information architecture and a fifteen-minute path
from “what is Auths?” to one protected REST effect, followed by agent
delegation and receipt verification. Preserve the same five nouns and five
verbs as readers descend into deeper material.

This epic owns authored product teaching. Executable source and generated
reference facts are supplied by Epics 7 and 8 rather than copied into prose.

## Zero-context starting point

Read:

- the parent specification, especially sections 3–11;
- Epics 1–5 in this folder;
- `docs/plans/simplify/README.md` and its final five-verb target;
- `docs/target-state/` product-surface decisions;
- `docs/product/AUTHS_AUTHORITY_LAYER.md`;
- `bindings/typescript/README.md` and production integration guide;
- `bindings/python/README.md` and integration recipes;
- the Rust SDK README and open production reference demo README; and
- the fixture release bundle and page schema from Epic 5.

Treat repository plans as research, not public truth. Resolve claims against
the release contract and installed artifacts.

## Product model

Use only these default verbs:

```text
create -> delegate -> execute -> resume -> verify
```

Use only these default nouns:

```text
actor -> authority -> action -> outcome -> receipt
```

Approvals, profiles, custody, trusted context, stores, lifecycle transitions,
commitments, disclosure, and provider reconciliation are progressive depth.
They appear when the reader's task requires them, not as prerequisites for
understanding the first example.

## Information architecture

Implement the parent navigation tree with these launch-critical paths:

```text
/
├── start/what-is-auths
├── start/rest-api
├── start/delegate-to-an-agent
├── start/verify-a-receipt
├── development/
│   ├── sdks
│   ├── runtime-api
│   ├── cli
│   ├── agents-and-mcp
│   ├── testing
│   └── versioning
├── guides/
│   ├── authority
│   ├── delegation
│   ├── approvals
│   ├── recovery
│   └── receipts-and-disclosure
└── concepts/
    ├── outcomes
    ├── exact-effects
    ├── identity-vs-authority
    └── transport-vs-authorization
```

Reference, architecture, integrations, and operations landing pages may exist
as honest placeholders until their owning epics complete. They must not claim
coverage that is absent.

## Page contract

Every guide follows:

1. **Outcome** — one sentence describing the working result.
2. **Before you begin** — only real prerequisites.
3. **Build** — numbered, executable steps with progress.
4. **What Auths proved** — plain-language authority and effect explanation.
5. **Failure paths** — closed outcomes and safe next actions.
6. **Take it further** — deeper pages, never duplicated essays.

Each page declares semantic dependencies and contains no hand-authored
signature, parameter, endpoint, package-version, or support table.

## REST quickstart

The launch path must let a developer:

1. install one maintained SDK;
2. start or connect to the local open reference;
3. create exact authority for one route-shaped application action;
4. execute once through a closed local gateway;
5. inspect a bounded successful outcome and receipt summary;
6. replay the same request and see it fail closed; and
7. mutate the action bytes and see verification reject them.

The primary path uses safe development defaults and no cloud account,
database, identity provider, approval provider, or manually assembled port.
The page states clearly that development custody and state are not a production
deployment.

## Agent and receipt follow-ups

The agent guide attenuates the quickstart authority rather than inventing a
new example domain. It demonstrates narrower action, expiry, use count, and
delegation depth and shows a widening attempt fail.

The receipt guide begins with a bounded human summary, then explains opaque,
summary, and authorized full disclosure. It must not render sensitive receipt
details by default or imply that a receipt caused authorization.

## UX behavior

- The two-row global header always offers `Start`, `SDK`, `Concepts`, and
  `Architecture`; deeper navigation is contextual and edge-aligned rather than
  competing in the global row.
- One selected SDK language persists across the entire journey.
- The recommended language defaults to TypeScript for web-oriented REST
  readers but the initial selector makes Rust and Python equally visible.
- Switching language keeps the reader at the same semantic step.
- “Why?” callouts explain one concept without forcing a protocol detour.
- Security-critical warnings are inline and never hidden in accordions.
- Completed, denied, indeterminate, recoverable, verified, and rejected have
  distinct words and accessible visual treatment.
- Provider-unknown always says “observe before retry.”
- Page Markdown actions sit beneath the title/description before the first
  semantic section. Section actions appear only where a long page benefits
  from an independently useful bounded projection.

## Content implementation steps

- [ ] Write the home page around a concrete exact-authority story and outcome
  routes, not package names.
- [ ] Write `what-is-auths` using five nouns, five verbs, and identity versus
  authority.
- [ ] Build the REST quickstart around the Epic 7 scenario identity.
- [ ] Build delegation and receipt follow-ups over the same actors and action.
- [ ] Add concise denial, expiry, replay, mutation, indeterminate, and
  provider-unknown paths.
- [ ] Build development, SDK, runtime API, CLI, agents/MCP, testing, and
  versioning landing pages.
- [ ] Name and route the SDK and runtime API destinations distinctly in global,
  contextual, breadcrumb, search, and related-content navigation.
- [ ] Build authority, delegation, approval, recovery, receipt, outcome,
  exact-effect, identity, and transport concept pages.
- [ ] Add stable reference links rather than URLs.
- [ ] Generate the affected-page dependency graph from frontmatter.
- [ ] Review every security statement against contract evidence.

## Usability protocol

Recruit at least five developers who have never worked in Auths. Give them only
the docs home URL and the goal “protect one REST effect and explain what a
replay does.” Do not provide verbal help.

Record:

- time to identify the recommended start;
- time to first working effect;
- commands copied and edited;
- language switches;
- every hesitation longer than two minutes;
- every mistaken assumption about identity, transport, approval, execution, or
  receipts; and
- whether the developer can explain the exact authority afterward.

At least four of five must finish in under fifteen minutes. Treat confusion as
a product defect even if the code works.

## Adversarial content tests

Fail review or CI when:

- a quickstart references an untested snippet;
- a page restates a signature or fixed limit;
- a security warning exists only on a deep page;
- transport success is described as authorization;
- approval is described as reusable authority;
- denial and indeterminate are collapsed;
- provider-unknown recommends blind retry;
- a receipt summary exposes full details;
- the language switch changes semantic steps;
- an SDK guide or reference is labelled only “API reference”;
- global navigation expands into the full information architecture and crowds
  out the recommended start;
- contextual navigation collapse does not widen the reading surface;
- an unpublished feature is presented as stable; or
- a page links to `next` from stable without an explicit warning.

## Validation commands

```text
pnpm lint:content
pnpm test:dependencies
pnpm test:examples
pnpm build
pnpm test:browser
pnpm test:a11y
```

Archive the anonymized usability script, aggregate timings, observed problems,
and resulting issue links without participant personal data.

## Exit gate

This epic is complete when the progressive information architecture is live in
preview, the REST/delegation/receipt journey uses one vocabulary and tested
scenario identities, failure paths remain honest, four of five unfamiliar
developers succeed without help in under fifteen minutes, and the resulting
reader can explain exactly what was authorized and what was not.

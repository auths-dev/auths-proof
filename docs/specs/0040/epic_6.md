# Epic 6 — Build Journey Composition Contracts

**Parent:** [AP-SPEC-040](../0040-stripe-quality-documentation-platform.md)

**Repository:** `auths-proof-docs`

**Depends on:** Epic 5 and Content Epic 0

**Blocks:** Epics 9–11

## Outcome

Build the typed page models, journey composition primitives, dependency
resolution, and usability instrumentation required to deliver progressive
product teaching without embedding public copy or choosing the final
information architecture in platform code.

Content Epics 1–4 own the routes, recommendations, explanations, and reader
journeys. Executable source and generated reference facts are supplied by
Epics 7 and 8. This epic owns only the composition machinery joining those
inputs into the verified page graph.

## Ownership boundary

Follow [Content Epic 0](./content/epic_0.md). This epic may define closed page
shapes, registered components, validation, and instrumentation. It must not:

- author or approve public narrative;
- freeze global navigation labels or landing-card order;
- copy signatures, endpoints, errors, limits, evidence, or executable code;
- create a second route or navigation corpus; or
- render HTML, Markdown, search, or agent output from separate content trees.

## Zero-context starting point

Read:

- the parent specification, especially sections 3–11;
- Epics 1–5 in this folder;
- `docs/specs/0040/README.md` and `content/epic_0.md`;
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

## Journey composition contract

Provide closed models for:

- topic landings with editorially ordered card references;
- deterministic integration-chooser inputs and recommendations;
- outcome guides with prerequisites, steps, explanation, failure paths, and
  deeper links;
- semantic tours with accessible diagrams and progressive depth;
- contextual navigation derived from page identities; and
- stable page and section actions over the verified graph.

Content Epics 1–3 supply instances of these models. The model validates route,
page, operation, scenario, claim, and related-page identities but does not
choose the public taxonomy.

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

## Quickstart composition

Provide a guide-step model that can bind prose to qualified scenario steps
without copying their code or results. It must support install, setup, action,
execution, inspection, replay, mutation, and cleanup step kinds while allowing
Content Epics 2 and 4 to select the actual journey.

The component rejects raw commands or code as step data. Displayed source and
expected results resolve from Epic 7 scenario identities.

## Follow-up composition

Provide continuation links that can carry a scenario family and semantic
operation from one guide to another. Content may reuse actors and actions
without duplicating scenario data. Receipt components enforce opaque, summary,
and authorized-full disclosure modes supplied by generated facts.

## UX behavior

- Global and contextual navigation consume Content Epic 1's verified editorial
  configuration; component code does not hard-code its labels or order.
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

## Platform implementation steps

- [ ] Implement typed landing, chooser, guide, tour, step, continuation, and
  contextual-navigation models.
- [ ] Implement registered MDX components over those models.
- [ ] Resolve all product facts and executable displays through stable bundle
  identities.
- [ ] Generate the affected-page dependency graph from frontmatter.
- [ ] Reject duplicate routes, dangling identities, raw executable examples,
  and manually authored generated-fact slots.
- [ ] Add preview provenance labels for generated facts, tested scenarios, and
  editorial narrative.
- [ ] Add reusable usability instrumentation without collecting participant
  personal data.
- [ ] Qualify the models against bounded fixture pages supplied by Content
  Epic 0; do not treat fixture prose as public content.

## Usability instrumentation

Provide privacy-safe tooling that lets the content lane run unfamiliar-reader
tests. Content Epic 2 owns recruiting and conducting the study; this epic owns
only the event schema and aggregate report format.

Record:

- time to identify the recommended start;
- time to first working effect;
- commands copied and edited;
- language switches;
- every hesitation longer than two minutes;
- every mistaken assumption about identity, transport, approval, execution, or
  receipts; and
- whether the developer can explain the exact authority afterward.

Do not record page bodies, code values, credentials, receipt contents, or
participant identity. Content Epic 2 defines the success threshold.

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
- platform code hard-codes the public navigation taxonomy instead of consuming
  verified editorial configuration;
- contextual navigation collapse does not widen the reading surface;
- an unpublished feature is presented as stable; or
- a page links to `next` from stable without an explicit warning.

## Validation commands

```text
npm run lint:content
npm run test:dependencies
npm run test:examples
npm run build
npm run test:browser
npm run test:a11y
```

Archive the anonymized usability script, aggregate timings, observed problems,
and resulting issue links without participant personal data.

## Exit gate

This epic is complete when Content Epics 1–4 can express their landings, tours,
choosers, guides, continuations, and contextual navigation without duplicating
product facts or executable source; every input compiles into one verified page
graph; and preview diagnostics expose provenance and affected-page ownership.

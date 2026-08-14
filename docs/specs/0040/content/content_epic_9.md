# Content Epic 9 — Assurance Narrative and Editorial Governance

**Depends on:** [Content Epic 0](./epic_0.md), Content Epics 1–8, and Platform
Epics P9–P11.

**Ownership:** This epic owns assurance explanation, editorial claim selection,
limitations, and content-review policy. P9 owns fact-backed assurance
components, P10 owns machine rendering, and P11 owns qualification and release
orchestration.

## Outcome

Every public Auths claim is versioned, evidenced, limited, searchable, available
to humans and agents, and prevented from drifting away from the released
software.

## Current problem

Auths has substantial formal, adversarial, differential, supply-chain, and live
evidence, but the docs currently summarize assurance more readily than they let
a reader trace an exact claim to current evidence. Content completeness and
usability also need explicit editorial requirements that P11 can enforce
through one release gate.

Stripe separates its security narrative from product instructions and publishes
machine-readable page actions and discovery surfaces across the documentation.
[Research evidence](./STRIPE_CONTENT_RESEARCH.md#batch-5--sdks-cli-agents-failures-and-assurance)

## Assurance model

```text
claim -> stable identity -> applicable release -> evidence -> reproduction
   |                                                |
   +-------------- limitation and scope ------------+
```

### Required assurance sections

- protocol semantics and canonicalization;
- attenuation and delegation;
- critical extensions;
- replay, use, budget, and lifecycle state;
- approval and plan commitment;
- sealed commands and closed gateways;
- receipt integrity and bounded disclosure;
- cryptographic, identity, transport, and provider agility;
- Rust/TypeScript/Python differential evidence;
- formal models and their exact scope;
- fuzzing and adversarial fixtures;
- supply-chain provenance, SBOM, SLSA, and release reproducibility;
- production field evidence and explicit limitations;
- supported runtimes and compatibility policy; and
- security reporting and outside-review status.

## Claim page contract

Every claim page includes:

- stable claim identity;
- plain-language statement;
- normative semantic owner;
- first and latest applicable releases;
- evidence artifacts and checksums;
- reproduction command or procedure;
- what the evidence proves;
- what it does not prove;
- current status: passing, degraded, superseded, withdrawn;
- related failures, profiles, and architecture pages; and
- source-at-release links.

No prose may convert an experimental, partial, or model-scoped result into a
general production guarantee.

## Content governance

| Content | Owner | Update trigger |
|---|---|---|
| SDK/runtime/CLI/reference facts | Generated release bundle | Public contract change |
| Security semantics | Rust semantic owner + security reviewer | Semantic identity change |
| Quickstart source/results | Scenario project | Fixture/package change |
| Operations procedures | Runtime/component owner | Configuration or behavior change |
| Integration ownership | Port/profile owner | Topology change |
| Product narrative | Documentation/product owner | Reviewed editorial change |
| Assurance claims | Evidence owner | Evidence or limitation change |

## Editorial requirements supplied to P11

P11 must enforce the following requirements over the exact current-head docs
release. This epic defines their editorial meaning but does not implement a
parallel pipeline:

1. release-bundle checksum and contract parsing;
2. public documentation coverage;
3. generated reference completeness;
4. all tested quickstarts and differential comparison;
5. HTML/Markdown semantic parity;
6. navigation, sitemap, search, and canonical links;
7. internal/external links;
8. accessibility, responsive, visual, and interaction tests;
9. Lighthouse performance budgets;
10. secret, privacy, unsupported-claim, and stale-version scans;
11. Pagefind/static search and agent discovery surfaces;
12. deployment manifest, preview smoke, atomic promotion, and rollback; and
13. unfamiliar-reader usability fixtures.

## Editorial requirements for machine-readable surfaces

- canonical `.md` for every public page;
- bounded section Markdown by stable section identity;
- `/llms.txt` and bounded `/llms-full.txt`;
- `/.well-known/auths-docs.json`;
- `/reference/manifest.json`;
- `/search-index.json`;
- `/sitemap.xml` and `/robots.txt`; and
- optional read-only documentation MCP after static surfaces qualify.

P10 renders these surfaces from the verified page graph; this epic does not
author a separate Markdown or agent corpus. The documentation MCP, if enabled,
can search, read, resolve symbols, and explain stable errors. It cannot create
authority, accept credentials, execute effects, or access unpublished evidence.

## Implementation steps

- [ ] Curate the claims, evidence, limitations, and statuses exported by P3/P4
  into the assurance information architecture.
- [ ] Author the assurance landing and category-page narratives around P9's
  generated claim components.
- [ ] Link product/security statements to exact claims.
- [ ] Declare content ownership and stable dependencies under Content Epic 0.
- [ ] Provide the editorial requirements above to P11's exact-head
  qualification gate.
- [ ] Review P11 preview change summaries grouped by affected reader journey.
- [ ] Run structured usability tests for chooser, first quickstart, failure
  handling, SDK lookup, and assurance reproduction.
- [ ] Check off all content epics only after their evidence appears in the
  current release report.

## Acceptance criteria

- Every security claim resolves to current evidence and an explicit limitation.
- Withdrawing or superseding evidence automatically changes or blocks affected
  public claims.
- Search, Markdown, agent discovery, and human HTML expose the same release and
  stable identities.
- P11 proves that no required check passes against a stale source or docs head.
- P11 proves rollback restores HTML, Markdown, search, manifests, and downloads
  together.
- Usability participants can select a path, complete a quickstart, diagnose a
  failure, locate an SDK contract, and inspect evidence without facilitator
  intervention.

## Validation

```text
npm ci
npm run test:content
npm run test:assurance
npm run test:a11y
npm run test:links
npm run test:markdown
npm run build
```

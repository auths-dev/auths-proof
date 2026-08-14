# AP-SPEC-040 Content Epics

These epics turn the research in
[`STRIPE_CONTENT_RESEARCH.md`](./STRIPE_CONTENT_RESEARCH.md) into an executable
content program for Auths documentation. They run as the editorial lane beside
AP-SPEC-040 Platform Epics P1–P11. The platform lane builds source truth,
generation, components, and release qualification. This lane chooses reader
journeys and authors the public explanation that occupies those components.

[Content Epic 0](./epic_0.md) is the binding ownership contract. If another
epic appears to contradict it, Epic 0 wins until the specs are reconciled.

The rendered-site audit in
[`SITE_CONTENT_AND_LINK_AUDIT.md`](./SITE_CONTENT_AND_LINK_AUDIT.md) revoked the
completion status of Content Epics 1–9. Their first implementation produced
useful primitives and fixtures but did not satisfy coherent hierarchy,
topic-local navigation, content depth, or link-intent requirements. Do not
check them off again until Content Epics 10–19 qualify the resulting site.

## Execution order

| Order | Epic | Dependency | Exit result |
|---:|---|---|---|
| 0 | [Platform and editorial ownership](./epic_0.md) | P1 and P5 contracts | Facts, scenarios, and narrative have non-overlapping owners |
| 1 | [Global information architecture and topic landings](./content_epic_1.md) | C0, P5–P6 | Every durable domain has a landing and contextual tree |
| 2 | [Getting started and integration chooser](./content_epic_2.md) | C0–C1, P6 | A new reader reaches the right first build path |
| 3 | [Semantic tours and lifecycle concepts](./content_epic_3.md) | C0–C1, P6 | Readers understand Auths before reading reference |
| 4 | [Outcome quickstarts and tested projects](./content_epic_4.md) | C0, C2–C3, P7 | Each recommended path works end to end |
| 5 | [Developer resources and generated reference](./content_epic_5.md) | C0, P4 and P8 | SDK, Runtime API, CLI, error, and version surfaces are complete |
| 6 | [Agents, MCP, and integrations](./content_epic_6.md) | C0, C3–C5, P9 | Agent and composition paths are understandable and independent |
| 7 | [Adoption and migration](./content_epic_7.md) | C0, C2–C6, P9 | Existing systems can adopt Auths incrementally |
| 8 | [Operations, testing, failure, and recovery](./content_epic_8.md) | C0, C4–C7, P9 | Teams can run Auths and respond safely |
| 9 | [Assurance narrative and governance](./content_epic_9.md) | C0–C8, P9 | Claims remain evidenced, current, searchable, and usable |
| 10 | [Canonical information architecture](./content_epic_10.md) | Audit, C0 | Every page has one section, parent, and canonical route |
| 11 | [Topic shell and page-type contracts](./content_epic_11.md) | C10, P5–P6 | Navigation and content depth are enforced universally |
| 12 | [Rebuild Get started](./content_epic_12.md) | C10–C11, P7 | First journeys are executable and coherent |
| 13 | [Complete Identity and trust](./content_epic_13.md) | C10–C12 | Identity remains agnostic and independently usable |
| 14 | [Complete Authority](./content_epic_14.md) | C10–C13 | Five verbs progressively disclose full authority semantics |
| 15 | [Complete Agents and MCP](./content_epic_15.md) | C10–C14 | Agent and MCP journeys are executable and self-contained |
| 16 | [Complete Production operations](./content_epic_16.md) | C10–C15 | Operators receive tested procedures and runbooks |
| 17 | [Complete Developers and integrations](./content_epic_17.md) | C10–C16 | Build, test, integrate, and extend paths are complete |
| 18 | [Complete Reference and Assurance](./content_epic_18.md) | C10–C17, P8–P10 | Exact lookup and evidence utilities are complete |
| 19 | [Full-site qualification](./content_epic_19.md) | C10–C18, P11 | Orphans, shallow pages, and misleading links fail CI |

Only one content epic is in progress at a time. Update the checkbox in this
README only after every acceptance criterion in the epic passes.

## Progress

- [x] Content Epic 0 — Platform and editorial ownership
- [ ] Content Epic 1 — Global information architecture and topic landings
- [ ] Content Epic 2 — Getting started and integration chooser
- [ ] Content Epic 3 — Semantic tours and lifecycle concepts
- [ ] Content Epic 4 — Outcome quickstarts and tested projects
- [ ] Content Epic 5 — Developer resources and generated reference
- [ ] Content Epic 6 — Agents, MCP, and integrations
- [ ] Content Epic 7 — Adoption and migration
- [ ] Content Epic 8 — Operations, testing, failure, and recovery
- [ ] Content Epic 9 — Assurance narrative and governance
- [x] Content Epic 10 — Canonical information architecture and route ownership
- [x] Content Epic 11 — Topic shell, left navigation, and page-type contracts
- [x] Content Epic 12 — Rebuild Get started as an executable journey
- [x] Content Epic 13 — Complete Identity and trust documentation
- [ ] Content Epic 14 — Complete Authority documentation
- [ ] Content Epic 15 — Complete Agents and MCP documentation
- [ ] Content Epic 16 — Complete Production operations documentation
- [ ] Content Epic 17 — Complete Developer, integration, and extension documentation
- [ ] Content Epic 18 — Complete Reference and Assurance utilities
- [ ] Content Epic 19 — Full-site content and link qualification

## Zero-context agent prompt

```text
Work through AP-SPEC-040 content epics in docs/specs/0040/content/README.md.

Before implementation:
1. Read docs/specs/0040-stripe-quality-documentation-platform.md.
2. Read docs/specs/0040/README.md and content/epic_0.md completely.
3. Read completed AP-SPEC-040 platform epics.
4. Read docs/specs/0040/content/STRIPE_CONTENT_RESEARCH.md.
5. Read the current content epic completely.
6. Inspect both auths-proof and the independent auths-docs repository.

Rules:
- Auths-owned semantic facts come from immutable release artifacts.
- Treat every public block as generated fact, tested scenario, or editorial
  narrative; never give one block multiple owners.
- Do not copy Stripe wording, taxonomy, or visual identity.
- Do not hand-author SDK signatures, endpoint inventories, errors, versions,
  evidence status, or executable code represented as tested.
- Keep Rust, TypeScript, and Python semantically identical and idiomatic.
- Preserve progressive disclosure and security boundaries.
- Every public page requires canonical Markdown.
- Run the epic validation commands and record evidence before checking it off.
- One content epic is one focused commit in each repository it changes.
```

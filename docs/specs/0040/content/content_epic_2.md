# Content Epic 2 — Getting Started and the Integration Chooser

**Status:** Complete in `auths-docs` commit `21dec44`.

**Depends on:** [Content Epic 0](./epic_0.md), Content Epic 1, and Platform
Epic P6.

**Ownership:** This epic owns reader questions, recommendation policy, and
public explanations. Platform P6 owns chooser and guide models; generated facts
and scenario code remain bundle-owned.

## Outcome

A reader with no Auths knowledge can identify the correct integration mode in
under three minutes and reach a qualified first build without learning the
entire authority model.

## Current problem

The existing start experience privileges one REST guide and exposes SDK/runtime
formats before the reader has chosen deployment, trust, or effect boundaries.
Auths needs several opinionated first paths, not one universal quickstart.

Stripe uses prerequisites, audience exits, product choosers, and named outcome
recipes before deep implementation. [Research evidence](./STRIPE_CONTENT_RESEARCH.md#batch-2--tours-prerequisites-testing-and-outcome-recipes)

## Journey

```text
What are you protecting?
        |
        +-- local application effect ------> local SDK quickstart
        +-- service/runtime effect --------> production runtime quickstart
        +-- delegated agent action --------> agent delegation quickstart
        +-- cross-company operation -------> portable authority quickstart
        +-- evidence only -----------------> offline verification quickstart
        +-- custom protocol/profile -------> extension path
```

## Required pages

| Route | Type | Purpose |
|---|---|---|
| `/get-started` | Topic landing | Recommended first path and prerequisites |
| `/get-started/choose` | Chooser | Select integration by effect, deployment, trust, and operator needs |
| `/get-started/prerequisites` | Prerequisite catalog | Runtime, language, keys, state, trust, and sandbox requirements |
| `/get-started/local` | Outcome recipe | Protect one local application effect |
| `/get-started/runtime` | Outcome recipe | Submit one exact effect to the open runtime |
| `/get-started/agent` | Outcome recipe | Delegate one tool to one agent |
| `/get-started/cross-company` | Outcome recipe | Authorize across independent identity systems |
| `/get-started/verify` | Outcome recipe | Verify proof or receipt without executing |
| `/get-started/evaluate` | Evaluation guide | Run deterministic fixtures and compare outcomes |

## Chooser dimensions

Parse the reader's choices into a closed recommendation model:

- effect location: in-process, local service, remote service, provider;
- actor: person, workload, agent, organization;
- identity/trust source: raw key, OIDC, SPIFFE, application resolver, other;
- authority need: direct, delegated, approved plan, verification only;
- state need: none, replay, budget, durable recovery;
- custody: development signer, application signer, KMS/HSM port;
- integration ownership: Auths-maintained profile or application-owned profile;
- operational posture: evaluation, self-hosted production, integration author.

The chooser returns one primary route, up to two alternatives, and the reasons
for the recommendation. It never generates authority or collects credentials.

## Implementation steps

- [ ] Author the deterministic recommendation table against P6's chooser
  schema.
- [ ] Author prerequisites with early exits for non-developers, SDK users,
  runtime operators, agent builders, and integration authors.
- [ ] Write the five outcome recipes using the same actors and one comprehensible
  incident/reporting domain.
- [ ] Link every recipe to a Content Epic 4 tested project.
- [ ] State what the reader will produce, how long it should take, and what is
  deliberately excluded at the top of each path.
- [ ] End every path with success evidence, one fail-closed mutation, and next
  steps into concepts, operations, and reference.
- [ ] Add a “bring your existing identity” branch without implying that Auths
  owns identity providers or cryptographic adapters.
- [ ] Declare page dependencies so P6 can generate affected-page relationships.

## Acceptance criteria

- Five unfamiliar developers choose the intended route from five fixture
  scenarios with no facilitator explanation.
- No first path requires capabilities, approvals, Iroh, a hosted runtime, or a
  specific identity suite unless that path's outcome needs it.
- Each route distinguishes local evaluation from production requirements.
- Every route exposes exactly one primary outcome and one adversarial failure.
- All links resolve to stable identities and canonical Markdown exists.

## Validation

```text
npm run test:chooser
npm run test:content
npm run test:links
npm run test:markdown
npm run test:usability-fixtures
npm run build
```

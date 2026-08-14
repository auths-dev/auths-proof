# Content Epic 3 — Semantic Tours and Lifecycle Concepts

> **Status revoked by rendered-site audit.** Requalify through Content Epics
> 10–19; existing checked tasks record prior implementation, not completion.

**Status:** Complete in `auths-docs` commit `c2fe2ec`.

**Depends on:** [Content Epic 0](./epic_0.md), Content Epic 1, and Platform
Epic P6.

**Ownership:** This epic owns conceptual teaching and accessible conceptual
diagrams. Lifecycle states, outcome names, trust facts, and evidence are
embedded from the release bundle rather than redefined in prose.

## Outcome

Readers understand the Auths model, boundaries, and state transitions before
they encounter low-level APIs.

## Current problem

Auths has unusually precise semantics, but its explanation is fragmented across
architecture, specifications, demos, and reference terminology. A reader can
learn how to call a method without understanding why the authority, execution,
or recovery types exist.

Stripe uses API tours and lifecycle pages to explain relationships and state
independently from quickstarts and reference. [Research evidence](./STRIPE_CONTENT_RESEARCH.md#batch-3--product-choice-interactive-quickstarts-and-lifecycle-concepts)

## Required tours

### Auths in fifteen minutes

Teach the five nouns and five verbs using one bounded operation:

```text
actor --create--> authority --delegate--> narrower authority
  |                                      |
  +-- exact action ----------------------+
                         |
                      execute
                         |
        denied | indeterminate | recoverable | completed
                         |
                      receipt --verify--> inert decision
```

### Identity and trust

Explain identity material, authentication evidence, trust roots, resolvers,
cryptographic suites, and the boundary between proving who signed and deciding
what that signer may do. Show Ed25519 and P-256 only as proof of replaceability.

### Authority lifecycle

Explain authoring, commitment, attenuation, delegation depth, critical
extensions, expiry, revocation, use and budget state, and exhaustion.

### Execution lifecycle

Explain parse, verify, authorize, reserve, seal, gateway entry, provider
observation, receipt, recoverable reference, resume, and terminal outcomes.

### Approval-bound plans

Explain exact-plan commitment, threshold or ordered approval, substitution
resistance, cancellation, partial/unknown provider outcomes, and why approval
alone cannot execute.

### Receipt and disclosure lifecycle

Explain decision versus execution receipts, opaque/summary/full disclosure,
authorization for disclosure, sensitive detail, and offline verification.

## Page contract

Each tour or lifecycle page contains:

1. the problem the primitive solves;
2. a horizontal overview diagram and text equivalent;
3. states or components with stable identities;
4. invariants in plain language;
5. a happy path and at least three failure branches;
6. “use this when” and “do not use this when”;
7. links to tested quickstarts and generated reference; and
8. versioned evidence links for security claims.

## Implementation steps

- [ ] Add stable page and section identities for all six tours.
- [ ] Compose the registered P6/P9 `Tour`, `Lifecycle`, `Invariant`, and
  `FailurePath` components; do not implement alternate renderers here.
- [ ] Reference release-bundle state, outcome, profile, and error identities in
  page dependencies.
- [ ] Author the six tours using one consistent example domain.
- [ ] Author accessible diagram source and text equivalents for P5's build-time
  renderer; prohibit browser Mermaid.
- [ ] Add explicit composition diagrams showing identity, authority, transport,
  state, custody, and provider ports as independently replaceable.
- [ ] Review every invariant against Rust-owned semantics and frozen fixtures.
- [ ] Declare related-reference links for P8 to resolve from generated symbols.

## Acceptance criteria

- No tour includes an invented public symbol or hand-authored outcome enum.
- A reader can explain identity versus authority, approval versus execution,
  transport versus authorization, and recoverable versus retry after completing
  the tours.
- Every diagram has an equivalent ordered text description.
- Mutation, replay, expiry, widening, revocation, and provider-unknown appear in
  at least one lifecycle path.
- HTML and canonical Markdown carry the same semantic content.

## Validation

```text
npm run test:content
npm run test:diagrams
npm run test:evidence-links
npm run test:markdown
npm run test:a11y
npm run build
```

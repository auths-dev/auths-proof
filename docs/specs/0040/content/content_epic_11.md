# Content Epic 11 — Topic Shell, Left Navigation, and Page-Type Contracts

**Depends on:** Content Epic 10 and Platform Epics P5–P6.

## Outcome

Every page preserves the reader's location and every page type must satisfy a
job-specific minimum content contract before it can render publicly.

## Current problem

Eighty-three pages lack left navigation. The generic editorial renderer allows
a title and one paragraph to masquerade as a complete guide, reference page,
integration, or runbook.

## Implementation

- [ ] Build one reusable `TopicShell` with global navigation, collapsible
  topic-local left navigation, breadcrumbs, active state, previous/next, and
  mobile drawer behavior.
- [ ] Render the same topic tree on landings, guides, quickstarts, concepts,
  integrations, operations pages, and reference introductions.
- [ ] Define closed schemas for `landing`, `concept`, `guide`, `quickstart`,
  `integration`, `reference`, and `runbook`.
- [ ] Require guides to contain outcome, prerequisites, ordered steps, code or
  an explicit no-code rationale, success, fail-closed behavior, and next step.
- [ ] Require integrations to contain ownership matrix, data flow, secrets,
  state, failure ownership, executable composition, and limitations.
- [ ] Require runbooks to contain owner, severity, preconditions, tested
  commands, observations, stop conditions, rollback/resume, reconciliation,
  retention, and escalation.
- [ ] Require reference pages to resolve generated signatures or inventories;
  prose alone cannot qualify as reference.
- [ ] Label cross-topic cards as **Related topics**, never **Open guide** inside
  the primary content sequence.
- [ ] Add responsive, keyboard, screen-reader, and nav-collapse tests.

## Acceptance

- Every non-landing public page renders the correct owning topic navigation.
- A page cannot build when its type-specific required blocks are missing.
- Mobile and desktop navigation expose identical hierarchy and active state.
- Reference and quickstart layouts retain synchronized floating code behavior.


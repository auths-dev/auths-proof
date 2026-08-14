# Epic 9 — Build Deep-Content Composition Contracts

**Parent:** [AP-SPEC-040](../0040-stripe-quality-documentation-platform.md)

**Repository:** `auths-proof-docs`

**Depends on:** Epics 3, 5, 6, and 8 and Content Epic 0

**Blocks:** Epics 10–11

## Outcome

Build the fact-backed page models, components, validators, and dependency
contracts required for architecture, operations, integrations, and assurance.
Content Epics 6, 8, and 9 own the routes, prose, recommendations, and conceptual
diagrams published through those contracts.

This epic makes deep editorial content safe to author without copying product
facts, runbook commands, configuration, integration inventories, or assurance
status into a second source of truth.

## Ownership boundary

Follow [Content Epic 0](./content/epic_0.md). This epic owns composition
machinery and generated projections. It does not own public narrative, page
selection, route taxonomy, integration recommendations, or assurance claim
interpretation.

## Zero-context starting point

Read:

- parent sections 5–10 and 16;
- Epics 3, 5, 6, and 8;
- `docs/specs/0040/README.md` and `content/epic_0.md`;
- `AGENTS.md` and the profile/domain abstraction boundary plan;
- `docs/product/AUTHS_AUTHORITY_LAYER.md`;
- `docs/target-state/`;
- `docs/research/competition/`;
- `docs/integrations/`;
- AP-SPEC-038 and all `docs/specs/0038/epic_*.md`;
- AP-SPEC-039 to identify enterprise-only material;
- `release/assurance/open-production-candidate-1/`;
- `release/RELEASE_CONTROL.md` and `RELEASE_RUNBOOK.md`;
- open production, incident response, PostgreSQL, OpenTofu, and relevant field
  lab demo documentation; and
- the verified docs bundle's profile, lifecycle, error, and evidence facts.

Repository plans and demo claims are leads, not public facts. Reconcile every
claim with the selected release artifact.

## Supported editorial shapes

Support the following page families without hard-coding their final route
inventory:

```text
/architecture/
├── system-map
├── trust-boundaries
├── identity-authority-transport
├── exact-effect-profiles
├── lifecycle-and-recovery
├── custody-and-signing
├── stores-and-replay
├── outcomes-and-receipts
└── threat-model

/operate/
├── open-reference
├── configuration-and-doctor
├── postgresql
├── kms-and-pkcs11
├── observability
├── backup-and-restore
├── recovery-and-reconciliation
├── upgrades-and-rollback
└── incident-response

/integrations/
├── oauth-oidc
├── spiffe
├── policy-engines
├── rebac
├── cloud-iam
├── ucan-biscuit
└── http-message-signatures

/assurance/
├── claims-and-limitations
├── conformance-and-fixtures
├── differential-evidence
├── formal-evidence
├── release-provenance
└── independent-review
```

The tree is an initial fixture for validating the models. Content Epics 6, 8,
and 9 own the final public inventory and ordering. Enterprise fleet
coordination, centralized multi-tenant operations, paid governance, and hosted
control-plane features remain separately classified and cannot become an
open-core prerequisite.

## Architecture teaching contract

Every architecture page distinguishes:

- identity evidence from authority;
- authority from approval;
- approval from execution authorization;
- transport delivery from verification;
- pure decision from durable lifecycle state;
- durable reservation from provider effect;
- definite non-effect from unknown effect;
- receipt commitment from authorized disclosure; and
- protocol guarantees from profile/application/provider guarantees.

Use horizontal diagrams with text equivalents. Diagrams are conceptual views
over typed release facts, not replacements for them.

Example system map:

```text
identity evidence -> create/delegate authority -> native verification
                                                |
                                                v
                                        durable reservation
                                                |
                                                v
                                      closed profile gateway
                                                |
                                      +---------+---------+
                                      v                   v
                                definite outcome    outcome unknown
                                      |                   |
                                      v                   v
                                   receipt         observe + resume
```

## Operations contract

Every operations procedure includes:

1. supported topology and prerequisites;
2. exact configuration fields generated from the selected release;
3. secret slots without values;
4. readiness and safe diagnostic commands;
5. expected healthy output;
6. failure categories and effect-aware actions;
7. rollback/recovery behavior;
8. privacy and telemetry boundaries; and
9. evidence that qualified the procedure.

Copyable commands use placeholders that cannot resemble working credentials.
Commands must be tested against an isolated reference deployment. Do not
publish internal endpoints, customer identifiers, or provider resource IDs.

## Integration contract

Integration guides are “Auths with,” not manufactured-versus comparisons. Each
guide states:

- what the adjacent system supplies;
- what Auths supplies;
- where meaning is translated;
- which party owns identity, policy, state, custody, transport, effect, and
  receipts;
- what cannot be inferred from the adjacent token/decision/identity;
- replay and lifecycle responsibilities;
- failure and unknown-effect behavior; and
- one executable or conformance-backed example.

Use the evidence-based competitive research and primary specifications. Link
to the relevant external specification near claims. Do not imply another
project lacks a property that its current primary documentation supplies.

## Assurance contract

Generated assurance panels show only claims present in the release bundle,
their exact evidence subjects, qualification status, limitations, source
commit, and verification instructions.

Authored prose may explain why evidence matters but cannot upgrade
“qualification evidence” to proof of universal correctness, production
availability, compliance, certification, or external audit.

## Components and data

Use:

- `TrustBoundary` for ownership and untrusted inputs;
- `Lifecycle` for transition/effect/recovery state;
- `OutcomeMatrix` for closed result behavior;
- `ReceiptView` for disclosure levels;
- `ProfileContract` for exact-effect boundaries;
- `OperationalCallout` for effect-aware action;
- `Diagram` with accessible text; and
- generated `VersionBadge`, `ReferenceLink`, and evidence panels.

Authored MDX declares semantic dependencies. Generated configuration, limits,
profiles, errors, and assurance facts are embedded by identity.

## Platform implementation steps

- [ ] Implement typed architecture, operations, integration, and assurance page
  models.
- [ ] Implement `TrustBoundary`, `Lifecycle`, `OutcomeMatrix`, `ReceiptView`,
  `ProfileContract`, `OperationalCallout`, and generated evidence components.
- [ ] Resolve configuration, commands, profiles, errors, limits, evidence, and
  scenario output exclusively from immutable bundle identities.
- [ ] Validate accessible diagram text and trust-boundary semantics without
  owning the editorial diagram itself.
- [ ] Validate integration ownership matrices and primary-source citations.
- [ ] Validate runbook preconditions, stop conditions, recovery, and tested
  command identities.
- [ ] Validate assurance claims against current evidence and limitations.
- [ ] Provide Content Epics 6, 8, and 9 with preview fixtures and provenance
  diagnostics.
- [ ] Reject open-core pages that depend on enterprise-only components.

## Adversarial review

Reject:

- a diagram that shows transport or approval creating authority;
- a lifecycle diagram that turns provider-unknown into failure or retry;
- a runbook copying a secret or realistic provider identifier;
- configuration prose disagreeing with generated defaults;
- an integration guide that treats an OAuth scope, SPIFFE identity, policy
  decision, IAM credential, UCAN, or Biscuit as interchangeable with Auths;
- an assurance claim without limitation or release subject;
- a demo result presented as broad production evidence;
- formal evidence described as covering code outside its model;
- enterprise coordination described as required for self-hosting;
- a command not executed against the selected release; and
- a security-critical action hidden behind progressive disclosure.

## Validation commands

```text
npm run lint:content
npm run test:dependencies
npm run test:runbooks
npm run test:links
npm run test:diagrams
npm run test:markdown
npm run build
npm run test:a11y
```

External links are checked nightly to avoid flaky pull-request failures, while
primary-specification URL syntax and internal links remain PR gates.

## Exit gate

This epic is complete when Content Epics 6, 8, and 9 can author their material
using typed, fact-backed components; runbook commands and assurance facts cannot
drift from the selected release; and every deep page compiles into the same
verified page graph used by the rest of the site.

# Auths business launch roadmap

**Status:** Proposed execution roadmap. Product, pricing, repository, license,
publication, customer, and security-review decisions remain owner-controlled.

**Companion strategy:** [Auths Product and Go-to-Market
Strategy](GO_TO_MARKET_STRATEGY.md)

**Commercial evidence gate:** [AP-SPEC-031: Commercial discovery and product
selection](../specs/0031-commercial-discovery.md)

**Integration evidence gate:** [AP-SPEC-030: Design-partner integration
program](../specs/0030-design-partner-integrations.md)

**SDK feedback program:** [AP-SPEC-036: SDK ergonomics and external-consumer
workflow closure](../specs/0036_sdk_ergonomics.md)

## 1. Purpose

This document turns the product strategy into a launch sequence for an open
protocol project and a venture-scale company around it.

It recommends a starting product wedge, defines V1 and V2 epics, supplies
implementation-shaped subtasks and API sketches, and proposes a clean
open-core boundary. It does not replace the technical phase gates or turn an
unvalidated commercial hypothesis into an approved build.

In this document, **V1** and **V2** refer to commercial product releases. They
do not rename the Auths protocol, the `1.0.0-rc.1` release candidate, or any
assurance claim.

## 2. Business thesis

AI agents increasingly act through credentials that are broader and longer-
lived than the task they are performing. Identity systems can establish who
or what an agent is. They do not, by themselves, give every action a portable,
locally verifiable, narrowly delegated statement of authority.

Auths can become the authority layer between an agent's intention and an
external effect:

```text
Human or organization
        |
        | delegates bounded authority
        v
Parent agent or workflow
        |
        | delegates less
        v
Child agent
        |
        | presents authority with exact action
        v
Local Auths enforcement ---- denied/indeterminate ----> no effect
        |
        | authorized, sealed command
        v
Closed provider gateway ----> GitHub / MCP / HTTP / database / cloud
```

The open project should make this model credible and useful without an Auths-
hosted service. The company should sell the operational coordination that
organizations need once they use the model across teams, environments,
agents, and providers.

### 2.1 The first product hypothesis

The recommended first commercial wedge is an **Agent Action Gateway**:

> A customer-operated enforcement gateway that lets teams attach an agent,
> delegate exact authority, stop out-of-authority actions before provider
> execution, and produce inspectable evidence.

The gateway is a useful label for a product bundle, not a new semantic center.
The open verifier still decides authorization locally. Profile-owned gateways
still own exact provider effects. A commercial deployment may coordinate
trusted configuration, approvals, receipts, and operations, but it must not
privately redefine what `authorized` means.

This wedge is recommended because it:

- demonstrates a visible outcome: the forbidden action does not happen;
- complements identity, secrets, and agent-framework products;
- supports headless, supervised, hosted, and on-premises use;
- begins with one workflow and expands by profile rather than by universal
  policy language;
- creates real demand signals for approval, inventory, receipt, and lifecycle
  products; and
- keeps the open SDK as the adoption engine.

AP-SPEC-031 still controls final product selection. If design partners show a
different repeated, budgeted problem, this roadmap must be revised.

### 2.2 Product ladder

| Layer | Product | Customer outcome | Default boundary |
| --- | --- | --- | --- |
| Adoption | Open protocol, verifier, SDKs, profiles, fixtures | Build and verify bounded authority locally | open source |
| First wedge | Agent Action Gateway | Stop unauthorized agent effects and retain evidence | open enforcement path plus commercial operations |
| Operations | Auths Control Plane | Manage organizations, trusted state, approvals, grants, and environments | commercial hosted/on-premises |
| Integration | Enterprise connectors | Connect identity, custody, KMS/HSM, SIEM, workflow, and provider systems | commercial where vendor-specific |
| Assurance | Support and assurance | Deploy, review, operate, and upgrade with confidence | commercial service |

## 3. Users, champions, and buyer hypotheses

The initial user is an agent-framework maintainer or platform engineer. The
likely champion is the person responsible for the internal agent platform,
developer platform, or application security program. The economic buyer is
not yet known; likely hypotheses include a VP of Engineering, platform leader,
CISO, or security engineering leader.

Research must keep these roles separate:

| Role | Job to be done | Evidence to collect |
| --- | --- | --- |
| SDK user | Protect an action without learning protocol internals | setup time, glue code, failures |
| Agent owner | Give an agent freedom inside a fixed boundary | denied effects, approval burden |
| Platform operator | Manage agents and authority across environments | repeated operational work |
| Security reviewer | Understand the trust boundary and evidence | review time, unresolved risks |
| Economic buyer | Reduce a costly, urgent operational risk | budget, procurement, commitment |

No launch plan should assume that the most enthusiastic developer controls a
budget.

## 4. Product principles

Every product decision should preserve these rules:

1. Identity and authority remain distinct.
2. Authority is committed to the action and travels with it.
3. Verification remains local and effect-free.
4. A hosted service is optional, never required for semantic verification.
5. Delegation can only preserve or reduce authority.
6. Only an authorized, verifier-sealed command can reach a closed gateway.
7. Denial is terminal for unchanged trusted inputs, even after restart.
8. Human approval is configurable and transaction-bound, not mandatory
   babysitting.
9. Profiles own domain semantics; the platform does not grow a generic
   operation-tag executor.
10. Commercial code may operate open semantics but may not privately alter
    them.

## 5. Open-core boundary

### 5.1 What must remain open

The complete local safety path must remain in `auths-proof` under its approved
open-source licenses:

- protocol specification and canonical encodings;
- authority, attenuation, validity, revocation, and verification semantics;
- formal models, translation evidence, and conformance fixtures;
- Rust verifier and authoring implementation;
- SDK workflows needed to create, delegate, inspect, and verify authority;
- sealed-command and closed-gateway interfaces;
- profile interfaces and maintained reference profiles;
- development fixtures and adversarial test suites;
- approval, custody, status, and trusted-context ports;
- local receipt generation and inspection;
- enough examples and documentation to operate without an Auths account; and
- public compatibility and assurance claims.

If removing a commercial service would make an existing proof unverifiable or
turn a safe local gateway into an unsafe one, the boundary is wrong.

### 5.2 What may be commercial

Commercial products may coordinate and operate the open core:

- organizations, projects, environments, and role administration;
- signed trust-bundle and policy distribution;
- fleet inventory for principals, agents, grants, and expirations;
- approval routing, escalation, schedules, and enterprise workflow adapters;
- durable receipt retention, indexing, search, export, and legal holds;
- revocation and status operations with monitored distribution;
- hosted and on-premises control-plane deployment;
- KMS, HSM, keychain, identity, SSO, SIEM, ticketing, and provider connectors;
- audit dashboards and compliance-oriented reports;
- operational alerts, upgrade coordination, support, and assurance services;
- managed profile lifecycle and compatibility operations; and
- enterprise tenancy, availability, backup, and disaster recovery.

Commercial coordination must produce explicit, signed, locally consumable
state. The local verifier decides what that state means.

### 5.3 Repository and license recommendation

Do not add an `ee/` directory yet. The current repository has an intentional
layering model, and a sixth top-level shipping layer plus a second license is
an architectural and legal decision, not a folder-creation shortcut.

Before the first proprietary implementation, record an ADR and owner decision
between these options:

#### Option A — separate private enterprise repository (recommended)

```text
auths-proof/                    # public, current Apache-2.0/MIT licensing
  core/
  exchange/
  product/
  bindings/
  demos/

auths-enterprise/               # private, commercial license
  apps/control-plane/
  services/approval-router/
  services/receipt-index/
  services/trust-distributor/
  connectors/identity/
  connectors/custody/
  connectors/siem/
  deployments/hosted/
  deployments/on-prem/
  docs/
```

The enterprise repository consumes published, immutable open packages. It may
not use private hooks into the verifier or receive unreleased semantic logic.
This provides the clearest contribution, licensing, release, and trust
boundary.

#### Option B — an `ee/` tree in the monorepo

This may be chosen later if atomic development materially outweighs licensing
and contribution complexity:

```text
ee/
  LICENSE
  README.md
  control-plane/
  approval-router/
  receipt-index/
  connectors/
  deployments/
```

If chosen, CI MUST enforce:

```text
ee/*  ---> published public Auths interfaces
open  -X-> ee/*
```

The `ee/` tree needs a commercial license, explicit file headers, separate
artifact manifests, isolated build and test jobs, no inclusion in open source
packages, and no reverse dependency from open code. An ADR must update the
architecture classifier before the directory exists.

### 5.4 Boundary test for every proposed feature

Before implementation, answer:

1. Is this needed to author, delegate, verify, enforce, or inspect one action
   locally? If yes, it belongs in the open core.
2. Does it define protocol or profile semantics? If yes, it belongs in the
   open core.
3. Does it coordinate many users, agents, environments, records, or external
   systems? It may be commercial.
4. Would withholding it make the open path deceptively unsafe? If yes, it must
   be open.
5. Can the enterprise implementation consume a stable public interface? If
   not, improve the public interface before adding a private hook.

## 6. Launch stages

```text
Foundation
   |
   v
V1 design-partner preview
   |
   | repeatable activation + paid problem evidence
   v
V1 general launch
   |
   | operational demand + reliable customer deployment
   v
V2 enterprise operations
```

Calendar dates should be assigned only after scope, owner capacity, review
timing, and design-partner availability are known. Entry and exit evidence is
more important than an invented date.

## 7. Foundation epics

### F0-E1 — Freeze the category and message

**Outcome:** A technical buyer understands Auths in one minute.

Subtasks:

- Write one category statement: “portable authority for agent actions.”
- Lead with the protected effect, not formal methods or cryptography.
- Publish an identity-versus-authority explanation.
- Document local, headless, hosted, and on-premises deployment shapes.
- Define prohibited claims until external review completes.
- Test the message with at least ten target users and record confusion.

Exit evidence:

- most target users can restate the difference between identity and authority;
- the demo can show an authorized action and a stopped action; and
- published claims match the exact assurance bundle.

### F0-E2 — Close the SDK activation loop

**Outcome:** A new developer protects one action quickly and without protocol
glue.

Subtasks:

- Complete the governing AP-SPEC-027, AP-SPEC-035, and AP-SPEC-036 units.
- Keep TypeScript as the primary product-design surface.
- Make the GitHub sandbox demo an external released-package consumer.
- Add one MCP example using the same attach/delegate/authorize shape.
- Measure time to first denial and first sandboxed effect.
- File an Auths issue for every repeated piece of application glue.
- Publish a capability matrix with honest preview labels.

Target API:

```ts
const auths = await loadAuths({ signer, trustedAuthority });
const agent = await auths.attachAgent({ authority, approval });
const child = await agent.delegate({ authority: narrower, signer: ephemeral });
const result = await child.authorize(profile.action(input));

if (result.kind === "authorized") {
  await gateway.execute(result.command);
}
```

Exit evidence:

- no hand-authored protocol encoding or capability brands;
- a clean external install passes on supported platforms;
- forbidden side effects are tested; and
- the friction scorecard reaches the AP-SPEC-036 target.

### F0-E3 — Establish commercial discovery

**Outcome:** Product selection is based on pain and willingness to pay.

Subtasks:

- Recruit three to five design partners from framework and internal-agent
  teams.
- Observe current credential, approval, incident, and audit workflows.
- Map user, champion, operator, reviewer, and economic buyer separately.
- Test hosted, on-premises, hybrid, and fully local preferences.
- Quantify the cost of existing approval and incident work.
- Ask for a concrete next commitment, not general enthusiasm.
- Maintain a hypothesis ledger under AP-SPEC-031.

Exit evidence:

- at least three real integrations;
- at least two independently maintained integrations;
- a repeated operational problem; and
- credible willingness to pay from the likely buyer.

### F0-E4 — Decide the company boundary

**Outcome:** Proprietary work cannot contaminate or weaken the open protocol.

Subtasks:

- Obtain legal advice on trademarks, inbound contributions, and the commercial
  license.
- Record the separate-repository versus `ee/` decision in an ADR.
- Define public interfaces enterprise code may consume.
- Add dependency and artifact-boundary enforcement.
- Define coordinated disclosure and security support policies.
- Decide whether a CLA is needed; do not impose one by default.
- Publish a plain-language open-core promise.

Exit evidence:

- approved license and repository decision;
- automated no-reverse-dependency check;
- contribution documentation; and
- no enterprise-only semantic requirement in the local safety path.

## 8. V1 product definition

### 8.1 V1 promise

> Attach an agent, give it bounded authority for a real tool, stop actions
> outside that authority, and understand the resulting evidence—without
> sending verification to Auths.

V1 should focus on one excellent workflow, not broad platform surface area.
The recommended flagship is a GitHub change plan because it is visible,
sandboxable, consequential enough to matter, and naturally demonstrates
branch, path, action, approval, and pull-request constraints. MCP is the first
runtime adapter and should share the same authority model.

### 8.2 V1 packaging hypothesis

- **Community:** open protocol, SDKs, local gateway interfaces, reference
  profiles, conformance tools, and self-operated examples.
- **Design-partner pilot:** deployment help, an early customer-operated action
  gateway, basic approval routing, receipt export, and direct support.
- **Enterprise pilot:** on-premises packaging and one or two required
  connectors, only after the customer problem is validated.

Do not place a toll on local verification or price per local authorization.
Candidate value metrics to test include managed agents, protected production
environments, active governed workflows, or an annual platform subscription.

## 9. V1 epics

### V1-E1 — Open SDK and profile release

**Outcome:** The open product is a credible adoption path.

Subtasks:

- Finish TypeScript Full Workflow capability and Python parity.
- Publish exact supported-platform and browser matrices.
- Ship application-profile authoring and conformance kits.
- Ship development custody separately from production custody ports.
- Provide MCP and GitHub reference profiles or integrations.
- Add migration, compatibility, and deprecation policy.
- Keep raw protocol APIs visibly advanced.
- Generate API docs and compile every example in CI.

Launch gate:

- independent review and release claims permit publication;
- packages are reproducible and provenance subjects are correct;
- external-consumer tests pass from immutable artifacts; and
- no normal example bypasses the sealed command boundary.

### V1-E2 — Customer-operated Agent Action Gateway

**Outcome:** A team can protect one real provider workflow.

Subtasks:

- Define a public `ClosedGateway<Command, Receipt>` interface per profile.
- Implement one production-shaped GitHub gateway outside the verifier.
- Implement one MCP gateway with explicit server/tool audience binding.
- Require profile-scoped credentials and prohibit mutation credentials shared
  across unrelated actions.
- Add idempotency, reconciliation, and partial-effect receipts per profile.
- Add dry-run or sandbox deployment modes.
- Prove denied and indeterminate decisions execute zero provider effects.

Illustrative boundary:

```ts
interface GitHubGateway {
  execute(command: VerifiedGitHubChangePlan): Promise<GitHubExecutionReceipt>;
}

// There is deliberately no execute(operationTag, payload, credential).
```

Launch gate:

- one design partner operates the gateway in its own environment;
- credentials remain profile- and action-scoped;
- restart and retry cannot escape authority; and
- provider failure and partial-effect behavior are documented and tested.

### V1-E3 — Minimal approval routing

**Outcome:** Teams can choose autonomy or supervision without changing
authorization semantics.

Subtasks:

- Implement grant-only, action-only, plan-once, always, and headless modes.
- Bind approvals to exact transaction and configuration commitments.
- Start with one local user-presence provider and one headless provider.
- Add a provider-neutral webhook or workflow port only if a design partner
  requires it.
- Record required and executed approval configuration in receipts.
- Test cancellation, expiry, replay, mutation, and provider unavailability.

Illustrative policy:

```ts
const approval = approvalPolicy.planOnce({
  expiresIn: "5m",
  maxUses: 1,
  require: ["human-presence"],
});
```

Launch gate:

- autonomous users can run inside fixed authority without prompts;
- supervised users can require an exact human decision; and
- approval evidence is never described as identity unless independently
  established.

### V1-E4 — Evidence export and local inspection

**Outcome:** A developer and reviewer can explain why an action did or did not
happen.

Subtasks:

- Expose stable stages, codes, commitments, authority summaries, and work
  metrics.
- Produce a bounded local receipt bundle.
- Add redaction and safe-to-log classifications.
- Export JSON without exposing credentials, private material, or full payloads
  by default.
- Provide a local inspector example, not a mandatory hosted dashboard.
- Document authorization evidence separately from provider execution evidence.

Launch gate:

- a non-core maintainer diagnoses representative denial and indeterminate
  cases; and
- inspection data cannot be converted into a verified command.

### V1-E5 — Pilot operations and support

**Outcome:** The company can support a small number of real deployments.

Subtasks:

- Write deployment, backup, recovery, upgrade, and rollback runbooks.
- Define support severity and response targets that can actually be staffed.
- Create a security contact and vulnerability intake process.
- Establish a release channel and compatibility notification process.
- Collect product telemetry only with explicit consent and bounded fields.
- Keep customer proofs, credentials, action bodies, and receipts out of default
  telemetry.
- Run failure exercises with each pilot.

Launch gate:

- support obligations are written and staffed;
- recovery exercises pass;
- customer data boundaries are approved; and
- no unreviewed consequential effect is presented as production-ready.

### V1-E6 — V1 go to market

**Outcome:** Auths reaches the narrow audience with a demonstrable promise.

Subtasks:

- Publish the GitHub sandbox demonstration with both allowed and stopped
  paths.
- Publish the MCP delegation reference flow.
- Write technical material on identity versus authority, terminal denial,
  local verification, and authority that travels with an action.
- Offer an “agent authority design review” to qualified teams.
- Co-develop integrations with three to five design partners.
- Contribute profile and conformance support to selected framework ecosystems.
- Present exact assurance evidence without broad security claims.
- Turn repeated onboarding questions into SDK and documentation fixes.

Primary channels:

- agent-framework and MCP maintainer communities;
- security and platform engineering communities;
- technical essays and executable demos;
- direct founder-led outreach to internal-agent teams;
- partner integrations and conference workshops; and
- open conformance fixtures that other implementers can run.

Avoid broad paid acquisition until activation and buyer evidence exist.

V1 funnel:

```text
Essay or demo
    -> sandbox denial
    -> SDK integration
    -> authority design review
    -> design-partner workflow
    -> customer-operated pilot
    -> paid operational product
```

### V1-E7 — Commercial validation

**Outcome:** One paid product problem is selected or explicitly rejected.

Subtasks:

- Run problem and buyer interviews under AP-SPEC-031.
- Price-test outcomes, not feature bundles.
- Request paid pilot or equivalent procurement evidence.
- Compare approval, inventory, receipt, policy-distribution, connector, and
  support needs.
- Test annual platform and support packaging.
- Record why the open SDK is insufficient for the paid operational job.
- Select at most one first commercial problem.

Launch gate:

- named economic buyer;
- repeated urgent problem;
- agreed deployment model;
- willingness-to-pay evidence;
- open-core boundary review; and
- owner-approved product and packaging decision.

## 10. V1 launch checklist

V1 may launch only when all applicable items have evidence:

- [ ] Exact release and assurance claims are current.
- [ ] Required independent review and remediation gates pass.
- [ ] TypeScript external-consumer activation meets its scorecard.
- [ ] Python capability labels match real behavior.
- [ ] One GitHub and one MCP path demonstrate closed enforcement.
- [ ] Denied and indeterminate actions cause no provider effect.
- [ ] Approval modes work in headless and supervised configurations.
- [ ] Customer-operated deployment and recovery are documented.
- [ ] Security reporting and support ownership exist.
- [ ] Open-core repository and license decision is recorded.
- [ ] A design partner can maintain an integration without the core author.
- [ ] Every public claim names its exclusions.

## 11. V1 success measures

Use a small set of behavior metrics:

- median time to first local denial;
- median time to first sandboxed authorized effect;
- number of hand-written protocol or security glue lines;
- percentage of integrations maintained without a core author;
- number of real workflows with narrower child authority than parent;
- rate of denial explanations resolved without core support;
- number of qualified teams moving from demo to integration;
- number moving from integration to customer-operated pilot;
- paid pilot or procurement commitments; and
- forbidden-effect test coverage across maintained profiles.

Downloads and stars are useful distribution signals, not product-market fit.

## 12. V2 product definition

V2 should turn one-workflow enforcement into organization-scale operation.
The recommended V2 product is **Auths Control Plane**, available hosted and
on-premises, with the local verifier and customer-operated gateway remaining
independent.

### 12.1 V2 promise

> Operate bounded agent authority across teams and environments: distribute
> trusted state, route approvals, inventory grants, revoke compromised
> authority, retain evidence, and integrate existing enterprise systems.

V2 scope must be earned by repeated V1 operations. It should not become a
generic identity platform, secrets manager, agent framework, or universal
policy engine.

## 13. V2 epics

### V2-E1 — Organization and environment model

**Outcome:** Customers can separate authority administration across real
organizational boundaries.

Subtasks:

- Model organization, project, environment, profile installation, and
  operator role.
- Keep these as control-plane administration, not protocol identity truth.
- Define tenant isolation and data residency boundaries.
- Support hosted and on-premises deployments from the same public contracts.
- Add explicit export and deletion behavior.
- Integrate enterprise SSO for control-plane access without coupling Auths
  authority semantics to one identity provider.

### V2-E2 — Signed trust and policy distribution

**Outcome:** Fleets receive current trusted configuration without outsourcing
verification.

Subtasks:

- Define signed, versioned trust bundles using public formats.
- Support staged rollout, rollback, expiry, and environment pinning.
- Cache sufficient state for bounded offline verification.
- Surface stale, missing, and conflicting state as indeterminate where
  semantics require it.
- Publish control-plane compatibility and migration evidence.

Illustrative consumption:

```ts
const snapshot = await trustStore.loadPinned({
  organization: "acme",
  environment: "production",
  version: "2027-04-15.3",
});

const auths = await loadAuths({
  signer,
  trustedAuthority: snapshot.verifyLocally(rootKeys),
});
```

The control plane distributes a candidate snapshot. The open SDK verifies and
interprets it locally.

### V2-E3 — Agent, grant, and revocation inventory

**Outcome:** Operators know what authority exists and can end it safely.

Subtasks:

- Inventory principals, agents, grant chains, profiles, audiences, budgets,
  and expirations.
- Show effective authority and delegation ancestry.
- Implement revocation/status publication using open formats.
- Measure propagation and stale-state windows.
- Add compromised-authority and departed-operator runbooks.
- Keep private keys outside the inventory service.

### V2-E4 — Enterprise approval orchestration

**Outcome:** Organizations route exact approvals through existing workflows.

Subtasks:

- Add group, escalation, schedule, separation-of-duty, and break-glass rules.
- Integrate approved chat, ticketing, and pager systems.
- Bind every response to the exact transaction and policy configuration.
- Preserve headless operation when policy permits it.
- Expose provider outages without converting them into denials or approvals.
- Retain bounded evidence for later review.

### V2-E5 — Durable receipt service

**Outcome:** Customers can find and export authorization and execution evidence
across a fleet.

Subtasks:

- Ingest profile-owned receipt envelopes without creating a global semantic
  union.
- Index common envelope fields and profile-specific opaque projections.
- Implement retention, redaction, legal hold, export, and deletion policies.
- Integrate SIEM and object storage.
- Separate authorization decision, approval, gateway attempt, reconciliation,
  and final effect state.
- Define integrity and completeness limitations explicitly.

### V2-E6 — Connector platform

**Outcome:** Auths fits existing enterprise custody and operations.

Subtasks:

- Prioritize connectors from paid customer evidence.
- Start with one cloud KMS/HSM, one enterprise identity provider, and one SIEM
  only if demanded.
- Keep connector protocols behind public provider-neutral ports.
- Add capability negotiation and unsupported-platform errors.
- Test credential scoping, rotation, revocation, outage, and recovery.
- Never make one connector the required identity or custody method.

### V2-E7 — On-premises productization

**Outcome:** Regulated or sovereignty-sensitive customers can operate Auths in
their environment.

Subtasks:

- Define supported Kubernetes and non-Kubernetes deployment shapes from
  customer evidence.
- Provide signed artifacts, SBOMs, provenance, upgrade, rollback, backup, and
  disaster-recovery procedures.
- Document all outbound network requirements and support an offline mode where
  promised.
- Add customer-managed storage and key options.
- Establish version-support and patch policies.
- Test air-gapped update procedures only if sold.

### V2-E8 — Governance and assurance package

**Outcome:** Buyers can review and operate the system with accurate evidence.

Subtasks:

- Maintain independent security review and remediation history.
- Publish precise protocol, implementation, SDK, and product claim boundaries.
- Offer deployment architecture reviews and threat-model workshops.
- Provide control mappings only where reviewed; do not imply certification.
- Define incident communication and support escalation.
- Commission specialized review as enterprise surfaces expand.

### V2-E9 — V2 go to market

**Outcome:** Distribution moves from founder-led experiments to a repeatable
enterprise motion without losing technical credibility.

Subtasks:

- Turn the strongest V1 workflow into a documented customer case study with
  permission.
- Build solution guides for agent platforms, internal developer platforms,
  and regulated deployments.
- Recruit a small set of systems-integrator and framework partners.
- Offer paid architecture and deployment pilots.
- Create a security-review packet and on-premises evaluation kit.
- Develop buyer-specific material for platform, security, and engineering
  leadership.
- Measure pilot-to-production conversion and time blocked in procurement.

## 14. V2 entry and exit gates

V2 work begins only when:

- V1 has real customer-operated use;
- the first commercial product problem and buyer are selected;
- at least two customers repeat the same operational need;
- the open-core and license boundary is approved; and
- the company can support the operational promises it is about to make.

V2 launches only when:

- hosted and on-premises isolation and recovery evidence pass;
- trust distribution preserves local verification and bounded offline use;
- revocation/status behavior and stale-state limits are documented;
- enterprise approvals remain transaction-bound;
- receipt integrity, completeness, privacy, and retention limits are explicit;
- supported connectors have failure and credential-rotation tests;
- security review covers the commercial attack surface; and
- customer support and incident ownership are staffed.

## 15. What not to build before evidence

Defer the following unless several real integrations require them:

- a broad CLI;
- a large visual policy editor;
- a universal policy language;
- a new identity network;
- a secrets manager;
- a generic agent runtime;
- wrappers for every agent framework;
- connectors for every cloud and identity vendor;
- a hosted verifier required for correctness;
- cross-profile command or receipt unions;
- compliance badges without completed assessments; and
- per-verification pricing that discourages local safety checks.

## 16. Commercial experiments

Run low-cost experiments before full product implementation:

| Hypothesis | Experiment | Strong signal |
| --- | --- | --- |
| Teams pay to stop unsafe agent effects | paid authority-design and gateway pilot | budgeted pilot with real workflow owner |
| Approval routing is the first paid pain | manually operate a bounded routing service | repeated use and renewal request |
| Receipt search has operational value | prototype index over exported local receipts | security/operator uses it in review |
| On-premises is required | deployment architecture workshop | procurement requirement and sponsor |
| Framework distribution works | maintained upstream example/adapter | non-core installs and retained usage |
| Assurance creates purchase confidence | share exact review packet | shorter security review or buyer commitment |

Every experiment needs a falsification condition. “They liked the demo” is not
a purchase signal.

## 17. Suggested operating cadence

### Weekly

- Review SDK friction and newly filed core issues.
- Review design-partner integration progress.
- Record denied effects, unexpected glue, and support questions.
- Keep public claims aligned with current evidence.

### Monthly

- Review buyer, deployment, and willingness-to-pay evidence.
- Re-rank commercial hypotheses.
- Audit open-core boundary proposals.
- Stop features without integration or buyer evidence.

### At each release gate

- Reproduce artifacts and exact assurance claims.
- Review semantic and profile changes.
- Review public surface and compatibility impact.
- Review security findings and unresolved exclusions.
- Decide explicitly whether to publish, promote, defer, or stop.

## 18. Decision register

### Decided

- Auths is an open protocol plus a company built around operational tools and
  services.
- The open local path cannot depend on an Auths-hosted service.
- TypeScript is the first product-design SDK; Python follows with semantic
  parity.
- MCP is the first runtime adapter and delegation is the flagship idea.
- The product supports autonomous and supervised configurations.
- The initial audience is framework builders and internal-agent teams.
- No CLI workstream is planned before SDK and integration evidence.
- Commercial code may coordinate open semantics but not redefine them.

### Recommended hypotheses requiring evidence

- “Agent Action Gateway” is the first product category and paid wedge.
- GitHub change plans are the first compelling sandbox workflow.
- The enterprise repository should be separate from `auths-proof`.
- V2 should focus on a hosted/on-premises control plane.
- Annual platform/support pricing is a better fit than per-verification usage.

### Owner decisions still required

- the exact first paid product;
- the economic buyer;
- pricing and packaging;
- separate enterprise repository versus `ee/`;
- commercial license and contribution model;
- hosted service data boundaries;
- support commitments;
- design-partner and customer agreements;
- publication and promotion of release artifacts; and
- wording of production, security, and compliance claims.

## 19. Immediate next actions

1. Finish the current TypeScript SDK sequence and use
   `auths-agent-demo` as external-consumer evidence.
2. Implement AP-SPEC-036 only through separately authorized bounded PR units.
3. Run AP-SPEC-030 design-partner recruitment and AP-SPEC-031 discovery in
   parallel with safe repository-local engineering.
4. Produce the GitHub sandbox and MCP demonstrations around the same
   attach/delegate/authorize mental model.
5. Validate the Agent Action Gateway problem before building a broad control
   plane.
6. Record the enterprise repository and licensing decision before creating
   proprietary code.
7. Select V1 scope from observed activation and commercial evidence.
8. Begin V2 only after repeated V1 operational demand exists.

## 20. Final boundary

Auths should be generous with the mechanism that makes the protocol trustworthy
and useful: semantics, verification, authoring, delegation, enforcement
interfaces, evidence, and conformance.

The company can build substantial value around the difficult organizational
work that begins after one action works: distributing trusted state, operating
fleets, routing approvals, managing lifecycle and revocation, retaining
evidence, integrating enterprise systems, and supporting deployments.

That is a credible open-core business only if the open path remains complete.
The strongest commercial product will make Auths easier to operate at scale,
not make users dependent on a private answer to whether an action was
authorized.

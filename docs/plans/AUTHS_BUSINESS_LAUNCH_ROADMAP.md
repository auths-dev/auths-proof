# Auths business launch roadmap

**Status:** Evidence-driven execution roadmap. Product, pricing, repository,
license, publication, customer, and security-review decisions remain
owner-controlled.

**Last reorganized:** 2026-08-13

**Companion strategy:** [Auths Product and Go-to-Market
Strategy](GO_TO_MARKET_STRATEGY.md)

**Commercial evidence gate:** [AP-SPEC-031: Commercial discovery and product
selection](../specs/0031-commercial-discovery.md)

**Integration evidence gate:** [AP-SPEC-030: Design-partner integration
program](../specs/0030-design-partner-integrations.md)

**SDK feedback program:** [AP-SPEC-036: SDK ergonomics and external-consumer
workflow closure](../specs/0036_sdk_ergonomics.md)

## 1. Purpose

This document governs the path from a technically credible open protocol to a
validated product and company.

It is deliberately organized around two facts:

1. Auths has demonstrated unusually high engineering throughput.
2. Customer evidence, independent trust, procurement, renewal, and production
   operating history cannot be generated at the same speed as code.

The roadmap therefore does not limit ambition according to conventional
solo-founder estimates. Nor does it treat rapid implementation as evidence
that a product hypothesis is correct.

Its job is to make Auths' engineering velocity produce information:

```text
hypothesis
    -> smallest useful implementation
    -> real external observation
    -> continue, change, sell, operate, or stop
```

V1 and V2 in this document refer to commercial product stages. They do not
rename the Auths protocol, the `1.0.0-rc.1` release candidate, or an assurance
claim.

## 2. Execution premise: engineering is not the scarce resource

### 2.1 Observed repository velocity

The first repository commit was created on 2026-07-24. At the 2026-08-13
measurement point—less than 20 days later—the history contained:

- 383 commits;
- 299 non-merge commits;
- 76 identifiable merged pull requests;
- 19 active development days; and
- a Rust core, TypeScript and Python SDKs, formal evidence, cross-language
  fixtures, production-shaped demos, package validation, and extensive CI.

Commit counts and lines of code are not customer value. Generated artifacts,
documentation, and merge commits also make raw totals imperfect. Even with
those caveats, the history is strong evidence that Auths should not be planned
using an ordinary solo-founder implementation rate.

This history is a planning input, not a permanent productivity promise. The
roadmap must not require exhaustion, treat every day as a record day, or use
historical speed to erase review and operational risk.

### 2.2 The actual constraints

The limiting factors are increasingly:

- access to qualified users and economic buyers;
- elapsed time using Auths in maintained external workflows;
- independent security and architectural review;
- procurement and deployment decisions;
- operation through failures, upgrades, incidents, and recovery;
- willingness to pay, expand, and renew; and
- choosing one valuable problem from many technically possible ones.

Auths can build an approval router quickly. It cannot infer from that build
whether approval routing is the first product customers will buy.

Auths can package an on-premises control plane quickly. It cannot manufacture
evidence that on-premises deployment is a real procurement requirement.

### 2.3 Product maturity states

Every roadmap item MUST use one of these states. A later state includes, but
does not replace, the evidence from earlier states.

| State | Meaning | Evidence |
| --- | --- | --- |
| **Hypothesized** | A plausible problem, surface, or product exists on paper | written claim and falsification condition |
| **Implemented** | The bounded behavior exists and passes its stated repository evidence | code, fixtures, CI, demo, exact exclusions |
| **Externally usable** | A non-core user can install and exercise it without private help or source dependencies | clean-environment external-consumer evidence |
| **Validated** | Independent users demonstrate that it solves a repeated, important problem | observed workflows, repeated use, maintenance, measured outcome |
| **Sold** | A qualified buyer commits money or equivalent procurement authority to the exact outcome | paid pilot, purchase order, signed design engagement, or equivalent |
| **Operationally proven** | It has survived real operation, support, failure, recovery, upgrade, and time | operating history, exercises, incidents, support and renewal evidence |

These terms are not interchangeable:

- implemented is not validated;
- validated is not sold;
- sold is not production-proven;
- a polished demo is not an externally maintained integration; and
- an enthusiastic user is not necessarily an economic buyer.

Every status report, experiment, epic, and launch claim must name the actual
state.

## 3. Business thesis

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
Closed provider gateway ----> payment / code / cloud / data / tool
```

The open project should make this useful without an Auths-hosted service. The
company should sell the operational coordination organizations need once they
use the model across teams, environments, agents, and providers.

### 3.1 First commercial hypothesis

The current category hypothesis is an **Agent Action Gateway**:

> A customer-operated enforcement gateway that lets a team attach an agent,
> delegate exact authority, stop out-of-authority actions before provider
> execution, and retain inspectable evidence.

This is a hypothesis, not a committed SKU. AP-SPEC-031 selects or rejects the
first paid problem from external evidence.

The gateway is a product bundle, not a semantic center. The open verifier
decides authorization locally. Profile-owned gateways own exact provider
effects. Commercial coordination may distribute trusted state, route
approvals, retain receipts, and operate deployments; it may not privately
redefine `authorized`.

### 3.2 Product ladder

| Layer | Candidate product | Customer outcome | Default boundary | Current maturity |
| --- | --- | --- | --- | --- |
| Adoption | Open protocol, verifier, SDKs, profiles, fixtures | Build and verify bounded authority locally | open source | implemented in substantial part; external validation incomplete |
| Proof surfaces | GitHub, payments, cross-company incident response | Understand and test the value in concrete effects | open demos and profiles | implemented demonstrations; market role unvalidated |
| First paid wedge | Agent Action Gateway or evidence-selected alternative | Stop unsafe effects and retain evidence | open enforcement plus paid operations/service | hypothesized |
| Operations | Auths Control Plane | Operate authority across teams and environments | commercial hosted/on-premises | architectural option, not committed backlog |
| Assurance | Support, review, deployment, and operations | Adopt with credible assistance and evidence | commercial service | partially implementable; unsold |

## 4. Product principles

Every product decision must preserve these rules:

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
11. Fast implementation must be used to test a hypothesis, not silently turn
    it into strategy.
12. New profiles remain vertical until cross-domain evidence earns a shared
    abstraction.

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
between these options.

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
  connectors/
  deployments/
  docs/
```

The enterprise repository consumes published, immutable open packages. It may
not use private hooks into the verifier or receive unreleased semantic logic.

#### Option B — an `ee/` tree in the monorepo

This may be chosen later if atomic development materially outweighs licensing
and contribution complexity. If chosen, CI MUST enforce:

```text
ee/*  ---> published public Auths interfaces
open  -X-> ee/*
```

The `ee/` tree needs a commercial license, explicit file headers, separate
artifact manifests, isolated build and test jobs, no inclusion in open-source
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

## 6. Two-speed operating model

Auths must operate two concurrent loops.

```text
ENGINEERING LOOP                         EVIDENCE LOOP
bounded hypothesis                      qualified conversation
      |                                         |
2–10 day implementation                 observed current workflow
      |                                         |
executable demonstration                buyer and pain mapping
      |                                         |
external-consumer test                  commitment / refusal / budget
      +-------------------+---------------------+
                          |
                    decision record
                          |
             continue | change | sell | stop
```

The engineering loop may run faster. It must not declare the evidence loop
complete.

### 6.1 Three-week evidence cycle

Until the first paid wedge is selected, work in repeating three-week cycles.
Each cycle should produce:

- 15 cumulative qualified conversations in the first cycle, then enough new
  conversations to test changed hypotheses;
- at least five observed current workflows in the first cycle;
- no more than two bounded engineering experiments;
- one externally testable demonstration or concierge workflow;
- an updated competitor and alternative-solution ledger;
- one explicit continue/change/stop decision; and
- a written account of what was learned that could not have been learned from
  repository work alone.

The cycle is not successful merely because the implementations ship.

### 6.2 Initial founder-capacity allocation

Until a paid problem is selected, use this as the default allocation and
review it every three weeks:

| Work | Starting allocation | Why |
| --- | ---: | --- |
| Customer, buyer, and partner discovery | 40% | highest-latency missing evidence |
| Evidence-triggered engineering | 35% | exploit demonstrated implementation speed |
| Security review, operations, and release integrity | 15% | protect the credibility of the product |
| Competitive analysis and category communication | 10% | make the distinction legible to buyers and investors |

This is not a permanent organization design. Once a sold pilot exists, the
allocation follows the pilot's success criteria and support burden.

### 6.3 Build authorization levels

| Level | Permitted work | Required evidence | Default time box |
| --- | --- | --- | --- |
| **L0 — research artifact** | interview guide, mockup, sample report, architecture sketch | named hypothesis | hours to 2 days |
| **L1 — disposable experiment** | local prototype, demo variation, concierge tooling | observed problem or comparison question | 2–5 days |
| **L2 — open vertical** | profile-owned end-to-end implementation with fixtures and CI | repeated technical need or strategic open-core value | 5–10 days |
| **L3 — pilot product** | deployable paid surface, runbooks, bounded support | E4 pilot path and named buyer | pilot-specific |
| **L4 — operated product** | availability, retention, tenancy, recovery, support | sale plus explicit operational obligations | contract-specific |

L0–L2 work can be fast and aggressive. L3 and L4 require evidence because
they create support, security, data, and reliability obligations—not because
the code is necessarily difficult.

## 7. Immediate executable roadmap

This is the committed execution sequence. The V2 option map in Section 13 is
not part of this queue.

### Track A — Commercial discovery, starting immediately

**State:** specified; execution evidence incomplete.

**Three-week outcome:** identify a repeated problem worth deeper solution
validation, or explicitly record that no wedge is yet supported.

Tasks:

1. Conduct 15 qualified conversations across agent-framework maintainers,
   internal-agent platform teams, security/platform leaders, and likely
   economic buyers.
2. Observe at least five current workflows involving credentials, approvals,
   consequential actions, incident response, or audit evidence.
3. Record user, champion, operator, security reviewer, and economic buyer
   separately.
4. Ask what has already been built, bought, or rejected.
5. Test payments, code change, and cross-company infrastructure response as
   distinct value stories.
6. Ask for a concrete next commitment and a budget range; do not ask only
   whether Auths sounds useful.
7. Maintain the AP-SPEC-031 hypothesis ledger.

Early discovery passes when:

- the same named problem appears in at least three independent organizations;
- at least one plausible buyer discusses a real budget or paid engagement;
- the current alternative and cost of doing nothing are understood; and
- the next solution experiment has a falsifiable success condition.

Early discovery does **not** require three integrations or independent
maintenance. Those belong to later solution validation.

### Track B — Category and competitive clarity

**State:** category hypothesis exists; direct-capability comparison incomplete.

**Outcome:** a technical buyer understands Auths in one minute and can explain
why it is not simply identity, OAuth scopes, cloud IAM, or another capability
token.

Tasks:

- Test “portable authority for consequential software actions.”
- Lead with the protected effect, not formal methods or cryptography.
- Publish identity-versus-authority and transport-versus-authority
  explanations.
- Produce a primary-source comparison covering UCAN, Biscuit, ZCAP-LD,
  macaroons, SPIFFE, OAuth/DPoP/GNAP where relevant, Cedar, OPA, and cloud IAM.
- Compare exact action binding, attenuation, replay/budget state, approvals,
  sealed commands, closed effects, receipts, local verification, cryptographic
  agility, and assurance evidence.
- State where Auths overlaps or composes; do not claim generic superiority.
- Define prohibited claims until independent review completes.

Time box: five working days for the initial category and competitor packet.

Stop/change rule: if qualified users consistently restate Auths as “another
token format” or “another policy engine,” revise the category and onboarding
before adding broader platform surface.

### Track C — SDK activation and external use

**State:** substantial Rust, TypeScript, and Python implementation exists;
external activation evidence remains the governing test.

**Outcome:** an unfamiliar developer protects one effect without learning
protocol internals.

Tasks:

- Keep the five simple product verbs as the normal path.
- Preserve TypeScript/Python semantic parity over Rust-owned meaning.
- Measure time to first denial and first sandboxed effect.
- Require clean installed-package consumption on supported platforms.
- File an Auths issue for repeated application glue.
- Publish an honest capability and runtime matrix.
- Keep raw protocol and framework construction behind progressive disclosure.

Exit evidence:

- no hand-authored protocol encoding or unchecked capability brands;
- clean external installs pass;
- an unfamiliar developer completes the chosen recipe;
- forbidden effects are tested; and
- repeated friction results in product simplification, not tutorial prose
  covering accidental complexity.

### Track D — Three proof surfaces with different jobs

Do not force one demo to carry every product message.

| Surface | Role | Why it exists | Commercial status |
| --- | --- | --- | --- |
| **GitHub change** | developer activation | familiar, reversible, sandboxable, easy to install | onboarding candidate, not assumed paid wedge |
| **Stripe refund/payout** | economic value proof | exact amount, object, use count, time, and approval make bounded authority legible | leading paid-wedge experiment |
| **Cross-company incident response** | enterprise future proof | demonstrates separate organizations, identity systems, clouds, agents, approvals, transport, and receipts | strategic showcase, not production claim |

Each surface must show:

- an authorized effect;
- an out-of-authority effect stopped before provider execution;
- mutation, replay, expiry, and ambiguous-outcome behavior;
- a safe disclosure view for resulting evidence; and
- the distinction between authorization and observed provider success.

The first paid wedge is selected from evidence. Repository investment alone
does not select it, but the thirteen Stripe demo directories are valid evidence
that payments can be tested quickly and should not be ignored in positioning.

### Track E — Independent trust and release credibility

**State:** extensive internal evidence exists; independence and elapsed
operational evidence remain incomplete.

Tasks:

- Complete the applicable independent review and remediation gates.
- Keep public claims tied to exact assurance artifacts and exclusions.
- Publish reproducible packages only when promotion evidence passes.
- Establish a security contact and vulnerability process.
- Recruit independent SDK and integration maintainers.
- Record what is mathematically modeled, mechanically connected to shipping
  code, empirically tested, or outside the assurance boundary.

Independent review is not delayed until the commercial product is complete.
It should run in parallel because reviewer availability is a high-latency
constraint.

## 8. Product and buyer discovery

The initial SDK user is likely an agent-framework maintainer or platform
engineer. The likely champion owns the internal agent platform, developer
platform, or application security program. The economic buyer is not yet
known.

| Role | Job to be done | Evidence to collect |
| --- | --- | --- |
| SDK user | Protect an action without learning protocol internals | setup time, glue, failures |
| Agent owner | Give an agent freedom inside a fixed boundary | denied effects, approval burden |
| Platform operator | Manage agents and authority across environments | repeated operational work |
| Security reviewer | Understand trust boundaries and evidence | review time, unresolved risk |
| Economic buyer | Reduce an urgent, costly risk | budget, procurement, commitment |

No launch plan may assume the most enthusiastic developer controls a budget.

### 8.1 Discovery versus validation

The roadmap uses two distinct gates.

**Problem discovery** asks:

- Does a repeated problem exist?
- Who feels it?
- What does it cost?
- Who can buy a solution?
- What alternatives are already trusted?

**Solution validation** asks:

- Can Auths solve it in the customer's real workflow?
- Can a non-core maintainer own the integration?
- Does Auths reduce risk or operating work measurably?
- Will the customer pay for and continue using the result?

Solution validation may require:

- at least three real integrations;
- at least two integrations maintainable outside the core project;
- the same operational need in at least two organizations;
- E3 or stronger commitment; and
- a credible E4 paid-pilot path.

Those are deliberately stronger than the early-discovery gate.

## 9. V1: evidence-selected product vertical

### 9.1 V1 promise

The provisional promise is:

> Attach an agent, give it bounded authority for a consequential action, stop
> actions outside that authority, and understand the resulting evidence—without
> sending verification to Auths.

V1 is one excellent outcome vertical, not every operational surface Auths can
eventually support.

### 9.2 V1 selection gate

V1 scope is selected only when:

- one recurring problem has been observed in at least three organizations;
- a named user, champion, operator, reviewer, and likely buyer are understood;
- a bounded Auths implementation demonstrates the outcome;
- at least one organization reaches E3 commitment;
- a paid or formally sponsored pilot path exists;
- the deployment and data boundary are understood;
- the wedge passes the open-core boundary test; and
- competing wedges are explicitly deferred or rejected.

Selection may produce a no-build decision. That is better than converting
velocity into an unsupported product.

### 9.3 Candidate V1 components

These components are option inventory. Only those required by the selected
vertical become committed work.

| Candidate | Current state | Evidence that activates product work | Maximum work before evidence |
| --- | --- | --- | --- |
| Open SDK/profile release | substantially implemented | external activation and release gates | bounded friction fixes |
| Customer-operated closed gateway | implemented in several vertical forms | customer workflow needs protected effect | one vertical |
| Approval routing | open mechanisms exist | repeated approval coordination pain | concierge or one provider |
| Evidence export/inspection | implemented in bounded local form | reviewer/operator repeatedly needs it | sample export and local viewer |
| Durable receipt search | hypothesized commercial operation | repeated cross-fleet investigation need | static/ephemeral index prototype |
| Grant/agent inventory | hypothesized commercial operation | repeated inability to answer “what authority exists?” | sample report over synthetic/exported data |
| Trust/status distribution | architectural option | repeated multi-environment freshness problem | signed snapshot proof |
| Deployment/support package | partially specifiable | sponsor requires assistance to pilot | paid design engagement |

### 9.4 V1 launch evidence

V1 may be described as launched only when all applicable evidence exists:

- exact release and assurance claims are current;
- required independent review and remediation gates pass;
- TypeScript and Python labels match actual installed behavior;
- the selected profile demonstrates closed enforcement;
- denied and indeterminate actions cause no provider effect;
- required approval modes work;
- customer deployment and recovery are documented;
- security reporting and support ownership exist;
- the open-core repository and license decision is recorded;
- at least one integration is maintainable without the core author; and
- every claim names its exclusions.

“V1 launched” does not automatically mean “operationally proven.” That state
requires elapsed customer operation and recovery evidence.

## 10. Commercial experiments and money

Auths must test money directly. Price ranges below are experiments, not public
pricing or revenue forecasts.

| Offer hypothesis | Initial range to test | What the customer receives | Strong signal | Falsification condition |
| --- | ---: | --- | --- | --- |
| Authority architecture review | $5k–$15k | threat/workflow review and bounded integration design | qualified buyer pays for a named workflow | praise without budget or access |
| Design-partner implementation | $15k–$40k | one bounded sandbox/reversible integration with success criteria | sponsor supplies engineering/security time and payment | free custom work with no operator |
| Paid production pilot | $25k–$75k | one reviewed consequential workflow, deployment, runbooks, support | procurement path and success owner exist | pilot cannot name measurable outcome |
| Annual operations product | $50k–$200k | evidence-selected coordination surface and support | conversion or renewal after pilot | value depends on withholding local verification |

The exact price, currency, terms, support burden, and packaging remain owner
decisions. Interviews should test outcomes and willingness to pay, not ask
prospects to select features from the V2 map.

### 10.1 Runway and funding model

Before proprietary product work begins, record:

- available founder runway in months;
- monthly personal and company burn;
- the maximum unfunded operating-service commitment;
- the maximum time allowed before reassessing the wedge;
- the milestone that justifies the first hire; and
- the milestone that would make external funding useful rather than merely
  available.

A reasonable initial fundraising evidence gate is:

- a repeated urgent problem in at least three organizations;
- at least one paid pilot or equivalent procurement commitment;
- a credible route from open adoption to paid operations;
- independent evidence supporting the security boundary; and
- a concrete use of funds that accelerates sales, review, integrations, or
  operations rather than compensating for speculative scope.

This is a gate hypothesis, not a claim about investor requirements.

## 11. Success measures

Measure behavior by maturity state.

### Implemented and externally usable

- time to first local denial;
- time to first sandboxed authorized effect;
- hand-written protocol/security glue;
- clean installed-package success by supported runtime;
- parity failures across Rust, TypeScript, and Python; and
- forbidden-effect coverage across maintained profiles.

### Validated

- independent maintained integrations;
- repeated workflows with narrower child authority than parent;
- denial explanations resolved without core support;
- repeated operational problems across organizations;
- retained use after the first demonstration; and
- measured reduction in credential scope, approval work, or investigation
  time.

### Sold

- paid design engagements;
- paid or formally sponsored pilots;
- named economic buyers;
- procurement progress;
- contract value and support obligation; and
- conversion from integration to paid operation.

### Operationally proven

- production duration;
- upgrade, rollback, backup, and recovery exercises;
- incidents and time to resolution;
- ambiguous provider outcomes successfully reconciled;
- support load per deployment;
- expansion and renewal; and
- customer-operated recovery without core-author intervention.

Downloads and stars are useful distribution signals, not product-market fit.

## 12. Competitive and alternative-solution workstream

Before the first formal design-partner call packet is considered complete,
publish an evidence-based comparison answering:

> Why not use the identity provider, scoped credential, policy engine, or
> capability-token system we already have?

The comparison must include direct and adjacent alternatives, using their
primary specifications and documentation:

- UCAN;
- Biscuit;
- ZCAP-LD;
- macaroons;
- OAuth scopes, token exchange, DPoP, and GNAP where applicable;
- SPIFFE/SPIRE;
- Cedar, OPA, and relationship-based authorization systems;
- cloud IAM and provider-specific restricted credentials; and
- application-specific signed requests and approval workflows.

Required dimensions:

- identity versus authority ownership;
- attenuation and delegation;
- exact application-byte/effect commitment;
- offline/local verification;
- replay, use, budget, and lifecycle state;
- transaction-bound approvals;
- sealed-command and closed-gateway boundary;
- denial, indeterminate, and provider-unknown outcomes;
- authorization and execution receipts;
- cryptographic, identity, transport, and provider agility;
- formal and differential evidence; and
- operational complexity.

The result must identify overlap, composition, and disadvantages. It must not
manufacture differentiation by mischaracterizing another project.

## 13. V2 architectural option map

V2 records plausible company architecture. It is **not** a nine-epic
engineering queue, a promise to customers, or permission to create a broad
control plane.

Each option is uncommitted until its activation evidence exists.

| Option | Customer job | Activation evidence | Cheapest informative test | Operational obligation created |
| --- | --- | --- | --- | --- |
| Organization/environment administration | separate authority operation across teams | two customers repeat administration pain | clickable model and access review | tenancy, access control, deletion |
| Signed trust/status distribution | deliver current trusted state to fleets | repeated multi-environment staleness/rollout problem | signed snapshot plus local verification | availability, rollout, rollback, freshness |
| Agent/grant/revocation inventory | know what authority exists and end it | operators cannot answer inventory questions from local tools | report over exported/synthetic data | completeness, privacy, lifecycle accuracy |
| Enterprise approval orchestration | route exact approvals through existing workflows | repeated cross-team routing/escalation pain | concierge service or one demanded connector | delivery, identity mapping, audit, outage behavior |
| Durable receipt service | find/export evidence across a fleet | real investigations require cross-receipt search | bounded ephemeral index | retention, integrity, deletion, legal hold |
| Connector platform | fit existing custody/identity/SIEM systems | paid deployment blocked by the same connector class | one public-port adapter | credential handling, rotation, vendor support |
| On-premises productization | satisfy sovereignty or procurement constraints | sponsor makes it a written buying requirement | architecture workshop and install spike | upgrades, backup, air gap, support matrix |
| Governance/assurance package | shorten security and deployment review | exact evidence changes buyer progress | reviewed security packet | claim maintenance, incident communication |

### 13.1 V2 build rule

For any option:

1. Record the buyer, problem, current workaround, and falsification condition.
2. Use L0 or L1 work to test it first.
3. Require the same need in at least two organizations before a reusable
   product design.
4. Require a paid or formally sponsored pilot path before L3 work.
5. Consume stable open interfaces; never add a private verifier hook.
6. Keep provider/domain semantics vertical.
7. Record data, security, availability, support, and recovery obligations
   before accepting them.
8. Mark the result implemented, validated, sold, or operationally proven—never
   simply “done.”

### 13.2 V2 sequence after evidence

When evidence activates one option, build only the minimum coherent slice:

```text
repeated customer problem
        |
        v
one bounded prototype or concierge test
        |
        v
paid pilot with explicit success criteria
        |
        v
customer-operated deployment and recovery
        |
        v
repeat with second customer
        |
        v
extract reusable commercial product
```

Do not build the surrounding options merely because they appear adjacent in a
control-plane diagram.

## 14. What not to build before evidence

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

High shipping velocity makes this list more important, not less. These items
are technically buildable; the risk is building them before learning whether
they create customer value or weaken Auths' product boundary.

## 15. Operating cadence

### Weekly

- Conduct scheduled buyer/user conversations before optional new engineering.
- Review SDK friction and newly filed core issues.
- Record denied effects, unexpected glue, and support questions.
- Review every active build against its hypothesis and time box.
- Keep public claims aligned with current evidence.

### Every three weeks

- Review the hypothesis ledger and maturity-state table.
- Decide continue, change, sell, operate, or stop for each experiment.
- Re-rank wedges and V2 options using external evidence.
- Review founder allocation, runway, and support commitments.
- Stop or archive work without a learning objective.

### At each release gate

- Reproduce artifacts and exact assurance claims.
- Review semantic and profile changes.
- Review public surface and compatibility impact.
- Review security findings and unresolved exclusions.
- Decide explicitly whether to publish, promote, defer, or stop.

### At each customer commitment

- Name the exact effect and success metric.
- Bound data, credentials, deployment, availability, and support.
- Record what is implemented versus externally validated.
- Price the obligation rather than an aspirational feature list.
- Refuse any term that makes the open local path deceptively unsafe.

## 16. Decision register

### Decided

- Auths is an open protocol plus a company built around operational tools and
  services.
- The open local path cannot depend on an Auths-hosted service.
- Rust owns protocol meaning; TypeScript and Python must preserve semantic
  parity.
- Identity, cryptography, transport, providers, custody, and approval remain
  swappable behind explicit ports and profiles.
- The product supports autonomous and supervised configurations.
- New profiles begin as complete verticals.
- No broad CLI, generic policy language, or control plane is planned without
  evidence.
- Fast implementation does not upgrade a hypothesis to a product fact.

### Recommended hypotheses requiring evidence

- “Agent Action Gateway” is a useful product category.
- Payments are the clearest economic-value proof surface.
- GitHub is the easiest developer activation surface.
- Cross-company incident response is the strongest enterprise future story.
- A separate private enterprise repository is preferable to `ee/`.
- Annual platform/support pricing fits better than per-verification usage.
- One or more V2 operational options can become a venture-scale product.

### Owner decisions still required

- the first paid problem and economic buyer;
- exact V1 scope;
- price, packaging, pilot terms, and support commitments;
- runway and funding plan;
- separate enterprise repository versus `ee/`;
- commercial license and contribution model;
- hosted-service data boundaries;
- publication and promotion of release artifacts; and
- wording of production, security, and compliance claims.

## 17. Immediate next actions

Execute in this order, with engineering and evidence work overlapping where
shown:

1. Start the three-week commercial-discovery cycle: 15 conversations and five
   observed workflows.
2. Write the primary-source “why Auths versus alternatives” comparison.
3. Package the GitHub path as the fastest unfamiliar-developer activation
   test.
4. Package one Stripe refund or payout path as the economic-value test.
5. Use the cross-company incident response demo for enterprise architecture
   conversations, while preserving its demo/non-production exclusions.
6. Run only bounded SDK or demo changes that answer observed questions.
7. Ask qualified prospects for a paid architecture review, design engagement,
   or pilot—not general enthusiasm.
8. Select one V1 vertical, change the hypothesis, or record no-build based on
   the evidence.
9. Record the enterprise repository, license, runway, and support decisions
   before proprietary operated-product work.
10. Activate at most one V2 option at a time from repeated customer evidence.

## 18. Final boundary

Auths should remain extremely ambitious. Its demonstrated engineering velocity
makes a broad technical future plausible and justifies preserving a concrete
architectural option map.

The roadmap must nevertheless keep four statements separate:

```text
we built it
    != users repeatedly need it
    != a buyer paid for it
    != we have operated it reliably over time
```

The open project should be generous with the mechanism that makes the protocol
trustworthy and useful: semantics, verification, authoring, delegation,
enforcement interfaces, evidence, conformance, and local inspection.

The company can create substantial value around the organizational work that
begins after one action works: distributing trusted state, operating fleets,
routing approvals, managing lifecycle and revocation, retaining evidence,
integrating enterprise systems, and supporting deployments.

The strongest use of Auths' shipping speed is not to complete the longest
possible feature list. It is to run unusually fast, technically credible,
falsifiable experiments until the market reveals which part of the authority
layer should become the company.

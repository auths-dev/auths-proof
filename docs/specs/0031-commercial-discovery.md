# AP-SPEC-031: Commercial discovery and product selection

**Status:** Specified as a parallel evidence program — problem, buyer, and
deployment discovery begins during Phase 7; product selection remains gated on
integration and willingness-to-pay evidence

**Governs:** Commercial discovery from Phase 7 onward and the later evidence
gate for selecting at most one initial paid-product problem

**Source strategy:** [Auths Product and Go-to-Market Strategy](../plans/GO_TO_MARKET_STRATEGY.md)

**Aligned with:** [Post-Milestone-6 Technical and Go-to-Market
Alignment](../plans/POST_MILESTONE_6_TECHNICAL_AND_GO_TO_MARKET_ALIGNMENT.md)

**Depends on:** Approved research privacy and consent operations for early
discovery; AP-SPEC-030 and its repeated-needs register for integration-backed
selection; and recorded owner decisions for any exact license, package,
repository, or commercial boundary

**Scope:** A disciplined commercial-discovery program for identifying the
economic buyer, deployment preference, budgeted operational problem, initial
paid product, packaging, and willingness to pay without weakening the open
protocol

**Normative language:** **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are
requirements on the discovery process and its evidence.

## 1. Decision

Auths will not choose its first paid product from a speculative feature list.

Commercial discovery begins during Phase 7 with problem, buyer, current-
workflow, deployment, procurement, and willingness-to-pay research. It does
not wait for the SDK.

Demonstrated use of the SDK, delegation flow, and customer-operated runtime is
required later to validate solution behavior and product selection. Interviews
can identify a problem; they cannot prove that the proposed Auths product
solves it.

Candidate products include:

- approval workflow service;
- agent and grant fleet inventory;
- durable receipt retention, search, and export;
- policy distribution and lifecycle operations;
- managed connectors;
- hosted organization and trust management;
- on-premises enterprise control plane;
- support, deployment, and assurance packages.

This list is a hypothesis set, not a roadmap. The selection gate chooses at
most one initial product problem for committed build planning.

### 1.1 Phase lanes

| Lane | Timing | Permitted output |
| --- | --- | --- |
| Problem and buyer discovery | Phase 7 onward | interview and workflow evidence, buyer and deployment hypotheses |
| Claim and trust-language testing | Phases 8–9 | reactions to the exact assurance boundary without production promises |
| Integration observation | Phases 9–10 | restricted design-partner behavior and repeated-needs evidence |
| Operational and solution validation | Phase 11 onward | customer-operated workflow, deployment, support, and recovery evidence |
| Product selection | after all decision gates pass | one PRD or a no-build decision |

Discovery may continue across all lanes. A later lane does not retroactively
upgrade weak evidence from an earlier one.

## 2. Commercial doctrine and provisional boundaries

The business model MUST preserve these constraints:

- local verification remains useful without an Auths-operated service;
- the open local path required to author, delegate, verify, enforce safely, and
  inspect evidence is not crippled to force conversion;
- hosted and on-premises deployment are both testable;
- commercial value comes from operations, coordination, governance,
  integration, support, and service;
- pricing does not discourage correct local verification;
- identity-method, transport, and cryptographic agility remain intact;
- customer evidence, not desired valuation, determines the first offer.

These are architectural and product constraints. They do not decide the exact
license, which packages or repositories contain commercial code, the first
paid product, deployment topology, pricing metric, price, support commitment,
or certification program.

Those exact boundaries remain provisional until the named owner records the
decision at the applicable gate. Research artifacts MUST label them
`hypothesis`, `recommended`, or `owner-approved`. An executing agent MUST NOT
turn a recommendation into code, licensing changes, publication, or a customer
promise.

## 3. Questions to answer

The program MUST answer:

1. Who feels the operational pain strongly enough to sponsor a purchase?
2. Who uses Auths day to day, who approves deployment, and who controls budget?
3. Which repeated problem cannot be solved adequately with the open SDK alone?
4. Is that problem urgent, frequent, and expensive?
5. Is the required product hosted, on-premises, hybrid, or deployment-neutral?
6. What security, privacy, procurement, and support requirements govern it?
7. What outcome would a buyer pay to obtain?
8. What unit of value makes pricing understandable?
9. What free/open boundary maintains trust and adoption?
10. Which candidate should be explicitly rejected or deferred?

## 4. Goals

The program MUST produce:

- a hypothesis ledger that begins with early research and is later reconciled
  with AP-SPEC-030 integration evidence;
- a map of users, champions, security reviewers, operators, and economic
  buyers;
- problem interviews and workflow observations;
- hosted, on-premises, and hybrid deployment evidence;
- solution tests using low-cost prototypes or service simulations;
- willingness-to-pay evidence;
- a documented open-core boundary test for each candidate;
- one evidence-backed first commercial product decision or an explicit
  no-build decision;
- a follow-on product requirements document only after selection.

## 5. Non-goals

The program MUST NOT:

- assign arbitrary ARR, valuation, customer-count, or market-share targets;
- turn expressions of interest into booked demand;
- count free implementation help as willingness to pay;
- build several candidate products in parallel;
- sign long-term commitments for unimplemented capabilities;
- make compliance certifications or legal guarantees;
- require hosted verification;
- move customer policy or operational state into the open kernel;
- collect sensitive customer artifacts in the public repository;
- optimize for GitHub stars, impressions, or downloads as commercial proof;
- build a CLI because one interviewee casually requests one.

## 6. Discovery journey

```text
+-----------------------------+   +-----------------------------+
| Early discovery             |   | Design-partner evidence     |
| problem + buyer + workflow  |   | usage + repeated needs      |
+---------------|-------------+   +--------------|--------------+
                +--------------------+------------+
                                     v
+---------------------------------------------------------------+
| Problem validation                                            |
| observe workflow -> quantify pain -> identify buyer           |
+-------------------------------+-------------------------------+
                                v
+---------------------------------------------------------------+
| Deployment and trust test                                     |
| local only | hosted | on-premises | hybrid                    |
+-------------------------------+-------------------------------+
                                v
+---------------------------------------------------------------+
| Solution test                                                 |
| mockup/service simulation -> buyer commitment                 |
+-------------------------------+-------------------------------+
                                v
+---------------------------------------------------------------+
| Open-core and economics review                                |
| value unit -> packaging -> willingness to pay                 |
+-------------------------------+-------------------------------+
                                v
+---------------------------------------------------------------+
| Select one product, continue discovery, or do not build       |
+---------------------------------------------------------------+
```

### 6.1 Problem interview

The researcher SHOULD begin from observed behavior:

- “Show me how agent authority is issued and changed today.”
- “What happens when a person leaves or an agent is replaced?”
- “How do you find which agents can call a particular tool?”
- “How do you approve a high-risk action?”
- “How do you investigate a denied or disputed action?”
- “Which evidence do security, audit, or operations teams require?”
- “Which parts must remain inside your infrastructure?”
- “What have you built or paid for to solve this already?”

The researcher MUST not lead with the candidate product or ask only whether it
sounds useful.

### 6.2 Solution test

A solution test MAY use:

- a clickable mockup;
- a manually operated concierge workflow;
- a static sample report;
- a local prototype over synthetic data;
- an architecture and deployment review;
- a paid design engagement.

It SHOULD avoid production implementation until the buyer, problem, and
deployment model are supported by evidence.

## 7. Evidence model

### 7.1 Evidence strength

Evidence is ranked from weakest to strongest:

| Level | Evidence |
| --- | --- |
| E0 | Internal belief or analogy |
| E1 | Prospect states a preference |
| E2 | Prospect demonstrates the current workflow and pain |
| E3 | Prospect invests meaningful engineering or security-review time |
| E4 | Prospect agrees to a scoped pilot with success criteria |
| E5 | Prospect signs a paid pilot, purchase order, or equivalent commitment |

Product selection requires E2 observations from at least three independent
organizations, at least one E3 commitment, and a credible path to E4. Pricing
confidence requires E4 or E5 evidence; hypothetical price reactions alone are
insufficient.

### 7.2 Hypothesis ledger

```yaml
schema: auths.commercial-hypothesis/1
hypothesis_id: H-012
candidate_product: receipt-operations
segment: internal-agent-platform
problem: bounded non-sensitive statement
user_role: platform-engineer
buyer_role: security-platform-lead
deployment_requirement: on-premises
value_unit: retained-and-searchable-action-receipts
evidence_for:
  - evidence_id: partner-004-observation-7
    level: E2
evidence_against: []
status: testing
next_test: bounded non-sensitive description
```

Evidence identifiers point to access-controlled research material where
necessary. No personal contact information, customer secrets, proof bodies, or
credentials belong in the repository ledger.

### 7.3 Interview record

Each record MUST capture:

- opaque organization and participant identifiers;
- participant role in the workflow and purchase;
- current process;
- frequency and consequence of the problem;
- existing workaround and cost;
- security and deployment constraints;
- evidence level;
- direct factual observations;
- researcher interpretation, clearly separated;
- candidate invalidations;
- consent and redaction status.

## 8. Candidate-product architecture tests

Every candidate must be evaluated against the open-core architecture before
commercial selection.

```text
+--------------------------- customer system --------------------------+
| agent -> open Auths SDK -> local verifier -> closed customer gateway |
+-------------------------------|--------------------------------------+
                                |
                                | optional operational integration
                                v
+-------------------- candidate commercial product --------------------+
| governance | inventory | workflows | retention | connectors | support|
+-----------------------------------------------------------------------+

No commercial product may sit on the mandatory local verification path.
```

For each candidate, record:

- data it receives;
- data it stores;
- authority it can change;
- failure behavior when unavailable;
- hosted, on-premises, and hybrid topology;
- tenant and operator trust boundaries;
- export and deletion requirements;
- integration and credential boundaries;
- whether the open SDK remains fully useful without it;
- package and repository ownership if eventually built.

A candidate fails the architecture test if unavailability prevents ordinary
local verification, unless the customer explicitly configured that external
service as an additional approval-policy requirement.

## 9. Candidate scorecard

Candidates are compared using evidence, not weighted to force a predetermined
winner:

| Dimension | Required interpretation |
| --- | --- |
| Problem evidence | Number and strength of independent observations |
| Buyer clarity | Identified role with authority and budget |
| Urgency | Consequence and deadline of leaving the problem unsolved |
| Frequency | How often the workflow occurs |
| Existing spend | Money or engineering time already committed |
| Open-core fit | Paid value does not cripple local open use |
| Deployment fit | Hosted/on-premises model satisfies observed constraints |
| Product leverage | Reuses stable SDK/protocol surfaces |
| Semantic risk | Does not create a generic executor or policy engine |
| Delivery risk | Scope can reach a meaningful pilot |
| Defensibility | Compounds integrations, operational trust, or assurance |
| Evidence against | Explicit reasons not to build |

Scores MUST link to evidence identifiers and include a confidence rating.
Unresolved assumptions remain visible.

## 10. Packaging and willingness-to-pay tests

Pricing is tested after the problem and buyer are credible.

The program SHOULD test:

- which outcome is purchased;
- whether value is per organization, deployment, managed connector, governed
  agent fleet, approval workflow, retained receipt volume, or support level;
- whether local verification remains unmetered;
- whether a hosted and on-premises edition require different packaging;
- pilot scope and success criteria;
- procurement and support expectations.

The program MUST distinguish:

- a price a prospect says is reasonable;
- a budget range they control;
- an approved pilot;
- a signed commercial commitment.

Only the last two materially validate willingness to pay.

## 11. Research operations and privacy

Private research data SHOULD live in an access-controlled system, not the
public repository. The repository MAY contain:

- redacted hypothesis ledgers;
- evidence summaries;
- scorecards;
- decision records;
- mockups using synthetic data.

The program MUST define:

- participant consent;
- retention and deletion;
- access control;
- separation of contact data from technical evidence;
- redaction review;
- handling of regulated or confidential workflows;
- whether interviews may be recorded or transcribed.

No customer proof, key, credential, policy, patient data, financial record, or
proprietary action payload may enter research artifacts without explicit
authorization and a defined secure location.

## 12. APIs and artifact contracts

This program does not create a production runtime API. It defines research artifact
contracts so an executing agent cannot turn vague interest into a product
commitment.

```ts
type EvidenceLevel = "E0" | "E1" | "E2" | "E3" | "E4" | "E5";

interface CommercialEvidence {
  readonly evidenceId: string;
  readonly level: EvidenceLevel;
  readonly sourceType:
    | "interview"
    | "workflow-observation"
    | "integration"
    | "security-review"
    | "pilot"
    | "purchase";
  readonly observedAt: string;
  readonly redactedSummary: string;
}

interface CandidateDecision {
  readonly candidateId: string;
  readonly decision:
    | "select"
    | "continue-discovery"
    | "defer"
    | "reject";
  readonly evidenceFor: ReadonlyArray<string>;
  readonly evidenceAgainst: ReadonlyArray<string>;
  readonly openCoreReview: "pass" | "fail";
  readonly rationale: string;
}
```

Automated agents MAY summarize evidence. They MUST NOT promote its level,
invent buyer statements, or infer commercial commitment not present in the
source.

## 13. Decision gates

### Gate A: Problem

Pass when at least three independent organizations demonstrate the same
operational problem at E2 or stronger.

### Gate B: Buyer

Pass when the economic-buyer role, champion, operator, and security reviewer
are identified and at least one buyer invests at E3 or stronger.

### Gate C: Solution

Pass when prospects can evaluate a concrete workflow or prototype and agree on
measurable pilot success criteria.

### Gate D: Deployment

Pass when the required hosted, on-premises, or hybrid topology and data
boundary are understood well enough to estimate a pilot.

### Gate E: Open core

Pass when the candidate adds paid operational value without making local
verification dependent on a commercial service.

### Gate F: Integration

Pass when at least two independent AP-SPEC-030 integrations demonstrate the
same operational problem, the repeated-needs register distinguishes it from
one-off adapter work, and the candidate does not require a generic executor or
semantic leakage into shared/core code.

### Gate G: Commercial

Pass when at least one qualified prospect progresses toward an E4 paid or
formally sponsored pilot on explicit scope and terms.

Failure at a gate results in continued discovery, a changed hypothesis, or a
no-build decision—not fabricated certainty.

## 14. Deliverables

The product-selection gate produces:

1. redacted hypothesis ledger;
2. buyer and workflow maps;
3. problem-interview evidence;
4. deployment and security requirement matrix;
5. candidate architecture reviews;
6. solution-test results;
7. candidate scorecard;
8. packaging and willingness-to-pay evidence;
9. one commercial product selection record or a no-build record;
10. a separate implementation PRD only for the selected candidate.

The PRD MUST state the buyer, problem, success metric, open/paid boundary,
deployment topology, data model, integration surface, and pilot exit criteria.

## 15. Exit gate

The product-selection gate passes when one of these outcomes is documented:

### Selection

- one recurring problem has E2 observations from at least three independent
  organizations;
- at least two independent AP-SPEC-030 integrations demonstrate the same
  repeated operational problem;
- the buyer and user roles are distinct where applicable and understood;
- at least one organization supplies E3 or stronger commitment;
- a credible E4 pilot path exists;
- deployment and security requirements are bounded;
- the candidate passes the open-core architecture test;
- evidence supports a value unit and packaging experiment;
- competing candidates are explicitly deferred or rejected;
- a separate product requirements document is ready for review.

### No-build

- evidence does not support a paid product yet;
- failed hypotheses and counter-evidence are retained;
- the next discovery test is named;
- no speculative implementation is started.

Commercial discovery does not end when this gate passes. The gate does not
require a particular paid product, price, ARR target, hosted service, or
enterprise control plane. A disciplined no-build decision is a valid result.

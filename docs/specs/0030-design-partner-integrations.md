# AP-SPEC-030: Design-partner integration program

**Status:** Specified as a phased program — recruitment begins during Phase 9,
restricted integrations begin under Phase 9–10 gates, and consequential
customer pilots wait for Phase 11

**Governs:** Design-partner recruitment and restricted integration during
Phases 9–10, customer-operated pilots after Phase 11, and flagship evidence in
Phase 13

**Source strategy:** [Auths Product and Go-to-Market Strategy](../plans/GO_TO_MARKET_STRATEGY.md)

**Aligned with:** [Post-Milestone-6 Technical and Go-to-Market
Alignment](../plans/POST_MILESTONE_6_TECHNICAL_AND_GO_TO_MARKET_ALIGNMENT.md)

**Depends on:** AP-SPEC-032 for recruitment; AP-SPEC-033 for restricted Phase 9
preview; AP-SPEC-027 and AP-SPEC-028 for Phase 10 integration; and the
applicable AP-SPEC-029 and Phase 11 runtime, recovery, and security gates for
consequential pilots

**Scope:** A repeatable program for integrating Auths with agent-framework
maintainers and teams building internal agents, measuring product friction,
and converting repeated integration work into evidence for the next product
surface

**Normative language:** **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are
requirements on the program and any supporting implementation.

## 1. Decision

Auths will recruit design partners during independent review, integrate them
against restricted developer-preview surfaces, and widen effects only as the
technical program earns the required runtime and recovery gates.

The program is not a sales-logo exercise. Each integration must exercise
bounded delegation in a maintained agent workflow, produce a structured
integration diary, measure the time and friction involved, and test whether
developers can understand failures without reading verifier internals.

The program will recruit from two initial groups:

1. maintainers of agent frameworks, runtimes, or MCP tooling;
2. platform teams building internal agents that perform real tool or HTTP
   actions.

At least two integrations must become maintainable by two people outside the
Auths core project before the program can close.

## 2. Product questions

The program exists to answer:

- Can a developer attach an existing agent without becoming an Auths protocol
  expert?
- Is parent-to-child delegation valuable in a real workflow, or do users only
  adopt identity verification?
- Which SDK concepts cause the most confusion or custom code?
- Which authorization denials are difficult to diagnose?
- Which approval modes match hobbyist, internal, and regulated workflows?
- Which operational tasks recur across organizations?
- Do users need a CLI, visual inspector, hosted service, on-premises control
  plane, receipt search, policy distribution, or framework adapter?
- Who owns implementation and operation inside the organization?

Answers must be supported by observed behavior or explicit partner evidence.
Internal intuition alone does not close a question.

## 3. Goals

The program MUST produce:

- a documented partner-selection rubric;
- a standard onboarding and security-review packet;
- several real SDK integrations;
- one integration diary per partner;
- setup-time, failure, and support measurements;
- an inventory of all custom adapter and glue code;
- redacted authority, delegation, and denial examples;
- a repeated-needs synthesis;
- decisions to improve, defer, or reject candidate product surfaces;
- at least two integrations maintained by independent non-core contributors.

## 4. Non-goals

The program MUST NOT:

- promise a hosted service, control plane, CLI, connector, or compliance
  feature before evidence supports it;
- bypass an integration's native authorization or provider controls;
- import customer-specific semantics into `core/`;
- turn partner code into a generic executor;
- collect proofs, action bodies, credentials, receipts, or identity data
  through mandatory telemetry;
- treat interviews without usage as proof of product behavior;
- count a demo run by an Auths maintainer as external maintenance;
- publish a partner's name, architecture, metrics, or security details without
  explicit permission;
- accept custom changes that weaken local verification or open-core
  independence.
- expose a production credential, regulated dataset, financial mutation,
  infrastructure mutation, or irreversible customer effect before the
  applicable Phase 11 gate;
- describe Phase 9 or Phase 10 restricted use as a production pilot.

## 5. Partner selection

Each candidate is scored against:

| Criterion | Required evidence |
| --- | --- |
| Active agent workflow | An agent currently calls at least one real tool or API |
| Authority problem | Existing credential or permission is broader than the task |
| Delegation fit | Parent, orchestrator, workflow, or sub-agent can delegate less |
| Maintainer access | A technical owner can work directly with the SDK |
| Test environment | Side effects can be exercised safely and observed |
| Commitment | Partner agrees to a bounded implementation and feedback cycle |
| Learning value | Workflow differs materially from completed integrations |

The first cohort MUST recruit three to five integrations and include:

- at least one framework or runtime maintainer;
- at least one internal-agent platform team;
- at least one autonomous, grant-only workflow;
- at least one strongly supervised workflow.

At least two participants MUST have maintainers capable of updating and
operating their integration without the core author.

Regulated organizations MAY participate, but Auths MUST not claim regulatory
compliance merely because they do.

### 5.1 Phase and effect-risk gates

| Lane | Earliest gate | Permitted effect |
| --- | --- | --- |
| Recruitment and problem mapping | AP-SPEC-032 complete and Phase 9 active | no Auths-controlled provider effect required |
| Restricted review preview | AP-SPEC-033 Section 11 conditions | synthetic, local, sandboxed, read-only, draft, or demonstrably reversible |
| Phase 10 measured integration | AP-SPEC-027/028 preview gates | pinned preview artifacts and restricted effects only |
| Customer-operated pilot | applicable Phase 11 runtime, custody, recovery, and security gates | explicitly reviewed bounded customer effect |
| Flagship evidence | Phase 13 | continuously operated reviewed flagship workflow |

An effect cannot move to a later lane merely because a partner accepts the
risk. The technical gate, credential boundary, recovery behavior, data rules,
and written charter MUST all permit it.

## 6. Integration experience

### 6.1 Partner journey

```text
+----------------------------------------------------------------+
| 1. Map one real action                                         |
|    agent -> tool -> credential -> side effect -> observation   |
+-------------------------------+--------------------------------+
                                v
+----------------------------------------------------------------+
| 2. Define authority                                            |
|    root -> parent -> child -> exact action                     |
+-------------------------------+--------------------------------+
                                v
+----------------------------------------------------------------+
| 3. Integrate SDK and closed gateway                            |
|    attach -> delegate -> authorize -> execute -> receipt       |
+-------------------------------+--------------------------------+
                                v
+----------------------------------------------------------------+
| 4. Run adversarial cases                                       |
|    expanded, expired, replayed, mutated, wrong audience        |
+-------------------------------+--------------------------------+
                                v
+----------------------------------------------------------------+
| 5. Partner maintains and explains it                           |
|    clean setup -> diagnose denial -> update dependency         |
+-------------------------------+--------------------------------+
                                v
+----------------------------------------------------------------+
| 6. Record evidence and repeated needs                          |
+----------------------------------------------------------------+
```

### 6.2 Action-mapping worksheet

Before code changes, the partner and Auths maintainer MUST identify:

- the exact external effect;
- current agent and human actors;
- current credential holder and scope;
- trusted and untrusted inputs;
- the narrowest useful parent authority;
- the child attenuation;
- action canonicalization;
- approval mode;
- closed gateway and credential timing;
- observable evidence that the side effect did or did not happen;
- retry, restart, and unknown-outcome behavior;
- sensitive fields that must not enter receipts or research artifacts.

If the workflow requires unrelated effects with different credentials,
evidence, or lifecycle semantics, they are separate profiles or integration
slices.

## 7. Architecture

```text
+---------------------- auths-proof ----------------------+
| cohesive product integration                           |
| exact action -> evaluator -> verified command           |
| credential port -> closed gateway -> domain receipt     |
+---------------------------|------------------------------+
                            | pinned published contracts
                            v
+-------------------- partner repository -----------------+
| agent/framework -> Auths SDK -> non-semantic adapter    |
| local wiring/configuration -> existing tool/provider    |
+---------------------------|------------------------------+
                            |
                            | local, opt-in measurements
                            v
+---------------- integration evidence bundle -------+
| timing summary | friction log | denial exercises   |
| adapter inventory | maintenance handoff            |
+----------------------|-----------------------------+
                       v
+---------------- Auths synthesis --------------------+
| repeated needs | rejected ideas | product decisions|
+----------------------------------------------------+
```

Customer repositories MUST consume published or explicitly pinned Auths
artifacts. They MUST NOT use mutable sibling path dependencies.

Partner repositories MAY own only non-semantic integration code during this
program, including:

- framework and runtime adapters;
- application wiring and configuration;
- UI and developer-experience code;
- provider SDK plumbing behind an Auths-owned closed port; and
- partner-local test harnesses and synthetic fixtures.

New exact effects and security semantics MUST begin in one cohesive Auths
product integration under `product/integrations/auths-<domain>/`. This includes
canonical actions, policy and evidence types, evaluators, verified commands,
credential ports and scopes, gateways, lifecycle transitions, reconciliation,
stable codes, and receipt meaning.

Partner-specific non-semantic code remains in the partner repository unless it
is:

- generally useful;
- semantically identical to an existing Auths contract;
- accepted through normal architecture and conformance review;
- free of partner secrets, endpoints, and proprietary policy.

Before Phase 12 conformance machinery exists, a partner repository MUST NOT
become the sole owner of new Auths security semantics. After Phase 12, an
independently maintained external profile MAY own semantics only through the
versioned profile SDK and conformance process; it does not thereby become part
of Auths' formal or provider-correctness claim.

### 7.1 Measurement boundary

Measurements are local and opt-in. The default implementation writes a
redacted summary that the partner reviews before sharing.

The measurement layer MAY record:

- named workflow step;
- monotonic duration;
- result kind, stage, and stable code;
- count of configuration steps;
- count and category of custom adapter lines;
- count of support interventions;
- SDK and profile versions.

It MUST NOT record:

- raw proofs or canonical actions;
- credentials or key identifiers;
- action bodies;
- person or organization identity;
- private repository, patient, financial, or customer data;
- receipts unless separately reviewed and redacted.

## 8. Program artifacts

Each integration receives an opaque identifier such as `partner-004`. Public
and repository artifacts use that identifier unless naming permission is
recorded.

### 8.1 Integration brief

```yaml
schema: auths.design-partner-brief/1
integration_id: partner-004
segment: internal-agent-team
workflow_summary: bounded non-sensitive description
profile: auths.mcp/1
authority_shape: parent-to-child
approval_mode: risk-based
deployment: local
success_effect: bounded non-sensitive description
owner_role: platform-engineer
```

No contact information belongs in the repository artifact.

### 8.2 Integration diary

The diary MUST record:

- baseline architecture and permission problem;
- initial SDK version and documentation used;
- each integration session and elapsed active time;
- confusing concepts and API failures;
- custom adapter code and why it exists;
- all denial scenarios attempted;
- whether the partner diagnosed each failure unaided;
- approval and custody configuration;
- deployment constraints;
- maintenance handoff result;
- candidate product needs in the partner's own words;
- explicit redactions.

### 8.3 Metrics summary

```json
{
  "schema": "auths.design-partner-metrics/1",
  "integration_id": "partner-004",
  "sdk_version": "0.x",
  "minutes_to_first_authorized_action": 0,
  "minutes_to_first_delegation": 0,
  "manual_artifact_count": 0,
  "custom_adapter_line_count": 0,
  "support_intervention_count": 0,
  "denial_cases_attempted": 0,
  "denial_cases_diagnosed_without_help": 0,
  "maintained_by_partner": false
}
```

Zeroes in the example are placeholders, not targets.

### 8.4 Repeated-needs register

Every candidate need is recorded with:

- problem statement;
- affected integrations;
- current workaround;
- frequency and severity;
- proposed owning layer;
- whether it requires hosted or on-premises infrastructure;
- open-core impact;
- evidence for and against building it;
- decision: build, investigate, defer, or reject.

## 9. APIs and integration contract

Partners use only published SDK and profile APIs.

The minimum integration contract is:

```ts
interface DesignPartnerIntegration<P extends Profile> {
  readonly id: string;
  readonly profile: P;

  attach(): Promise<AttachedAgent<P>>;
  runAuthorizedScenario(): Promise<ScenarioEvidence>;
  runDeniedScenarios(): Promise<ReadonlyArray<ScenarioEvidence>>;
  verifyNoForbiddenEffects(): Promise<EffectAudit>;
}
```

This interface MAY exist only in the design-partner testkit. It MUST NOT become
a production framework that dispatches provider behavior.

`ScenarioEvidence` contains result kind, stable stage/code, redacted
commitments, credential-call count, provider-call count, and observed effect.
It contains no secrets or arbitrary partner payload.

## 10. Evaluation protocol

Each partner integration runs four reviews:

### Review A: Baseline

- observe the current workflow;
- record existing credential breadth;
- identify one exact effect;
- agree on the bounded Auths claim.

### Review B: Assisted integration

- partner follows published documentation;
- Auths maintainer observes but does not preempt every error;
- diary records setup time and interventions.

### Review C: Adversarial and restart exercise

- valid delegated action;
- expanded child authority;
- mutated action;
- expired grant;
- wrong audience;
- replay;
- restart followed by forbidden action;
- domain-specific unknown outcome when applicable.

### Review D: Maintenance handoff

- partner rebuilds from a clean checkout;
- partner diagnoses an intentional denial;
- partner updates one non-semantic configuration value;
- partner identifies where authority, execution, and receipts are represented;
- partner assumes normal maintenance responsibility.

## 11. Product-change policy

Partner feedback MAY trigger SDK improvements immediately when the change:

- clarifies an existing concept;
- removes accidental setup work;
- preserves protocol and profile meaning;
- adds focused tests and documentation.

New product surfaces require repeated evidence. As a default:

- one integration establishes a problem report;
- two independent integrations justify focused investigation;
- three integrations spanning at least two organizations justify a product
  proposal;
- semantic abstraction still follows the stricter profile/domain extraction
  gates.

Urgent security defects bypass product-discovery thresholds and follow the
security process.

## 12. Required evidence

The program MUST retain:

- reviewed integration briefs and diaries;
- redacted metric summaries;
- exact SDK/profile versions;
- clean-checkout reproduction steps;
- adversarial scenario results;
- effect-call evidence;
- maintenance handoff evidence;
- a synthesis separating repeated needs from one-off requests;
- decisions and their supporting evidence.

Private partner materials MAY live outside the public repository. The public
record should retain only redacted findings and opaque evidence identifiers.

## 13. Program gates

### 13.1 Recruitment gate

Recruitment is ready when:

- three to five partners have signed the bounded participation charter;
- the cohort covers both initial user groups and both autonomous and strongly
  supervised operation;
- each proposed effect has an assigned risk lane and data boundary;
- at least two participants name a non-core maintainer; and
- no charter promises production, compliance, certification, hosted service,
  or unsupported effect scope.

### 13.2 Restricted-integration gate

Restricted integration evidence is sufficient to inform SDK iteration when:

- at least three real integrations complete the applicable evaluation protocol;
- at least one framework or runtime maintainer and one internal-agent team are
  represented;
- multiple partners use parent-to-child delegation rather than identity alone;
- at least two integrations are maintained by two people outside the Auths core
  project;
- developers diagnose the standard negative cases without reading verifier
  internals;
- setup time, friction, adapter work, and support interventions are measured;
- new security semantics remain in cohesive Auths product integrations;
- every effect stayed inside its permitted technical and risk lane;
- the repeated-needs register identifies evidence-supported candidates for
  AP-SPEC-031; and
- no mandatory telemetry or hosted verification dependency was introduced.

### 13.3 Customer-pilot and program exit gate

The full design-partner program closes only when:

- the applicable Phase 11 runtime, custody, recovery, deployment, and security
  gates passed before consequential customer operation;
- at least one customer-operated integration completed backup, restore,
  upgrade, rotation, interruption, ambiguous-outcome, and incident-diagnosis
  exercises;
- at least one reviewed flagship workflow has operated under the Phase 13
  conditions;
- external maintainers can upgrade and operate at least two integrations;
- every finding and effect-risk exception has an owner and disposition; and
- repeated integration and operational evidence is sufficient for AP-SPEC-031
  to select a paid product or record a disciplined no-build decision.

No specific CLI, hosted, on-premises, governance, or pricing decision is
required. The purpose of this program is to earn those decisions.

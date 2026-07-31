# AP-SPEC-033: Independent review and remediation gate

**Status:** Specified — Phase 9 execution begins only after AP-SPEC-032 has
completed both exit gates

**Governs:** Phase 9 of the
[Post-Milestone 6 Productization and Release Plan](../target-state/POST_MILESTONE_6_PRODUCTIZATION_AND_RELEASE_PLAN.md)

**Aligned with:** [Post-Milestone-6 Technical and Go-to-Market
Alignment](../plans/POST_MILESTONE_6_TECHNICAL_AND_GO_TO_MARKET_ALIGNMENT.md)

**Depends on:** [AP-SPEC-032](0032-reproducible-release-candidate-and-exact-assurance-claim.md),
[AP-SPEC-034](0034-auths-public-naming-consolidation.md),
one immutable and non-withdrawn release candidate, its exact assurance-claim
bundle, and approved review ownership, budget, disclosure, and severity policy

**Scope:** Independent formal-methods, Rust/protocol-security, and stateful-
execution review of one fixed release candidate and claim bundle; structured
finding intake; remediation and regression evidence; independent retest; and
the exact gate that permits a labeled Phase 10 developer preview

**Normative language:** **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are
requirements on review operations, repository changes, evidence, and claims.

## 1. Decision

Auths will submit the exact Phase 7 release candidate and Phase 8 assurance
claim to independent specialists before beginning the Phase 10 developer
surface.

Phase 9 is not a request for a general endorsement. It is a bounded attempt to
find defects in exact artifacts and claims:

```text
immutable RC + exact claim bundle
                |
                v
+--------------- independent review tracks ----------------+
| formal methods | Rust/protocol security | stateful effects |
+------------------------|-----------------------------------+
                         v
              structured findings registry
                         |
              +----------+-----------+
              |                      |
              v                      v
        claim correction       code/evidence fix
              |                      |
              +----------+-----------+
                         v
             regression evidence + retest
                         |
                         v
                Phase 9 gate report
```

The reviewed source revision, release subjects, semantic identities, assurance
claims, reviewer scope, findings, remediation, and retest evidence MUST remain
connected by immutable identifiers and digests.

If remediation changes a frozen byte, semantic identity, release subject, or
claim subject, the old candidate cannot silently inherit the fix. AP-SPEC-032
MUST produce a new RC ordinal and rebound claim bundle before affected review
can close.

## 2. Bounded outcome

Successful Phase 9 completion supports only this statement:

> Independent reviewers assessed the named release candidate and assurance
> claims within their recorded scopes; every finding has a recorded
> disposition and owner; no critical finding remains unresolved; and the
> remediation identified as complete has passed independent retest.

It does not establish:

- that Auths is defect-free;
- that unreviewed revisions inherit the result;
- that all reviewers assessed every subsystem;
- that an external provider is correct, available, atomic, or deterministic;
- that a future Phase 10 SDK or Phase 11 runtime was reviewed;
- that Auths is production-ready, certified, compliant, or covered by an SLA;
- that a private report may be summarized as an unqualified public audit; or
- that medium, low, informational, accepted, or out-of-scope risks do not
  exist.

## 3. Entry gate and owner decisions

Phase 9 MUST NOT begin until:

- AP-SPEC-032 Phase 7 and Phase 8 are complete;
- the immutable RC is retrievable and not withdrawn;
- the release manifest, semantic-freeze inventory, claim registry, assurance
  statement, and evidence-bundle digests agree;
- consumer verification succeeds from a clean environment;
- the owner names a review coordinator who is not the sole author or approver
  of the in-scope implementation;
- review budget and contracting authority are recorded;
- confidentiality, coordinated-disclosure, report-retention, and publication
  rules are recorded;
- the severity and risk-acceptance policy in this specification is approved;
- the required reviewer competencies and conflict rules are approved; and
- each track has an agreed statement of work and completion criteria.

The owner MAY use one firm for multiple tracks only when the firm assigns
reviewers with the required distinct competencies and reports scope and
conflicts per track. Cost or scheduling pressure MUST NOT silently remove a
track.

## 4. Reviewer independence and competence

Every lead reviewer MUST:

- be organizationally independent from the Auths implementation and release
  approval;
- have no authorship responsibility for the in-scope production code or proof
  artifacts;
- disclose financial, employment, contribution, and advisory conflicts;
- be free to report adverse findings without payment or publication being
  conditioned on a favorable result;
- identify the exact portions personally reviewed and work delegated to other
  reviewers; and
- authenticate the final report or deliver it through an integrity-protected
  channel.

Paid review is independent review when these conditions hold. Independence
does not require anonymity or unpaid work.

The formal-methods lead MUST be able to review Lean theorem statements,
translation/refinement arguments, axioms, representation boundaries, and
qualification evidence.

The Rust/protocol-security lead MUST be able to review Rust memory and type
safety, cryptographic protocol use, bounded parsing, canonicalization,
authorization semantics, replay controls, configuration binding, dependency
and secret handling, and release integrity.

The stateful-execution lead MUST be able to review transactional persistence,
concurrency, crash boundaries, claims and reservations, credential ordering,
nondeterministic provider delivery, ambiguous outcomes, reconciliation, and
recovery.

## 5. Review target and packet

### 5.1 Scope manifest

One machine-readable scope manifest MUST bind:

- RC tag and full commit;
- release-manifest, semantic-freeze, evidence-bundle, and claim-registry
  digests;
- release subjects assigned to each track;
- source paths, generated artifacts, theorem declarations, tests, fixtures,
  and claims assigned to each track;
- explicitly excluded surfaces and the reason for each exclusion;
- approved reviewer identities and conflict declarations;
- review start date and packet version; and
- required deliverables and retest expectations.

A source or claim may appear in multiple tracks. Shared coverage does not make
ownership ambiguous: each track records what property it reviewed.

### 5.2 Review packet

The packet MUST include:

- offline artifact and evidence verification instructions;
- repository build, test, formal-reproduction, and conformance instructions;
- architecture and trust-boundary documentation;
- threat models and known residual assumptions;
- formal assurance manifest, source-closure report, qualification evidence,
  axioms, and external models;
- protocol, profile, evaluator, canonicalization, decision-code, and receipt
  inventories;
- state-transition, credential, replay, reconciliation, and recovery models;
- dependency, SBOM, provenance, benchmark, architecture, and compliance
  evidence;
- prior relevant review findings and their status; and
- a protected channel for suspected vulnerabilities.

The packet MUST be reproducible from recorded release subjects. Reviewer-only
access instructions MAY be separate, but private material MUST NOT silently
change the public review target.

## 6. Required review tracks

### 6.1 Formal methods and assurance boundary

This track MUST assess:

- whether public theorem claims match exact Lean declarations and premises;
- whether rich authorization, attenuation, and bounded-policy statements
  express the intended security properties;
- Aeneas and Charon qualification, version pinning, generated artifacts, and
  source-closure claims;
- representation mappings between production Rust and Lean values;
- transitive axioms, external models, trusted code, and unresolved `sorry` or
  equivalent escape hatches;
- Kani claims and their bounds, harness assumptions, and relationship to the
  general Lean claims;
- whether differential, mutation, property, fuzz, conformance, and integration
  evidence are described at the strength they actually provide;
- whether authorization, execution, provider acceptance, observation, and
  reconciliation remain distinct; and
- every Phase 8 claim classified as theorem or refinement.

The reviewer MUST attempt to construct counterexamples at representation and
trust boundaries, not merely confirm that proof commands succeed.

### 6.2 Rust, cryptography, and protocol security

This track MUST assess:

- canonical encoding and rejection of alternate, trailing, over-depth,
  oversized, or unknown-version inputs;
- signature descriptors, domain separation, algorithm agility, key handling,
  and verification-method binding;
- delegation attenuation, time, audience, resource, permission, budget, and
  depth enforcement;
- required-versus-executed policy and evaluator configuration equality;
- sealed verified-command construction and inability to forge it through
  public APIs;
- replay, commitment, receipt, and stable-code integrity;
- allocation and deterministic-work bounds before expensive processing;
- secret lifetime, redaction, credential ordering, test keys, and logging;
- use of `unsafe`, build scripts, native dependencies, and dependency-policy
  exceptions;
- denial and indeterminate behavior at every public boundary; and
- release subject, SBOM, checksum, provenance, and claim synchronization.

Cryptographic review MUST distinguish correct use of reviewed primitives from
proof of the primitives themselves.

### 6.3 Stateful authorization and exact-effect execution

This track reviews the stateful and provider-facing behavior present in the RC,
not the future Phase 11 production runtime.

It MUST assess:

- atomic replay and reservation behavior;
- capacity conservation and concurrent final-unit races;
- durable decision, claim, execution-intent, delivery, observation, and
  reconciliation transitions;
- denial and indeterminate persistence;
- credential acquisition only after all required authorization and claim
  gates;
- exact equality between verified commands and outbound provider commands;
- crashes before credentials, before delivery, after possible delivery, and
  after provider response;
- ambiguous provider outcomes and prohibition on blind duplicate execution;
- reconciliation freshness, revocation, retry, and terminal-state behavior;
- isolation level, compare-and-swap, transaction, lock, and fencing
  assumptions;
- receipt truth across authorization, provider acceptance, observation, and
  recovery; and
- domain ownership of provider, credential, lifecycle, and receipt semantics.

Findings about capabilities absent from the RC MUST be recorded as future
requirements or exclusions, not misreported as defects in an implemented
surface.

### 6.4 Cross-track claim review

Each track MUST identify claims it supports, contradicts, narrows, or cannot
assess. The review coordinator MUST reconcile disagreements without merging
different evidence classes into one verdict.

At least one reviewer outside the original Phase 8 claim authorship MUST read
the complete human-readable assurance statement for misleading composition,
not only validate individual registry entries.

## 7. Reviewer experience and status view

The repository SHOULD provide one read-only command that verifies the packet
and renders review status without editing findings:

```text
+------------------------------------------------------------------+
| Auths Phase 9 review · auths-v1.0.0-rc.N                         |
+------------------------------------------------------------------+
| Packet      verified · commit 8f62... · manifest 14ac...        |
| Formal      complete · findings 0C 1H 3M 2L                     |
| Protocol    retest     · findings 0C 0H 2M 4L                   |
| Stateful    active     · findings 1C 2H 1M 0L                   |
+------------------------------------------------------------------+
| Gate        BLOCKED · unresolved critical STATE-004             |
| Claims      2 narrowed · 1 suspended                             |
+------------------------------------------------------------------+
```

The view MUST be generated from validated artifacts. Color, labels, or a
summary count MUST NOT override the structured gate result.

## 8. Finding and gate artifact APIs

### 8.1 Finding schema

Every finding MUST record at least:

```yaml
schema: auths.review-finding/1
finding_id: PROTOCOL-007
track: rust-protocol-security
severity: high
title: bounded non-sensitive title
status: open
rc_tag: auths-v1.0.0-rc.N
subject_digests:
  - sha256:...
source_locations:
  - product/example/src/lib.rs
affected_claim_ids:
  - AUTHS-RC-example
security_property: exact property affected
preconditions: bounded triggering conditions
impact: bounded impact statement
reproduction_evidence: reviewer-private-or-public-reference
owner: repository-owner-id
disclosure: coordinated
```

The public repository MAY contain a redacted security-safe projection while
remediation is pending. The canonical private finding MUST retain the exact
reproduction and affected subjects under approved access controls.

### 8.2 Severity

Severity MUST be based on reachable impact, authority or secret exposure,
integrity loss, exploit prerequisites, affected deployment, and evidence—not
reputation or remediation cost.

| Severity | Required handling |
| --- | --- |
| Critical | Blocks Phase 9 exit and all affected previews; must be remediated and independently retested. |
| High | Blocks the affected claim, surface, and production release; must be remediated and retested or receive bounded owner acceptance with a deadline and explicit release block. |
| Medium | Requires an owner, disposition, regression plan where applicable, and target gate. |
| Low | Requires a recorded disposition and rationale. |
| Informational | Records a limitation, hardening opportunity, or documentation correction without implying a vulnerability. |

A critical finding MUST NOT be risk-accepted to close Phase 9. Severity changes
require reviewer rationale and retain the previous classification.

### 8.3 Status and disposition

Allowed statuses are:

- `open`;
- `triaged`;
- `remediation-planned`;
- `remediated-awaiting-retest`;
- `retest-passed`;
- `retest-failed`;
- `risk-accepted`;
- `duplicate`; or
- `not-applicable`.

`duplicate` and `not-applicable` require reviewer-visible rationale. Repository
owners MUST NOT unilaterally mark an adverse finding closed.

### 8.4 Gate report

The machine-readable gate result MUST expose at least:

```ts
type ReviewSeverity =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "informational";

interface Phase9GateReport {
  readonly schema: "auths.phase9-gate/1";
  readonly rcTag: string;
  readonly rcCommit: string;
  readonly reviewPacketDigest: string;
  readonly claimRegistryDigest: string;
  readonly trackReportDigests: ReadonlyArray<string>;
  readonly decision: "blocked" | "phase10-preview-permitted";
  readonly unresolvedBySeverity: Readonly<Record<ReviewSeverity, number>>;
  readonly blockedSurfaceIds: ReadonlyArray<string>;
  readonly suspendedClaimIds: ReadonlyArray<string>;
  readonly knownRiskRegisterDigest: string;
  readonly decidedAt: string;
  readonly ownerApprovalId?: string;
}
```

The gate calculator MUST be pure over validated registry and report inputs.
`ownerApprovalId` is required only for `phase10-preview-permitted`; its presence
cannot override a critical finding, missing track, stale subject, failed
retest, or active release block.

## 9. Remediation and candidate replacement

Every confirmed security finding MUST produce at least one durable regression
or assurance artifact appropriate to its layer:

- Lean theorem or corrected statement;
- Aeneas/Charon qualification or source-closure obligation;
- Kani harness;
- canonical negative fixture;
- mutation, property, fuzz, conformance, or integration test;
- architecture or compliance rule;
- operational control and exercise; or
- explicit residual assumption or exclusion in the claim registry.

Documentation alone is sufficient only when the implementation is correct and
the defect is exclusively an inaccurate or ambiguous claim.

Remediation is classified as:

1. **Claim-only:** no release subject or semantic identity changes. Publish a
   new claim-bundle version, preserve the superseded wording, and retest the
   claim.
2. **Implementation without semantic change:** source or artifact bytes change
   while meaning remains compatible. Produce a new RC ordinal through
   AP-SPEC-032 and retest affected implementation and claims.
3. **Semantic correction:** protocol, policy, evaluator, action, receipt,
   persisted-state, or code meaning changes. Assign new semantic identity or
   version, produce migration and compatibility evidence where applicable,
   issue a new RC ordinal, and rerun every affected review obligation.

No report or pull request may describe a superseded RC as remediated. The
finding record MUST name the candidate that contains the fix and the candidate
against which retest passed.

## 10. Retest

Independent retest MUST:

- be performed by the original reviewer or another qualified independent
  reviewer approved for the track;
- reproduce the original condition against the original candidate where safe;
- verify the new regression fails on the defective behavior and passes on the
  remediation;
- verify the fix did not broaden authority or weaken an adjacent invariant;
- check every affected claim and release subject;
- record exact commit, RC tag, semantic identities, commands, and evidence;
- state what was not retested; and
- authenticate the retest result.

A passing repository test run is necessary evidence where applicable but is
not an independent retest by itself.

## 11. Restricted Phase 9 preview

Phase 9 MAY support AP-SPEC-030 recruitment and a restricted preview only when:

- AP-SPEC-032 is complete;
- the preview is labeled non-production and pre-audit;
- effects are synthetic, local, sandboxed, read-only, draft, or demonstrably
  reversible;
- no production credential, regulated data, financial mutation,
  infrastructure mutation, or irreversible external effect is in scope;
- the participant receives the exact assurance exclusions and known-finding
  notice appropriate to the preview;
- the preview uses pinned RC or review artifacts;
- collection of evidence is local, opt-in, and redacted; and
- any reviewer or owner can suspend the affected preview after a finding.

Preview use does not satisfy a review obligation and MUST NOT be cited as
independent security evidence.

## 12. Security, confidentiality, and disclosure

- Vulnerability reports MUST use the approved protected channel.
- Public artifacts MUST not expose an unremediated exploit recipe before the
  coordinated-disclosure decision.
- Confidentiality MUST NOT be used to hide review scope, reviewer identity,
  unresolved severity counts, claim withdrawals, or the existence of a
  release-blocking condition from authorized decision-makers.
- Reports and evidence MUST follow recorded retention, access, backup,
  deletion, and legal-disclosure rules.
- Reviewer access MUST be least-privilege, time-bounded, and revoked at the end
  of the engagement.
- Test credentials and keys MUST be synthetic and unmistakably non-production.
- A reviewer MUST be able to report coercion, conflict, or scope interference
  directly to the owner.

Public disclosure follows the approved coordinated-disclosure policy. A
public summary MUST name exact reviewed revisions and scopes and MUST preserve
all material limitations.

## 13. Required artifacts and validation

Phase 9 MUST produce:

1. approved review charter and owner decisions;
2. digest-bound scope manifest and reproducible review packet;
3. reviewer competence and conflict declarations;
4. one report per required track;
5. validated canonical findings registry;
6. claim-impact and remediation map;
7. regression evidence for every confirmed security finding;
8. independent retest records for every finding represented as remediated;
9. current known-risk and release-block register;
10. public security-safe summary; and
11. machine-readable and human-readable Phase 9 gate reports.

Validation MUST reject:

- a report bound to the wrong commit, RC, subject, scope, or claim bundle;
- missing reviewer independence or conflict declarations;
- findings with unknown severities, statuses, owners, or affected subjects;
- a severity downgrade without retained rationale;
- critical risk acceptance;
- a remediated status without regression and independent retest evidence;
- a retest that targets a different fix than the recorded remediation;
- a withdrawn or superseded candidate presented as current;
- a claim that remains public after its supporting evidence was invalidated;
- a gate report that omits private unresolved finding counts; and
- Phase 10 permission while the applicable release block remains active.

The gate calculation MUST be deterministic and tested with mutation and
boundary cases.

## 14. Pull-request and external-event boundaries

Phase 9 is not one pull request. The minimum boundaries are:

1. **Review-contract PR.** Add this specification, schemas, gate calculator,
   and validation tests.
2. **Packet PR.** Add the scope manifest and reproducible packet references for
   the exact AP-SPEC-032 candidate.
3. **Review engagement.** External reviewers receive the fixed packet. This is
   an external event and changes no repository semantics.
4. **Finding-intake PRs.** Add security-safe finding projections, claim blocks,
   and regression obligations without combining unrelated remediation.
5. **Remediation PRs.** Fix bounded findings with their regression evidence.
6. **Replacement-RC events.** When required, execute AP-SPEC-032 for a new RC
   and claim bundle.
7. **Retest records.** Add or bind authenticated independent retest evidence.
8. **Gate-closure PR.** Publish the final registry projection, known-risk
   register, claim state, and gate report without implementation changes.

Finding confidentiality MAY require private coordination before public PRs.
It does not permit skipping the repository evidence and release gates.

## 15. Phase 9 exit gate

Phase 9 is complete only when:

- all three required review tracks completed their recorded scopes;
- every report is bound to the current non-withdrawn RC and claim bundle;
- every finding has severity, affected subjects and claims, owner, disposition,
  and disclosure state;
- no critical finding remains unresolved;
- every critical remediation passed independent retest;
- each unresolved high finding has explicit bounded owner acceptance, deadline,
  affected-claim suspension, and release-blocking status;
- every finding represented as remediated has durable regression evidence and
  independent retest;
- superseded candidates and claims are visibly superseded;
- the public assurance statement reflects every material narrowing,
  assumption, exclusion, and unresolved risk;
- the known-risk register and gate calculation validate;
- the owner approves only an explicitly labeled Phase 10 developer preview;
  and
- the gate report names what must still occur before production, public v1,
  certification, compliance, or SLA claims.

Passing Phase 9 permits AP-SPEC-027 and the local, reversible AP-SPEC-028 work.
It does not permit consequential customer effects, a production runtime, or
unqualified public security claims.

## 16. Handoff

After Phase 9:

- AP-SPEC-027 may implement the Phase 10 TypeScript developer preview;
- AP-SPEC-028 may implement the Phase 10 local and reversible MCP reference
  vertical;
- AP-SPEC-029 may implement its provider-neutral Phase 10 contracts;
- AP-SPEC-030 may widen from recruitment into measured restricted
  integrations; and
- AP-SPEC-031 discovery continues, but product selection remains evidence-
  gated.

Deployable custody, consequential customer operation, runtime chaos and
recovery, deployment penetration testing, profile conformance qualification,
flagship production operation, and public v1 remain governed by Phases 11
through 15 and their separate execution plans.

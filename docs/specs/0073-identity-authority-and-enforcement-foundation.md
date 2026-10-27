# AP-SPEC-073: Identity, delegated authority, and enforcement foundation

- **Status:** Architecture and implementation program in progress. Initial verification contracts are implemented; the complete program and new execution paths are not qualified.
- **Date:** 26 October 2026.
- **Updated:** 27 October 2026; implementation goal active, first bounded slice defined in the companion assessment. No acceptance criterion is yet closed.
- **Mission:** Build an authorization and identity layer for human–agent, machine–agent, and agent–agent work.
- **Repository decision:** Evolve this monorepo through direct subsystem replacements. Compatibility with disposable prelaunch state is not a requirement.
- **Starting revision:** `9b1fe3c202a202750704730aebc47e0585a24470` on `codex/ap-spec-071`.
- **Working branch:** `codex/identity-authority-foundation`.
- **Companion:** [Initial implementation assessment](../plans/0073-foundation-assessment.md).
- **Terms:** MUST/MUST NOT describe proposed acceptance requirements. They do not claim existing implementation or silently override current repository policy.

## 1. Purpose and authority of this document

For every operation, Auths must establish **who acts, on whose authority, against which resource, under what constraints, and what evidence supports the resulting claims**.

The user has established the mission, permitted substantial replacement, and requested a durable specification and isolated worktree. The mechanisms below are proposed design decisions. Naming a mechanism here is not evidence that it is required, implemented, or safe. The implementation program must first distinguish existing foundations worth retaining from gaps requiring replacement.

This specification supplements the existing contracts while it is a draft. `AGENTS.md`, `architecture.toml`, `compliance.toml`, workspace metadata, and `xtask` retain their authority. Changes to those contracts must accompany the bounded implementation that needs them. Historical material in `docs/target-state/` is context, except where the repository contract explicitly requires following a boundary plan.

Relevant existing work:

- [AP-SPEC-061: machine-checked verifier](0061-end-to-end-machine-checked-verifier.md).
- [AP-SPEC-063: generalized gateway](0063-generalized-gateway.md).
- [AP-SPEC-065: k-of-n approvals](0065-native-k-of-n-approvals.md).
- [AP-SPEC-066: gateway qualification](0066-production-gateway-polish-and-recipe-qualification.md).
- [AP-SPEC-071: human-agent read/write delegation](0071-human-agent-read-write-delegation-demo.md).
- [AP-SPEC-072: adapter proposals and qualification](0072-agent-authored-adapter-studio-and-qualification.md).
- [Domain abstraction boundary plan](../target-state/PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md).
- [ADR 0012: credential-isolated gateway](../adr/0012-declarative-credential-isolated-gateway-boundary.md) and [ADR 0013: recipe capabilities and budgets](../adr/0013-recipe-capabilities-and-sum-budget.md).

## 2. Scope, threat model, and limits

The system covers identity establishment and lifecycle; holder-bound delegation; bounded authority composition; current resource policy; live admission; controlled disclosure and effects; and evidence sufficient to explain those stages separately.

Assume compromised agents, hostile inputs, independently administered trust domains, concurrent workers, stale evidence, clock uncertainty, key compromise, process crashes, and ambiguous provider responses. Transport authentication and organizational affiliation confer no implicit authority. Provider permissions remain an independent ceiling.

The system does not promise that a correctly identified agent is honest, that an authorized action is wise, or that a model follows natural-language intentions. It cannot retract plaintext from an uncontrolled recipient, obtain immediate revocation while disconnected, or guarantee exactly-once effects at a provider lacking the necessary protocol. A workflow spanning providers is not an atomic distributed transaction merely because it shares an Auths task.

Unbounded work and input sizes remain unacceptable even when development time and resources are unconstrained. Every public protocol and verification boundary needs finite, testable limits.

## 3. Identity model

| Concept | Contract |
| --- | --- |
| Principal | Enduring identifier within an explicit identity method and trust domain; never equated by display name or email alone. |
| Controller | Entity authorized to administer identity lifecycle. Control does not transfer the controller's resource permissions. |
| Workload | Identified software deployment and configuration. A workload claim has an issuer, scope, and validity. |
| Instance | Particular executing process or runtime with a bound credential; shared workload identity does not establish instance uniqueness. |
| Session | Bounded authenticated interaction, with channel and audience bindings where required. |
| Delegation | Explicit authority granted to a holder; independent of identity administration. |

Humans, agents, services, and devices use the same authority rules. Their authentication and assurance methods may differ. External identity adapters produce bounded evidence for a canonical principal-control contract. They MUST NOT infer authority from authentication success.

Lifecycle contracts must cover enrollment, rotation, suspension, compromise, recovery, and federation. Recovery MUST specify the status of old keys, sessions, grants, and descendants. It MUST NOT revive compromised authority implicitly. Historical verification and eligibility for a new operation are separate questions.

An attestation proves only the claims its trusted issuer makes. Software measurements and deployment evidence are policy inputs; they do not establish model honesty or complete isolation. A verifier selects trust roots and assurance requirements out of band. A proof cannot select its own trusted issuer.

## 4. Authority, delegation, and composition

A conceptual delegation binds issuer, holder, parent authority, engagement scope, resources, operations, typed argument restrictions, permitted recipients, validity, delegation permission/depth, approval requirements, enforcement audience, revocation dependencies, and budget references. This is a semantic inventory, not a proposed universal struct with optional fields.

The first implementation SHOULD retain the existing canonical model wherever it represents these meanings correctly. Wire changes require explicit schema, fixture, binding, and formal updates.

The authority kernel MUST establish:

1. Every parent link is valid and authorizes the issuer's delegation.
2. Each child preserves or narrows each applicable authority dimension.
3. A holder demonstrates control of an accepted verification method for the invocation.
4. Delegation permission is explicit; permission to act does not imply permission to delegate.
5. Cycles, excessive depth, unsupported constraints, and ambiguous composition fail closed.
6. Trust anchors bound initial authority; a valid signature is insufficient.

An **engagement** is the explicit scope within which authority and information may be combined. Existing task identity is a candidate representation, not automatically a new type. A read authorized under engagement A and a send under engagement B MUST NOT authorize a combined read-and-send workflow. Crossing that boundary needs explicit authority and resource-side acceptance.

Within an engagement, several branches may satisfy a deliberately declared authorization plan. Arbitrary union of grants is prohibited. The plan must bind which branches satisfy which requirements, common resource/recipient constraints, and budget attribution. Existing multi-party approval and proof-plan semantics must be assessed before introducing new composition semantics.

The narrowing calculus should use decidable, bounded relations over explicitly supported types. General implication checking over arbitrary user policy programs is outside the kernel. Organizational policy may decide issuance and acceptance, but cannot redefine the grant attenuation relation.

### 4.1 First slice: delegation to an already approved recipient

Initially retain the current task/card format and its explicitly named final agent. A read may use intermediaries only when the task's approving human issued a grant on the exact single branch accepted by native verification. The task human need not be the terminal grant issuer. Parent linkage, depth, attenuation and all other kernel checks remain mandatory; an unrelated grant or a different branch cannot establish that ancestry. The same task/card, resource, account, recipient channel and original budget remain bound at admission.

This slice does not admit runtime-selected recipients, new participant enrollment, machine task activation, or independent child budgets. Those require the subsequent role and participant protocol. The [assessment's D1–D3 decisions](../plans/0073-foundation-assessment.md) define the scope and pending verification.

### 4.2 Task roles: initiation is separate from exact approval

The next direct source cutover uses task schema 3 with required
`initiator_principal` and `approver_principal` fields, both pinned by the
operator. Native task activation authenticates the initiator; read ancestry
must include that initiator. Exact write, effect-plan and recovery approvals
authenticate the approver. Bounded-upfront mode cannot stand in for an independent
approver: it is supported only when both roles are the same principal and the
operator permits the mode. Neither role may equal the acting agent in this
initial independently approved task profile.

The [role cutover contract](../plans/0073-task-role-cutover.md) records schema,
commitment, state rejection and fixture obligations. A human-initiated vertical
may deliberately choose one principal for both roles. Role labels do not prove
human presence or identity assurance. Participant enrollment, instance generation
and shared ancestor budgets remain separate implementation work.

### 4.3 Participant enrollment verification

The native enrollment verification boundary now has a closed descriptor and
separate parent, child-acceptance and resource-authority proofs. The
[participant contract](../plans/0073-engagement-participant-contract.md#9-native-enrollment-verification-boundary)
defines exact grant linkage, canonical commitments, bounds and trusted inputs.
The returned value is a verified proposal; the task journal now durably publishes
it under its transaction lock. Operation admission and participant capacity
remain implementation work. Core proof wire
semantics are retained, and no provider action runs during verification.

Native root bootstrap now proves holder control and separate resource authority
for an exact immutable root commitment. Pins still require an authenticated
engagement and operator installation.

A bounded pure enrollment tree now owns immutable ancestry, retained revocation,
ID/principal non-reuse and canonical state validation against independently
installed root pins. Enrollment derives its current parent snapshot from this
tree before native verification. Registered channels bind both child principal
and instance generation. The task journal now owns root bootstrap, child enrollment
and retained operator revocation in one protected record and transaction. It
rechecks trusted time inside the lock and root association on reopening. This
source integration still awaits hosted behavioral evidence. Operation admission,
ancestor charging and child dispatch remain incomplete; pending-root tasks still
use the existing initial-agent gate. See the
[task-journal contract](../plans/0073-engagement-participant-contract.md#14-native-root-and-enrollment-in-the-existing-task-journal).

## 5. Portable verification and live admission

Portable verification answers whether exact action bytes are covered by the supplied authority under explicit trust, evidence, time, and configuration inputs. It does not promise current global state.

Live admission answers whether the operation may enter execution now. An admission authority owns a declared consistency boundary for replay, budgets, revocation epochs, and approval consumption. Resource-owner policy and provider access remain separate ceilings.

An admission transaction MUST atomically establish the applicable current predicates and reserve capacity before issuing an execution permit. The permit binds the action/plan commitments, engagement, actor, resource, recipient where relevant, enforcement audience, policy/configuration versions, connection generation where relevant, and replay identity. Its expiration and consumption rules are explicit. A portable verification result is not an execution permit.

The revocation contract must name its linearization point. The initial design target is that revocation prevents later admissions in the same authority partition; already admitted operations follow explicit entry/cancellation rules. It must not imply that revocation undoes an entered effect. Any additional pre-entry revocation gate needs an atomic ordering contract with entry authorization, not a racy read followed by an unguarded send.

Distributed budgets use coordinated admission or disjoint escrow allocations. If a parent has 100 units, two children cannot each independently spend 100. Allocation, reservation, consumption, uncertain exposure, and provably releasable capacity must be distinguishable, with unit and scope identifiers preventing accidental mixing. The conservation equation and transition rules belong to each admitted budget mechanism.

Disconnected enforcement requires preallocated capacity, bounded validity, explicit evidence freshness, and a stated revocation delay. It cannot make the same fresh-state claim as coordinated online admission.

## 6. Architecture and enforcement modes

The baseline below describes contractual responsibilities, not a complete deployed topology or proof that each boundary is established.

```mermaid
flowchart LR
    A["Caller: proof and canonical action"] --> V["Offline verifier and sealed action"]
    V --> G["Managed gateway: recipe, admission, execution, recovery"]
    C["Credential custody"] --> G
    G --> P["Provider"]
    G --> R["Receipts and observations"]
    V --> S["Application-owned SDK integration"]
    S --> X["Application-owned effect and evidence"]
```

The proposed responsibility split is:

```mermaid
flowchart TB
    I["Identity authorities and lifecycle"] --> D["Delegation and engagement control"]
    D --> A["Acting human, machine, or agent"]
    A -->|"Signed invocation and authority"| E["Resource enforcement boundary"]
    P["Resource-owner policy"] --> E
    E --> K["Deterministic verification kernel"]
    E --> L["Admission authority: replay, budgets, epochs, approvals"]
    E --> N["Native resource execution"]
    E --> M["Isolated mediated executor"]
    C["Credential custody"] --> M
    M --> R["Legacy resource"]
    E --> J["Private evidence journal"]
    L --> J
```

These are responsibility boundaries, not a requirement for a microservice per box or a mandatory central Auths service. Each trust domain controls its accepted issuers, policies, resources, and admission partitions. Federation does not grant access automatically.

Two enforcement modes are proposed:

- **Native:** the resource participates in verification, admission, effect application, and truthful outcome reporting. Its conformance requirements include demonstrating that protected effects cannot bypass those gates within the claimed deployment boundary.
- **Mediated:** a credential-isolated executor translates an admitted operation into a closed provider request. Credentials and unrestricted authenticated clients never reach the agent.

Current policy admits managed production writes through the data-only gateway. Native managed execution or additional isolated execution families require an explicit ADR and executable policy updates before production implementation. Application-owned integration remains available with its existing, weaker claim. This draft does not admit arbitrary Rust, WASM, scripts, or callbacks inside the gateway.

Provider semantics remain profile-owned and version-pinned. Installation approval binds request construction, evidence interpretation, and recovery behavior. A provider name MUST NOT select a hidden branch in the shared authorization or gateway kernel.

## 7. Typed progression from intent to effect

```mermaid
flowchart LR
    I["Intent"] --> A["Validated action"]
    A --> P["Bound execution plan"]
    P --> D["Admitted operation"]
    D --> E["Execution attempt"]
    E --> O["Observed outcome or unresolved uncertainty"]
```

Each transition has an owner, explicit inputs, errors, commitments, and a postcondition. Different stages have different information; one mutable record passed everywhere is not the target.

| Transition | Required invariant |
| --- | --- |
| Intent to action | User intent is translated into a bounded, reviewed contract; prose alone cannot authorize an effect. |
| Action to plan | Resource identity, recipients, provider mapping, relevant versions, and exact payload are bound without widening authority. |
| Plan to admission | Required approvals and current resource policy match the plan; capacity and replay state change atomically. |
| Admission to entry | Permit audience, generation, configuration, and exact request match; durable entry rules precede possible irreversible exposure. |
| Entry to outcome | Receipt claims follow actual observation and recovery evidence; missing response is not failure evidence. |

Exact approval binds the finalized plan. Bounded-upfront approval is a distinct contract whose later plans must satisfy its limits. Every security-relevant change invalidates affected approvals and permits. Sealed Rust values protect local call boundaries; remote permits additionally require authenticity, audience, freshness, and replay checks.

## 8. Recovery protocols and shared mechanisms

There is no proposed universal workflow state machine. Begin with concrete protocols and extract identical mechanisms only under the existing evidence gates.

| Protocol | Boundary | Required uncertain-outcome behavior |
| --- | --- | --- |
| Disclosure | First possible release to a recipient | Retain release accounting after lost acknowledgement; do not infer non-delivery. |
| External mutation | First possible provider entry | No blind retry after response loss; preserve capacity until sound reconciliation. |
| Resource creation | New resource may exist | Resolve exactly one authorized resource with adequate search evidence before dependent work. |
| Delegation issuance | A holder may possess usable authority | Issuance retry and descendant revocation have explicit identities and lifecycle semantics. |

Durable compare-and-swap, atomic claims, bounded journals, and checked arithmetic are candidates for shared implementation. Admission eligibility, capacity release, reconciliation, and receipt meaning remain concrete until semantic equivalence is established.

Lease expiry does not prove an external effect did not happen. Fencing works only where the recipient enforces the fence. Idempotency is a provider contract with scope and retention, not an assumption attached to an arbitrary header. An uncertain effect MUST NOT become retryable merely because a worker restarted.

## 9. Information flow and custody

Authority includes both access and permitted disclosure: source selection, projected fields, byte bounds, recipient identity, execution environment, onward recipients, and approved output channels. An external model API, memory store, log sink, and tool runner are potential recipients.

Controlled execution must demonstrate that protected content cannot escape through alternate storage or network paths within the deployment claim. Content already delivered to an uncontrolled principal cannot be recalled or reliably constrained by a subsequent token. Retention and purpose restrictions without technical enforcement must be labeled contractual.

Read authority and send authority cannot be combined across unrelated engagements. A resource-side policy must also validate permitted flow within one engagement. Labels supplied solely by the acting agent cannot establish provenance.

Provider custody binds account subject, connection identity and generation, approved endpoint, and permitted request. Provider credentials, human signing keys, and reusable authenticated clients never enter an agent's execution environment. Private evidence uses appropriate protected commitments; low-entropy private content must not be exposed through guessable public hashes.

## 10. Central contracts for time, evidence, and configuration

Centralization must remove repeated interpretation at security boundaries, not only repeated code.

- **Time:** distinguish authenticated event time, observation time, evidence validity, and evaluation time. Re-evaluation cannot refresh an old event. Production supplies time through an explicit contract; the kernel never reads a clock. Cross-host claims specify uncertainty/skew and freshness bounds. Clock rollback and unavailable trusted time have explicit denial/indeterminate behavior. Monotonic time is for local durations, not portable historical timestamps.
- **Canonicalization:** one authoritative encoding and commitment contract per protocol object. Bindings do not substitute hashes or invent alternative action identities.
- **Configuration:** required and executed verifier, policy, integration, and trust configuration are bound. Cache keys cover the actual semantic configuration, evidence freshness, and state dependencies, or cache only the immutable subset.
- **Persistence:** atomicity, ordering, process-crash behavior, power-loss durability, and backup/restore rollback detection are explicit contracts. Publishing an admission outcome must not outrun the durability on which it relies.
- **Evidence:** identity, grant, approval, reservation, release, entry, observation, and revocation records state different facts. Signatures authenticate assertions; they do not prove an external effect by themselves.

The implementation assessment must first locate the current owner of each contract. Existing implementations are retained where their semantics fit and their evidence is convincing.

## 11. UX and proposed APIs

Human controls render the canonical authority and plan that enforcement consumes. They show principal and instance identity, delegation ancestry, actual account/resource, onward delegation, recipients, expiry, budgets, approval mode, and revocation consequences. The interface distinguishes authorization, admission, release, acknowledgement, provider entry, observation, and unknown outcome.

```text
+----------------------------------------------------------------+
| Engagement: prepare and publish the approved project update      |
| Initiator: scheduled service  | Acting instance: agent B         |
| Authority: organization -> service -> agent A -> agent B         |
| Read: selected fields -> B only | Write: one exact update        |
| Shared remaining budget: ...   | Expires: ...                    |
| Proposed change: ...           | Required human approval: ...   |
| [Inspect authority] [Approve exact change] [Revoke future use]    |
| Timeline: admitted / released / acknowledged / entered / unknown |
+----------------------------------------------------------------+
```

Conceptual operations are `establish_identity`, `delegate`, `propose`, `approve`, `admit`, `execute`, `inspect`, `reconcile`, and `revoke`. Names are placeholders, not new public ABI commitments. Each privileged operation authenticates its own caller and checks its own authority. Receipt identifiers and engagement identifiers are not bearer credentials.

Public SDKs guide callers through typed stages. Native Rust owns security semantics. Python, TypeScript/WASM, and other bindings use bounded decoding, stable results, and the same canonical corpus. Diagnostic previews never produce an executable permit. An agent receiving work applies the same resource-side acceptance contract as any other service.

## 12. Package ownership and assurance

Keep the current five shipping layers. The conceptual component names in this proposal do not authorize new top-level directories or one crate per noun.

| Existing layer | Proposed responsibility |
| --- | --- |
| `core/` | Canonical model, identity-control verification, attenuation/composition, deterministic verification, portable evidence contracts, formal linkage. |
| `exchange/` | Bounded transport and authenticated delivery of protocol objects without authority amplification. |
| `product/` | Identity lifecycle services, issuance, policy/evidence acquisition, live admission, custody, enforcement, durable recovery, private evidence, operator controls. |
| `bindings/` | Thin ABI/language surfaces over authoritative implementations. |
| `demos/` | Complete representative flows, independent observers, hostile deployment scenarios. |

Formal targets include narrowing, explicit composition, budget conservation, entry/revocation ordering, replay, uncertain outcomes, and exact request derivation. A standalone Lean theorem is not a shipping-Rust proof. Claims require representation invariants and translation/refinement evidence following the existing formal program.

Every claim records its model, implementation boundary, trusted assumptions, canonical fixtures, hostile tests, and exact-revision CI evidence. Simulation proves only its modeled boundary. Live provider evidence and deployment-isolation evidence remain separate.

## 13. First complete implementation milestone

The representative flow is **machine → agent A → agent B, with a human approving one consequential effect**. It exercises all three relationships without changing the authorization rules based on actor category.

1. An organization authorizes a scheduled service to initiate a bounded engagement.
2. The service grants A a finite resource set, expiry, recipient set, and shared budget.
3. A delegates a strict subset to a distinct B instance; siblings consume the same parent capacity or explicit disjoint allocations.
4. B reads an approved projection through credential-isolated enforcement into its designated channel.
5. B proposes one exact write; a separately authorized human approves that plan.
6. Enforcement admits and enters the write, recording the distinction between entry and observed effect.
7. A sibling races for final capacity, revocation races with admission, and the executor loses the response or crashes at defined boundaries.
8. The user sees a truthful timeline; reconciliation cannot cause a duplicate effect or cross-engagement disclosure.

Use an already admitted provider family for the first mediated execution. A test-controlled provider can force failures; a separately observed live or sandbox effect supplies provider evidence. A native resource implementation follows only after its ADR and qualification contract. Do not block the first slice on every identity system, provider, or federated deployment.

Acceptance scenarios below are required evidence, **all pending at spec creation**:

| ID | Scenario and required result |
| --- | --- |
| F01 | Holder/instance substitution or audience mismatch: refusal before custody or disclosure. |
| F02 | Widen any grant dimension, use an invalid parent, or exceed delegation depth: deterministic refusal. |
| F03 | Combine read/send authority from different engagements: refusal without release or send. |
| F04 | Concurrent siblings race for final capacity: total allocation and consumption stay within the parent limit. |
| F05 | Replay a signed invocation or copy its permit to another executor: no second unaccounted entry. |
| F06 | Change payload, recipient, resource, recipe, connection generation, or required configuration after approval: refusal. |
| F07 | Re-evaluate stale human evidence at a fresh time: it remains stale; invalid time evidence cannot authorize. |
| F08 | Lose read acknowledgement after release: retained accounting and no automatic redelivery. |
| F09 | Crash before durable claim, after claim, and after possible provider entry: outcomes follow the respective protocol; unknown does not permit blind retry. |
| F10 | Create succeeds but response is lost: zero/multiple/incomplete matches remain unresolved; a uniquely proven resource can be used only within its bound scope. |
| F11 | Revoke an ancestor while admission races: histories match the stated linearization rule; descendants cannot bypass it. |
| F12 | Rotate or recover an identity: compromised credentials and invalid descendants cannot regain authority through recovery. |
| F13 | Attempt credential, log, error, model-call, and alternate-egress exfiltration: the claimed deployment boundary is exercised and limitations recorded. |
| F14 | Rust and bindings process canonical, malformed, oversized, and boundary inputs: decisions, commitments, and error classes agree within bounded work. |
| F15 | Stale cache, store rollback, or restored old epoch: no resurrection of spent or revoked authority under the declared recovery model. |
| F16 | Receipts and UI distinguish entered, observed, denied, and unknown; no signature or successful HTTP response alone creates an unsupported success claim. |

Each scenario needs a reproducible setup, expected state and external effects, actual result, artifact/revision, and remaining assumptions. An existing test may satisfy a requirement only after its exact coverage is demonstrated.

## 14. Delivery sequence and decision gates

| Milestone | Deliverable | Exit condition |
| --- | --- | --- |
| M0: baseline and contracts | Source-backed retain/strengthen/replace/remove assessment; gap-to-F01–F16 mapping; decision records. | Each proposed replacement names a concrete contract failure or missing capability and why smaller changes are insufficient. |
| M1: authority slice | Concrete identity/engagement/delegation semantics and bounded fixtures for the representative flow. | Canonical forms, tightening/composition rules, limits, failure classes, and formal obligations are explicit. |
| M2: admission and disclosure | Shared-capacity and revocation contracts plus controlled read boundary. | Concurrency, replay, stale evidence, and acknowledgement-loss evidence passes on the exact revision. |
| M3: exact effect and recovery | Human approval, mediated write, crash recovery, independent observation. | Applicable F01–F16 evidence and truthful UI close the representative flow. |
| M4: broader enforcement | Native resource ADR, another trust domain, additional identity/provider conformance. | Claims remain scoped; new integration paths have their own isolation and recovery evidence. |

M0 begins with the companion assessment. Production redesign is not considered complete because this document exists. No mass deletion, package reshuffle, new token format, or universal state machine is a prerequisite for M0.

Resolve these decisions at the stated gates rather than guessing:

- **Before M1:** retain or change existing task/plan identity; authority composition semantics; first identity lifecycle profile; canonical format and finite protocol limits.
- **Before M2:** admission partition and transaction boundary; budget units/allocation model; revocation versus entry ordering; clock/freshness and persistence guarantees.
- **Before M3:** exact provider and isolation deployment; approval presentation; observation/reconciliation contract and permitted retries.
- **Before M4:** native execution ADR and assurance contract; federation lifecycle; escrow/offline support and explicit revocation limitations.

These are deferred engineering decisions with gates, not requests to pause documentation work or re-ask permission for the accepted mission.

## 15. Replacement and completion discipline

Retain working boundaries unless evidence supports replacement. Preserve adversarial scenarios, canonical intent, and provider assumptions even when implementation tests must change. Each replacement is a bounded direct cutover; remove its superseded production path and reject obsolete disposable state. Test-only references can remain independent oracles. No dual runtime, compatibility reader, or migration framework is required by this program.

Changes that admit new shared semantics require the existing comparison/case-file process or an explicit ADR. Changes to production enforcement require policy and compliance updates in the same bounded change. The future architecture diagram is not an exception to those requirements.

Use hosted CI under the repository's GitHub-first policy. Record exactly what ran; documentation review does not establish runtime or formal correctness. The worktree began with planning changes only; subsequent implementation, publication, and verification status are recorded in the companion assessment.

The program is successful when independently identified humans, machines, and agents can delegate bounded work through one understandable authority contract, while resource owners enforce each admission, disclosure, and effect with truthful evidence and explicit limitations.

## References

- [Nyxis handler model](https://github.com/NyxFoundation/nyxis/blob/785c11a628/Nyxis/Handler.lean), [proof boundary](https://github.com/NyxFoundation/nyxis/blob/785c11a628/ASSUMPTIONS.md), and [outbox semantics](https://github.com/NyxFoundation/nyxis/blob/785c11a628/Nyxis/Internal/Outbox.lean): design comparisons, not imported security guarantees.
- [SPIFFE concepts](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/): workload identity, trust domains, and identity evidence.
- [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396.html): structured OAuth authorization details.
- [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html): sender-constrained OAuth tokens and replay considerations; not a complete exact-effect authorization protocol.

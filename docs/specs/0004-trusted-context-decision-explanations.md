# AP-SPEC-004: Trusted-Context Decision Explanations

**Status:** Proposed
**Intended audience:** deployment operators, security reviewers, incident
responders, SDK authors, and application-profile integrators
**Normative language:** the terms **MUST**, **MUST NOT**, **SHOULD**, and
**MAY** define requirements on explanation generation and disclosure
**Scope:** deterministic, bounded explanations of which proof, registry, and
verifier-trusted context facts supported, contradicted, or left an Auths-Proof
authorization decision indeterminate

## Abstract

Auths-Proof currently returns a stable decision, stage, code, digests,
authorized branches, assurance records, resource totals, and configuration
commitments. These values are sufficient for interoperable enforcement but not
for an operator answering:

- Which trust anchor was considered?
- Which context requirement rejected this branch?
- Was status missing, stale, revoked, or issued by the wrong authority?
- Did assurance fail for the root, an intermediate, or the actor?
- Did the proof authorize fewer branches, actors, or roots than local policy
  required?
- Did the engine execute the configuration committed by the context?

This specification adds an optional diagnostic path that records decisions
inside the same verifier and adapter execution that produced the verdict. It
then derives a bounded causal explanation suitable for a CLI, JSON API, audit
attachment, or deployment readiness report.

The explanation is not a new authorization result, is not proof-carried, and
cannot create a `VerifiedAction`. It is cryptographically bound to the existing
portable result and context digests so it cannot be mistaken for another
decision.

## 1. Existing surfaces

| Concern | Current source |
| --- | --- |
| Portable decision and resource record | [`core/crates/auths-model/src/lib.rs`](../../core/crates/auths-model/src/lib.rs), `PortableVerificationResult` |
| Three-way native outcome and sealed action | [`core/crates/auths-verifier/src/lib.rs`](../../core/crates/auths-verifier/src/lib.rs), `VerificationOutcome` and `VerifiedAction` |
| Staged verifier | [`core/crates/auths-verifier/src/lib.rs`](../../core/crates/auths-verifier/src/lib.rs) |
| Principal-method inputs and control facts | [`core/crates/auths-ports/src/lib.rs`](../../core/crates/auths-ports/src/lib.rs), `PrincipalControlInput` and `ControlEvidence` |
| Verifier context | [`core/crates/auths-model/src/lib.rs`](../../core/crates/auths-model/src/lib.rs), `VerifierContext` |
| Assurance satisfaction evidence | [`core/crates/auths-model/src/lib.rs`](../../core/crates/auths-model/src/lib.rs), `AssuranceSatisfaction` |
| SDK’s current coarse explanation | [`product/sdk/auths-sdk/src/lib.rs`](../../product/sdk/auths-sdk/src/lib.rs), `Explanation` |
| Configuration/context startup binding | [`product/config/auths-config/src/lib.rs`](../../product/config/auths-config/src/lib.rs), `BoundConfiguration` |
| Readiness and privacy-preserving events | [`product/operations/auths-operations/src/lib.rs`](../../product/operations/auths-operations/src/lib.rs) |
| Decision and audit receipts | [`product/receipts/auths-receipts/src/lib.rs`](../../product/receipts/auths-receipts/src/lib.rs) |
| Existing human-facing demo projection | [`demos/live-lab/src/lib.rs`](../../demos/live-lab/src/lib.rs), `portable_projection` |

The current SDK deliberately returns only:

```rust
pub struct Explanation {
    code: &'static str,
    message: &'static str,
    retryable: bool,
}
```

That surface remains the safe default for ordinary applications. Detailed
explanations are an explicit operator capability with a disclosure policy.

## 2. Goals and non-goals

### 2.1 Goals

The implementation MUST:

- identify every verifier-trusted context fact consulted by the decision;
- distinguish satisfied, contradicted, unavailable, and unexamined facts;
- identify proof or executable-registry facts when they interact with context;
- show branch, participant-role, trust-root, and plan relationships;
- distinguish the decisive cause from non-decisive failures in alternative
  branches;
- preserve the exact portable decision and sealed-action boundary;
- generate the trace during the original verification path, not by guessing
  from the final code;
- remain deterministic, bounded, offline, and `no_std`-capable in core;
- support privacy-preserving operator and audit projections;
- bind every report to the proof, action, context, result, registry manifest,
  and verifier configuration.

### 2.2 Non-goals

The explanation system does not:

- decide authorization independently;
- recommend weakening policy;
- fetch missing facts;
- resolve DIDs, certificates, status, or registry entries;
- reveal private key material, raw signatures, HSM handles, credential IDs, or
  undisclosed action bodies;
- prove that a different context would authorize an action;
- make a denial retryable;
- replace signed decision or execution receipts.

## 3. Terminology

**Fact**
A bounded proposition evaluated by the verifier, such as “the action audience
equals the expected audience” or “this status statement is fresh at the
evaluation time.”

**Origin**
The immutable source of a fact: trusted context, proof object, executable
registry configuration, or derived verifier state.

**Fact result**
`Satisfied`, `Contradicted`, `Unavailable`, or `NotEvaluated`.

**Contribution**
The relationship between a fact and the final decision:

- `Decisive`: directly determines the selected final code;
- `NecessarySupport`: required for the successful path;
- `SufficientAlternative`: one of multiple successful alternatives;
- `ContributingBlocker`: blocks a branch but not necessarily the whole plan;
- `ContextConstraint`: a local policy floor applied after proof-carried
  composition;
- `Informational`: evaluated but not causal for this result.

**Causal slice**
The smallest deterministic subgraph of recorded evaluations needed to explain
the final result under target V1 evaluation rules. It is a syntactic
explanation of the executed verifier, not a philosophical or probabilistic
causal claim.

## 4. Architecture

### 4.1 Components

```text
+------------------------------- core --------------------------------+
|                                                                     |
|  verify / verify_portable                                           |
|          |                                                          |
|          v                                                          |
|  one internal staged evaluator -----> bounded VerificationTrace     |
|          |                                  |                       |
|          v                                  v                       |
|  VerificationOutcome              trace events + causal graph       |
|                                                                     |
|  principal adapters -----> ControlEvaluation ----^                  |
+---------------------------------------------------------------------+
                                  |
                                  v
+----------------------------- product -------------------------------+
| auths-operations                                                    |
|   ExplanationReport + redaction + text/JSON renderers               |
|                                  |                                  |
|                                  v                                  |
| product/tools/auths-explain CLI                                     |
+---------------------------------------------------------------------+
```

### 4.2 Repository layout

```text
core/crates/auths-ports/src/
├── lib.rs
└── diagnostics.rs

core/crates/auths-verifier/src/
├── lib.rs
├── trace.rs
└── causal.rs

product/operations/auths-operations/src/
├── lib.rs
├── explanation.rs
└── render/
    ├── mod.rs
    ├── text.rs
    └── json.rs

product/tools/auths-explain/
├── Cargo.toml
└── src/main.rs
```

The trace and causal-slice model lives in core because only the verifier knows
which checks actually ran and how branches composed. Rendering, configuration
loading, filesystem access, terminal output, and disclosure policy live in
product tooling.

The new product package MUST be classified in
[`architecture.toml`](../../architecture.toml). No reverse dependency is
introduced.

## 5. Core trace model

### 5.1 Stable fact identifiers

Fact identifiers are closed target V1 enum values, not free-form strings:

```rust
pub enum FactKind {
    ContextConfigurationMatches,
    RegistryManifestAccepted,
    ExpectedPlanMatches,
    TrustAnchorAcceptedMethod,
    TrustAnchorProfile,
    TrustAnchorPermission,
    TrustAnchorResourceNamespace,
    GrantLinkage,
    GrantDepth,
    GrantPermissionAttenuation,
    GrantValidityAttenuation,
    GrantAudienceAttenuation,
    GrantBodyAttenuation,
    GrantBudgetAttenuation,
    GrantStatusAttenuation,
    GrantAssurancePolicy,
    ActionActor,
    ActionTerminalGrant,
    ActionProfile,
    ActionPermission,
    ActionValidity,
    ActionAudience,
    ActionChallenge,
    ActionBodyDigest,
    ActionBudget,
    ChannelBinding,
    PrincipalControl,
    PrincipalStatus,
    GrantStatus,
    AssuranceRequirement,
    ResourceNamespace,
    ProfilePolicy,
    CriticalExtension,
    Attachment,
    PlanNode,
    MinimumAuthorizedBranches,
    MinimumDistinctActors,
    MinimumDistinctRoots,
    WorkReservation,
}
```

Adding a variant requires a trace schema version review and exhaustive renderer
updates.

### 5.2 Origins and locators

```rust
pub enum FactOrigin {
    TrustedContext(ContextLocator),
    Proof(ProofLocator),
    ExecutableRegistry {
        registry_id: RegistryEntryId,
        configuration: AdapterConfigurationId,
    },
    Derived(DerivedLocator),
}

pub enum ContextLocator {
    Configuration,
    Composition,
    TrustAnchor { index: u16, id: TrustAnchorId },
    ExpectedAudience,
    ExpectedChallenge,
    EvaluationTime,
    AssurancePolicy { requirement: Option<u16> },
    PrincipalStatus { statement: Option<PrincipalStatusId> },
    GrantStatus { statement: Option<GrantStatusId> },
    ResourceMatcher,
    ProfilePolicy,
    ChannelPolicy,
    Limit { kind: LimitKind },
}
```

Locators identify canonical fields without retaining references to secret or
mutable application objects.

### 5.3 Values

Raw values are not stored by default. The trace stores typed summaries:

```rust
pub enum FactValue {
    Present(bool),
    Equal(bool),
    Contains(bool),
    Count { actual: u64, required: u64 },
    TimeRelation(TimeRelation),
    Digest(Digest),
    Identifier(BoundedIdentifier),
    Decision(VerificationCode),
    Redacted,
}
```

Challenges, action bodies, evidence payloads, signatures, keys, credential IDs,
certificate bytes, HSM handles, and local record bodies MUST be represented by
digests or `Redacted`.

### 5.4 Events

```rust
pub struct FactEvaluation {
    pub sequence: u32,
    pub stage: VerificationStage,
    pub branch: Option<ProofRef>,
    pub participant: Option<PrincipalId>,
    pub role: Option<ParticipantRole>,
    pub kind: FactKind,
    pub origin: FactOrigin,
    pub value: FactValue,
    pub result: FactResult,
    pub code: Option<VerificationCode>,
    pub parents: BoundedVec<FactNodeId>,
}

pub struct VerificationTrace {
    pub schema: TraceSchema,
    pub events: BoundedVec<FactEvaluation>,
    pub final_node: FactNodeId,
    pub truncated: bool,
}
```

`truncated` MUST never be true for a valid trace produced under the same
`VerifierLimits`; capacity is reserved before verification. If trace capacity
cannot be reserved, detailed explanation returns an operational error and the
ordinary verifier remains available.

When verification finalizes before a context field could be consulted, the
report builder adds an inventory node with `NotEvaluated`. It MUST NOT imply
that an unexamined field was satisfied merely because an earlier check already
determined the result.

### 5.5 Bounds

The maximum event count is computed before evaluation:

```text
base events
+ plan nodes × PLAN_EVENTS
+ grant edges × GRANT_EVENTS
+ principals × CONTROL_EVENTS
+ assurance requirements × ASSURANCE_EVENTS
+ status statements × STATUS_EVENTS
+ attachments × ATTACHMENT_EVENTS
+ registry entries × REGISTRY_EVENTS
```

Every multiplier is a protocol implementation constant with checked
arithmetic. The result MUST be below a hard diagnostic maximum.

Diagnostic memory is not charged as protocol work because explanations are an
optional local tool, but the tool MUST report trace bytes and refuse inputs
above its configured diagnostic limit.

## 6. One execution path

### 6.1 Internal evaluator

There MUST NOT be a “normal verifier” and a separately implemented “explain
verifier.” Both public APIs call one internal evaluator:

```rust
pub fn verify(
    proof: &[u8],
    action: &CanonicalAction,
    context: &VerifierContext,
    registries: &ImmutableRegistries<'_>,
) -> VerificationOutcome {
    verify_internal(proof, action, context, registries, TraceMode::Discard)
        .outcome
}

pub fn verify_explained(
    proof: &[u8],
    action: &CanonicalAction,
    context: &VerifierContext,
    registries: &ImmutableRegistries<'_>,
) -> Result<ExplainedVerification, TraceError> {
    verify_internal(proof, action, context, registries, TraceMode::Collect)
        .into_explained()
}
```

Trace recording is internal and infallible after reservation. User callbacks
MUST NOT execute inside the verifier.

### 6.2 Semantic equivalence invariant

For every input:

```rust
let ordinary = verify(proof, action, context, registries);
let explained = verify_explained(proof, action, context, registries)?;

assert_eq!(
    project_outcome(&ordinary),
    project_outcome(explained.outcome())
);
```

For authorization, both paths MUST expose byte-identical sealed canonical
action bytes and the same authority metadata.

The portable result encoding remains unchanged. Explanation is a local
versioned artifact, not a V1 wire-format extension.

## 7. Adapter diagnostics

### 7.1 Problem

The verifier can observe `PrincipalControlError`, but configured adapters often
know the more useful fact: which local credential, checkpoint, trust interval,
device record, or trust-domain policy was consulted. Reconstructing that fact
after failure would duplicate adapter semantics.

### 7.2 Unified adapter evaluation

`PrincipalMethod` is extended around one required evaluation method:

```rust
pub struct ControlEvaluation {
    result: Result<ControlEvidence, PrincipalControlError>,
    diagnostics: BoundedVec<ControlFact>,
}

pub trait PrincipalMethod {
    fn id(&self) -> &PrincipalMethodId;
    fn configuration_id(&self) -> AdapterConfigurationId;
    fn maximum_work_units(&self) -> u64;

    fn evaluate_control(
        &self,
        input: PrincipalControlInput<'_>,
        diagnostics: DiagnosticMode,
    ) -> ControlEvaluation;

    fn verify_control(
        &self,
        input: PrincipalControlInput<'_>,
    ) -> Result<ControlEvidence, PrincipalControlError> {
        self.evaluate_control(input, DiagnosticMode::Discard).into_result()
    }
}
```

Built-in adapters MUST derive success, failure, and diagnostic facts from the
same internal parse/evaluate result. A diagnostic method MUST NOT reparse or
re-verify evidence after the outcome is known.

### 7.3 Adapter fact examples

| Adapter | Required local diagnostic facts |
| --- | --- |
| Raw key | descriptor key type, self-certifying principal match, suite match |
| `did:key` | Multikey codec, derived principal, exact method, suite match |
| `did:keri` | terminal sequence/SAID, threshold, selected key index, checkpoint coverage |
| Bundled `did:web` | selected trust interval digest, asserted-time coverage, statement-existence pin |
| WebAuthn | selected credential-record digest, RP-ID hash, origin, flags, counter policy, validity |
| HSM | selected reviewed-record digest, transaction binding, protection level, non-exportability, validity |
| SPIFFE X.509 | selected trust-domain configuration, URI SAN, EKU, path, validity, optional status |

Local record bodies are represented by configuration-bound digests. Operators
may correlate those digests with their deployment inventory without placing
the inventory in the explanation.

## 8. Causal-slice rules

### 8.1 Pre-composition failure

If decode, resolution, configuration, or principal control finalizes the
result, the decisive event is the first protocol-ordered event that emitted the
final code. Its ancestors include only facts required to reach that check.

### 8.2 `all-of`

- Authorized: every child’s necessary-support slice is included.
- Denied: every denied child is a `ContributingBlocker`; the child whose stable
  code wins canonical selection is `Decisive`.
- Indeterminate: no child is denied; every indeterminate child contributes,
  and the canonical requirement is `Decisive`.

### 8.3 `any-of`

- Authorized: every authorized child is a `SufficientAlternative`; failed
  children are informational.
- Denied: every child is denied; the canonical denial is decisive.
- Indeterminate: no child authorizes and at least one is indeterminate; the
  canonical indeterminate requirement is decisive, while denied children are
  contributing blockers.

### 8.4 `k-of-n`

- Authorized: all authorized children are shown; the report states that any
  canonical subset of size \(k\) is sufficient and does not claim one unique
  cause.
- Denied: `authorized + indeterminate < k`; the count fact and canonical denial
  are decisive.
- Indeterminate: `authorized < k` and `authorized + indeterminate >= k`; the
  count fact and canonical missing requirement are decisive.

### 8.5 Verifier-local composition requirements

The proof-carried plan result and each local floor are separate nodes:

```text
plan authorized
  ├── authorized branches = 2; required >= 3        [CONTRADICTED]
  ├── distinct actors = 2; required >= 2            [SATISFIED]
  └── distinct roots = 1; required >= 2             [CONTRADICTED]
```

The final code is `composition-requirement-not-met`. The tool MUST show every
failed local floor, even though the portable result has one code.

## 9. Explanation report

### 9.1 Model

```rust
pub struct ExplanationReport {
    pub schema: ExplanationSchema,
    pub decision: VerificationDecision,
    pub code: VerificationCode,
    pub stage: VerificationStage,
    pub proof_digest: Digest,
    pub action_digest: Digest,
    pub context_digest: ContextDigest,
    pub result_digest: VerificationResultDigest,
    pub registry_manifest: RegistryManifestId,
    pub required_configuration: Option<VerifierConfigurationId>,
    pub local_configuration: VerifierConfigurationId,
    pub summary: BoundedString,
    pub causal_nodes: Vec<ExplainedFact>,
    pub branch_summaries: Vec<BranchExplanation>,
    pub remediation: Vec<RemediationHint>,
    pub disclosure: DisclosureLevel,
}
```

`remediation` is emitted only for indeterminate requirements and operational
configuration mismatch. Hints are descriptive:

```text
provide a trusted principal-status snapshot fresh at evaluation time
install the exact principal method named by the trusted context
load the verifier configuration committed by the context
```

The tool MUST NOT suggest removing assurance, status, composition, audience,
challenge, or resource requirements.

### 9.2 Disclosure levels

| Level | Intended use | Values |
| --- | --- | --- |
| `summary` | application response/log | decision, stage, code, retryability |
| `operator` | local deployment diagnosis | IDs, roles, counts, timestamps, digests; no raw proof/context values |
| `audit` | controlled offline review | canonical non-secret context values and object identifiers; still no keys, signatures, credential IDs, evidence payloads, or action bodies |

`summary` remains the default. `audit` requires an explicit command-line flag
and writes only to a caller-selected file; it is not printed to a shared
terminal by default.

### 9.3 Binding

The explanation identifier is:

```text
SHA-256(
  "AUTHS-EXPLANATION\0\1" ||
  result_digest ||
  context_digest ||
  registry_manifest ||
  local_configuration ||
  disclosure_level ||
  canonical_explanation_body
)
```

An explanation MAY be included as a disclosed artifact in an
`auths-receipts::AuditBundle`. It does not alter the decision receipt and MUST
be labeled with a distinct media type:

```text
application/vnd.auths.explanation.v1+cbor
```

## 10. CLI UX

### 10.1 Command

```text
auths explain \
  --proof request.proof.cbor \
  --action request.action.cbor \
  --context verifier.context.cbor \
  --engine-config deployment.adapter-context.json \
  --disclosure operator \
  --format text
```

The CLI performs no acquisition. All four inputs are explicit files.

### 10.2 Authorized output

```text
AUTHS DECISION  AUTHORIZED
Result          sha256:6f…
Context         sha256:91…
Configuration   required 33… · executed 33… · MATCH

Why this authorized
  ✓ Plan 2-of-3 authorized 2 branches
  ✓ Local minimum authorized branches: 2 ≥ 2
  ✓ Local distinct actors: 2 ≥ 2
  ✓ Local distinct roots: 2 ≥ 2

  Branch 4a…  actor did:key:…  root key:sha256:…
    ✓ trusted root accepted did-key-v1
    ✓ permission auths.mcp.tools.call present
    ✓ audience auths://service exact
    ✓ actor assurance user-verified satisfied by evidence 9c…

  Branch b7…  actor spiffe://example.org/worker
    ✓ trust domain configuration 18…
    ✓ X.509 path, URI SAN, EKU, validity, and status satisfied
```

### 10.3 Denied output

```text
AUTHS DECISION  DENIED · audience-mismatch
Stage           authority

Decisive fact
  ✗ Action audience does not equal verifier-trusted expected audience
    expected digest  7e…
    actual digest    a1…
    source           context.expected_audience

Satisfied before denial
  ✓ verifier configuration matched
  ✓ registry manifest matched
  ✓ principal control and signature succeeded

This is a stable denial. Fetching additional evidence will not change it.
```

### 10.4 Indeterminate output

```text
AUTHS DECISION  INDETERMINATE · stale-status
Stage           authority

Unavailable requirement
  ? Principal status observation is older than local policy permits
    participant       intermediate[1]
    evaluation time   2026-07-27T10:00:00Z
    observed at       2026-07-27T09:54:30Z
    maximum age       300 s
    source            context.principal_status_snapshot

Possible remediation
  Supply a trusted status snapshot fresh at the same evaluation boundary.
```

### 10.5 Exit codes

| Exit | Meaning |
| --- | --- |
| `0` | authorized and explanation generated |
| `2` | denied and explanation generated |
| `3` | indeterminate and explanation generated |
| `4` | explanation input/configuration/tooling failure |

The CLI MUST NOT use the same exit code for a protocol denial and a malformed
operator invocation.

## 11. JSON API

The product API is:

```rust
pub fn explain(
    verification: &ExplainedPortableVerification,
    disclosure: DisclosurePolicy,
) -> Result<ExplanationReport, ExplanationError>;

pub fn encode_explanation(
    report: &ExplanationReport,
) -> Result<Vec<u8>, ExplanationError>;

pub fn render_text(
    report: &ExplanationReport,
    width: TerminalWidth,
) -> Result<String, ExplanationError>;
```

Canonical JSON projection uses stable kebab-case identifiers. Human messages
are non-normative and may improve without changing codes; fact kinds, origins,
results, contributions, and graph edges are normative within an explanation
schema version.

Example projection:

```json
{
  "schema": "auths-proof-explanation/v1",
  "decision": "denied",
  "stage": "authority",
  "code": "audience-mismatch",
  "bindings": {
    "proof": "sha256:…",
    "action": "sha256:…",
    "context": "sha256:…",
    "result": "sha256:…"
  },
  "facts": [
    {
      "id": 17,
      "kind": "action-audience",
      "origin": "trusted-context/expected-audience",
      "result": "contradicted",
      "contribution": "decisive",
      "expected_digest": "sha256:…",
      "actual_digest": "sha256:…"
    }
  ]
}
```

## 12. Deployment integrations

### 12.1 Readiness

[`auths-operations::ReadinessReport`](../../product/operations/auths-operations/src/lib.rs)
is extended with an optional configuration-difference report when required and
executed configuration IDs differ. It lists registry category and adapter
configuration IDs, not secret records.

### 12.2 SDK

The current coarse `auths_sdk::Explanation` remains unchanged. An explicit
operator API is added:

```rust
pub fn verify_explained<P: ActionProfile>(
    &self,
    proof: &[u8],
    action: &CanonicalAction,
    request: &RequestContext,
    profile: &P,
    disclosure: DisclosurePolicy,
) -> Result<ExplainedVerifyResult<P::Command>, SdkError>;
```

Application code cannot turn `ExplainedVerifyResult::Denied` into an
`Authorized` value. Only the verifier’s sealed output constructs the authorized
variant.

### 12.3 Receipts

Decision receipts continue to bind the portable result. An explanation may be
stored as an optional audit disclosure whose digest is referenced by deployment
metadata. Operators MUST be able to discard explanations without invalidating
the underlying decision receipt.

## 13. Determinism and cross-language behavior

For the same proof, action, context, executable registry configuration,
disclosure policy, and explanation schema:

- the fact graph MUST have the same node identities and edges;
- fact ordering MUST be canonical;
- the causal slice MUST be identical;
- canonical CBOR explanation bytes MUST be identical.

Human text rendering need not be byte-identical across languages.

The independent Go and TypeScript verifiers MAY initially expose summary
explanations only. They MUST NOT claim detailed-explanation conformance until
they emit the same canonical fact graph over the shared explanation corpus.

## 14. Testing strategy

### 14.1 Equivalence

Every canonical V1 fixture runs through both paths:

```rust
for fixture in target_v1_corpus() {
    let ordinary = verify_portable(fixture.inputs());
    let explained = verify_portable_explained(fixture.inputs())?;

    assert_eq!(ordinary, explained.result);
    assert_eq!(
        explained.report.bindings().result_digest(),
        ordinary.result_digest()
    );
}
```

### 14.2 Completeness

The explanation corpus MUST include at least one decisive event for every
stable `DenialReason` and `Requirement`. Authorized fixtures MUST account for:

- selected trust anchor;
- every grant attenuation dimension;
- terminal action coverage;
- every required assurance fact;
- relevant status facts;
- plan composition;
- all verifier-local composition floors;
- configuration and registry commitments.

### 14.3 Privacy

Automated tests scan summary and operator projections for:

- raw proof bytes;
- action body bytes;
- signature bytes;
- public-key bytes;
- WebAuthn credential IDs;
- HSM handles;
- certificate DER;
- raw adapter trust records.

Synthetic canary values inserted into those fields MUST never appear in
rendered output.

### 14.4 Causal correctness

Mutation tests change one trusted-context field at a time and assert that:

- the expected fact node changes;
- unrelated fact nodes remain stable;
- final decision equivalence with the ordinary verifier holds;
- the decisive node carries the actual final code;
- alternative-branch failures are not mislabeled decisive.

### 14.5 Bounds and totality

Property and fuzz tests cover:

- maximum plan shape;
- maximum grants, evidence, status records, and attachments;
- graph edge validation;
- renderer widths from 40 to 240 columns;
- canonical codec round trips;
- malformed trace input;
- no panic for arbitrary explanation bytes.

## 15. Security requirements

- Detailed explanation generation is disabled unless explicitly requested.
- Production network responses SHOULD use `summary` disclosure.
- `operator` and `audit` reports SHOULD remain local or encrypted.
- Explanation data is subject to the same retention policy as authorization
  logs and may be more sensitive than a decision receipt.
- Report digests MUST be checked before correlating an explanation with a
  receipt.
- Renderers MUST escape terminal control characters and JSON/HTML content.
- A renderer failure MUST NOT change or retry verification.
- Explanation generation MUST NOT trigger network, storage, or custody effects.
- Remediation hints MUST never propose weakening a trust anchor or local
  policy.
- A report MUST label facts originating in proof bytes separately from facts
  trusted by the verifier.

## 16. Acceptance criteria

The tooling is complete when:

1. ordinary and explained verification produce identical outcomes for the
   complete V1 corpus;
2. authorization exposes the same sealed canonical action;
3. every stable denial and requirement code has an explanation fixture;
4. every `VerifierContext` field has at least one satisfied and one
   contradicted/unavailable trace case where applicable;
5. all seven adapters emit configuration-bound diagnostic facts;
6. plan causal slices pass `all-of`, `any-of`, and `k-of-n` truth-table tests;
7. operator output contains no privacy canaries;
8. explanation encoding is deterministic and bounded;
9. CLI exit codes distinguish protocol outcomes from tooling failures;
10. an explanation can be discarded without changing or invalidating the
    portable result or decision receipt.

## 17. Publication artifact

```text
auths-proof-explanations-v1/
├── EXPLANATION-MODEL.md
├── schema.cddl
├── fact-inventory.json
├── fixtures/
│   ├── authorized/
│   ├── denied/
│   └── indeterminate/
├── privacy-canary-results.json
├── cross-language-status.json
└── SHA256SUMS
```

The publication MUST state that an explanation is a diagnostic projection of a
specific verifier execution. It is neither an authorization credential nor a
counterfactual guarantee that changing one displayed fact would produce
authorization.

# AP-SPEC-060: Evidence-conditioned authority

- **Status:** Epic steps 1–4 implemented: kernel, fixtures, and bindings in
  #133, and the gateway observer. The client observation requests are in
  #134. Step 5 (live) is open. §17 (per-extension attenuation) is
  implemented on `epic-5-policy` (AP-SPEC-057 Epic 5, step 1) for the
  `exact-marker-v1` and `observation-requirement-v1` laws, with the
  readings in §18; the `bounded-policy-commitment-v1` law is implemented
  with AP-SPEC-025 §24 on `epic-5-bounds` (Epic 5, step 2), readings in
  AP-SPEC-025 §25. §15 (SDK attachment, the Rust–Lean link) and §16 (the
  observer quorum) are specified and not implemented. §16 is a wire
  change.
- **Depends on:** [AP-SPEC-011](0011-rich-authority-refinement-and-bounded-authorization.md)
  (rich authority model and Rust–Lean link),
  [AP-SPEC-059](0059-commitment-bound-provider-evidence.md) (the outcomes the
  first observer signs), `core/spec/v1/registry.md`
- **Relates to:** [AP-SPEC-025](0025-closed-bounded-authorization-policy.md).
  The boundary between them is drawn in §6.
- **Scope:** a grant may require that **fresh observations, signed by trusted
  observers, satisfy a closed set of typed conditions** before the verifier
  authorizes an action. Two uses motivate it:
  - make "the record still holds the expected value before it is replaced"
    part of verification;
  - authorize step N only if step N−1's outcome was observed.
- **Normative language:** **MUST**, **MUST NOT**, **SHOULD**, and **MAY** specify
  implementation requirements

## 1. Decision and claim

Today a grant bounds **what** may be done: profile, permission, resource,
audience, validity, body digests, and budget. It cannot bound **the state of
the world in which** it may be done. An Airtable update action carries both an
`expected` and a `replacement` value, but no verifier checks `expected` against
anything. Checking it is the application's job, and the application can skip
it.

This spec adds an **observation requirement** to grants. A requirement names a
trusted observer, the subject being observed, a maximum age, and a conjunction
of closed, typed conditions over the observed facts. The actor attaches signed
observations to the action. The verifier authorizes only if every requirement
in the chain is met by an attached observation that is authentic, about the
right subject, fresh at the verifier's evaluation time, and satisfies every
condition.

**Claim, once implemented.** `VerifiedAction` implies that, for every
observation requirement in the grant chain, an observer trusted for that
subject signed facts that satisfied the requirement's conditions at a time no
earlier than `evaluation_time − max_age`.

**Not a claim.**

- **The fact still held at execution.** Between observation and write, the
  world can change. Closing that window needs a conditional provider write,
  which is profile-owned. The spec narrows the window; it does not remove it.
- **The observer told the truth.** Observers are trusted inputs, like status
  issuers. A lying observer is a trust failure, not a verifier failure.
- **Missing observations mean anything.** A missing observation is
  `indeterminate`, never a false condition.

This remains inside the existing security invariant: "Authority may be
preserved or narrowed through delegation; it must never be amplified." A
requirement only removes actions from the authorized set (§4.3).

## 2. Why this is not a policy language

Conditions are a closed set of atoms joined only by AND. There is no OR, NOT,
arithmetic, string operation, pattern, quantifier, variable, or user-defined
function. That is what makes the attenuation law in §4.3 a one-line theorem,
and it is what keeps 060 out of AP-SPEC-025's territory. A need that these
atoms cannot express is either a new atom, which requires a protocol review
and a new manifest, or a product-layer evaluator under 0025.

## 3. Wire objects

### 3.1 Observation statement

```text
ObservationStatement = {
  version:      1,
  observer:     PrincipalId,          ; signer
  schema:       ObservationSchemaId,  ; e.g. "auths.gateway-outcome/1"
  subject:      ResourceId,           ; what was observed
  observed_at:  Timestamp,
  facts:        { 1*16 FactName => FactValue },
}
FactValue = uint64 | bytes .size (0..64) | text .size (0..256)
SignedObservation = signed ObservationStatement under the observer's
                    principal method and a registered signature suite,
                    with its own domain separator
                    "auths.observation-statement/1"
```

Observations travel as **detached attachments** of the canonical action. The
action statement's signed `attachments` descriptors bind their digests
(`core/crates/auths-model/src/lib.rs:1439`), and the verifier already checks
detached bytes against those digests
(`core/crates/auths-verifier/src/lib.rs:2074`). No new `verify_v1` input is
needed. The actor cannot swap an observation after signing. The actor can
choose which valid observations to attach; freshness and subject binding
(§4.1) are what make that choice harmless.

### 3.2 Observation requirement (grant critical extension)

The extension is registered as `observation-requirement-v1`:

```text
ObservationRequirement = {
  observer_anchor: ObserverAnchorId,
  schema:          ObservationSchemaId,
  subject:         ResourceId / ActionFactRef,
  max_age_seconds: 1..86400,
  conditions:      [ 1*16 Condition ],
}
Condition = eq-literal(FactName, FactValue)
          / eq-action(FactName, ActionFactRef)
          / uint-range(FactName, lo: uint64, hi: uint64)   ; lo <= hi
          / member(FactName, [ 1*16 FactValue ])
ObservationRequirements = [ 1*8 ObservationRequirement ]
```

Because it is a critical extension, verifiers without the handler deny it
under the existing unknown-critical-extension rule. Old verifiers fail
closed.

### 3.3 Observer anchor (trusted-context field)

```text
ObserverAnchor = {
  id:                 ObserverAnchorId,
  principal:          PrincipalId,
  accepted_methods:   [ PrincipalMethodId ],
  schemas:            [ ObservationSchemaId ],
  subject_namespaces: [ ResourceId ],        ; uri-namespace-v1 matching
  validity:           ValidityWindow,
}
TrustedContext.observer_anchors: [ 0*32 ObserverAnchor ]
```

Observer anchors are **separate from** `TrustAnchor`. An observer can make
facts count; it cannot authorize an action, issue a grant, or appear in an
authority chain. The verifier MUST reject a principal that acts as both an
authority and an observer in one proof with
`observation.observer-in-authority-chain`. Without this rule, an agent could
observe for itself.

### 3.4 Action facts

`eq-action` and an `ActionFactRef` subject need values from the action body.
The kernel treats bodies as opaque (`CanonicalAction` doc), so the profile
provides them. The `ProfilePolicy` port
(`core/crates/auths-ports/src/lib.rs:326`) gains one pure method:

```rust
fn action_fact(&self, action: &CanonicalAction, name: &FactName)
    -> Result<Option<FactValue>, RegistryOperationError>;
```

The method is pure, bounded, and covered by the profile policy's existing
configuration commitment. A name the profile does not define returns `None`,
and the requirement is then `indeterminate`
(`observation.action-fact-unavailable`). `exact-v1` defines no facts.
Profiles that want observation-conditioned grants register a new policy ID
that defines them, such as `mcp-arguments-v1`, which exposes top-level
verified MCP arguments by name.

## 4. Verifier semantics

### 4.1 New stage

The stage runs after `VerifiedAuthority` and before `VerifiedAction`. Each
requirement from every grant in the chain is checked independently:

1. Find attached observations whose `schema` equals the requirement's and
   whose observer is the principal of `observer_anchor`. Verify each
   signature with the anchor's accepted methods. An invalid signature makes
   that observation **ignored**, not the whole proof denied, so one bad
   attachment cannot block a good one. The count is still reported.
2. Resolve the subject (a literal, or through `action_fact`). It must equal
   the observation's `subject` exactly and lie inside one of the anchor's
   `subject_namespaces`.
3. Freshness: `observed_at <= evaluation_time` and
   `evaluation_time − observed_at <= max_age_seconds`. Anchor validity must
   contain `observed_at`. A future-dated observation is ignored.
4. Evaluate every condition against the observation's facts. A missing fact
   name or a type mismatch makes the condition false.
5. The requirement is **satisfied** if some remaining observation makes every
   condition true.

Result:

| Situation | Result | Code |
| --- | --- | --- |
| Every requirement satisfied | continue | — |
| A requirement has a fresh, authentic, subject-matching observation, and every such observation makes some condition false | **denied** | `observation.condition-false` |
| A requirement has no fresh, authentic, subject-matching observation | **indeterminate** | `observation.missing` |
| Action fact unavailable | indeterminate | `observation.action-fact-unavailable` |
| Observer also in the authority chain | denied | `observation.observer-in-authority-chain` |
| Limit exceeded | denied | kernel limit codes |

`denied` wins over `indeterminate` when requirements disagree, matching the
existing combination rule. The result reports, for each requirement, the
observation digest that satisfied it. That makes the evidence the decision
used auditable.

### 4.2 Limits

At most 8 requirements per grant and 32 per chain. At most 16 conditions per
requirement. At most 32 observation attachments, each at most 4 KiB. Work is
reserved before evaluation, as for every registry handler.

### 4.3 Attenuation law

A child grant MUST contain every parent requirement, byte-identical, and MAY
add more. A child that drops or changes a parent requirement is denied as
amplification at chain validation (`authority.observation-requirement-dropped`).

Because conditions are conjunctions and requirements are conjunctions, the
set of actions a child authorizes is a subset of the parent's, for every
context and observation set. §7 makes this a Lean theorem.

## 5. The two motivating uses

**Expected before replacement (Airtable update).**

```text
requirement:
  observer_anchor: gateway-observer
  schema:          auths.gateway-readback/1
  subject:         action_fact("record_uri")
  max_age_seconds: 60
  conditions:      [ eq-action("field.Status", "expected") ]
```

The gateway reads the record, signs a read-back observation, and the agent
attaches it. The verifier authorizes the replacement only if the signed
current value equals the action's `expected` value, observed within the last
60 seconds.

**Chained step (step N after step N−1).**

```text
requirement:
  observer_anchor: gateway-observer
  schema:          auths.gateway-outcome/1
  subject:         action_fact("depends_on")        ; step N-1's commitment URI
  max_age_seconds: 3600
  conditions:      [ member("stage", ["observed-by-provider"]) ]
```

The gateway signs its AP-SPEC-059 outcomes as observations. Step N's grant
cannot be used until step N−1's effect is provider-bound.

Both uses need the gateway to hold an **observer signing key**. That is new
custody in the product layer, and it uses the existing custody ports.
Gateway-signed observations are inputs to grants, not the standalone
receipts that board §5 refuses.

## 6. Boundary with AP-SPEC-025

| | 060 | 025 |
| --- | --- | --- |
| Layer | core | product |
| Question | Were these signed facts true recently? | Does this action fit budgets, capacity, and domain rules given state? |
| Portable and offline | yes; in the proof | evaluator-specific |
| Language | 4 atoms, AND only | closed per-domain evaluators |
| Stateful | no | reservations, obligations |

A 025 domain evaluator MAY read observation facts that 060 already
verified. It MUST NOT re-verify observations itself.

## 7. Formal work

This is required before the manifest changes, per AGENTS.md and registry
rules:

- A Lean model of observation requirements with the theorem
  **`requirements_monotone`**: adding a requirement (or a condition) never
  enlarges the authorized set. Also `child_requirements_superset →
  authorized(child) ⊆ authorized(parent)`.
- The condition evaluator and freshness check are written as pure,
  bounded, extractable Rust predicates, and qualified through the existing
  Aeneas route (`formal/qualification/aeneas/qualification.toml`). They must
  be extractable from the first commit so AP-SPEC-061 can include them
  without refactoring.
- Observation signature verification stays in the existing codec and crypto
  trust boundary until AP-SPEC-061 moves it.

## 8. Wire-change obligations

Per AGENTS.md, one atomic change updates:

- the CDDL (`core/spec/v1/auths-proof.cddl`) and model types;
- the codec and domain separators;
- the registry (new critical extension, new profile policy IDs, and new
  manifest);
- the trusted context;
- canonical fixtures under `core/fixtures/v1` (via `cargo xtask wire
  --update`, reviewed);
- native tests, WASM, Python, TypeScript, and independent implementations;
- the compatibility evidence.

Under the prelaunch rule, the old manifest is rejected, not dual-read.

## 9. Epic and acceptance

1. **Formal first** (1 week). The Lean model and both theorems in §7 are
   added to the assurance manifest. Done: `cargo xtask formal` is green in
   hosted CI.
2. **Fixtures** (1 week). Positive and negative vectors for every row of the
   §4.1 table, every limit, dropped and altered parent requirements,
   observer-in-chain, future-dated, stale-by-one-second, and wrong-subject
   cases. Done: the vectors exist and fail.
3. **Core** (2–3 weeks). Model, codec, extension handler, verifier stage,
   port method, and the Aeneas-qualified predicates. Done: the corpus passes
   natively and in WASM, with identical codes in the Python and TypeScript
   bindings.
4. **Gateway observer** (1–2 weeks, after AP-SPEC-059 step 3). The observer
   key, signed read-back, and outcome observations. Done: a hosted test runs
   the two §5 uses end to end with the counting provider. A stale or changed
   `expected` is denied **before** credential access, and step N is
   indeterminate until step N−1 is provider-bound.
5. **Live** (board rule 9). The Airtable expected-before-replacement flow
   through the isolated gateway. Done: the ledger entry uses §1's claim and
   non-claim wording.

**Acceptance:** steps 1–5 on one exact revision, and the claim ledger updated.
The hostile suite gains two cases: a replaced-in-between record, and a
self-signed observation from the agent's own key. Each has zero unauthorized
provider entries.

## 10. Non-goals

- OR, NOT, arithmetic, strings, patterns, or any policy language (§2).
- Observers that fetch facts during verification. Verification stays
  offline; observations arrive as attachments.
- Guaranteeing facts at execution time (§1).
- Observation revocation. Short `max_age` is the control; an observer anchor
  is removed from the trusted context.
- Using observations to widen anything, including grant validity or budgets.

## 11. Readings this spec had to choose

| Sentence | Readings | Pick |
| --- | --- | --- |
| Board: "the verifier enforces" | (a) core verifier; (b) product evaluator | (a): the point is a portable, offline-checkable law. 025 keeps stateful rules. |
| Board: "equality, range, freshness" | (a) exactly those; (b) plus set membership | (b): `member` is needed for outcome stages and adds no expressiveness beyond a bounded OR of equalities on one fact. |
| Missing evidence | (a) denied; (b) indeterminate | (b): it follows the registry rule that an unavailable required input is indeterminate. |
| Can the critical-extension handler do this alone? | (a) yes; (b) no | (b): `CriticalExtensionHandler::evaluate` sees only the extension bytes (`core/crates/auths-ports/src/lib.rs:385`), so a verifier stage is required. |

## 12. Verification and release boundary

Hosted CI on the exact revision is the gate. This spec runs no checks. No
document may describe grants as conditioned on observed state before step 4
is green.

## 13. Readings fixed during implementation

Each reading below is the narrowest fail-closed design that keeps §1's claim.
The executable contract is `core/spec/v1/` and the canonical corpus.

| # | Spec text | Kernel fact | Reading fixed |
|---|---|---|---|
| 1 | §4.3: a child "MAY add more" requirements | *Superseded by §17.* The kernel's extension dimension was equality, so requirements were carried unchanged and an added requirement was `delegation-expanded`. | **Superseded by §17 and §18.** The kernel now judges each extension identifier by its handler's law: a child keeps every parent requirement byte-identical or strictly narrowed and may add requirements (vector `observation-requirement-added`). |
| 2 | §4.2: at most 32 requirements per chain | Since §17, each delegate may add up to eight requirements, so a chain of five grants can exceed 32. | The stage deduplicates requirements byte-exactly across the chain and enforces 32 with `resource-limit-exceeded`. A native test pins 32 accepted and 33 denied over five grants; the corpus shapes carry at most two grants, so the bound has no corpus vector. |
| 3 | Codes `observation.condition-false`, `observation.missing`, `observation.action-fact-unavailable`, `observation.observer-in-authority-chain`, `authority.observation-requirement-dropped` | Stable V1 codes are flat kebab-case strings without a namespace. | `observation-condition-false`, `observation-missing`, `observation-action-fact-unavailable`, `observer-in-authority-chain`, and `observation-requirement-dropped`. |
| 4 | §3.1: own domain separator `"auths.observation-statement/1"` | Every signed object uses the `AUTHS` preimage with a registered numeric object type. | Observations are signed under object type 9 with an empty profile ID and version zero; requirement content identifiers use identifier type 11. |
| 5 | §3.1: a signed observation is the statement plus a signature | Every registered principal method needs control evidence to establish the verification key. | `signed-observation` also carries at most four evidence objects, the observer's own control evidence. The method verifies with purpose assertion and must consume exactly that evidence. |
| 6 | §3.1: observations travel as detached attachments | Attachment descriptors carry no semantic type. | An attachment is an observation exactly when its signed descriptor carries the media type `application/vnd.auths.observation.v1+cbor`. The reported observation digest is that attachment's digest, already bound by the action signature. |
| 7 | §4.1: the stage runs "after `VerifiedAuthority` and before `VerifiedAction`" | Authority is established per authorization-plan branch and combined by the plan. | The stage runs at the end of each branch's authority, after its assurance, so a denied or indeterminate observation stage composes through `AllOf`, `AnyOf`, and `KOfN` like any other branch failure. |
| 8 | §4.1 step 1: an invalid signature makes the observation ignored; "the count is still reported" | — | Invalid signatures, unaccepted methods, and every other ineligibility make an observation ignored. Malformed observation bytes are `malformed-proof` and an over-bound observation is `resource-limit-exceeded`, because the actor signed those attachments. The ignored count is not in the portable result; the work total reflects the verification attempts. |
| 9 | §3.3: the observer-in-chain rule | — | A requirement's resolved observer principal must not equal the trust anchor, an issuer or subject of a chain grant, or the actor. The check runs before any observation is evaluated. A requirement naming an observer anchor the context lacks is `observation-missing`. |
| 10 | §3.2 value bounds | The critical-extension handler contract returns resource exhaustion or invalid input. | More than eight requirements, sixteen conditions, or sixteen membership values is `resource-limit-exceeded`. Any other invalid or non-canonical requirement bytes, including a maximum age outside `1..=86400` or `lo > hi`, is `local-policy-denied`, as for every handler. Fact bounds past 16 facts, 64 bytes, or 256 text bytes are `resource-limit-exceeded`. |
| 11 | §3.4: `ProfilePolicy` gains `action_fact` | Every existing profile policy predates it. | `action_fact` is a default method returning `Ok(None)`: an existing policy defines no facts, so a requirement that needs one fails closed as `observation-action-fact-unavailable`. An action-fact subject must be a text value that parses as a resource. `exact-v1` defines no facts, so the corpus shows action-fact requirements only as indeterminate; equal and changed `expected` values are proved by native tests with a fact-defining test policy. |
| 12 | §8: new manifest, trusted-context field, result reporting | — | The manifest is `34` repeated 32 times and the configuration commitment includes the new handler. The trusted context always carries key 14 (zero to 32 observer anchors, strictly ordered). The portable result is ABI 3 and always carries key 16, the sorted `(requirement ID, observation digest)` pairs. Thirty-three observer anchors are covered by a unit test, because every corpus context must decode. |
| 13 | §3.2: requirements on grants | Critical-extension handlers do not see their carrier. | The handler validates `observation-requirement-v1` wherever it appears; the stage reads it only from grants, so on an action it has no effect. |
| 14 | §7: predicates extractable and qualified | — | `observation_fresh`, `observation_subject_equal`, `fact_name_equal`, `fact_value_equal`, `uint_range_contains`, `member_values_contain`, `observation_fact`, `condition_value_holds`, `observation_condition_holds`, `observation_conditions_hold`, and `requirement_verdict` in `auths-model` are translated by the pinned Charon/Aeneas route and exercised by qualification cases. The Lean theorems are over the abstract model; a refinement proof linking them to the translated predicates is not yet written. |

## 14. Gateway observer readings

The gateway is the first observer. Where §5 left a choice open, the
implementation fixed the narrowest reading below.

| # | Question | Reading fixed |
|---|---|---|
| 1 | Observer key and principal | A `raw-key-v1` Ed25519 principal. The operator creates its 32-byte seed with `auths-gateway observer-init` in the gateway's private state directory (mode 0600, never overwritten, zeroized in memory); `observer-show` prints the anchor facts (principal, method, suite, both schemas, subject namespaces) and the verifier configuration to pin. The application socket never reaches the seed. Custody is software, not hardware. |
| 2 | How the agent obtains observations | A separate closed application request, `auths.gateway-observe/1`, of kind `read-back` (exactly the recipe's observation path arguments) or `outcome` (a logical operation ID). The result carries the canonical signed observation and the attachment media type. The submit result is unchanged. Without a provisioned observer key every request is refused. |
| 3 | Read-back subject and facts | Subject: the closed observation URL with the observed JSON pointer as fragment. Facts: `value` (a string of at most 256 bytes as text, a non-negative integer as uint; anything else is refused, not coerced) and `echo` when the recipe declares one and the record carries a string. `observed_at` is taken before the GET is sent. |
| 4 | Outcome subject and facts | Subject: `auths-gateway://<namespace>/operations/<operation-id>`. Facts: `commitment` (lowercase hex text, so it compares with an MCP string argument) and `stage` (the stored stage in kebab-case, with an `attempting` record read as `unknown`, as the store reports it). No provider is contacted. |
| 5 | Action facts | `mcp-arguments-v1` exposes top-level verified MCP arguments by name with the same typing as observed values, accepts only canonical `auths.mcp/2` actions, and is committed in the gateway's verifier configuration. The trusted context selects it as its profile policy. |
| 6 | Binding an action-fact subject to the written record | The recipe gains an optional `preconditions` block: `read_back_subject` names the argument that must equal this request's read-back subject, and `verified` lists arguments no request renders, compared only by observation requirements. The gateway refuses a mismatched subject with `gateway.recipe.precondition-subject-mismatch` before any claim. Without it, an observation of one record could license a write to another. |
| 7 | Evaluation time | The gateway verifies each submission at its own clock through `TrustedContext::for_request`, keeping the installed audience and challenge. Freshness against an install-time evaluation time would be meaningless. |
| 8 | "Step N is indeterminate until step N−1 is provider-bound" | With no outcome observation attached, step N is `observation-missing` (indeterminate). With a signed outcome of another stage, it is `observation-condition-false` (denied), as §4.1 requires for an eligible observation that falsifies a condition. Either way step N's logical operation stays unclaimed, so a later action with a fresh observation can proceed. |

## 15. Amendment (2026-09-23): SDK attachment and the Rust–Lean link

Two gaps remain after the kernel, gateway observer, and client requests.

### 15.1 Attaching an observation to the next action

The Python and TypeScript clients can request a gateway-signed observation,
but neither SDK can attach one to an action. There is no authoring surface
for detached attachments in either SDK.

1. The native authoring path gains one operation. It takes a canonical
   action and zero or more signed observations, and returns the action with
   each observation carried as a detached attachment. The attachment
   descriptors are bound by the action statement before signing.
   - The operation validates each observation's media type and size. It
     does not verify the observation; the verifier does.
2. Python and TypeScript expose that operation as a thin projection. It is
   not a second implementation.
3. **Acceptance:** a packed Python consumer and a packed npm consumer each
   run the expected-before-replacement journey against the gateway's test
   harness:
   - request a read-back observation;
   - attach it to the replacement action;
   - submit, and the write is authorized;
   - change the record, and the stale observation is denied before any
     credential lease.

### 15.2 Linking the theorems to the shipping predicates

The Lean theorems (§13, reading 14) are proved over the abstract model. The
eleven Aeneas-translated Rust predicates are qualified, but no proof yet
connects them to the model.

1. Add a refinement module that states and proves, for each translated
   predicate, equality with its model counterpart. It follows the pattern of
   `formal/Auths/Refinement/Production.lean` for the authority predicates.
2. Register the refinement claims in the assurance manifest with their
   axiom sets.
3. **Acceptance:** `cargo xtask formal` passes with the new claims in the
   inventory. The monotonicity and attenuation theorems then cover the
   translated Rust, subject to the published translation assumptions of
   AP-SPEC-011 §13.

### 15.3 Related amendments

Observer quorum (§16) and extension attenuation (§17) are wire changes
specified below. They are part of this specification's scope, not future
work.

## 16. Amendment (2026-09-23): observer quorum

A requirement names one observer anchor today. Several requirements naming
different observers give an N-of-N quorum, because requirements combine by
conjunction. No construction gives K-of-N with K < N. A quorum is only
meaningful if its members are independent, and two keys run by one operator
are not.

This section replaces the single observer with a quorum over independent
operator domains. It is a clean cutover under the prelaunch rule: the
single-observer form is removed, not kept as an alias.

### 16.1 Wire

```text
ObserverAnchor = {
  id:                 ObserverAnchorId,
  principal:          PrincipalId,
  operator_domain:    OperatorDomain,        ; 1..128 bytes, canonical token
  accepted_methods:   [ PrincipalMethodId ],
  schemas:            [ ObservationSchemaId ],
  subject_namespaces: [ ResourceId ],
  validity:           ValidityWindow,
}

ObservationRequirement = {
  observers:       [ 1*8 ObserverAnchorId ],   ; distinct, sorted
  quorum:          1..8,                        ; K; quorum <= len(observers)
  schema:          ObservationSchemaId,
  subject:         ResourceId / ActionFactRef,
  max_age_seconds: 1..86400,
  conditions:      [ 1*16 Condition ],
}
```

- **Operator domains.** `operator_domain` names who operates the observer.
  It is asserted by whoever provisions the trusted context, the same party
  that decides which observers to trust.
- **Invalid contexts.** A trusted context is invalid, and rejected at
  decode, if two anchors share a principal or if one anchor appears twice.
- **Invalid requirements.** A requirement whose `quorum` exceeds the number
  of its distinct observers, or whose observers repeat, is invalid and
  denied with the existing extension-validation code.

### 16.2 Semantics

For each requirement:

1. **Qualifying observations.** For each named observer anchor present in
   the context, collect the attached observations that:
   - are signed by that anchor's principal, verified by its accepted
     methods;
   - match the requirement's schema and subject;
   - lie inside the anchor's `subject_namespaces`;
   - are fresh under the §4.1 rules.

   Observations that fail these checks are ignored, as in §4.1.
2. **Classifying operator domains.** For each operator domain among the
   named anchors:
   - **Satisfying:** at least one qualifying observation from an anchor in
     that domain makes every condition true.
   - **Refuting:** the domain is not satisfying, and every anchor in it with
     a qualifying observation has only observations that falsify some
     condition.
   - **Absent:** otherwise.

   Observations are counted per operator domain, never per anchor or per
   observation, so one operator cannot meet a quorum alone.
3. **Result.** Let `D` be the number of distinct operator domains among the
   named anchors present in the context, and `K` the quorum.
   - **Satisfied** when at least `K` domains are satisfying.
   - **Denied**, with `observation-quorum-refuted`, when the refuting
     domains are more than `D − K`. The quorum can then no longer be met by
     any additional observation.
   - **Indeterminate**, with `observation-quorum-unmet`, otherwise.

   A requirement whose named anchors span fewer than `K` distinct operator
   domains in the context is indeterminate with `observation-quorum-unmet`.
   It can never be satisfied under that context, and the verifier reports it
   rather than guessing.
4. **Combination.** Across requirements, `denied` dominates `indeterminate`,
   as in §4.1. The single-observer codes `observation-condition-false` and
   `observation-missing` are removed, replaced by the two quorum codes.
   `observer-in-authority-chain` is unchanged and applies to every named
   observer.
5. **Reporting.** For each requirement, the result reports the satisfying
   operator domains and one observation digest per satisfying domain.

### 16.3 Limits

- At most 8 observers per requirement, and a quorum of at most 8.
- At most 32 observer anchors per context.
- At most 32 observation attachments.

Work is reserved per requirement as observers × attachments × conditions,
before evaluation.

### 16.4 Formal obligations

The Lean model gains observers, operator domains, and quorum. The following
theorems are added to the assurance manifest:

- `quorum_monotone`: raising `K` never enlarges the authorized set.
- `observer_subset_monotone`: removing observers from a requirement, with
  `K` fixed, never enlarges the authorized set.
- `domain_counting_sound`: two anchors in one operator domain never count
  toward more than one member of the quorum.
- `quorum_decision_partition`: for every observation set, exactly one of
  satisfied, refuted, or unmet holds.

The quorum predicate is written as a pure, bounded, extractable function and
Aeneas-qualified, with the refinement link of §15.2.

### 16.5 Wire-change obligations and acceptance

This follows §8: CDDL, codec, registry manifest (a new identifier),
`registry.md`, `error-codes.md`, canonical fixtures generated through
`cargo xtask wire --update`, native tests, WASM, and the independent Go and
TypeScript implementations.

The fixtures cover, at minimum:

- K = N and K < N;
- a quorum met exactly, and missing by one;
- two anchors of one operator domain counted once;
- refutation reaching `D − K + 1`;
- a quorum larger than the distinct domains;
- duplicate observers or principals rejected at decode;
- the observer limits at the boundary and one past it.

**Acceptance:** Rust, Go, and TypeScript agree on every new vector; the four
theorems are registered and pass `cargo xtask formal`; and the gateway
hostile suite shows a 2-of-3 quorum. In that suite, the gateway observer
plus one independent read-only observer authorizes the write. Two observers
of one operator domain do not. One refuting observer out of three leaves the
quorum reachable, and two refuting observers deny it.

## 17. Amendment (2026-09-23): per-extension attenuation

The kernel treats critical extensions as the eleventh authority dimension
and requires a child grant's extensions to equal its parent's byte for byte
(`extensions_attenuate` and `evaluate_author_scope_view` in
`core/crates/auths-authority/src/lib.rs`). That is sound but too strict:

- a delegate cannot add an observation requirement (§13, reading 1);
- a delegate cannot narrow a bounded-policy commitment (AP-SPEC-025 §24).

Both are narrowings, which delegation must allow.

### 17.1 Rule

1. Every critical-extension handler declares an attenuation law:
   `attenuates(child_bytes: Option, parent_bytes) -> bool`.
2. **Child extensions attenuate the parent's** when, for every extension
   identifier the parent carries:
   - the child carries the same identifier; and
   - the handler's law accepts the pair.
3. **Extensions the child adds** that the parent lacks are accepted only if
   their handler declares `attenuates(child_bytes, absent) = true`. That
   means adding the extension can only narrow authority.
4. A parent with no extension scope still constrains nothing.
5. An identifier without a registered handler is denied, as today.

### 17.2 Laws of the registered handlers

| Extension | Law |
| --- | --- |
| `exact-marker-v1` | Byte equality; adding it is refused. This is today's behavior, so the marker still changes no authority. |
| `observation-requirement-v1` | Every parent requirement is present in the child, either byte-identical or narrowed. A requirement is narrowed when all of the following hold, and at least one is strictly narrower: <ul><li>quorum greater than or equal;</li><li>observers a subset;</li><li>`max_age` less than or equal;</li><li>conditions a superset, compared as a set of canonical atoms;</li><li>schema and subject equal.</li></ul> The child MAY add requirements, and adding the extension where the parent has none is accepted. |
| `bounded-policy-commitment-v1` (AP-SPEC-025 §24) | The child's body carries its own policy commitment plus the digest of the parent's commitment. The kernel accepts the pair only when that digest equals the parent's commitment. Whether the child's policy is actually tighter is a product-layer question: the registered evaluator's tightening decider (AP-SPEC-025 §15) answers it before eligibility. An unregistered decider, or one that cannot decide, is indeterminate. Adding the extension where the parent has none is accepted, because any bound narrows an unbounded grant. |

### 17.3 Formal obligations

1. The rich authority model in Lean (AP-SPEC-011) replaces its
   extension-equality dimension with a per-identifier preorder.
2. The model proves the kernel's rule preserves the existing theorem that
   delegation never widens authority, **given** that each handler's law is a
   preorder that narrows. That hypothesis is discharged per handler:
   - `exact-marker-v1`: trivially.
   - `observation-requirement-v1`: from §16.4's monotonicity theorems.
   - `bounded-policy-commitment-v1`: the kernel only checks the parent
     link. Narrowing is discharged by the registered evaluator's tightening
     law (AP-SPEC-025 §15). That boundary is recorded in the assurance
     manifest as a product-layer premise, not claimed as a kernel theorem.
3. `extensions_attenuate` and the author-scope check are rewritten as pure
   extractable predicates over the handler laws. They are re-qualified with
   Aeneas, and the refinement to the rich model is re-proved.

### 17.4 Wire and acceptance

The registry manifest changes (a new identifier), because attenuation
semantics change. Fixtures cover:

- a child adding a requirement;
- a child narrowing quorum, observers, max age, or conditions;
- a child widening each of those, which is denied as delegation-expanded;
- a child dropping a parent requirement;
- the marker added or changed, which is denied;
- the bounded-policy parent link correct and wrong.

**Acceptance:** Rust, Go, and TypeScript agree on every vector; the formal
gate passes with the revised dimension; and §13 reading 1 is superseded. A
delegate can now add observation requirements.

## 18. Readings fixed while implementing §17

Each reading is the narrowest fail-closed choice that keeps §17's claim.

| # | Spec text | Reading fixed |
|---|---|---|
| 1 | §17.1: `attenuates(child_bytes: Option, parent_bytes)` | The kernel port is `auths_model::CriticalExtensionLaws::attenuates(id, child: Option<&[u8]>, parent: Option<&[u8]>) -> bool`, and every handler declares `CriticalExtensionHandler::attenuates(child, parent) -> Result<bool, _>`. The kernel checks parent-identifier presence itself and consults a law only for a payload the child carries: with the parent's payload, or with `None` when only the child carries the identifier. A handler failure (malformed or over-limit bytes) is a refusal. |
| 2 | §17.1: "an identifier without a registered handler is denied" | The verifier's laws are those of the handlers the trusted context accepts; an identifier without an accepted handler has no law and the edge is `delegation-expanded`. Pre-signing planning (`plan_child_grant`) takes the laws as an argument; the bindings pass the target-V1 core laws. |
| 3 | §17.2: marker "byte equality; adding it is refused" | `exact-marker-v1` accepts `(Some c, Some p)` exactly when `c == p`, and refuses `(Some, None)`. |
| 4 | §17.2: requirement "byte-identical or narrowed", "at least one strictly narrower" | Covering is byte identity, or: the same observer anchor, schema, and subject; a maximum age no larger; a superset of the parent's condition atoms, where an atom is compared by its canonical encoding; and a strictly smaller age or a strict superset. A reordered condition list is neither, so it is refused (vector `observation-requirement-conditions-reordered`). |
| 5 | §17.2: "quorum greater than or equal; observers a subset" | §16 is not implemented, so a requirement names one observer anchor and has an implicit quorum of one. "Observers a subset" is anchor equality and "quorum no smaller" holds trivially. When §16 lands, its `observers` and `quorum` fields join the law under §17's text. |
| 6 | §17.4: widening is `delegation-expanded`; §4.3 already names `observation-requirement-dropped` | A parent requirement is *dropped* when no child requirement addresses it with the same schema and subject; the verifier denies that before the kernel with `observation-requirement-dropped`. A child requirement that addresses it without covering it (a larger age, a missing or changed atom, another observer) reaches the kernel, whose law denies the edge as `delegation-expanded`. |
| 7 | §17.4: "the registry manifest changes" | The manifest is `35` repeated 32 times. Each core handler's configuration commitment also names its attenuation law, so the verifier configuration identifier changes with it. |
| 8 | §17.3: "a per-identifier preorder … given each law is a preorder that narrows" | The rich Lean model takes the registered laws as a class `ExtensionLaws v` (law, and the worlds a payload admits) and the premise `ExtensionLawsNarrow v`. `delegate_never_widens_authority` and `chain_never_widens_authority` prove that no accepted edge or chain admits an authorization fact, including every extension payload, that its start refuses. The refinement theorems hold for every law the translated handler-law instance computes (premise `LawsRefine`). |
| 9 | §17.3: discharge for the marker and observation requirements | `exact_marker_law_lawful` and `observation_requirement_law_lawful` prove each law a narrowing preorder over decoded payloads. The observation discharge uses `requirements_monotone`'s argument extended with `fresh_monotone_max_age`, not §16.4's theorems, which do not exist yet. That the byte-level handler agrees with the decoded law rests on the canonical codec, recorded as a residual assumption. |
| 10 | §17.3: "re-qualified with Aeneas" | The kernel predicates (`critical_extensions_attenuate`, the retained and admitted loops, and `extensions_attenuate`) are in `auths-authority`, generic over the laws, and translated by the pinned Charon/Aeneas route; their model leaves (`critical_extension_find`, `_entries`, `_id`, `_payload`) and the observation law predicates are translated in `auths-model`. The requirement-law predicates are qualified and exercised natively; their Lean link to the abstract law is §15.2's work. |
| 11 | §17.2 and §17.3: `bounded-policy-commitment-v1` | The kernel law checks only the parent link: a child keeps the extension only with the digest of its parent's exact extension bytes, and adds it to an unbounded parent only without one. Narrowing is the registered product evaluator's tightening decider, run by the gateway before eligibility; `Auths.Product.CeilingCount.bounded_policy_law_lawful` discharges the premise for the one registered evaluator and the assurance manifest records it as a product-layer premise, not a kernel theorem. |

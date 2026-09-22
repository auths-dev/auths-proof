# AP-SPEC-060: Evidence-conditioned authority

- **Status:** Draft; written on owner direction before its epic starts
  (board §4, 2026-09-22). Nothing in this document is implemented. This is a
  **core protocol change**: new wire objects, a new critical extension, a
  trusted-context field, a port method, a verifier stage, and a new
  registry manifest.
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

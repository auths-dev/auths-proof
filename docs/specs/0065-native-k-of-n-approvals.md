# AP-SPEC-065: Native K-of-N approvals

- **Status:** Draft, being implemented in the pull request that adds it
  (branch `kofn-approvals`). This is track A of auths-research spec 10
  ("Native K-of-N approvals and boolean rules in the verifier kernel"),
  option K-B, including the grant-carried variant A14, which the owner moved
  into this first release on 2026-09-30. Track B (request attributes and
  condition formulas, option R-C) is a later pull request; §13 records what it
  still needs.
- **Evidence:** auths-research study 006 measured the Auths verifier as
  **P** on property P4 ("authorized only when at least K of the N approvers
  the verifier names approved this exact action, each approver counted once,
  with K and the set fixed by the verifier"): 43 of 50 allow cases were
  refused unless application code first arranged the approvals into the exact
  positional plan the verifier pinned. Biscuit and OPA were **N**. Spec 10's
  "Update: study 006's final results" confirms the measurement at the study's
  close.
- **Depends on:** [AP-SPEC-001](0001-formal-attenuation-and-composition.md)
  (plans and composition, unchanged here),
  [AP-SPEC-060](0060-evidence-conditioned-authority.md) (verifier-held anchors
  separate from trust anchors, ignored invalid attachments, and per-extension
  attenuation, §17), [AP-SPEC-064](0064-status-issuer-scope.md) (status issuer
  scope), [AP-SPEC-061](0061-end-to-end-machine-checked-verifier.md) (extraction
  rules).
- **Changes:** the trusted context, the proof bundle, the verifier-limits
  object, the portable verification result, a new signed object (the approval
  statement), a new grant critical extension (`approval-requirement-v1`), a new
  registry manifest, two new result codes, the product approval quorum and
  AP-SPEC-062 remote approvals.
- **Normative language:** **MUST**, **MUST NOT**, **SHOULD**, and **MAY**
  specify implementation requirements.

## 1. Decision and claim

Today a relying party that wants "two of these three managers approved this
exact action" has two tools, and neither says that:

- a `k_of_n` authorization plan, whose leaves are positional: every leaf
  needs a signed action, so an approver who did not approve still needs a
  placeholder, and the verifier can fix the approver set only by pinning the
  exact plan;
- composition floors (minimum distinct actors and roots), which count
  authority branches, so every approver must also be a trust anchor, and one
  approval of another action rejects the whole proof (`plan-action-mismatch`).

This spec adds **approval requirements**. A requirement names a set of
approver principals and a threshold K. An approver approves an action by
signing an **approval statement** that binds the exact action, the relying
party's audience and challenge, and the requirement's identifier. The
presenter attaches every approval it holds, in any order and with
repetitions and strays. The verifier counts **distinct approvers** whose
approval is authentic, current, bound to this exact action and requirement,
and not from a principal in the authority chain.

A requirement is carried in one of two places:

1. **The trusted context** (keys 15 and 16). The relying party fixes K and
   the approver set. It is evaluated once per request, after the plan
   authorizes and the composition floors hold.
2. **A grant** (critical extension `approval-requirement-v1`). The issuer
   conditions the authority it delegates on approvals. It is evaluated for
   each branch whose chain carries it, with the observation stage, and a
   child grant may keep or narrow it but never drop or widen it.

**Claim.** An action is authorized only if, for every approval requirement in
the trusted context and every requirement carried by the chain of the branch
that authorized, at least K distinct listed approvers each approved exactly
this action for exactly that requirement. Approvals confer no authority: an
approver is never a trust anchor for the action, never a branch, and never
counted by the composition floors. The verdict does not depend on the order
or repetition of approvals, and adding an approval never turns an authorized
verdict into a refusal.

**Not a claim.**

- Approvers are identified by principal identifier. One key anchored as two
  approver principals counts twice, as the threat model states for trust
  anchors (key-level distinctness is out of scope).
- An approval proves control of an anchored key, not that a human decided.
- The verifier does not collect approvals, route requests, or remember them.
  Replay protection for the action is the enforcement point's one-use claim,
  as before.

## 2. Why this is not a policy language

The only new construct is a threshold over an exact, verifier-named set of
principals. There are no variables, patterns, callbacks, or rules over
request content. An approval binds exact canonical-action fields by equality.
ADR 0004's exact-permission decision and AP-SPEC-060 §2's closed-language
decision stand. The threshold is the same generated function the plan
evaluator runs, `threshold_counts` (`core/crates/auths-algebra-kernel`), over
counts of distinct approvers.

## 3. Wire objects

All objects follow `core/spec/v1/auths-proof.cddl`: integer keys,
deterministic CBOR, and strictly ascending sets unless stated otherwise.

### 3.1 Approver anchor (trusted-context key 15)

```cddl
approver-anchor = {
  0: principal-id,
  1: [1*1024 bounded-id],   ; accepted principal methods
  2: timestamp,             ; not_before
  3: timestamp,             ; expires_at
  4: status-policy,         ; how the approver's principal status is checked
}
```

Key 15 is `[*32 approver-anchor]`, strictly ascending by principal. An
approver anchor is separate from every trust anchor and observer anchor: it
lets the verifier check one approver's signatures and nothing else. Context
construction MUST reject an anchor whose accepted methods are not all
accepted principal methods of the context, whose status policy names a
principal-status method the context does not accept, or whose window has
`not_before > expires_at`.

### 3.2 Approval requirement (trusted-context key 16)

```cddl
approval-requirement = {    ; "K of these N principals"
  0: [1*16 principal-id],   ; approvers, strictly ascending
  1: uint .ge 1 .le 16,     ; K, at most the number of approvers
}
```

Its identifier is the domain hash of its canonical bytes under **identifier
type 12**. Key 16 is `[*4 approval-requirement]`, strictly ascending by
identifier. Context construction MUST reject a requirement that names a
principal without an approver anchor in key 15, or whose K exceeds its
number of approvers. A requirement names principals, not anchor labels, so
an approver can compute the identifier from public values.

### 3.3 Approval statement and signed approval (proof-bundle key 10)

```cddl
approval-statement = {
  0: protocol-version,
  1: principal-id,          ; approver
  2: digest32,              ; approval requirement ID (identifier type 12)
  3: media-type,
  4: digest32,              ; canonical body digest
  5: capability,
  6: resource,
  7: budget-ceiling / null, ; requested budget
  8: digest32 / null,       ; request-attributes digest, null when none
  9: audience,
  10: digest32,             ; challenge
  11: timestamp,            ; not_before
  12: timestamp,            ; expires_at, not before not_before
}

approval-signing-input = {
  0: approval-statement,
  1: signature-descriptor,
}

signed-approval = {         ; at most 4096 bytes
  0: approval-statement,
  1: signature-envelope,
  2: [*4 evidence-object],  ; the approver's control evidence, ascending by EvidenceId
}
```

- An approval statement is signed under **object type 10** with the approved
  action's profile ID and profile version
  (`core/spec/v1/domain-separation.md`), so an approval for one profile never
  verifies for another.
- Key 8 is the request-attributes digest of track B. Until canonical actions
  carry request attributes, a verifier compares it with `null`: an approval
  whose key 8 is a digest matches no action and is ignored.
- Proof-bundle key 10 is `[*128 signed-approval]`. Its order and repetitions
  carry no meaning, and it is encoded in the order presented. The bundle's
  duplicate-object rule MUST NOT apply to it: Ed25519 is deterministic, so
  two approvals of one statement by one key are byte-identical, and a
  presenter that holds both must not be refused for presenting them.
- The **approval digest** is the raw SHA-256 of the exact canonical
  `signed-approval` bytes.

### 3.4 Grant critical extension `approval-requirement-v1`

```cddl
; The exact bytes of the `approval-requirement-v1` critical extension:
; one to four requirements, strictly ascending by identifier.
approval-requirements = [1*4 approval-requirement]
```

### 3.5 Verifier limits (keys 27 to 29)

| Key | Bound | Hard and default value |
| --- | --- | --- |
| 27 | signed approvals in one proof | 128 |
| 28 | approver anchors in one trusted context | 32 |
| 29 | approval requirements in one trusted context | 4 |

A deployment MAY lower each. The verifier-limits object therefore has 30
entries. The per-requirement bounds (16 approvers, K at most 16) and the
per-grant bound (four requirements) are structural, in the CDDL above.

### 3.6 Portable result (verification-result key 17)

```cddl
approval-satisfaction = {
  0: digest32,              ; approval requirement ID
  1: [1*16 digest32],       ; approval digests that counted, strictly ascending
}
```

Key 17 is `[*64 approval-satisfaction]`, strictly ascending by requirement
identifier, one entry per requirement that authorized: every requirement of
the trusted context and every requirement carried by the chain of an
authorized branch. `VerifiedAction::approval_satisfactions` exposes the same
list. A refused result carries an empty list.

## 4. Approval semantics

### 4.1 Where requirements are evaluated

- **A1, trusted context.** The requirements of key 16 are evaluated after
  the plan authorizes and the composition floors hold, once per request, in
  ascending identifier order. They only remove actions from the authorized
  set. A quorum is a property of the request, not of one branch.
- **A14, grants.** For each branch, after its observation stage, collect the
  distinct requirements (by identifier) carried by the `approval-requirement-v1`
  extensions of every grant in the chain, root first, in first-appearance
  order. More than 16 is `resource-limit-exceeded`. Each is evaluated as
  below; a denied requirement denies the branch, otherwise an indeterminate
  one makes it indeterminate, and the plan composes branches as today.
- **Caching.** A requirement's verdict depends only on the requirement, the
  proof, the canonical action, and the trusted context (§4.2), never on the
  branch. Each distinct requirement is therefore evaluated at most once per
  verification: the first evaluation, in the verifier's fixed order (branches
  in plan order, then the context's requirements), reserves the work, and
  every later appearance reuses its verdict and counted approvals. At most 64
  distinct requirements are evaluated in one verification; the 65th is
  `resource-limit-exceeded`.
- Within one list, the first denied requirement stops the list with
  `approval-threshold-not-met`; an indeterminate requirement is remembered
  and the list continues, ending `approval-unavailable`. Denial dominates, as
  for observation requirements.

### 4.2 Evaluating one requirement

Let R be a requirement with approver set S, threshold K, and identifier r;
t the context's evaluation time; and E the **authority principals** of the
proof: the issuer and the subject of every grant in the bundle and the actor
of every action in the bundle. Every grant lies on some branch's chain
(stage 2 rejects unused grants), so E contains every principal of every
chain that could authorize the action.

Take the proof's signed approvals, remove byte-identical repetitions, and
order the rest by ascending approval digest. Start with every approver in S
*absent*. For each approval x in that order:

1. **A2, candidates.** If x's approver is not in S, skip x.
2. **A7, no self-approval.** If x's approver is in E, skip x.
3. If x's approver is already *counted*, skip x. Its approval is not
   verified again.
4. **A4, exact requirement and action.** Skip x unless key 2 equals r, and
   keys 3 to 10 equal, in order, the canonical action's media type, the
   SHA-256 of its canonical body, its permission's capability and resource,
   its requested budget, `null`, the context's expected audience, and the
   context's expected challenge.
5. **A5, validity.** Skip x unless `not_before <= t <= expires_at`. Find the
   approver anchor for x's approver (key 15); skip x if there is none or its
   window does not contain t.
6. **A3, method.** Skip x unless the anchor's accepted methods contain the
   principal method of x's signature descriptor.
7. **A3, signature.** Verify x's signature exactly as a proof statement's
   signature is verified in stage 3, with purpose assertion, asserted signing
   time `not_before`, the object type 10 preimage, and x's own evidence in
   place of a control binding:
   - a principal method, signature suite, or evidence type the context does
     not accept or the registry does not install makes x *pending*;
   - otherwise reserve the method's maximum work and then the suite's work;
   - a method result that stage 3 maps to indeterminate makes x *pending*;
     any other method or signature failure skips x;
   - the evidence the method consumes MUST equal x's evidence, else x is
     skipped;
   - work above the method's reservation, or a reservation above the work
     limit, is `resource-limit-exceeded` for the whole verification.
8. **A6, status.** When the anchor's status policy is `SnapshotRequired`,
   evaluate the approver's principal status as the trust anchor's is
   evaluated (verification algorithm, "Principal status", with an absent
   statement giving `missing-principal-status`), with one change of scope:
   an approver anchor is no trust anchor, so a snapshot statement is out of
   scope unless the snapshot does not know its issuer or every rule naming
   its issuer has scope `any` (AP-SPEC-064 §2). A result of revoked,
   superseded, or any other denial skips x; any indeterminate result — a
   missing, stale, or unsupported status, or an unavailable fact of a status
   statement's control or extension check — makes x *pending*;
   `resource-limit-exceeded` fails the whole verification.
9. Otherwise x is **counted**: its approver becomes *counted* and x's digest
   is recorded for R. A *pending* x makes its approver *pending* unless it is
   already *counted*.

- **A8, distinct counting.** Let a be the number of approvers in S that are
  *counted* and i the number that are *pending*. R's verdict is
  `threshold_counts(K, a, i)`: authorized when a ≥ K, indeterminate when
  a < K ≤ a + i, denied otherwise. The counts are computed by the pure
  predicate `approval_counts` (§7).
- **A10, no poisoning.** A skipped approval never denies the proof. Only
  limits deny, with `resource-limit-exceeded`, and work is reserved before
  each signature and status check. Malformed or over-bound approval bytes are
  part of the proof bundle and fail decoding (`malformed-proof`,
  `non-canonical-proof`, or `resource-limit-exceeded`), as every other
  bundle object does.
- **A11, order independence.** The digest order and step 3 make the verdict,
  the recorded digests, and the work reserved independent of the order and
  repetition of approvals.
- **A12, reporting.** For each requirement that authorized, the recorded
  digests are reported in result key 17 (§3.6): one approval per counted
  approver, the first in digest order.
- **A13, plans unchanged.** `KOfN`, the exact-plan check, and the
  composition floors keep their semantics for authority branches. Approvals
  are not branches and do not count toward any floor.

### 4.3 Results

| Situation | Decision | Code | Portable stage |
| --- | --- | --- | --- |
| Every requirement authorized | continue | — | — |
| A requirement's verdict is denied | denied | `approval-threshold-not-met` | `authority` |
| A requirement's verdict is indeterminate and none is denied | indeterminate | `approval-unavailable` | `authority` |
| A limit is exceeded | denied | `resource-limit-exceeded` | the stage where it occurs |

No portable stage value is added: approval steps belong to stages 5 and 6.
`core/spec/v1/error-codes.md` labels both codes with the descriptive stage
`approval`.

## 5. Grant-carried requirements (A14)

### 5.1 The attenuation law

The `approval-requirement-v1` handler declares, under AP-SPEC-060 §17:

- A child requirement C **covers** a parent requirement P when C's approvers
  are a subset of P's and C's K is at least P's. Byte identity is the case of
  equal sets and equal K.
- A child payload attenuates a parent payload when every parent requirement
  is covered by some child requirement. The child MAY add requirements.
- Adding the extension where the parent has none is accepted: any
  requirement narrows an unconditioned grant.
- A child that carries no payload where the parent carries one is refused.

Covering narrows: every set of approvals that meets C meets P, because K_C ≥
K_P distinct counted approvers from S_C ⊆ S_P are K_P distinct counted
approvers from S_P. Dropping or widening a requirement is refused by the
authority kernel's extension law as `delegation-expanded`
(`branch.delegation-extensions`); there is no separate code.

### 5.2 Evaluation

Every requirement in the chain is evaluated, including a parent's
requirement that a child narrowed. Each is evaluated under its own
identifier, so an approval counts only for the requirement it names: a
narrowed requirement needs approvals naming the narrowed identifier. This is
the observation precedent (every chain requirement is met independently) and
keeps §4.2 identical for both carriers.

A grant requirement MAY name a principal that has no approver anchor in the
trusted context. That approver's approvals are skipped at step 5, because no
accepted method exists to verify them.

## 6. Limits

| Bound | Value | Failure |
| --- | --- | --- |
| Signed approvals in one proof | 128 (verifier-limits key 27) | `resource-limit-exceeded` at decode |
| One signed approval | 4096 bytes | `resource-limit-exceeded` at decode |
| Evidence objects in one approval | 4 | `resource-limit-exceeded` at decode |
| Approver anchors in one context | 32 (key 28) | `resource-limit-exceeded` at context decode |
| Approval requirements in one context | 4 (key 29) | `resource-limit-exceeded` at context decode |
| Approvers in one requirement | 16 | `resource-limit-exceeded` at decode (context or grant extension) |
| K in one requirement | 1 to the number of approvers | `malformed-proof` at context decode; invalid input for the grant handler |
| Requirements in one grant extension | 4 | `resource-limit-exceeded`, as for every handler |
| Distinct requirements in one chain | 16 | `resource-limit-exceeded` |
| Distinct requirements evaluated in one verification | 64 | `resource-limit-exceeded` |

These are the values spec 10 proposed; the owner accepted them (§14,
decision 8). The chain and verification bounds are this spec's.

## 7. Formal work

Formal work lands before the wire change, as AP-SPEC-060 §7 required.

- **F1.** `formal/Auths/Approval.lean` models an approval record (approver,
  bound action, requirement, window, verification truth), a requirement
  (principal list, K), the authority principals, per-approval verdicts,
  distinct counting, and `decide := thresholdCounts K a i`. Theorems:
  - `approval_decide_eq_threshold_counts`;
  - `approval_authorized_iff_distinct_quorum`: authorized iff at least K
    distinct listed principals have a counted approval;
  - `approval_duplicate_irrelevant`, `approval_outsider_irrelevant`,
    `approval_other_action_irrelevant`, `approval_self_approval_irrelevant`;
  - `approval_permutation_invariant`;
  - `approval_monotone_in_approvals`, `approval_antitone_in_threshold`,
    `approval_antitone_in_approvers`.
  Unlike the count-level model, this one names principals, so the duplicate
  and outsider cases are statable.
- **The A14 law.** `approvalRequirementLaw` is a `NarrowingLaw` over decoded
  requirement lists; `approval_requirement_law_lawful` proves it a preorder
  that narrows, which discharges `ExtensionLawsNarrow`'s premise for this
  handler, so the rich model's `delegate_never_widens_authority` and
  `chain_never_widens_authority` cover it.
  `approval_requirements_attenuate_monotone` states the narrowing directly:
  every approval set that meets a child's requirements meets its parent's.
- **F3.** The Rust predicates in `auths_model::approval` —
  `approval_counts` (distinct counting over per-approval verdicts) and the
  law predicates `approval_requirement_covers`,
  `approval_requirement_retained`, and `approval_requirements_attenuate` —
  are pure, bounded, and written under AP-SPEC-061's extraction rules. They
  are required symbols of `formal/qualification/aeneas/qualification.toml`,
  translated with the pinned Charon and Aeneas, and refined by
  `translated_approval_counts_refines_model` and the law refinements, each
  with manifest status *qualified*.

## 8. Check sites and codes

| Site | Code | Vector |
| --- | --- | --- |
| `branch.approval-threshold` | `approval-threshold-not-met` | `approval-grant-single` |
| `branch.approval-unavailable` | `approval-unavailable` | `approval-grant-status-unavailable` |
| `composition.approval-threshold` | `approval-threshold-not-met` | `approval-single` |
| `composition.approval-unavailable` | `approval-unavailable` | `approval-status-unavailable` |

Widened and dropped grant requirements are pinned at the existing
`branch.delegation-extensions`. Stable codes: `approval-threshold-not-met`
(denied) and `approval-unavailable` (indeterminate).

## 9. Wire-change obligations and compatibility

- **Prelaunch cutover.** The trusted context, the proof bundle, the
  verifier limits, and the portable result change shape, so every corpus
  vector is regenerated with `cargo xtask wire --update`. There is no reader
  for the previous shapes. The registry manifest becomes `37` repeated 32
  times, and a context pinned to `36` is denied, not dual-read.
- **Obligations** (`AGENTS.md`): model and codec, `core/spec/v1`, the
  registry manifest, native tests, WASM, Python, TypeScript, the independent
  Go and TypeScript verifiers, and the compatibility evidence change in one
  reviewed change.
- **Plans stay.** A deployment that pinned an exact quorum plan moves its
  approvers from trust anchors to approver anchors.

## 10. Product re-cut

The approval quorum (`product/sdk/auths-approval-quorum`) builds one actor
branch and approval statements instead of a `k_of_n` plan over approver
branches:

- A proposal fixes the canonical action, the actor's signed action and grant
  chain, one approval requirement (approver principals and K), and the
  approval window. Approvers sign approval statements, not envelopes.
- The recommended trusted context carries the actor's trust anchor, the
  approvers as approver anchors, and the requirement in key 16. The helper's
  composition floors are removed: the context's requirement is the quorum.
- Assembly needs only the approvals collected so far. **Any K of the listed
  N, whoever responds, is authorized**; the approver set no longer has to be
  fixed before the first signature, and a proposal may list more approvers
  than K without every one signing.
- The actor is never a listed approver: its approval would never count, so
  the proposal refuses to list it.
- AP-SPEC-062 requests carry the approval statement an approver signs, and
  the response carries the signed approval; both formats are now `/2`.
- The gateway's offline audit lists, per verified entry, the approvers the
  proof counted.

## 11. Epic and acceptance

1. This spec, with §14's readings.
2. Formal: F1 and the law (§7), registered in `Auths.lean`,
   `Theorems.lean`, and the assurance manifest.
3. Model and codec.
4. Corpus vectors through the testkit generator, with a `CHECK_SITES` entry
   for each new site.
5. `approval_counts` and the law predicates, translated and refined.
6. The verifier steps, result fields, and trace facts.
7. The `approval-requirement-v1` handler, the registry manifest, and the
   error registry.
8. WASM, Python, TypeScript, and the independent Go and TypeScript verifiers
   agree on every vector.
9. The product re-cut (§10), the gateway quorum tests, and both north-star
   journeys.
10. `core/spec/v1`, AP-SPEC-001 §5.5, the threat model, the quorum guide,
    AP-SPEC-062, the README, and the paper draft.

**Acceptance:** every step on one revision with green hosted CI; every
existing composition vector (`threshold-2-of-3`, `missing-plan-leaf`,
`plan-actions-differ`, `composition-*`) keeps its class and code; the
gateway's hostile quorum table holds with zero provider entries for every
refused case. No public text says Auths is N on P4 until a preregistered
re-measurement at the new commit reports it.

## 12. Non-goals

- Request attributes and condition formulas (track B): §13.
- Key-level distinctness of approvers.
- The observer quorum (AP-SPEC-060 §16), a separate wire change.
- Approvals that name the actor.
- Changing study 006's recipes or results.

## 13. Next increments

- **Track B (R-C).** Canonical-action key 6 (request attributes), action-
  envelope key 19 (their digest, bound at `binding.request-attributes`),
  condition formulas with `all`, `any`, and `not` over typed atoms in
  three-valued logic, the `bool` attribute type, verifier-context key 17, the
  grant extension `action-condition-v1` and its byte-retention law, codes
  `action-condition-false`, `action-condition-attribute-missing`,
  `action-condition-attribute-type-mismatch`, and `action-condition-dropped`,
  `formal/Auths/Condition.lean` (F2), `condition_eval` (F3), and the
  condition vectors of spec 10. When canonical actions carry attributes,
  approval statement key 8 binds their digest.
- **Re-measurement.** A preregistered follow-up of study 006 at the new
  commit re-runs P4 (and R1 after track B) with an L0-only Auths cell.

## 14. Readings

Owner decisions are dated 2026-09-30 and final. The rest are PROVISIONAL,
each the narrower fail-closed reading, until the owner confirms them
(`docs/PROGRAM_BOARD.md` §4).

| # | Question | Reading | Status |
| --- | --- | --- | --- |
| 1 | Should an approval bind the requirement identifier (spec 10, Q1)? | Yes (A4, step 4). | Owner decision, 2026-09-30 |
| 2 | Self-approval (Q2) | No principal in the authority chain counts: E is every grant issuer and subject and every actor in the proof (§4.2), the rule of `observer-in-authority-chain`. E is a superset of the chains that authorized, fixed before any branch runs, so a requirement's verdict never depends on branch order. | Owner decision, 2026-09-30; the superset is PROVISIONAL |
| 3 | Invalid approvals (Q3) | Ignored, never denying (A10). | Owner decision, 2026-09-30 |
| 4 | R-C or R-B (Q4) | R-C, for track B. Unused here. | Owner decision, 2026-09-30 |
| 5 | Attribute type (Q5) | A new `bool` type, for track B. Unused here. | Owner decision, 2026-09-30 |
| 6 | Verifier-context conditions (Q6) | Key 17 exists, for track B. Unused here. | Owner decision, 2026-09-30 |
| 7 | Grant-carried requirements (Q7) | In this release (A14, §5). | Owner decision, 2026-09-30 |
| 8 | Limits (Q8) | Spec 10's values (§6). | Owner decision, 2026-09-30 |
| 9 | Authoritative quorum configuration (Q9) | The trusted context's approval requirement. The threat model's "exact plan" wording and the quorum helper's floors go, as a clean cutover. | Owner decision, 2026-09-30 |
| 10 | Spec number | 065: 063 and 064 are taken. | PROVISIONAL |
| 11 | How A6 checks status | Approver anchors carry a status policy (key 4), because A6 uses the trust anchor's rule, which is policy-driven. Only issuers with scope `any`, or unknown to the snapshot, speak about an approver: AP-SPEC-064's `own` and `anchors` scopes name trust anchors, and an approver anchor is none. Any denial skips the approval; missing, stale, or unsupported status makes it pending. | PROVISIONAL |
| 12 | Which signature failures are pending (A3) | Stage 3's classification: an unaccepted or uninstalled method, suite, or evidence type and every method result stage 3 maps to indeterminate are pending; every other failure skips. | PROVISIONAL |
| 13 | Order of the per-approval checks | Cheap equality checks first, then signature, then status, each skip before any work (§4.2). The order fixes the work reported, which the corpus compares. | PROVISIONAL |
| 14 | Approvals of an approver already counted | Not verified again (step 3). One digest per counted approver is reported. | PROVISIONAL |
| 15 | One evaluation per requirement | Cached by identifier, at most 64 per verification (§4.1). | PROVISIONAL |
| 16 | Where grant-carried requirements are evaluated | Per branch, after the observation stage, as spec 10's C5 places grant-carried conditions: a grant restricts only the authority its chain confers. | PROVISIONAL |
| 17 | Codes for a dropped or widened grant requirement | `delegation-expanded`, from the extension law (§5.1); no new code. | PROVISIONAL |
| 18 | A narrowed parent requirement | Every chain requirement is evaluated under its own identifier (§5.2). | PROVISIONAL |
| 19 | A grant requirement naming an unanchored approver | Its approvals are skipped (A3: no accepted method). | PROVISIONAL |
| 20 | `approval-context-invalid` (K above the approver count) | A context-constructor conformance case, not a corpus vector: no convention yet fixes the digest and code of an undecodable context across implementations (AP-SPEC-064 §7). | PROVISIONAL |
| 21 | Approval statement key 8 | Compared with `null` until track B (§3.3). | PROVISIONAL |
| 22 | Result object count | Includes signed approvals; the signature-count limit does not, since key 27 bounds them. | PROVISIONAL |
| 23 | Grant extension order | Strictly ascending by identifier, as context key 16. | PROVISIONAL |

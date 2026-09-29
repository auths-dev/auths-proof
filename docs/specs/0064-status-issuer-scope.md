# AP-SPEC-064: Status issuer scope

- **Status:** Implemented with the reason-code conformance work in one pull request. The decision below follows the recommendation of the auths-research proposal "03. Status issuer scope"; the owner delegated the choice, and each reading in §8 is PROVISIONAL until the owner confirms it (`docs/PROGRAM_BOARD.md` §4).
- **Evidence:** auths-research study 005, hypothesis H5, preregistered: with every participating root trusted as a status issuer, a foreign organization's status statement changed the verifying organization's verdict about its own actor or grant in 300 of 300 attempts, identically in five implementations. The behaviour was specified, so this is a design change, not a defect fix.
- **Changes:** the trusted context's `status-trust-rule` (a wire change), principal-status and grant-status evaluation, and the proof-carried status check of stage 2.
- **Normative language:** **MUST**, **MUST NOT**, **SHOULD**, and **MAY** specify implementation requirements.

## 1. Problem and claim

A status trust rule named a method, an issuer, and a sequence floor, and said nothing about which subjects the issuer may speak about. Among trusted statements the greatest sequence won, whoever issued it. So a verifier that trusts several organizations' roots as status issuers, which is the only way inside the protocol to honour each organization's revocation of its own actors, also let any of them revoke or reinstate the verifying organization's own principals and grants at its own boundary.

**Claim.** A status statement counts in a branch only when the verifier's context gives its issuer authority over that branch's trust anchor. A statement outside that authority changes no result: for every snapshot, anchor, and subject, the status result equals the result on the same snapshot with the out-of-scope statements removed.

**Not a claim.**

- Among issuers in scope for one anchor, selection is unchanged: the greatest sequence wins, so one in-scope issuer can still undo another's revocation (§8, S1).
- A statement from an issuer that no rule names is still visible and untrusted, as before.
- Governance between organizations (who may ask whom to revoke, and how fast) is outside the protocol.
- Snapshot size and work are unchanged: a partner's statements still cost reserved work at the verifier.

## 2. Wire format

`status-trust-rule` gains a required fourth entry, the scope (`core/spec/v1/auths-proof.cddl`):

| Scope | Encoding | Covers a branch evaluated under anchor A when |
|---|---|---|
| `own` | `{0: 0}` | A's principal is the rule's issuer |
| `anchors` | `{0: 1, 1: [1*1024 bounded-id]}` | A's identifier is listed; the list is strictly ascending |
| `any` | `{0: 2}` | always |

A rule without a scope does not decode (`malformed-proof`). There is no reader for the three-entry rule, and no migration: operators recompile their contexts. Proofs, grants, actions, and status statements do not change.

## 3. Context validity

A trusted context MUST be rejected at construction, which the verifier reports as `malformed-proof` at stage `decode`, when:

1. a rule with scope `own` names an issuer that is the principal of no trust anchor in the context;
2. a rule with scope `anchors` lists an identifier that names no trust anchor in the context; or
3. two rules in one snapshot name the same issuer with different scopes.

An `anchors` list that is empty or holds a repeated identifier does not decode (`malformed-proof`); one out of order is not canonical (`non-canonical-proof` natively; the independent verifiers report every context decode failure as `malformed-proof`).

## 4. Evaluation

A snapshot *knows* an issuer when one of its rules names it; the issuer's scope is the scope those rules carry. A snapshot statement is *out of scope* for a branch under anchor A when the snapshot knows its issuer and the issuer's scope does not cover A.

1. Out-of-scope statements MUST be excluded from every step of the principal-status and grant-status checks of that branch: the statement's control check, its critical-extension check, the method check, the rule for an absent statement, and selection.
2. An out-of-scope statement MUST NOT produce a result code or fail the proof in stage 5. It remains subject to the structural checks every input object receives in stages 1 to 3.
3. Visibility is decided per issuer, not per method: an issuer out of scope is invisible under every method, so it cannot force `status-method-mismatch` by signing under a method it has no rule for.
4. A statement whose issuer the snapshot does not know is not out of scope. It keeps its treatment, including `status-issuer-untrusted` when no trusted statement remains.
5. Work is reserved for the snapshot's full statement count, so reserved work does not depend on scope.
6. Within one branch, one evaluation governs a subject in every position it holds. Two branches under different anchors MAY reach different results for one principal.

## 5. Stage 2, step 9

A proof-carried status statement is compared only with snapshot statements that have its subject, method, and issuer, because a sequence number orders one issuer's statements under one method. A comparison across issuers would let a partner's statement deny the holder's own statement before any branch runs.

The step runs in two passes, which the reason-code conformance work fixed at the same time: first the rollback check for every carried principal-status statement and then every carried grant-status statement, then the holding check (`digest-mismatch`) in the same order. This is native's order.

## 6. Configuring scopes

Count each organization's trust anchors at the verifier first. Approval-quorum members are depth-zero anchors, so one organization often has several.

- **An organization with one anchor (its root):** `own` for that root's rules.
- **An organization with several anchors:** its issuer uses `anchors`, listing every one of that organization's anchor identifiers. `own` would leave its statements out of scope under the other anchors, which fails closed for those anchors' own principals (`missing-principal-status`) and fails open for their delegates and actors, whose revocations would be ignored.
- **The verifying organization:** as above, and `any` only if it must also revoke partners' subjects at its own boundary.
- **Each partner organization:** `own` or `anchors`, never `any`.
- **A status service or delegated issuer:** `anchors`, listing the anchors of the organization it serves.
- The earlier behaviour, every root trusted for every subject, is still expressible explicitly: `any` for every root.

SDK constructors require the scope explicitly; there is no default.

## 7. Tests

- **Corpus** (`core/testkit/auths-testkit/src/status_scope.rs`): a two-organization fixture with roots V and F, a status service S that is no anchor, and an issuer U that no rule names. Its 23 vectors cover in-scope revocation, every out-of-scope revocation and reinstatement (anchor, delegate, actor, grant), per-issuer visibility across methods, an out-of-scope statement with an unknown extension and one with no control binding, the anchor still failing closed, a partner's own revocation, delegation to S through `anchors`, the verifier's `any`, the carried-status key, an unknown issuer, the multi-anchor recipe and why `own` misses a second anchor, and a third organization's boundary. Every existing vector keeps its class and code.
- **Context constructor** (`core/conformance/v1/manifest.json`): the three invalid configurations of §3 as `context-constructor` cases expecting `invalid-verifier-context`, and the same three spliced into encoded context bytes in codec, native `verify_v1`, and Go unit tests, each `malformed-proof` at `decode`. They are not corpus vectors, because no convention yet fixes the digest and code an undecodable context reports across implementations.
- **Property:** random snapshots and scopes over the fixture's identities; the result under each anchor equals the result with that anchor's out-of-scope statements removed (§1).
- **Cross-language:** Rust, Go, and TypeScript agree on the whole corpus.

## 8. Readings this spec had to choose

Each is PROVISIONAL, taken as the recommended or narrower reading.

1. **Option.** Explicit scope on each rule (this spec), rather than implicit owner scope with no wire change, issuers named in signed status policies, or filtering outside the protocol. Implicit scope cannot express a service key or the verifier's own authority over partners, and filtering cannot be enforced on independent verifiers.
2. **D1.** An out-of-scope statement is ignored and returns no code. A new denial code would still let a partner turn an authorized verdict into a denial.
3. **D2.** Visibility is per issuer (§4.3).
4. **D3.** An unknown issuer keeps failing closed (§4.4).
5. **D4 / S1.** Selection among in-scope issuers is unchanged. Letting any in-scope revocation dominate (S2) is a separate selection change.
6. **D5.** The carried-status rollback check keys on subject, method, and issuer (§5). This reverses the 2026-09-25 reading that keyed it on the subject alone.
7. **Extensions.** The accepted-extension check covers statements in scope only (§4.1). This narrows the 2026-09-25 reading that covered every statement about an evaluated subject whatever its issuer.
8. **D6.** A context whose scope is inconsistent is invalid (§3).
9. **Registry manifest.** Not bumped, and the status methods' configuration identifiers are unchanged. A pre-change context with a status trust rule no longer decodes, and one without rules evaluates identically, so no decodable context can mean two things. This follows the precedent of the earlier status wire cutover that removed `purpose`.
10. **`any`** is not restricted: the kernel cannot tell which anchor belongs to the verifier itself.
11. **No diagnostic** records ignored statements; the portable result is unchanged.

## 9. Non-goals

- S2 selection across in-scope issuers.
- Status authority carried in signed grants.
- Ignoring, rather than failing closed on, statements from issuers no rule names.
- Corpus vectors for undecodable contexts, which need a cross-implementation convention for their digest and code first.

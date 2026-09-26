# AP-SPEC-062: Remote approval requests

- **Status:** Draft. The owner directed it on 2026-09-26 for the north star in `docs/PROGRAM_BOARD.md` §0.
- **Depends on:**
  - the approval quorum (`product/sdk/auths-approval-quorum`, `docs/product/APPROVAL_QUORUM.md`, merged in PR #142);
  - profile review displays (`auths_profile_api::ReviewDisplay`);
  - custody signing (`auths-custody`).
- **Enables:** the north-star step "two managers approve", with the managers on their own devices and not inside the agent's process.
- **Scope:** a portable, canonical approval request that an agent sends to each approver, and the approver's signed answer. The review an approver sees is derived by native code from the exact canonical action bytes they sign. The Python and TypeScript SDKs expose the operations as thin projections. The packaged CLIs add `auths approve` as the reference approval surface.
- **Normative language:** **MUST**, **MUST NOT**, **SHOULD**, and **MAY** specify implementation requirements.

## 1. Decision and claim

Today one process builds a quorum proposal and holds every approver's signer (`QuorumApprover`). That is correct for tests and wrong for people. Managers approve on their own laptops, phones, or chat clients, at different times, within the quorum window: 24 hours by default, configurable up to 7 days.

This spec separates the three roles:

1. **Requester**, usually the agent's application. It builds the proposal and sends one request per approver.
2. **Approver.** It opens the request, sees a review, and approves or declines by signing with its own custody.
3. **Collector**, usually the requester. It gathers responses and assembles the quorum proof.

**Claim.** When an approver's surface shows the review returned by `open_request`, the approver's signature, if they approve, covers exactly the action that review describes. An approval that does not match one envelope of the proposal byte for byte is rejected at collection with a stable code. It never becomes part of a proof.

**Not a claim.**

- **A surface can still lie.** The guarantee holds only if the surface shows what `open_request` returned. A surface that renders its own text instead is outside this guarantee. The SDKs and CLI MUST render only the returned review.
- **Transport and delivery are out of scope.** Delivery, notification, and routing (email, chat, links) belong to the application. The request is safe to carry over any channel, but it is not confidential: anyone who receives it sees the review.
- **A declined request does not revoke the action.** A decline stops this proposal. Any proposal that does not reach its threshold is refused by the verifier anyway.
- **Approver freshness is not a claim.** An approver may approve late within the window. The window and the approver's grant expiry bound this, as they do today.

## 2. Wire formats (product layer)

Both formats are deterministic CBOR with the core codec rules: canonical map keys, minimal integers, no tags or floats, and no indefinite forms. Unknown keys fail closed. Neither format is a core wire object. Core verification is unchanged.

### 2.1 `auths.approval-request/1`

```text
ApprovalRequest = {
  0: "auths.approval-request/1",
  1: request_id,            ; 32 bytes = SHA-256(domain || proposal_digest || approver_principal)
  2: canonical_action,      ; exact CanonicalAction bytes (core encoding)
  3: envelope,              ; exact unsigned ActionEnvelope bytes for THIS approver
  4: plan,                  ; exact AuthorizationPlan bytes (k_of_n), for display only
  5: approvers,             ; [ 1*16 PrincipalId ], in proposal order
  6: required,              ; uint, 1..=len(approvers)
  7: approver,              ; PrincipalId this request is addressed to
  8: requester,             ; PrincipalId of the envelope actor that built the proposal
  9: window,                ; { 0: not_before, 1: expires_at } in unix seconds
}
```

- `domain` is `"auths.approval-request/1\0"`. `proposal_digest` is the SHA-256 of the deterministic encoding of `[canonical_action, plan, [envelopes…]]`.
- The request carries **no human-readable text**. All review text is derived from `canonical_action` (§3.1).
- The encoded request MUST be at most 64 KiB.

### 2.2 `auths.approval-response/1`

```text
ApprovalResponse = {
  0: "auths.approval-response/1",
  1: request_id,
  2: decision,              ; "approve" / "decline"
  3: approver,              ; PrincipalId
  4: body,                  ; approve  → SignedAction bytes for the request's envelope
                            ; decline  → SignedDecline bytes (§2.3)
  5: grants,                ; approver's grant chain (root first) with public control evidence
  6: action_evidence,       ; public control evidence for the signature
}
```

The encoded response MUST be at most 64 KiB. The grant chain is bounded by `MAX_APPROVAL_GRANTS`, and evidence by `MAX_STATEMENT_EVIDENCE`.

### 2.3 Signed decline

A decline is signed so the audit can show who refused and when. The approver signs `SHA-256("auths.approval-decline/1\0" || request_id || decided_at_be64)` with the same custody key and signature suite as an approval. `SignedDecline` carries `decided_at` and that signature.

A decline carries no authority. The verifier never consults it. The collector uses it only to stop collecting and to record the refusal.

### 2.4 Printable form

Requests and responses MAY travel as text, so they can be pasted into chat or email: `auths-ar1-` or `auths-as1-` followed by the base64url encoding (no padding) of the CBOR. The text form is bounded by the byte limits above.

## 3. Native operations

The operations live in the product layer, alongside `auths-approval-quorum`. They reuse `QuorumProposal`, `QuorumApproval`, and `ActionProfile::review_display`, and do not re-implement them.

### 3.1 Requester: `requests(proposal) -> [ApprovalRequest]`

Emits one request per listed approver, in proposal order. The operation is deterministic: the same proposal always gives the same bytes.

### 3.2 Approver: `open_request(bytes, profiles, now) -> ReviewedRequest`

This operation MUST perform every check below, in order, and fail closed with the first stable code (§5):

1. Decode within the limits, rejecting unknown keys and non-canonical encodings.
2. Check that `envelope`'s body digest, profile, permission, and budget equal those derived from `canonical_action`.
3. Check that `envelope`'s plan identifier equals the identifier of `plan`, and that `plan` is a `k_of_n` over exactly `approvers` with `k = required`.
4. Check that `envelope`'s actor is `approver`, and that `approver` is in `approvers`.
5. Check that `request_id` is recomputed correctly from the request's own contents.
6. Check that `now` lies inside `window`, and that `window` equals the envelope's validity window.
7. Find the registered profile for `canonical_action`'s profile identifier and obtain `review_display(canonical_action)`. An unregistered profile is refused, and no review is produced.

`ReviewedRequest` exposes:

- the review title and fields, with the display digest;
- who asked (`requester`) and who else is asked (`approvers`, `required`);
- the window;
- the `request_id`.

It holds the exact bytes that `approve` signs. No other path produces a `ReviewedRequest`.

### 3.3 Approver: `approve(reviewed, signer) -> ApprovalResponse` and `decline(reviewed, signer, now) -> ApprovalResponse`

- The signer's principal MUST equal `reviewed.approver`.
- `approve` signs the envelope through the existing custody signing request. The custody request's `display` is the same review, so a hardware or remote custodian shows the same fields.
- The custody request expires at the window's `expires_at`.

### 3.4 Collector: `collect(proposal, responses) -> Collection`

1. Decode each response.
2. Match it to its request by `request_id`, and reject a mismatched approver.
3. For an approval, require its signed envelope to equal the proposal's envelope for that approver, byte for byte. Otherwise reject it as `approval.response-mismatch`.
4. Reject a second response from the same approver as `approval.duplicate-response`.
5. Record each decline.

`Collection` reports, per approver, one of `pending`, `approved`, `declined`, or `rejected(code)`.

`Collection::assemble()` builds the proof through `QuorumProposal::assemble` once every listed approver has approved. Otherwise it returns `approval.incomplete`. The approver set is still fixed before signing, as `APPROVAL_QUORUM.md` requires. Choosing approvers after signing starts remains on the board's Not now list.

Signatures are checked by the verifier when the proof is used, not by `collect`. Before assembly, `collect` MAY check each signature locally so the requester learns of a bad approval early.

## 4. SDK and CLI surfaces

- **Python and TypeScript.** Each operation in §3 gets a thin typed projection: `approval_requests(proposal)`, `open_approval_request(data)`, `approve`, `decline`, and `collect_approvals`. Requests and responses are accepted as bytes or the printable form. The SDKs hold no validation logic, text templates, or constants. Public-API inventories and the WASM and native ABI manifests are updated in the same change.
- **CLI.** The packaged Python and npm CLIs gain:

  ```text
  auths approve <request-file-or-text> --signer <custody-config> [--decline] [--out <file>]
  ```

  The command:

  1. calls `open_approval_request`;
  2. prints the review exactly as returned (title, fields, display digest, requester, other approvers, window);
  3. asks `Approve this action? [y/N]`;
  4. calls `approve` or `decline`;
  5. writes the response.

  It never prints text that is not in the returned review. With a non-interactive terminal it refuses to approve unless `--yes` is given. It never approves by default.

## 5. Stable codes

All codes use the prefix `approval.`:

| Code | Meaning |
| --- | --- |
| `approval.malformed` | Not decodable within limits, non-canonical, or unknown key |
| `approval.oversized` | Byte or collection limit exceeded |
| `approval.action-mismatch` | Envelope does not describe `canonical_action` |
| `approval.plan-mismatch` | Plan identifier, approvers, or threshold disagree |
| `approval.not-addressed` | Envelope actor or signer is not the request's approver |
| `approval.request-id-mismatch` | `request_id` does not recompute |
| `approval.outside-window` | `now` outside the window, or window differs from envelope |
| `approval.profile-unregistered` | No registered profile can render the action |
| `approval.response-mismatch` | Signed envelope differs from the proposal's |
| `approval.duplicate-response` | Second response from one approver |
| `approval.incomplete` | Assembly attempted before every listed approver approved |

## 6. Fixtures and tests

- **Canonical fixtures.** `bindings/fixtures/approval/` holds requests, approvals, declines, and every §5 refusal. The fixtures are generated by a Rust generator, never written by hand. Rust, Python, and TypeScript MUST produce and accept identical bytes and identical codes.
- **The "shows one thing, signs another" case.** An attacker edits `canonical_action` in a request so it shows 15.00 while the envelope still describes 1500.00. `open_request` refuses it with `approval.action-mismatch`. The reverse edit is refused the same way. A response built by an attacker for a different envelope is refused at collection with `approval.response-mismatch`.
- **Gateway cases.** The quorum hostile suite gains a proof assembled from remote responses. It is authorized only at the threshold, and it is authorized exactly as the in-process quorum is.

## 7. North-star integration

- **README.** The journey's approval step becomes: the agent writes one request per manager, and each manager runs `auths approve`. Development keys remain development custody, and the README says so.
- **Journey tests.** `journey.py` and the npm journey exchange requests and responses as files. They add:
  - a declined manager, where the collector reports it and no refund is submitted;
  - a tampered request, where the approver's CLI refuses it and nothing is signed.
- **Audit bundle.** The bundle includes each response, so the audit can show who approved and who declined. The audit's per-refund verdicts are unchanged.

## 8. Epic and acceptance

1. **Fixtures first.** The generator and the §6 corpus exist. Done when the vectors fail against current code.
2. **Native operations.** §3 is implemented in the product layer. Done when every fixture and code agrees in Rust.
3. **SDKs.** The Python and TypeScript projections and ABI inventories are in place. Done when parity with Rust holds on the corpus.
4. **CLI.** `auths approve` works in both packaged CLIs. Done when an interactive and a `--yes` run pass package tests, and non-interactive without `--yes` refuses.
5. **North star.** The README, both journeys, and the audit bundle are updated. Done when the CI journey jobs pass with remote approvals, a decline, and a tampered request.

**Acceptance:** steps 1–5 on one revision with green hosted CI.

## 9. Non-goals

- Delivery channels such as Slack, email, and push. Applications build these on the SDK.
- Choosing approvers after signing starts. This stays on the board's Not now list.
- Encrypting requests. The application's channel provides confidentiality.
- Any change to core verification or core wire objects.

## 10. Readings this spec had to choose

| Question | Reading |
| --- | --- |
| Where the review text comes from | Only from `review_display(canonical_action)` of a registered profile. Requests carry no text. |
| Whether declines are signed | Yes, for the audit. They carry no authority. |
| Whether `collect` verifies signatures | Optional early check. The verifier is authoritative. |
| Request confidentiality | Not provided. It is visible to whoever receives it. |

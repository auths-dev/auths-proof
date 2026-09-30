# AP-SPEC-062: Remote approval requests

- **Status:** Implemented in draft PR #171 (epic steps 1–5). The owner directed it on 2026-09-26 for the north star in `docs/PROGRAM_BOARD.md` §0. Revised in PR #200 for native K-of-N approvals (AP-SPEC-065): requests carry an approval statement, responses carry a signed approval, and any `required` of the listed approvers suffice. The formats are now `/2`.
- **Depends on:**
  - the approval quorum (`product/sdk/auths-approval-quorum`, `docs/product/APPROVAL_QUORUM.md`, merged in PR #142) on native approvals (AP-SPEC-065);
  - profile review displays (`auths_profile_api::ReviewDisplay`);
  - custody signing (`auths-custody`).
- **Enables:** the north-star step "two managers approve", with the managers on their own devices and not inside the agent's process.
- **Scope:** a portable, canonical approval request that an agent sends to each approver, and the approver's signed answer. The review an approver sees is derived by native code from the exact canonical action bytes they sign. The Python and TypeScript SDKs expose the operations as thin projections. The packaged CLIs add `auths approve` as the reference approval surface.
- **Normative language:** **MUST**, **MUST NOT**, **SHOULD**, and **MAY** specify implementation requirements.

## 1. Decision and claim

An in-process quorum holds every approver's signer. That is correct for tests and wrong for people. Managers approve on their own laptops, phones, or chat clients, at different times, within the quorum window: 24 hours by default, configurable up to 7 days.

This spec separates the three roles:

1. **Requester**, usually the agent's application. It is the proposal's actor: it builds the proposal, signs the action itself, and sends one request per listed approver.
2. **Approver.** It opens the request, sees a review, and approves or declines by signing the request's approval statement with its own custody.
3. **Collector**, usually the requester. It gathers responses and, once any `required` listed approvers have approved, assembles the proof with the actor's signed action.

**Claim.** When an approver's surface shows the review returned by `open_request`, the approver's signature, if they approve, covers exactly the action that review describes, for exactly the requirement the request names. An approval that does not match the proposal's statement for its approver byte for byte is rejected at collection with a stable code. It never becomes part of a proof.

**Not a claim.**

- **A surface can still lie.** The guarantee holds only if the surface shows what `open_request` returned. A surface that renders its own text instead is outside this guarantee. The SDKs and CLI MUST render only the returned review.
- **Transport and delivery are out of scope.** Delivery, notification, and routing (email, chat, links) belong to the application. The request is safe to carry over any channel, but it is not confidential: anyone who receives it sees the review.
- **A declined request does not revoke the action.** A decline removes that approver from this proposal. The proposal proceeds if `required` other listed approvers approve; otherwise it cannot be assembled, and a proof that does not reach the installed threshold is refused by the verifier anyway.
- **Approver freshness is not a claim.** An approver may approve late within the window. The window, the actor's grant expiry, and the approver anchor's validity bound this.
- **The requester is not authenticated by the request.** `requester` is display information. The requester's own signature on the action is what authenticates it, and its approval would never count.

## 2. Wire formats (product layer)

Both formats are deterministic CBOR with the core codec rules: canonical map keys, minimal integers, no tags or floats, and no indefinite forms. Unknown keys fail closed. Neither format is a core wire object; the approval statement and signed approval they carry are (AP-SPEC-065). Core verification is unchanged by this spec.

### 2.1 `auths.approval-request/2`

```text
ApprovalRequest = {
  0: "auths.approval-request/2",
  1: request_id,            ; 32 bytes = SHA-256(domain || proposal_digest || approver_principal)
  2: canonical_action,      ; exact CanonicalAction bytes (core encoding)
  3: statement,             ; exact unsigned ApprovalStatement bytes for THIS approver
  4: approvers,             ; [ 1*16 PrincipalId ], strictly ascending: the requirement's approvers
  5: required,              ; uint, 1..=len(approvers): the requirement's threshold
  6: approver,              ; PrincipalId this request is addressed to
  7: requester,             ; PrincipalId of the actor that built the proposal
  8: window,                ; { 0: not_before, 1: expires_at } in unix seconds
}
```

- `domain` is `"auths.approval-request/2\0"`. `proposal_digest` is the SHA-256 of the deterministic encoding of the array `[canonical_action, statement]`: two byte strings holding the exact bytes of fields 2 and 3. `approver_principal` is the approver's principal identifier as UTF-8 text.
- The request carries **no human-readable text**. All review text is derived from `canonical_action` (§3.2).
- The encoded request MUST be at most 64 KiB, and `statement` at most 4 KiB. More than 16 approvers is `approval.oversized`; an empty approver list, or `required` outside `1..=len(approvers)`, is `approval.malformed`. `window` requires `not_before <= expires_at`.

### 2.2 `auths.approval-response/2`

```text
ApprovalResponse = {
  0: "auths.approval-response/2",
  1: request_id,
  2: decision,              ; "approve" / "decline"
  3: approver,              ; PrincipalId
  4: body,                  ; approve  → SignedApproval bytes (core encoding) for the request's statement
                            ; decline  → SignedDecline bytes (§2.3)
}
```

The encoded response MUST be at most 64 KiB. A signed approval carries its own control evidence, one to four objects. Approvers are named by the trusted context's approver anchors, so a response carries no grant chain.

### 2.3 Signed decline

A decline is signed so the audit can show who refused and when. The approver signs `SHA-256("auths.approval-decline/2\0" || request_id || decided_at_be64)` with the same custody key and signature suite as an approval. `SignedDecline` carries `decided_at`, that signature, and its control evidence:

```text
SignedDecline = {
  0: decided_at,            ; unix seconds
  1: principal_method,      ; the signature descriptor, as in an approval
  2: verification_method,
  3: suite,
  4: signature,             ; bytes over the digest above
  5: evidence,              ; [ 1*4 [ evidence_type, media_type, bytes ] ]
}
```

The evidence identifier is derived from the three values, as the core `EvidenceObject` rule does, so it is not carried.

The custody request for a decline uses object kind `approval-decline`, object identifier `request_id`, the 32-byte digest as signing preimage, and request identifier `approval-decline:<hex request_id>:<hex transaction binding>`, the core format for signing requests. Its display and expiry are those of an approval (§3.3).

A decline carries no authority. The verifier never consults it. The collector uses it only to stop collecting and to record the refusal.

### 2.4 Printable form

Requests and responses MAY travel as text, so they can be pasted into chat or email: `auths-ar2-` or `auths-as2-` followed by the base64url encoding (no padding) of the CBOR. The text form is bounded by the byte limits above. Surrounding ASCII whitespace is ignored; padding, a non-canonical encoding, or the other prefix is `approval.malformed`. Input that does not start with the prefix is read as CBOR.

## 3. Native operations

The operations live in the product layer, alongside `auths-approval-quorum`. They reuse `QuorumProposal`, `QuorumAction`, and `ActionProfile::review_display`, and do not re-implement them.

### 3.1 Requester: `requests(proposal) -> [ApprovalRequest]`

Emits one request per listed approver, in ascending approver order. The operation is deterministic: the same proposal always gives the same bytes. The requester is the proposal's actor, which the proposal refuses to list as an approver. The requester MAY send the requests to any or all of the approvers; the first `required` distinct approvals suffice.

### 3.2 Approver: `open_request(bytes, profiles, now) -> ReviewedRequest`

This operation MUST perform every check below, in order, and fail closed with the first stable code (§5):

1. Decode within the limits, rejecting unknown keys and non-canonical encodings.
2. Check that `statement`'s media type, body digest, permission, and budget equal those derived from `canonical_action`, that the statement carries no attributes, and that the action carries no detached attachments. Anything the review cannot show is refused. The statement is signed under `canonical_action`'s profile (AP-SPEC-065), so the profile needs no separate check.
3. Check that `approvers` are strictly ascending and do not include `requester`, and that the approval requirement over exactly `approvers` with threshold `required` has the statement's requirement identifier.
4. Check that `statement`'s approver is `approver` and that `approver` is in `approvers`.
5. Check that `request_id` is recomputed correctly from the request's own contents.
6. Check that `now` lies inside `window`, both ends inclusive, and that `window` equals the statement's validity window.
7. Find the registered profile for `canonical_action`'s profile identifier and obtain `review_display(canonical_action)`. An unregistered profile is refused, and no review is produced.

`ReviewedRequest` exposes:

- the review title and fields, with the display digest;
- who asked (`requester`) and who else is asked (`approvers`, `required`);
- the window;
- the `request_id`.

It holds the exact bytes that `approve` signs. No other path produces a `ReviewedRequest`.

### 3.3 Approver: `approve(reviewed, signer) -> ApprovalResponse` and `decline(reviewed, signer, now) -> ApprovalResponse`

- The signer's principal MUST equal `reviewed.approver`.
- `approve` signs the approval statement through the custody signing request for object kind `approval` (the core signing-object kind; request identifier `approval:<hex statement commitment>:<hex transaction binding>`). The signing input is the core approval preimage under `canonical_action`'s profile. The custody request's `display` is the same review, so a hardware or remote custodian shows the same fields.
- The custody request expires at the window's `expires_at`.

### 3.4 Collector: `collect(proposal, responses) -> Collection`

1. Decode each response.
2. Match it to its request by `request_id`, and reject a mismatched approver as `approval.not-addressed`. A response whose `request_id` names no request of this proposal cannot be attributed to an approver; it is reported as unattributed with `approval.response-mismatch`, and so is one that does not decode, with its decoding code.
3. For an approval, require its signed statement to equal the proposal's statement for that approver, byte for byte. Otherwise reject it as `approval.response-mismatch`.
4. Reject a second response from the same approver as `approval.duplicate-response`. The approver is then `rejected(approval.duplicate-response)` whatever the first response was: conflicting answers fail closed.
5. Record each decline.

`Collection` reports, per approver, one of `pending`, `approved`, `declined`, or `rejected(code)`, how many approved, and the unattributed responses by input position.

`Collection::assemble(action)` builds the proof through `QuorumProposal::assemble` from the actor's signed action once at least `required` listed approvers have approved, carrying every matching approval. Otherwise it returns `approval.incomplete`; an action that is not the proposal's envelope is `approval.action-mismatch`. Which approvers count is decided by who answers: "any K of these N, whoever responds".

Signatures are checked by the verifier when the proof is used, not by `collect`. Before assembly, `collect` MAY check each signature locally so the requester learns of a bad approval early.

## 4. SDK and CLI surfaces

- **Python and TypeScript.** Each operation in §3 gets a thin typed projection: `approval_requests(proposal)`, `open_approval_request(data)`, `approve`, `decline`, `collect_approvals`, and `assemble(action)` on the collection. The requester builds the proposal with `propose_mcp_approval` (`proposeMcpApproval`) from the approver principals, the threshold, and the actor with its optional terminal grant, and signs the action with its own custody signer (`sign_approval_action`, `signApprovalAction`). Requests and responses are accepted as bytes or the printable form. Refusals surface as `ApprovalRefused` carrying the stable code. The SDKs hold no validation logic, text templates, or constants. Public-API inventories and the WASM and native ABI manifests are updated in the same change.
- **CLI.** The packaged Python and npm CLIs, both installed as `auths`, gain:

  ```text
  auths approve <request-file-or-text> --signer <custody-config> [--decline] [--yes] [--out <file>]
  ```

  The command:

  1. calls `open_approval_request`;
  2. prints the review exactly as returned (title, fields, display digest, requester, other approvers, window) and the signer's custody kind when it is development custody;
  3. asks `Approve this action? [y/N]`, or `Decline this action? [y/N]` with `--decline`;
  4. calls `approve`, or `decline` with `--decline`;
  5. writes the response's printable form to `--out`, or to standard output.

  It never prints text about the action that is not in the returned review; the labels around the review and the prompt are fixed. The review and prompt go to standard error. With a non-interactive terminal it refuses to answer unless `--yes` is given. It never approves by default: any answer other than `y` or `yes` signs nothing. A refused request signs nothing.

  `--signer` names an `auths.approval-signer/1` JSON file: `custody` is `development-ed25519` with `seed_file` (a 32-byte seed, relative to the file), or `module` with `python` (`package.module:factory`) and `node` (a module path exporting `createSigner`); each factory receives the configuration and returns a custody signer. Approvers hold no grant chain: the trusted context names them.

## 5. Stable codes

All codes use the prefix `approval.`:

| Code | Meaning |
| --- | --- |
| `approval.malformed` | Not decodable within limits, non-canonical, or unknown key |
| `approval.oversized` | Byte or collection limit exceeded |
| `approval.action-mismatch` | Statement does not describe `canonical_action`, or the action to assemble is not the proposal's envelope |
| `approval.requirement-mismatch` | Requirement identifier, approvers, or threshold disagree, or the requester is listed |
| `approval.not-addressed` | Statement approver or signer is not the request's approver |
| `approval.request-id-mismatch` | `request_id` does not recompute |
| `approval.outside-window` | `now` outside the window, or window differs from the statement's |
| `approval.profile-unregistered` | No registered profile can render the action |
| `approval.response-mismatch` | Signed statement differs from the proposal's |
| `approval.duplicate-response` | Second response from one approver |
| `approval.incomplete` | Assembly attempted before `required` listed approvers approved |

## 6. Fixtures and tests

- **Canonical fixtures.** `bindings/fixtures/approval/` holds requests, approvals, declines, and every §5 refusal. The fixtures are generated by a Rust generator, never written by hand. Rust, Python, and TypeScript MUST produce and accept identical bytes and identical codes.
- **The "shows one thing, signs another" case.** An attacker edits `canonical_action` in a request so it shows 15.00 while the statement still describes 1500.00. `open_request` refuses it with `approval.action-mismatch`. The reverse edit is refused the same way. A response built by an attacker for a different statement is refused at collection with `approval.response-mismatch`.
- **Gateway cases.** The quorum hostile suite includes proofs assembled from remote responses by every pair of managers. Each is authorized exactly as the in-process quorum is; one answer, or two declines, leaves nothing to assemble.

## 7. North-star integration

- **README.** The journey's approval step becomes: the agent writes one request per manager, and any two managers run `auths approve`. Development keys remain development custody, and the README says so.
- **Journey tests.** `journey.py` and the npm journey exchange requests and responses as files. They add:
  - declined managers: with one decline and two approvals the refund proceeds; with two declines the collector reports it and no refund is submitted;
  - a tampered request, where the approver's CLI refuses it and nothing is signed.
- **Audit bundle.** The bundle includes each response, so the audit can show who approved and who declined. The audit's per-refund verdicts are unchanged. The responses travel in an optional top-level `approval_responses` list of `{operation_id, response}` (the printable form), because a declined refund has no submission entry. `auths-gateway audit` decodes each one, refuses a bundle with a malformed response as `audit.bundle-malformed`, and lists `{operation_id, approver, decision, decided_at}` in the report. It does not verify a decline's signature, which carries no authority.
- **No local pre-check.** The agent's collection checks statements byte for byte and does not verify signatures (§3.4). The examples submit the assembled proof and let the gateway's verifier decide, so a proposal whose threshold the agent lowered to one is refused by the gateway with `approval-threshold-not-met`, without a lowered local trust.

## 8. Epic and acceptance

1. **Fixtures first.** The generator and the §6 corpus exist. Done when the vectors fail against current code.
2. **Native operations.** §3 is implemented in the product layer. Done when every fixture and code agrees in Rust.
3. **SDKs.** The Python and TypeScript projections and ABI inventories are in place. Done when parity with Rust holds on the corpus.
4. **CLI.** `auths approve` works in both packaged CLIs. Done when an interactive and a `--yes` run pass package tests, and non-interactive without `--yes` refuses.
5. **North star.** The README, both journeys, and the audit bundle are updated. Done when the CI journey jobs pass with remote approvals, a decline, and a tampered request.

**Acceptance:** steps 1–5 on one revision with green hosted CI.

## 9. Non-goals

- Delivery channels such as Slack, email, and push. Applications build these on the SDK.
- Encrypting requests. The application's channel provides confidentiality.
- Any change to core verification or core wire objects.

## 10. Readings this spec had to choose

| Question | Reading |
| --- | --- |
| Where the review text comes from | Only from `review_display(canonical_action)` of a registered profile. Requests carry no text. |
| Whether declines are signed | Yes, for the audit. They carry no authority. |
| Whether `collect` verifies signatures | Optional early check. The verifier is authoritative. |
| Request confidentiality | Not provided. It is visible to whoever receives it. |
| What `proposal_digest` covers | The request carries only its addressed approver's statement, so an approver cannot recompute a digest over every statement. The digest covers `[canonical_action, statement]` for this approver; the statement's requirement identifier already fixes the whole approver set and threshold. |
| Who the requester is | The proposal's actor, which signs the action and is never a listed approver: its approval would never count (AP-SPEC-065). `open_request` refuses a request whose requester is listed with `approval.requirement-mismatch` at check 3. The requester is not authenticated by the request. |
| What check 2 compares | Media type, body digest, permission, and budget, no statement attributes, and no detached attachments, since the review renders only the body. The profile is bound by the approval's signing input. |
| How check 3 is decided | By rebuilding the approval requirement from `approvers` and `required` and comparing its identifier with the statement's. Unordered or duplicate approvers are refused here. |
| How a decline reaches custody | Through the custody signer contract with the product object kind `approval-decline`, in both SDKs. An approval uses the core signing-object kind `approval`. |
| Collection of unattributable and conflicting responses | An unknown `request_id` or an undecodable response is reported as unattributed and never counts. Any second response for one approver rejects that approver with `approval.duplicate-response`, even if the first was an approval. |
| The CLI's name | `auths approve`. The SDK packages ship one CLI, named `auths`, so the command is `auths approve`. This reverts the earlier reading, which avoided the name `auths`: on 2026-09-26 the owner chose `auths` as the packaged CLI's name, the deployment binary of `auths-node` was renamed `auths-node` to free it, and the separate identity CLIs that also installed `auths` were retired. `cargo xtask public-naming` refuses any second executable named `auths`. |
| The CLI's decline and default | `--decline` asks to confirm the decline; without it only `y`/`yes` approves and any other answer signs nothing. Non-interactive runs need `--yes` for either. |
| Where responses live in the audit bundle | A top-level optional `approval_responses` list, because declined refunds have no entry. The report lists them; verdicts never depend on them. |
| Whether the SDK exposes the review type as `ReviewedRequest` | The SDK names are `ApprovalReview` (Python and TypeScript), since the TypeScript API gate refuses a prefixed twin of `ApprovalRequest`. The native type keeps `ReviewedRequest`. |
| Whether the native-approval formats keep `/1` | No. Requests and responses changed shape (a statement replaces the envelope and plan; responses carry no grant chain), so the schemas and printable prefixes are `/2` (`auths-ar2-`, `auths-as2-`) and the decline domain is `auths.approval-decline/2`. Prelaunch, `/1` is not read. |
| How many approvals assembly carries | Every matching approval collected, not just the first `required`, ordered by approval digest, so one approval that fails verification later does not by itself lose the quorum. The verifier counts each listed approver once. |
| What the audit's `approvals` lists | The approvers whose approvals the verified proof counted, from the result's approval satisfactions, not the actors of the authorized branches. |

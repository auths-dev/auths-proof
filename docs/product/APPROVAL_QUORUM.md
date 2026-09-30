# Approval quorum: any two of three managers approve before the agent acts

An approval quorum lets an agent submit an action only after a threshold of
named approvers have each approved that exact action. Any `K` of the `N`
approvers suffice, whoever responds. The Python and TypeScript SDKs author
the proof; the verifier, and the gateway in front of the provider, enforce
the threshold from the operator's installed trust
([AP-SPEC-065](../specs/0065-native-k-of-n-approvals.md)).

| Claim | Owner |
| --- | --- |
| One canonical action, signed once by the actor under its own grant chain | Auths SDK (native `auths-approval-quorum`) |
| One approval statement per approver, bound to the action and the requirement | That approver's custody signer |
| Who may approve and how many must | The operator's trusted context: approver anchors and one approval requirement |
| Refusal before any credential lease; one provider entry per authorized action | The gateway |

## How the threshold is enforced

Approvals are not plan branches. The operator installs a trusted context
that:

- anchors the actor's authority as usual (a trust anchor and grants);
- names each approver with an approver anchor: its principal, accepted
  principal methods, validity, and status policy. An approver anchor grants
  no authority;
- carries one approval requirement: the approver principals and `K`.

Every approval statement binds the requirement's identifier, so a proof
cannot lower `K` or change the set: approvals signed for any other
requirement never count. Each listed approver counts once. An approval by an
unlisted principal, a stray or forged approval, a repeated one, or one by any
principal of the action's own authority chain (self-approval) never counts,
and invalid approvals are ignored rather than denying. Order never matters.

Approvers are compared by principal identifier, not by key. One key anchored
under two principal methods is two principals; anchor each approver's key
under one method.

The gateway verifies natively against that context before it claims the
operation or leases a credential. The hostile cases in
`product/runtime/auths-gateway/src/quorum_tests.rs`, driven from
`bindings/fixtures/gateway/approval-quorum.json`, record:

| Case | Gateway result | Provider entries | Credential leases |
| --- | --- | --- | --- |
| Managers A and B (C silent) | authorized | 1 | 1 |
| Managers A and C | authorized | 1 | 1 |
| Managers B and C | authorized | 1 | 1 |
| All three managers | authorized | 1 | 1 |
| One manager | denied `approval-threshold-not-met` | 0 | 0 |
| No approvals | denied `approval-threshold-not-met` | 0 | 0 |
| One manager approves twice | denied `approval-threshold-not-met` | 0 | 0 |
| One manager and one outsider | denied `approval-threshold-not-met` | 0 | 0 |
| Two managers and one outsider | authorized; the outsider does not count | 1 | 1 |
| Approvals for a requirement lowered to 1 | denied `approval-threshold-not-met` | 0 | 0 |

A replay of an authorized action is refused by the gateway's one-use claim.

## Who approves is decided by who answers

A proposal lists the approvers and `K`, not who must sign. Assembly needs
only the approvals collected so far: once `K` distinct listed approvers have
approved, the proof can be assembled, and the others need not answer. Every
matching approval collected is carried, so one approval that later fails
verification does not by itself lose the quorum. The actor is never a listed
approver; the SDK refuses to list it.

## The approval window

Human approvers need hours, not seconds. The action and every approval carry
the same validity: from `evaluation_time` for `validity_seconds`, which
defaults to 24 hours and is at most 7 days. Both values are held only in
`auths-approval-quorum`; the single-signer defaults (30 s, at most 300 s)
are unchanged. The window is cut to the actor's terminal-grant expiry, and
the arithmetic is the same core rule single-signer authoring uses. Each
approver anchor's validity must also cover the evaluation time.

Every approval must be collected, and the proof verified by the gateway,
inside the window. The gateway authorizes a quorum 23 hours after approval
and denies it with `action-outside-validity` after the window, before any
credential lease. The window is not a replay defence: the gateway's durable
one-use claim refuses a second entry inside and after it. `authored.requirement`
reports the window as `valid_from` and `valid_until` (`validFrom` and
`validUntil` in TypeScript).

## Python

```python
from pathlib import Path

from auths.authoring import author_mcp_quorum_proof
from auths.gateway import GatewayClient, GatewayEndpoint

authored = await author_mcp_quorum_proof(
    contract=TOOL,
    command=command,
    actor=agent_signer,
    grants=agent_grants,             # root first; empty when the actor is anchored
    required=2,
    approvers=[manager_a, manager_b, manager_c],
    signers=[manager_a_signer, manager_c_signer],
    trusted_context_template=operator_template,
    challenge=installed_challenge,
    evaluation_time=now,
)
gateway = GatewayClient(GatewayEndpoint(Path("/run/auths/app.sock")))
result = await gateway.submit(proof=authored.proof, action=authored.action)
```

`signers` are the approvers asked in process; each must be listed, and there
must be at least `required`. `authored.requirement` projects the requirement:
threshold, approvers, requirement identifier, and window. The operator's
template names the approvers with `ApproverAnchor` and the requirement with
`ApprovalRequirement` (`auths.self_hosted`).

## TypeScript

```ts
import { authorMcpQuorumProof } from "@auths-dev/sdk/self-hosted";
import { GatewayClient, GatewayEndpoint } from "@auths-dev/sdk/gateway";

const authored = await authorMcpQuorumProof({
  contract: tool,
  command,
  actor: agentSigner,
  grants: agentGrants,
  required: 2,
  approvers: [managerA, managerB, managerC],
  signers: [managerASigner, managerCSigner],
  trustedContextTemplate: operatorTemplate,
  challenge: installedChallenge,
  evaluationTime: now,
});
const gateway = new GatewayClient(new GatewayEndpoint("/run/auths/app.sock"));
const result = await gateway.submit({ proof: authored.proof, action: authored.action });
```

Each approver's custody signer sees the same review display, including the
requirement ("any K of N") and its identifier, and signs its own approval
statement. The actor and the approvers are asked concurrently; signers are
not closed by the SDK.

## Remote approvals: approvers on their own devices

[AP-SPEC-062](../specs/0062-remote-approval-requests.md) separates the
requester, the approvers, and the collector. The requester is the actor: it
builds the proposal, writes one request per listed approver, and signs the
action itself; each approver opens its request, sees the review native code
derives from the exact canonical action, and signs its approval statement
with its own custody; the collector matches responses and assembles once `K`
listed approvers have approved.

```python
from auths.authoring import (
    approval_requests, approve, collect_approvals, open_approval_request,
    propose_mcp_approval, sign_approval_action,
)

proposal = propose_mcp_approval(
    contract=TOOL, command=command, required=2,
    approvers=[manager_a, manager_b, manager_c],
    actor=agent, actor_grant=agent_grant,
    challenge=installed_challenge, evaluation_time=now,
)
requests = approval_requests(proposal)          # one auths-ar2- text per manager
# on each approver's device:
review = open_approval_request(request_text)    # native checks, native review
response = await approve(review, my_signer)     # or decline(review, my_signer)
# back at the collector, once any two managers answered:
action = await sign_approval_action(proposal, agent_signer, grants=agent_grants)
proof = collect_approvals(proposal, responses).assemble(action)
```

TypeScript has the same operations (`proposeMcpApproval`, `approvalRequests`,
`openApprovalRequest`, `approve`, `decline`, `signApprovalAction`,
`collectApprovals`). Both
packaged CLIs ship `auths approve <request> --signer <config>`, which
prints only the returned review and signs only on an explicit yes.

- A request carries no text: the review comes only from the registered
  profile's `review_display` of its canonical action, and the custody request
  shows the same fields and expires at the window's end.
- A request whose display and statement disagree (for example edited to show
  15.00 while the statement approves 1500.00) is refused with
  `approval.action-mismatch`. A response signed for a different statement is
  refused at collection with `approval.response-mismatch`.
- A decline is signed for the audit and carries no authority. It removes
  that approver; the proposal proceeds if `K` others approve, and otherwise
  nothing is submitted.
- The gateway hostile suite assembles every pair of managers from remote
  responses; each proof is byte-identical to the in-process quorum.

`bindings/fixtures/approval/remote-approval.json` is the corpus Rust, Python,
and TypeScript reproduce byte for byte, including every `approval.*` code.

## Runnable examples

`examples/approval-quorum/python/two_of_three.py` and
`examples/approval-quorum/typescript/two-of-three.mjs` author an agent's action
approved by any two of three managers from the fixture's public test keys,
show that a single approval is refused with `approval-threshold-not-met`, and
check that the proofs are byte-identical to the gateway vectors. Python and TypeScript produce the same
bytes and reach the same decisions on every vector.

`examples/stripe-refund-approval` puts an agent holding a bounded grant behind
any two of three managers: the trust names the managers as approvers and
requires two of them, a manager acting as the agent cannot approve its own
refund, and the gateway also enforces the agent's refund ceiling and daily
count. `auths-gateway audit` re-verifies every refund
offline.

## What this does not claim

- Approvers are not authenticated as humans; a signature proves control of a
  key the operator anchored.
- Membership changes are trust changes: the operator installs a new trusted
  context.
- The quorum authorizes one exact action. It does not qualify the provider or
  prove the effect; see the gateway's recorded outcomes.

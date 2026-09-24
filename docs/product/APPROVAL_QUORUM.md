# Approval quorum: two of three managers approve before the agent acts

An approval quorum lets an agent submit an action only after a threshold of
named approvers have each signed that exact action. The Python and TypeScript
SDKs author the proof; the verifier, and the gateway in front of the
provider, enforce the threshold from the operator's installed trust.

| Claim | Owner |
| --- | --- |
| One canonical action; one envelope per approver under a core `k_of_n` plan | Auths SDK (native `auths-approval-quorum`) |
| Each approver's signature | That approver's custody signer |
| Who is a member and how many distinct members must approve | The operator's trusted context |
| Refusal before any credential lease; one provider entry per authorized quorum | The gateway |

## How the threshold is enforced

The plan inside a proof is chosen by whoever assembles it, so it never sets
the threshold. The operator installs a trusted context that:

- anchors exactly the member principals (a principal that is not anchored
  produces a denied branch and does not count), and
- requires `k` authorized branches from `k` distinct actors (two approvals
  signed by one manager count once).

The gateway verifies natively against that context before it claims the
operation or leases a credential. The hostile cases in
`product/runtime/auths-gateway/src/quorum_tests.rs`, driven from
`bindings/fixtures/gateway/approval-quorum.json`, record:

| Case | Gateway result | Provider entries | Credential leases |
| --- | --- | --- | --- |
| Two of three managers | authorized | 1 | 1 |
| One manager, plan lowered to 1-of-1 | denied `composition-requirement-not-met` | 0 | 0 |
| Plan of two, one approval missing | denied `missing-reference` | 0 | 0 |
| One manager signs twice | denied `composition-requirement-not-met` | 0 | 0 |
| One manager and one outsider | denied `untrusted-root` | 0 | 0 |
| Two managers and one outsider | authorized; the outsider does not count | 1 | 1 |
| Three of three managers | authorized | 1 | 1 |

A replay of an authorized quorum is refused by the gateway's one-use claim.

## The approver set is fixed before the first signature

Every approver signs an envelope that commits to the whole plan, and the
verifier requires one signed action for every leaf of the plan. So:

- list only the approvers you are asking; every listed approver must sign;
- to replace an approver who declines, start a new proposal with the new
  set, and the remaining approvers sign again;
- listing more approvers than the threshold is allowed. A listed approval
  that fails verification is a denied branch and does not block the others;
  the "two managers and one outsider" case above shows this.

An approver who declines stops authoring with `AuthoringUnsuccessful`. The
SDK never submits a partial quorum.

## The approval window

Human approvers need hours, not seconds. Every approval carries the same
validity: from `evaluation_time` for `validity_seconds`, which defaults to
24 hours and is at most 7 days. Both values are held only in
`auths-approval-quorum`; the single-signer defaults (30 s, at most 300 s)
are unchanged. The window is cut to the earliest terminal-grant expiry among
the approvers, and the arithmetic is the same core rule single-signer
authoring uses.

Every approval must be collected, and the proof verified by the gateway,
inside the window. Each approver's custody signing request stays valid for
the whole window. The gateway authorizes a quorum 23 hours after approval
and denies it with `action-outside-validity` after the window, before any
credential lease. The window is not a replay defence: the gateway's durable
one-use claim refuses a second entry inside and after it. `authored.plan`
reports the window as `valid_from` and `valid_until` (`validFrom` and
`validUntil` in TypeScript).

## Python

```python
from pathlib import Path

from auths.authoring import QuorumApprover, author_mcp_quorum_proof
from auths.gateway import GatewayClient, GatewayEndpoint

authored = await author_mcp_quorum_proof(
    contract=TOOL,
    command=command,
    required=2,
    approvers=[QuorumApprover(manager_a), QuorumApprover(manager_b)],
    trusted_context_template=operator_template,
    challenge=installed_challenge,
    evaluation_time=now,
)
gateway = GatewayClient(GatewayEndpoint(Path("/run/auths/app.sock")))
result = await gateway.submit(proof=authored.proof, action=authored.action)
```

`QuorumApprover.grants` carries the approver's grant chain, root first. Leave
it empty when the approver is itself a trust anchor. `authored.plan` projects
the core plan: threshold, approvers, plan identifier, canonical plan bytes,
and one proof reference per approver.

## TypeScript

```ts
import { authorMcpQuorumProof } from "@auths-dev/sdk/self-hosted";
import { GatewayClient, GatewayEndpoint } from "@auths-dev/sdk/gateway";

const authored = await authorMcpQuorumProof({
  contract: tool,
  command,
  required: 2,
  approvers: [{ signer: managerA }, { signer: managerB }],
  trustedContextTemplate: operatorTemplate,
  challenge: installedChallenge,
  evaluationTime: now,
});
const gateway = new GatewayClient(new GatewayEndpoint("/run/auths/app.sock"));
const result = await gateway.submit({ proof: authored.proof, action: authored.action });
```

Each approver's custody signer sees the same review display, including the
approval quorum and the plan identifier, and signs its own envelope. Signers
are asked concurrently and are not closed by the SDK.

## Runnable examples

`examples/approval-quorum/python/two_of_three.py` and
`examples/approval-quorum/typescript/two-of-three.mjs` author a two-of-three
approval from the fixture's public test keys, show that a single approval is
refused with `composition-requirement-not-met`, and check that the proof is
byte-identical to the gateway vector. Python and TypeScript produce the same
bytes and reach the same decisions on every vector.

## What this does not claim

- Approvers are not authenticated as humans; a signature proves control of a
  key the operator anchored.
- Membership changes are trust changes: the operator installs a new trusted
  context.
- The quorum authorizes one exact action. It does not qualify the provider or
  prove the effect; see the gateway's recorded outcomes.

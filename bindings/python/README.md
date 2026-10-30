# `auths`

Auths lets an application request a protected provider write without holding
the provider credential. The application authors a proof for one exact action
and submits the proof and the action to an operator-run Auths gateway. The
gateway holds the provider credential, verifies the proof against its
installed trust, performs the write, and returns a closed result.

## Install

```bash
pip install auths
```

Published wheels include the native implementation. Consumers do not need a
Rust toolchain.

## Submit one exact write through the gateway

The gateway is the single provider-write path. The application never sends a
URL, method, header, body, or token to it: only proof bytes and the exact
action bytes that proof authorizes.

```python
from pathlib import Path

from auths.gateway import GatewayClient, GatewayEndpoint, GatewayUnknown


gateway = GatewayClient(GatewayEndpoint(Path("/run/auths/gateway.sock")))
result = await gateway.submit(proof=proof, action=action)
if isinstance(result, GatewayUnknown):
    # The write may have happened. Ask the gateway, never retry blindly.
    outcome = await gateway.observe_outcome(operation_id)
print(result.outcome)
```

There is no Auths application token, remote executor URL, or provider
credential in application code. The gateway endpoint is an
operator-provisioned local socket. Every mutation result is one closed dataclass:
`GatewayDenied`, `GatewayIndeterminate`, `GatewayNotEntered`,
`GatewayUnknown`, `GatewayResponseRecorded`, `GatewayObserved`, or
`GatewayObservedByProvider`. The gateway also signs local stored outcomes (`observe_outcome`) and returns
stored pre-entry observations (`observe_pre_entry`). Independently approved
provider recovery uses `recover(source_operation, proof=..., action=...,
approval=...)`, returning bounded native recovery-report/refusal JSON bytes.
It returns no provider content or disclosure acknowledgement. The former
unapproved `observe_read_back` route is removed.

The native `auths.gateway-recovery/2` report includes retained lifetime read and
response-byte reservations, observation transport and freshness limits, the
selected response receipt time, escalation and proposed next actions. Requesting
another observation requires fresh independent authorization and exact approval.
The report grants no retry, redelivery or refund authority.

Mutation `observed-by-provider` results use `auths.gateway-public-evidence/1`.
They expose a native record-scoped hiding commitment and receipt time; raw
response digests and echo tokens stay in the protected journal. Older evidence
shapes are rejected. Bindings validate the shape and never compute the commitment.

The [Stripe refund example](../../examples/stripe-refund-approval/README.md)
runs the whole journey: a grant with limits, approvals from any two of three
managers, gateway submission, and an offline audit.

To start from a working deployment of that example instead, run
`auths init stripe-refund-approval --gateway PATH/TO/auths-gateway`. It writes
a new project directory whose `bin/` commands wrap the gateway and this SDK:
setup, an install that takes the Stripe key only on standard input, start and
stop, the agent's request and submit, `auths approve` for each manager, the
export, the offline audit, and a self-test that sends hostile refunds through
the gateway. The project is a development deployment: one OS user, a file
attempt store, and a software observer key, with development custody for the
root, the managers, and the agent. It cannot establish credential isolation.

## Author the proof

`auths.authoring` and `auths.self_hosted` generate an exact MCP-shaped tool
from a `profile.toml` and author its proof; `auths.identity` authors
identities. To require that any K of N named approvers approve one exact
action before its actor submits it, see
[approval quorum](../../docs/product/APPROVAL_QUORUM.md). The installed `auths`
command runs `auths generate` for exact-tool code and `auths approve` for
approval requests. For the operator's side, `auths.self_hosted` compiles the
trust a gateway installs (`compile_trusted_context`, with `ApproverAnchor`
and `ApprovalRequirement` for approvals), issues a root grant
through a custody signer (`author_root_grant`), and loads the
`auths.approval-signer/1` files `auths approve` reads (`load_signer_file`).

For an application-owned provider adapter that is not an Auths-qualified
vertical, see the
[self-hosted exact-operation quickstart](../../docs/product/SELF_HOSTED_PROFILE_QUICKSTART.md).
An application holding its own provider token can bypass
`auths.execution.run_once`, so that path is not credential-isolated; the
gateway path is.

## Public compatibility surfaces

`auths` contains the stable shared error, receipt, and runtime-fact types.
`auths.gateway` is the provider-write client. Effect-free verification and
identity helpers are available at `auths.verify` and `auths.identity`. The
exact installed module inventory is frozen in `api/public-api.txt` and
`bindings/public-topology-v1.json`.

Run `python -m auths doctor` to inspect bounded installed runtime, ABI, and
profile facts. The report never reads application secrets or prints protocol
payloads.

The wheel's effect-free APIs support Windows. The gateway client uses a Unix
socket and is available on macOS and Linux.

## Capability status

The closed product workflow is being relaunched under AP-SPEC-040. This README
does not promote repository-local claims to an independently reviewed or
published release.

- Implementation tier: `full-workflow-sdk`
- Evidence status: `repository-local-in-progress`
- Promoted tier: `verifier-binding`
- Publication status: `blocked`
- Promotion status: `blocked`

Publication, promotion, and independent-review status remain governed by
`sdk-capability.json`.

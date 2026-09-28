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
operator-provisioned local socket. Every result is one closed dataclass:
`GatewayDenied`, `GatewayIndeterminate`, `GatewayNotEntered`,
`GatewayUnknown`, `GatewayResponseRecorded`, `GatewayObserved`, or
`GatewayObservedByProvider`. The gateway can also sign a read-only observation
of a provider field (`observe_read_back`), of an operation's stored outcome
(`observe_outcome`), or return the pre-entry observations it stored for an
operation (`observe_pre_entry`).

The [Stripe refund example](../../examples/stripe-refund-approval/README.md)
runs the whole journey: a grant with limits, a 2-of-3 approval quorum, gateway
submission, and an offline audit.

## Author the proof

`auths.authoring` and `auths.self_hosted` generate an exact MCP-shaped tool
from a `profile.toml` and author its proof; `auths.identity` authors
identities. To require that a threshold of named approvers sign one exact
action before it is submitted, see
[approval quorum](../../docs/product/APPROVAL_QUORUM.md). The installed `auths`
command runs `auths generate` for exact-tool code and `auths approve` for
approval requests.

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

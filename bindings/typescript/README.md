# `@auths-dev/sdk`

Auths lets an application request a protected provider write without holding
the provider credential. The application authors a proof for one exact action
and submits the proof and the action to an operator-run Auths gateway. The
gateway holds the provider credential, verifies the proof against its
installed trust, performs the write, and returns a closed result.

## Install

```bash
npm install @auths-dev/sdk
```

The package includes its WASM implementation. Consumers do not need Rust.

## Submit one exact write through the gateway

The gateway is the single provider-write path. The application never sends a
URL, method, header, body, or token to it: only proof bytes and the exact
action bytes that proof authorizes.

```ts
import { GatewayClient, GatewayEndpoint } from "@auths-dev/sdk/gateway";

const gateway = new GatewayClient(new GatewayEndpoint("/run/auths/gateway.sock"));
const result = await gateway.submit({ proof, action });
switch (result.outcome) {
  case "denied":
  case "indeterminate":
  case "not-entered":
    console.log("no provider write:", result.code);
    break;
  case "unknown":
    // The write may have happened. Ask the gateway, never retry blindly.
    break;
  default:
    console.log(result.outcome, result.status);
}
```

There is no Auths application token, remote executor URL, or provider
credential in application code. The gateway endpoint is an
operator-provisioned local socket. The gateway can also sign a read-only
observation of a provider field (`observeReadBack`), of an operation's stored
outcome (`observeOutcome`), or return the pre-entry observations it stored for
an operation (`observePreEntry`).

The [Stripe refund example](../../examples/stripe-refund-approval/README.md)
runs the whole journey: a grant with limits, a 2-of-3 approval quorum, gateway
submission, and an offline audit.

Keep the exact `code` on a `not-entered` result. Qualification refusals and
`gateway.connection.restore-rollback` mean this submission stopped before
provider entry; they do not establish the outcome of any earlier attempt.
An `unknown` result means the write may have happened. Retain its operation
identifier and ask the operator to reconcile it with `reobserve`; do not
resubmit it as a new operation. Signed observations require a separately
configured observer. An absent observer does not establish a signed outcome.

The operator's `doctor` report lists each required production check and
returns nonzero if any check fails. Use the
[production operations runbook](../../docs/operations/GATEWAY_PRODUCTION_RUNBOOK.md)
for diagnosis, emergency stop, rotation and recovery.

## Author the proof

`@auths-dev/sdk/self-hosted` generates an exact MCP-shaped tool from a
`profile.toml`, and `@auths-dev/sdk/identity` authors identities. To require
approvals from any K of N named approvers before an agent's exact action is
submitted, see [approval quorum](../../docs/product/APPROVAL_QUORUM.md). The
installed `auths` command runs `auths generate` for exact-tool code and
`auths approve` for approval requests.

For an application-owned provider adapter that is not an Auths-qualified
vertical, see the
[self-hosted exact-operation quickstart](../../docs/product/SELF_HOSTED_PROFILE_QUICKSTART.md).
An application holding its own provider token can bypass `runOnce`, so that
path is not credential-isolated; the gateway path is.

## Public compatibility surfaces

`@auths-dev/sdk` contains the stable shared error, receipt, and runtime-fact
types. `@auths-dev/sdk/gateway` is the provider-write client.
Effect-free verification and identity helpers are available at
`@auths-dev/sdk/verify` and `@auths-dev/sdk/identity`. The exact installed
entry-point inventory is frozen in `api/public-api.txt` and
`bindings/public-topology-v1.json`.

The minimum consumer toolchain is TypeScript 5.2 with `ES2022` and
`ESNext.Disposable`, on Node 20.6.0 or newer. The gateway client uses a Unix
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

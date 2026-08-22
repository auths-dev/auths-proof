# `@auths-dev/sdk`

Auths lets an application call a protected provider operation through a local
agent. The application selects a non-secret connection alias; the agent owns
authorization, provider credentials, durable execution, recovery, and
receipts.

## Install

```bash
npm install @auths-dev/sdk @auths-dev/profile-stripe
```

The package includes its WASM implementation. Consumers do not need Rust.

## Application API shape

The generated clients below are the intended Stripe-like application surface.
In this revision the real Stripe, PostgreSQL, and OpenTofu routes remain
unqualified and are therefore not advertised by a production agent. Only the
separately built synthetic testkit agent exposes the Stripe-shaped route.

```ts
import { connect } from "@auths-dev/sdk";
import { Stripe } from "@auths-dev/profile-stripe";

await using session = await connect();
const stripe = new Stripe(session, { connection: "billing" });
const refund = await stripe.refunds.create({
  paymentIntent: "pi_123",
  amount: 2_000,
  currency: "usd",
});
console.log(refund.id, refund.auths.receiptIds);
```

That is the application contract: connect to the local Auths agent, choose
a generated domain client and optional connection alias, then call the domain
method. There is no Auths application token, remote executor URL, or provider
credential in application code. `AUTHS_AGENT_SOCKET` is optional non-secret
local discovery configuration.

The same open session can be shared by generated Stripe, PostgreSQL, OpenTofu,
and future domain packages. Each package owns its domain vocabulary and typed
results; the root SDK stays domain-neutral.

For operator provisioning and clean-machine setup, see the
[local-agent quickstart](../../docs/product/LOCAL_AGENT_SDK_QUICKSTART.md).
For a new domain or provider kind, follow the
[profile authoring guide](../../docs/product/PROFILE_AUTHORING.md).

## Outcomes and recovery

The ordinary domain method returns its success DTO directly. Use the adjacent
`*Outcome` method when the application needs exhaustive handling of denial,
conflict, partial completion, or durable recovery. Recovery handles and
receipts are opaque SDK values. Each execution receipt is one canonical,
self-contained container with its linked signed decision embedded; offline
verification never needs a separate companion receipt argument.

```ts
const outcome = await stripe.refunds.createOutcome({
  paymentIntent: "pi_123",
  amount: 2_000,
  currency: "usd",
});
if (outcome.kind === "completed") {
  console.log(outcome.value.id);
} else if (outcome.kind === "recovery-required") {
  await stripe.refunds.recover(outcome.recovery);
}
```

## Public compatibility surfaces

`@auths-dev/sdk` contains the stable application session, operation, error,
receipt, and recovery types. `@auths-dev/sdk/profile-runtime` is also public
and versioned, but it is an extension compatibility surface for generated
domain packages, not a generic caller-defined execution API. Applications
normally import only the root SDK and one or more
`@auths-dev/profile-<domain>` packages.

Effect-free verification and identity helpers remain available at
`@auths-dev/sdk/verify` and `@auths-dev/sdk/identity`. The exact installed
entry-point inventory is frozen in `api/public-api.txt` and
`bindings/public-topology-v1.json`.

The minimum consumer toolchain is TypeScript 5.2 with `ES2022` and
`ESNext.Disposable`, on Node 20.6.0 or newer. The stateful Unix-socket
transport is implemented on macOS and Linux, while real provider profiles
remain qualification-gated. Windows fails closed pending its named-pipe
security implementation. Run
`npx --package @auths-dev/sdk auths doctor` to inspect bounded installed
runtime, ABI, and profile facts. The report never reads application secrets or
prints protocol payloads.

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

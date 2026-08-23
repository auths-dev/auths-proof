# Local-agent SDK quickstart

This is the canonical AP-SPEC-040 launch path for Python and TypeScript. An
application talks only to a local Auths agent and never receives an Auths token
or a provider credential.

The local Unix-socket transport is implemented on macOS and Linux. Real
provider effect profiles remain unadvertised until their exact-revision
qualification gates pass. Windows clients fail closed until the named-pipe
server, peer SID/PID checks, DACL validation, and authority storage required by
AP-SPEC-040 are complete.

## What exists before application startup

An operator creates an owner-only state directory and starts the product with:

```bash
install -d -m 0700 /run/auths
auths agent serve \
  --config /secure/config/agent.toml \
  --state-directory /run/auths
```

This binds separate local sockets under `/run/auths`:

- an agent socket readable by authorized application workloads; and
- an owner-only admin socket used for authority and provider provisioning.

The deployment maps an observed local workload identity to already-issued
Auths authority. The application does not assert its own principal or submit a
proof on each operation. The agent validates the peer, selects the configured
authority, and opens a short-lived local session.

For a connected domain, an operator also creates a named connection. For
example, after creating the non-secret Stripe descriptor file, the privileged
CLI flow is:

```bash
auths --admin-socket /run/auths/admin.sock connections add stripe \
  --alias billing \
  --descriptor /secure/config/stripe-billing.json \
  --allow-workload refund-worker \
  --allow-profile auths.stripe.refund/1 \
  < /secure/input/stripe-api-key
```

The CLI reads protected input only from a non-terminal stream or an explicitly
protected file. It sends the credential through the admin socket; it never
writes it into an SDK config file or application environment variable. The
application later refers only to the non-secret alias `billing`.

## Python application after profile qualification

Install the root SDK and the generated domain distribution:

```bash
python -m pip install auths auths-profile-stripe
```

Point discovery at a non-default local socket only when necessary:

```bash
export AUTHS_AGENT_SOCKET=/run/auths/agent.sock
```

Then call the generated API:

```python
import auths
from auths_profiles.stripe import Stripe


async with auths.connect() as session:
    stripe = Stripe(session, connection="billing")
    refund = await stripe.refunds.create(
        payment_intent="pi_123",
        amount=2_000,
        currency="usd",
    )
    print(refund.id)
```

## TypeScript application after profile qualification

Install the root SDK and generated domain package:

```bash
npm install @auths-dev/sdk @auths-dev/profile-stripe
```

Then call the same domain operation:

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
console.log(refund.id);
```

## The application contract

Application configuration may contain `AUTHS_AGENT_SOCKET` and non-secret
connection aliases. It must not contain:

- an Auths access token;
- a remote Auths executor URL;
- a Stripe, PostgreSQL, OpenTofu, or other provider credential;
- an admin socket path; or
- caller-selected profile manifests, callbacks, or provider adapters.

`connect()` negotiates the profiles statically compiled into the local agent.
A generated client refuses a missing or digest-mismatched profile before an
effect request. The ordinary method returns the generated success DTO. Its
adjacent outcome method exposes typed refusal and recovery states, and durable
recovery is resumed with the opaque handle issued by the agent.

## Clean-machine acceptance check

A clean application machine or container needs only:

1. a supported Python or Node runtime;
2. the root SDK and required generated domain packages;
3. local permission to the agent socket; and
4. the optional non-secret socket path.

It does not need Rust, the Auths source tree, an Auths application token, a
provider SDK, or provider credentials. A launch test is complete only when the
operator has separately proven agent startup, workload mapping, connection
onboarding, one successful generated method call, restart-safe replay, and
receipt retrieval.

## One-command disposable proof

Repository contributors can exercise that complete application journey without
a real Stripe account or provider credential:

```bash
node bindings/testkit/local-agent/run.mjs
```

The command builds the explicitly synthetic `auths-testkit-agent`, installs
fresh root and generated Stripe packages into temporary Python and Node
consumers, and proves fresh execution, replay, conflict, signed receipt
verification, agent restart, and durable replay. The testkit provider is
synthetic and does not count as production Stripe or operator-deployment
evidence.

Operators should also keep the
[provider connection lifecycle runbook](../operations/PROVIDER_CONNECTION_LIFECYCLE_RUNBOOK.md)
and [profile recovery runbook](../operations/PROFILE_RECOVERY_RUNBOOK.md) with
their deployment. Contributors start with
[profile and provider authoring](PROFILE_AUTHORING.md).

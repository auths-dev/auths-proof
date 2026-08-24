# Production SDK contract: one typed provider operation

> **Qualification status:** this document shows the frozen application API,
> not a currently promoted live-provider route. The production agent advertises
> no Stripe, PostgreSQL, or OpenTofu effect profile until its exact revision has
> completed the required live, crash, recovery, receipt, and independent-review
> gates. The disposable testkit agent proves this API with a synthetic Stripe
> provider only.

Auths applications connect to a local agent and call a generated domain
client. The application supplies domain input and, optionally, a non-secret
connection alias. The agent owns workload authentication, authorization,
provider credentials, durable execution, recovery, and receipts.

## Application setup after profile qualification

Install the root SDK and the generated package for the domain you need:

```bash
npm install @auths-dev/sdk @auths-dev/profile-stripe
pip install auths auths-profile-stripe
```

TypeScript:

```ts
import { connect } from "@auths-dev/sdk";
import { Stripe } from "@auths-dev/profile-stripe";

await using session = await connect();
const refund = await new Stripe(session, { connection: "billing" }).refunds.create({
  paymentIntent: "pi_123",
  amount: 2_000,
  currency: "usd",
});
console.log(refund.id, refund.auths.receiptIds);
```

Python:

```python
import auths
from auths_profiles.stripe import Stripe

async with auths.connect() as session:
    refund = await Stripe(session, connection="billing").refunds.create(
        payment_intent="pi_123",
        amount=2_000,
        currency="usd",
    )
    print(refund.id, refund.auths.receipt_ids)
```

The ordinary application API has no Auths bearer token, remote executor URL,
provider credential, arbitrary provider request, or caller-supplied authority.
`AUTHS_AGENT_SOCKET` may select a local socket; it is not a credential.

## Operator setup after profile qualification

Before the application starts, a privileged operator:

1. installs and starts the local Auths agent;
2. provisions a provider connection through the separate admin listener;
3. maps the observed workload identity to allowed profiles and connection
   aliases; and
4. verifies socket ownership and runs the bounded doctor command.

Provider secrets enter only the privileged administration flow. They are
stored behind the configured credential store and never returned to the
application or generated package. See
[Local-agent SDK quickstart](LOCAL_AGENT_SDK_QUICKSTART.md) for the concrete
operator/application split and clean-machine acceptance checks.

Connection onboarding, rotation, disable, revocation, backup, and restore are
covered by the
[provider connection lifecycle runbook](../operations/PROVIDER_CONNECTION_LIFECYCLE_RUNBOOK.md).

## Failure and recovery

The generated method returns the domain success value. Denial, unavailability,
conflict, partial completion, and possible effect are represented by typed
errors. If an effect may have happened, Auths returns a sealed recovery handle;
the caller invokes the generated `recover` method and does not repeat the
original operation.

The same session can be shared by generated Stripe, PostgreSQL, OpenTofu, and
future domain clients. Adding a domain package does not add credentials or
provider-specific methods to the root SDK.

See [profile recovery](../operations/PROFILE_RECOVERY_RUNBOOK.md) for the
operator procedure and [profile authoring](PROFILE_AUTHORING.md) for adding an
operation or provider kind.

## Release status

This is the AP-SPEC-040 prelaunch cutover contract. Repository-local checks are
not independent review or publication authorization; the language-specific
`sdk-capability.json` files remain authoritative for promotion status.

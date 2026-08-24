# `auths`

Auths lets an application call a protected provider operation through a local
agent. The application selects a non-secret connection alias; the agent owns
authorization, provider credentials, durable execution, recovery, and
receipts.

## Install

```bash
pip install auths auths-profile-stripe
```

Published wheels include the native implementation. Consumers do not need a
Rust toolchain.

## Application API shape

The generated clients below are the intended Stripe-like application surface.
In this revision the real Stripe, PostgreSQL, and OpenTofu routes remain
unqualified and are therefore not advertised by a production agent. Only the
separately built synthetic testkit agent exposes the Stripe-shaped route.

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
    print(refund.id, refund.auths.receipt_ids)
```

That is the application contract: connect to the local Auths agent, choose
a generated domain client and optional connection alias, then call the domain
method. There is no Auths application token, remote executor URL, or provider
credential in application code. `AUTHS_AGENT_SOCKET` is optional non-secret
local discovery configuration.

The same open session can be shared by generated Stripe, PostgreSQL, OpenTofu,
and future domain packages. Each package owns its domain vocabulary and typed
results; the root SDK stays domain-neutral.

Profiles that need trusted provider-derived evidence expose a typed preflight
instead of accepting an untrusted provider artifact. For example, OpenTofu
protects planning before it permits apply:

```python
from auths_profiles.opentofu import OpenTofu, SourceFile


opentofu = OpenTofu(session, connection="production")
plan = await opentofu.plans.create(
    source_files=(SourceFile(path="main.tf", contents="..."),),
    variables=(),
    dependency_lock="...",
    modules=(),
    workspace="production",
)
result = await opentofu.saved_plans.apply(prepared_plan=plan.prepared_plan)
```

The opaque prepared-plan token is bound to the workload, connection generation,
configuration, backend state, and exact plan. The application never supplies
provider credentials or asserts that its own plan is trusted.

For operator provisioning and clean-machine setup, see the
[local-agent quickstart](../../docs/product/LOCAL_AGENT_SDK_QUICKSTART.md).
For a new domain or provider kind, follow the
[profile authoring guide](../../docs/product/PROFILE_AUTHORING.md).

## Outcomes and recovery

The ordinary domain method returns its success DTO directly. Use the adjacent
`*_outcome` method when the application needs exhaustive handling of denial,
conflict, partial completion, or durable recovery. Recovery handles and
receipts are opaque SDK values and cannot be forged by constructing a dict.
Each execution receipt is one canonical, self-contained container with its
linked signed decision embedded; offline verification never needs a separate
companion receipt argument.

```python
outcome = await stripe.refunds.create_outcome(
    payment_intent="pi_123",
    amount=2_000,
    currency="usd",
)
if isinstance(outcome, Completed):
    print(outcome.value.id)
elif isinstance(outcome, RecoveryRequired):
    recovered = await stripe.refunds.recover(outcome.recovery)
```

## Public compatibility surfaces

`auths` contains the stable application session, operation, error, receipt,
and recovery types. `auths.profile_runtime` is also public and versioned, but
it is an extension compatibility surface for generated domain distributions,
not a generic caller-defined execution API. Applications normally import only
`auths` and one or more `auths_profiles.<domain>` packages.

Effect-free verification and identity helpers remain available at
`auths.verify` and `auths.identity`. The exact installed module inventory is
frozen in `api/public-api.txt` and `bindings/public-topology-v1.json`.

Run `python -m auths doctor` to inspect bounded installed runtime, ABI, and
profile facts. The report never reads application secrets or prints protocol
payloads.

The wheel's effect-free APIs support Windows. The stateful Unix-socket
transport is implemented on macOS and Linux, while real provider profiles
remain qualification-gated. Windows fails closed pending the named-pipe
security implementation.

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

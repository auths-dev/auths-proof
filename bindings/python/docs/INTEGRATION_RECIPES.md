# Python integration recipes

## Application integration

Applications use only the local session and generated domain clients:

```python
import auths
from auths_profiles.postgresql import Assignment, PostgreSQL


async with auths.connect() as session:
    database = PostgreSQL(session, connection="orders")
    result = await database.updates.execute(
        relation="public.orders",
        tenant_key="tenant-42",
        assignments=(Assignment(column="state", value="paid"),),
    )
```

The alias is non-secret. Auths tokens, remote executor URLs, database URLs, and
credentials are not application inputs. See
`docs/product/LOCAL_AGENT_SDK_QUICKSTART.md` for operator provisioning.

## Generated package integration

`auths.profile_runtime` is public and versioned specifically so independently
installed generated distributions can bind to an open root session. It is not
a caller-defined profile API. New domains are contributed through the Rust
profile manifest, connection contract, semantics, fixtures, and generator;
applications do not register callbacks or dynamically load provider code.

## Outcome integration

Use direct methods for the common success path and `*_outcome` for exhaustive
handling. Outcome classes are sealed and discriminated. Conflict and
recovery-required outcomes carry an opaque `RecoveryHandle`; use the generated
group's `recover` or `recover_outcome` method rather than retrying the provider
effect.

## Operator and mechanism integration

Provider connection onboarding is privileged deployment work over the admin
socket. Credentials remain in the agent's credential store and are leased only
after authorization and durable claim.

Identity, custody, reservation, and bounded-transport extension contracts have
their own conformance suites. Passing one of those suites qualifies only the
named mechanism. It does not qualify a new provider domain, domain errors,
reconciliation behavior, or receipt semantics.

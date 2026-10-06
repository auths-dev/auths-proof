# Python integration recipes

## Application integration

Applications submit a proof and the exact action it authorizes to the
operator-run gateway, which is the single provider-write path:

```python
from pathlib import Path

from auths.gateway import GatewayClient, GatewayEndpoint


gateway = GatewayClient(GatewayEndpoint(Path("/run/auths/gateway.sock")))
result = await gateway.submit(proof=proof, action=action)
```

The socket path is non-secret operator configuration. Auths tokens, remote
executor URLs, provider URLs, and credentials are not application inputs; the
operator binds provider credentials to gateway connections.

## Unknown writes

A `GatewayUnknown` result means the provider write may have happened. Do not
retry it. Ask the gateway for the operation's signed outcome with
`observe_outcome`, or read the provider field back through the gateway with
`observe_read_back`. Both return gateway-signed bytes that can be attached to
a later action or kept for an offline audit.

## Operator and mechanism integration

Provider connection onboarding and recipe review are privileged gateway
operator work. Credentials remain in the gateway's connection store and are
leased only after proof verification and a durable attempt claim.

Identity, custody, reservation, and bounded-transport extension contracts have
their own conformance suites. Passing one of those suites qualifies only the
named mechanism. It does not qualify a new provider domain, domain errors,
reconciliation behavior, or receipt semantics.


## Production diagnostics and recovery

The operator's `auths-gateway doctor` reports `auths.gateway-readiness/1`,
with every required check and the optional observer state; any failed or
unmade check gives a nonzero exit. Keep this output on the operator plane.
The application receives `not-entered` with the gateway's exact stable code
when qualification or a restore floor prevents a lease. It needs operator
repair of the connection or signed inputs before another authorized operation
can proceed. An `unknown` write retains its operation identity and is
reconciled by read-only `reobserve`, without issuing another provider write.

Signed observations require a configured observer. Production may be ready
with no observer; that deployment reports signed outcomes unavailable.
The [production runbook](../../../docs/operations/GATEWAY_PRODUCTION_RUNBOOK.md)
covers disable/revoke during custody outages, exact-generation collection,
rotation, qualification expiry/revocation and restore-floor recovery.

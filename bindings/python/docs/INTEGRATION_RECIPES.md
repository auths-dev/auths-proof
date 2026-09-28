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

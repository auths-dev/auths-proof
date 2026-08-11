# Python integration recipes

These recipes define boundaries, not Auths semantics. Each adapter must declare
contract version 1, run the `auths.testkit` checks that apply to its port, and
name its support owner and credential boundary.

## Remote KMS or HSM custody

Implement `auths.custody.Signer`. `public_identity()` returns the public
descriptor for the configured remote key. `sign(request)` sends only
`request.signing_preimage` to the selected key and returns the exact
`request_id`, `principal`, and `transaction_digest` unchanged with the remote
signature. Bound the provider timeout, propagate task cancellation, perform no
hidden retry, and map ambiguous remote outcomes to `ProviderOperationError`.
Never accept arbitrary bytes outside `SigningRequest` and never export a
private key.

```python
class KmsSigner:
    kind = "example.kms"
    lifecycle = "durable"

    async def public_identity(self):
        return self._descriptor

    async def sign(self, request):
        signature = await self._client.sign(
            key_id=self._key_id,
            message=request.signing_preimage,
            timeout=self._timeout,
        )
        return SigningResponse(
            request.request_id,
            request.principal,
            request.transaction_digest,
            signature,
        )

    async def aclose(self):
        await self._client.aclose()
```

## Resolver-backed identity

Implement `IdentityResolver` and compose it with `ResolverIdentityMethod`.
Honor `maximum_bytes`, return one exact method and identity, preserve
provenance and history, and reject redirects or private-network destinations
unless the application explicitly configured them. The resolver returns typed
relationships and opaque material; the selected suite adapter interprets that
material.

## Durable SQLite runtime state

Install the separately versioned `auths-sqlite` package and construct
`auths_sqlite.SQLiteRuntimeStore`. The adapter supplies atomic challenge
claims, budget reservations, command compare-and-swap, and idempotent receipt
storage. Its database is an operational component: configure filesystem
permissions, encryption, backups, monitoring, and recovery for the deployment.

## OpenTelemetry

Implement `auths.observability.Telemetry.emit` by mapping `AuthsEvent.name`,
`operation`, `stage`, `outcome`, `observed_at`, and bounded attributes to the
deployment's OpenTelemetry API. Do not attach proof bytes, signatures,
credentials, keys, request bodies, provider payloads, or idempotency keys.
Exporter failures must not change an authorization result or execute an
effect.

## FastAPI

Create one application-owned dependency that builds a profile action from
already parsed route inputs, calls `AttachedAgent.authorize`, and renders the
three result variants. Pass the request's application idempotency identifier
to the matching gateway. Keep authentication, authority, retry, and receipt
meaning in Auths; the framework adapter owns only request lifetime and HTTP
translation.

```python
async def authorize_publish(report_id: str, request_id: str):
    decision = await agent.authorize(reports.publish(report_id))
    if decision.kind == "authorized":
        return await gateway.execute(
            decision.command,
            idempotency_key=request_id,
        )
    if decision.kind == "denied":
        raise HTTPException(status_code=403, detail=decision.code)
    raise HTTPException(status_code=503, detail=decision.code)
```

No framework, KMS, resolver, database, or telemetry vendor is imported by the
base `auths` wheel.

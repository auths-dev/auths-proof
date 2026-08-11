from auths.profiles.mcp import McpGatewayCall, McpProfile
from auths import ApplicationCredentialProvider  # type: ignore[attr-defined]
from auths import ApplicationExecutionStore  # type: ignore[attr-defined]
from auths import product_waist_conformance  # type: ignore[attr-defined]

assert ApplicationCredentialProvider
assert ApplicationExecutionStore
assert product_waist_conformance


async def capability_boundaries(profile: McpProfile, raw: bytes) -> None:
    async def execute(_call: McpGatewayCall) -> None:
        return None

    gateway = profile.gateway(execute)
    await gateway.execute(raw, idempotency_key="negative")  # type: ignore[arg-type]
    await gateway.execute_plan(raw, idempotency_key="negative")  # type: ignore[arg-type]

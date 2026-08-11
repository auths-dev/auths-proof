from auths.profiles.mcp import McpGatewayCall, McpProfile
from auths import ApplicationCredentialProvider  # pyright: ignore[reportAttributeAccessIssue]
from auths import ApplicationExecutionStore  # pyright: ignore[reportAttributeAccessIssue]
from auths import product_waist_conformance  # pyright: ignore[reportAttributeAccessIssue]

assert ApplicationCredentialProvider
assert ApplicationExecutionStore
assert product_waist_conformance


async def capability_boundaries(profile: McpProfile, raw: bytes) -> None:
    async def execute(_call: McpGatewayCall) -> None:
        return None

    gateway = profile.gateway(execute)
    await gateway.execute(raw, idempotency_key="negative")  # pyright: ignore[reportArgumentType]
    await gateway.execute_plan(raw, idempotency_key="negative")  # pyright: ignore[reportArgumentType]

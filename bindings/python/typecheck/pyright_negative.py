from auths.profiles.mcp import McpGatewayCall, McpProfile


async def capability_boundaries(profile: McpProfile, raw: bytes) -> None:
    async def execute(_call: McpGatewayCall) -> None:
        return None

    gateway = profile.gateway(execute)
    await gateway.execute(raw, idempotency_key="negative")  # pyright: ignore[reportArgumentType]
    await gateway.execute_plan(raw, idempotency_key="negative")  # pyright: ignore[reportArgumentType]

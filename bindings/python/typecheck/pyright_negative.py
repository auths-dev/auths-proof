from auths import McpGatewayCall, McpProfile


async def capability_boundaries(profile: McpProfile, raw: bytes) -> None:
    async def execute(_call: McpGatewayCall) -> None:
        return None

    gateway = profile.gateway(execute)
    await gateway.execute(raw)  # pyright: ignore[reportArgumentType]
    await gateway.execute_plan(raw)  # pyright: ignore[reportArgumentType]

from auths import McpGatewayCall, McpProfile


async def capability_boundaries(profile: McpProfile, raw: bytes) -> None:
    async def execute(_call: McpGatewayCall) -> None:
        return None

    gateway = profile.gateway(execute)
    await gateway.execute(raw)  # type: ignore[arg-type]
    await gateway.execute_plan(raw)  # type: ignore[arg-type]

from typing import Awaitable, Callable

from auths import (
    AttachedAgent,
    AuthorizationRequest,
    McpAuthorizationResult,
    McpGatewayCall,
    McpProfile,
)


async def authorize_and_execute(
    *,
    agent: AttachedAgent,
    profile: McpProfile,
    execute: Callable[[McpGatewayCall], Awaitable[str]],
) -> McpAuthorizationResult:
    action = profile.call("update_demo_record", {"value": "reviewed"})
    result = await agent.authorize(action, request=AuthorizationRequest())
    if result.kind == "authorized":
        await profile.gateway(execute).execute(result.command)
    elif result.kind == "denied":
        assert not result.explanation.retryable
    else:
        assert result.explanation.retryable
    return result

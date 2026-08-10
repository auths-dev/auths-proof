from typing import Awaitable, Callable

from auths import (
    AttachedAgent,
    AuthorizationRequest,
    McpAuthorizationResult,
    McpGatewayCall,
    McpPlanAuthorizationResult,
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


async def authorize_plan_and_execute(
    *,
    agent: AttachedAgent,
    profile: McpProfile,
    execute: Callable[[McpGatewayCall], Awaitable[str]],
) -> McpPlanAuthorizationResult:
    plan = profile.plan(
        (
            profile.call("prepare_report", {"month": "august"}),
            profile.call("publish_report", {"month": "august"}),
        )
    )
    result = await agent.authorize_plan(
        plan,
        requests=(AuthorizationRequest(), AuthorizationRequest()),
    )
    if result.kind == "authorized":
        await profile.gateway(execute).execute_plan(result.command)
    else:
        assert result.failed_index >= 0
        assert result.result.kind in ("denied", "indeterminate")
    return result

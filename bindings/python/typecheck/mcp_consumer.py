from auths import Auths, ExecutionResult
from auths.profiles import McpAction, McpClosedProvider


async def execute_exact_action(
    auths: Auths,
    action: McpAction,
    provider: McpClosedProvider,
) -> ExecutionResult:
    return await auths.execute(action=action, provider=provider)

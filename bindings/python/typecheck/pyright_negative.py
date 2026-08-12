from auths import ApplicationCredentialProvider  # pyright: ignore[reportAttributeAccessIssue]
from auths import ApplicationExecutionStore  # pyright: ignore[reportAttributeAccessIssue]
from auths import Auths
from auths.profiles import McpClosedProvider

assert ApplicationCredentialProvider
assert ApplicationExecutionStore


async def capability_boundaries(
    auths: Auths, provider: McpClosedProvider, raw: bytes
) -> None:
    await auths.execute(action=raw, provider=provider)  # pyright: ignore[reportCallIssue, reportArgumentType]

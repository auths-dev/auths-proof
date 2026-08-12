from auths import ApplicationCredentialProvider  # pyright: ignore[reportAttributeAccessIssue, reportUnknownVariableType, reportUnusedImport]  # noqa: F401
from auths import ApplicationExecutionStore  # pyright: ignore[reportAttributeAccessIssue, reportUnknownVariableType, reportUnusedImport]  # noqa: F401
from auths import Auths
from auths.profiles import McpClosedProvider


async def capability_boundaries(
    auths: Auths, provider: McpClosedProvider, raw: bytes
) -> None:
    await auths.execute(action=raw, provider=provider)  # pyright: ignore[reportArgumentType]

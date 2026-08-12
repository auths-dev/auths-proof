from auths import ApplicationCredentialProvider  # type: ignore[attr-defined]
from auths import ApplicationExecutionStore  # type: ignore[attr-defined]
from auths import Auths
from auths.profiles import McpClosedProvider

assert ApplicationCredentialProvider
assert ApplicationExecutionStore


async def capability_boundaries(
    auths: Auths, provider: McpClosedProvider, raw: bytes
) -> None:
    await auths.execute(action=raw, provider=provider)  # type: ignore[arg-type]

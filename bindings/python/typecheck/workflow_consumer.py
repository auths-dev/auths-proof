from auths import Auths
from auths.profiles import McpToolAuthority


async def delegate_narrower(
    auths: Auths,
    authority: McpToolAuthority,
) -> Auths:
    return await auths.delegate(authority=authority, name="records-child")

from __future__ import annotations

import asyncio
import json

from auths.verify import verify_receipt
from auths.integrations import development
from auths.profiles import mcp


async def main() -> None:
    calls = 0

    async def publish_report(arguments, _context):
        nonlocal calls
        calls += 1
        return {"published": arguments["report"]}

    provider = mcp.development_provider(tools={"publish_report": publish_report})
    async with development.create_auths(
        authority=mcp.allow_tools(["publish_report"])
    ) as auths:
        completed = await auths.execute(
            action=mcp.call_tool(name="publish_report", arguments={"report": "weekly"}),
            provider=provider,
            request_id="recipe-three-success",
        )
        if completed.kind != "completed":
            raise RuntimeError(f"unexpected result: {completed.kind}")
        verify_receipt(completed.receipt)
        denied = await auths.execute(
            action=mcp.call_tool(name="delete_report", arguments={"report": "weekly"}),
            provider=provider,
            request_id="recipe-three-denied",
        )
        if denied.kind != "denied" or calls != 1:
            raise RuntimeError("undeclared effect reached provider")
    print(
        json.dumps(
            {
                "recipe": "03-execute-exact-action",
                "outcome": "completed",
                "denied": True,
                "calls": calls,
            }
        )
    )


if __name__ == "__main__":
    asyncio.run(main())

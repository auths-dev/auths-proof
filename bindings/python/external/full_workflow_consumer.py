from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from auths.integrations import development
from auths.profiles import mcp
from auths.verify import verify_receipt


async def run(_: Path) -> None:
    calls = 0

    async def publish_report(arguments, context):
        nonlocal calls
        calls += 1
        if context.tool != "publish_report":
            raise RuntimeError("profile context changed the tool")
        return {"published": arguments["report"]}

    provider = mcp.development_provider(tools={"publish_report": publish_report})
    async with development.create_auths(
        authority=mcp.allow_tools(["publish_report"])
    ) as auths:
        result = await auths.execute(
            action=mcp.call_tool(name="publish_report", arguments={"report": "weekly"}),
            provider=provider,
            request_id="external-consumer",
        )
        if result.kind != "completed" or calls != 1:
            raise RuntimeError("installed wheel did not execute the exact action")
        verify_receipt(result.receipt)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: full_workflow_consumer.py <binding-vectors>")
    asyncio.run(run(Path(sys.argv[1]).resolve()))

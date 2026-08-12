from __future__ import annotations

import asyncio
import json

from auths.integrations import development
from auths.profiles import mcp


async def main() -> None:
    calls = 0

    async def publish_report(_arguments, _context):
        nonlocal calls
        calls += 1
        return {"published": True}

    provider = mcp.development_provider(tools={"publish_report": publish_report})
    async with development.create_auths(
        authority=mcp.allow_tools(["publish_report", "delete_report"])
    ) as auths:
        agent = await auths.delegate(
            authority=mcp.allow_tools(["publish_report"]),
            name="report-agent",
            expires_in_seconds=300,
        )
        action = mcp.call_tool(name="publish_report", arguments={"report": "weekly"})
        first = await agent.execute(
            action=action, provider=provider, request_id="delegated-once"
        )
        second = await agent.execute(
            action=action, provider=provider, request_id="delegated-once"
        )
        broader = await agent.execute(
            action=mcp.call_tool(name="delete_report", arguments={"report": "weekly"}),
            provider=provider,
            request_id="delegated-broader",
        )
        if (
            first.kind != "completed"
            or second.kind != "exact-replay"
            or broader.kind != "denied"
            or calls != 1
        ):
            raise RuntimeError("delegated authority was not narrow and replay-safe")
    print(
        json.dumps(
            {
                "recipe": "04-delegate-to-agent",
                "outcome": f"{first.kind},{second.kind},{broader.kind}",
                "calls": calls,
            }
        )
    )


if __name__ == "__main__":
    asyncio.run(main())

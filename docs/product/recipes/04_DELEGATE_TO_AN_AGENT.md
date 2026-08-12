# 04 — Delegate to an agent

## Outcome

Give an agent narrower, expiring authority and prove exact replay and broader actions do not re-enter the provider.

## Before you start

Use a supported Node.js or CPython runtime and install the single Auths package. The executable source below is run against the packed npm artifact and wheel in CI.

## TypeScript

Source: `typescript/04-delegate-to-agent.ts`

```typescript
import { development } from "@auths-dev/sdk/integrations";
import { mcp } from "@auths-dev/sdk/profiles";

let calls = 0;
const provider = mcp.developmentProvider({ tools: {
  async publish_report() { calls += 1; return { published: true }; },
} });
const auths = await development.createAuths({ authority: mcp.allowTools(["publish_report", "delete_report"]) });
try {
  const agent = await auths.delegate({
    authority: mcp.allowTools(["publish_report"]),
    name: "report-agent",
    expiresInSeconds: 300,
  });
  const action = mcp.callTool({ name: "publish_report", arguments: { report: "weekly" } });
  const first = await agent.execute({ action, provider, requestId: "delegated-once" });
  const second = await agent.execute({ action, provider, requestId: "delegated-once" });
  const broader = await agent.execute({
    action: mcp.callTool({ name: "delete_report", arguments: { report: "weekly" } }),
    provider,
    requestId: "delegated-broader",
  });
  if (first.kind !== "completed" || second.kind !== "exact-replay" || broader.kind !== "denied" || calls !== 1) {
    throw new Error("delegated authority was not narrow and replay-safe");
  }
  console.log(JSON.stringify({ recipe: "04-delegate-to-agent", outcome: `${first.kind},${second.kind},${broader.kind}`, calls }));
} finally {
  await auths.close();
}
```

## Python

Source: `python/04_delegate_to_agent.py`

```python
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
```

## What Auths protected

The recipe uses Rust-owned canonicalization, commitments, authorization, and receipt/recovery semantics. TypeScript and Python coordinate bounded I/O but cannot mint an effect-capable authorization object.

## Break it safely

The executable includes its failure exercise and asserts that no unauthorized or duplicate provider entry occurs. CI fails if the adversarial result changes.

## Take it to production

Use durable child-key custody, governed status/revocation, and an atomic multi-node execution store.

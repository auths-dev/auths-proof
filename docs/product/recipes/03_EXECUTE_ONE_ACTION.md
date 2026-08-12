# 03 — Execute one exact action

## Outcome

Run one bounded MCP effect, reject an undeclared effect before provider entry, and verify the signed receipt.

## Before you start

Use a supported Node.js or CPython runtime and install the single Auths package. The executable source below is run against the packed npm artifact and wheel in CI.

## TypeScript

Source: `typescript/03-execute-exact-action.ts`

```typescript
import { verifyReceipt } from "@auths-dev/sdk/verify";
import { development } from "@auths-dev/sdk/integrations";
import { mcp } from "@auths-dev/sdk/profiles";

let calls = 0;
const provider = mcp.developmentProvider({
  tools: {
    async publish_report(input) {
      calls += 1;
      return { published: input.report };
    },
  },
});
const auths = await development.createAuths({ authority: mcp.allowTools(["publish_report"]) });
try {
  const completed = await auths.execute({
    action: mcp.callTool({ name: "publish_report", arguments: { report: "weekly" } }),
    provider,
    requestId: "recipe-three-success",
  });
  if (completed.kind !== "completed") throw new Error(`unexpected result: ${completed.kind}`);
  await verifyReceipt(completed.receipt);
  const denied = await auths.execute({
    action: mcp.callTool({ name: "delete_report", arguments: { report: "weekly" } }),
    provider,
    requestId: "recipe-three-denied",
  });
  if (denied.kind !== "denied" || calls !== 1) throw new Error("undeclared effect reached provider");
  console.log(JSON.stringify({ recipe: "03-execute-exact-action", outcome: completed.kind, denied: true, calls }));
} finally {
  await auths.close();
}
```

## Python

Source: `python/03_execute_exact_action.py`

```python
from __future__ import annotations

import asyncio
import json

from auths import verify_receipt
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
```

## What Auths protected

The recipe uses Rust-owned canonicalization, commitments, authorization, and receipt/recovery semantics. TypeScript and Python coordinate bounded I/O but cannot mint an effect-capable authorization object.

## Break it safely

The executable includes its failure exercise and asserts that no unauthorized or duplicate provider entry occurs. CI fails if the adversarial result changes.

## Take it to production

Replace the development signer, local trust, in-memory atomic state, and receipt sink with production mechanisms that pass Auths conformance.

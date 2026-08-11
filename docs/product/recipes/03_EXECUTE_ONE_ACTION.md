# Execute one protected action

Add **Receipt** while reusing **Authority** and **Action**. The MCP action
family and typed provider own the effect. Development mode supplies local
identity, signing, trust, state, and receipt storage.

```ts
import { development } from "@auths-dev/sdk/integrations";
import { mcp } from "@auths-dev/sdk/profiles";

const provider = mcp.developmentProvider({ tools: { publish_report: publishReport } });
await using auths = await development.createAuths({
  authority: mcp.allowTools(["publish_report"]),
});
const result = await auths.execute({
  action: mcp.callTool({ name: "publish_report", arguments: report }),
  provider,
});
console.log(result.receipt);
```

```python
from auths.integrations import development
from auths.profiles import mcp

provider = mcp.development_provider(tools={"publish_report": publish_report})
async with development.create_auths(
    authority=mcp.allow_tools(["publish_report"]),
) as auths:
    result = await auths.execute(
        action=mcp.call_tool(name="publish_report", arguments=report),
        provider=provider,
    )
    print(result.receipt)
```

Outcome: a completed receipt, a denial, an indeterminate result, or a typed
recoverable error. Application code coordinates no security transition.

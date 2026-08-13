import { development } from "../../../dist/integrations.js";
import { mcp } from "../../../dist/mcp.js";

const directory = process.argv[2];
const auths = await development.createRecoverableAuths({
  directory,
  authority: mcp.allowTools(["publish_report"]),
});
await auths.execute({
  action: mcp.callTool({ name: "publish_report", arguments: { name: "weekly" } }),
  provider: mcp.developmentProvider({
    tools: { publish_report: () => new Promise(() => undefined) },
  }),
  requestId: "crash-weekly-32",
});

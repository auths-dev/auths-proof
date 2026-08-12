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

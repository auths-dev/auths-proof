import { verifyReceipt } from "@auths-dev/sdk";
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

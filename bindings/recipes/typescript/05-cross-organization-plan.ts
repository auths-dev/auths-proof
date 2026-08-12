import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  approvalPolicy,
  decodeExecutionReference,
  decodeReceipt,
  encodeExecutionReference,
  encodeReceipt,
  thresholdApproval,
  verifyReceipt,
  type ApprovalProvider,
} from "@auths-dev/sdk";
import { development } from "@auths-dev/sdk/integrations";
import { mcp } from "@auths-dev/sdk/profiles";

const self = fileURLToPath(import.meta.url);
const mode = process.argv[2];
const directory = process.argv[3];

if (mode === "verify") {
  const receipt = decodeReceipt(await readFile(required(directory)));
  await verifyReceipt(receipt);
  console.log(JSON.stringify({ outcome: "verified-portable-receipt" }));
} else if (mode === "phase-one") {
  await phaseOne(required(directory));
} else if (mode === "phase-two") {
  await phaseTwo(required(directory));
} else {
  const root = process.env.AUTHS_RECIPE_OUTPUT ?? await mkdtemp(join(tmpdir(), "auths-recipe-five-ts-"));
  runChild("phase-one", root);
  runChild("phase-two", root);
  console.log(JSON.stringify({ recipe: "05-cross-organization-plan", outcome: "completed-after-restart", duplicateEntries: 0 }));
}

async function phaseOne(root: string): Promise<void> {
  const auths = await development.createRecoverableAuths({
    directory: root,
    authority: mcp.allowTools(["quarantine_service", "rotate_token"]),
    approval: await planApproval(),
  });
  const provider = mcp.developmentProvider({ tools: {
    async quarantine_service() { return { quarantined: true }; },
    async rotate_token() {
      await writeFile(join(root, "provider-applied"), "applied", { flag: "wx" });
      return { effect: "possible", cause: "unknown" } as const;
    },
  } });
  try {
    const plan = await mcp.plan([
      mcp.callTool({ name: "quarantine_service", arguments: { region: "eu-west-2" } }),
      mcp.callTool({ name: "rotate_token", arguments: { region: "eu-west-2" } }),
    ]);
    const result = await auths.execute({ plan, provider, requestId: "incident-plan" });
    if (result.kind !== "recoverable" || result.reference === undefined || result.completedReceipts.length !== 1) {
      throw new Error("ordered plan did not stop with one completed member");
    }
    await writeFile(join(root, "reference.bin"), encodeExecutionReference(result.reference));
    await writeFile(join(root, "typescript-receipt.json"), encodeReceipt(result.completedReceipts[0]!));
  } finally {
    await auths.close();
  }
}

async function phaseTwo(root: string): Promise<void> {
  const auths = await development.createRecoverableAuths({
    directory: root,
    authority: mcp.allowTools(["quarantine_service", "rotate_token"]),
    approval: await planApproval(),
  });
  let entries = 0;
  const provider = mcp.developmentProvider({
    tools: {
      async quarantine_service() { entries += 1; throw new Error("unexpected provider re-entry"); },
      async rotate_token() { entries += 1; throw new Error("unexpected provider re-entry"); },
    },
    async reconcile() {
      return existsSync(join(root, "provider-applied"))
        ? { effect: "applied", result: { rotated: true } } as const
        : { effect: "possible", cause: "unknown" } as const;
    },
  });
  try {
    const reference = decodeExecutionReference(await readFile(join(root, "reference.bin")));
    const result = await auths.resume({ reference, provider });
    if (result.kind !== "completed" || entries !== 0) throw new Error("recovery re-entered the provider");
    await verifyReceipt(result.receipt);
    await writeFile(join(root, "typescript-recovered-receipt.json"), encodeReceipt(result.receipt));
  } finally {
    await auths.close();
  }
}

async function planApproval() {
  const providers = [approver("company-a"), approver("company-b")];
  return {
    policy: await approvalPolicy.planOnce({
      policyId: "approval.cross-company-plan",
      maxUses: 2,
      requirements: ["company-a", "company-b"],
    }),
    provider: thresholdApproval({ threshold: 2, providers }),
  };
}

function approver(_organization: string): ApprovalProvider {
  return {
    async approve(request) {
      return {
        requestId: request.requestId,
        transactionDigest: request.transactionDigest.slice(),
        policy: request.policy,
        decision: "approved",
      };
    },
  };
}

function runChild(childMode: string, root: string): void {
  const result = spawnSync(process.execPath, [self, childMode, root], { encoding: "utf8" });
  if (result.status !== 0) throw new Error(result.stderr || result.stdout || `${childMode} failed`);
}

function required(value: string | undefined): string {
  if (value === undefined || value.length === 0) throw new Error("path is required");
  return value;
}

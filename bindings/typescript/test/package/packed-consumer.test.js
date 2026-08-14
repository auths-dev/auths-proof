import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { compileConsumer, installPackedSdk } from "./helpers/packed-install.mjs";

const entryPoints = [
  "@auths-dev/sdk",
  "@auths-dev/sdk/identity",
  "@auths-dev/sdk/verify",
  "@auths-dev/sdk/profiles",
  "@auths-dev/sdk/integrations",
  "@auths-dev/sdk/framework",
  "@auths-dev/sdk/testkit",
];

const removed = [
  "advanced", "approvals", "authority", "custody", "diagnostics", "inspection",
  "lifecycle", "mcp", "observability", "profile-kit", "runtime", "trust", "workflow",
];

test("packed package exposes only the reviewed public topology", async () => {
  const { directory } = await installPackedSdk("auths-typescript-consumer-");
  try {
    await writeFile(join(directory, "consumer.mjs"), `
      const expected = ${JSON.stringify(entryPoints)};
      for (const entry of expected) await import(entry);
      const root = await import("@auths-dev/sdk");
      const names = Object.keys(root).sort();
      const allowed = [
        "AuthsError", "ExecutionReference", "approval", "createAuths", "doctor",
      ];
      if (JSON.stringify(names) !== JSON.stringify(allowed)) {
        throw new Error("root drifted: " + names.join(","));
      }
      for (const path of ${JSON.stringify(removed)}) {
        try {
          await import("@auths-dev/sdk/" + path);
          throw new Error("removed subpath resolved: " + path);
        } catch (error) {
          if (error?.code !== "ERR_PACKAGE_PATH_NOT_EXPORTED") throw error;
        }
      }
    `);
    await writeFile(join(directory, "consumer.ts"), `
      import { approval, createAuths, doctor, type Auths, type AuthsErrorCode, type DoctorReport, type ProductionAuths } from "@auths-dev/sdk";
      import { loadIdentity } from "@auths-dev/sdk/identity";
      import { inspectDecision, verifyReceipt } from "@auths-dev/sdk/verify";
      import { githubIssueAddress, mcp, opentofuSavedPlanApply, postgresqlBoundedUpdate, type McpAction } from "@auths-dev/sdk/profiles";
      import { development } from "@auths-dev/sdk/integrations";
      import type { AtomicReservationStore, Signer } from "@auths-dev/sdk/framework";
      import { certifyAtomicStore } from "@auths-dev/sdk/testkit";
      void approval; void createAuths; void doctor; void loadIdentity; void inspectDecision; void verifyReceipt;
      void githubIssueAddress; void mcp; void opentofuSavedPlanApply; void postgresqlBoundedUpdate;
      void development; void certifyAtomicStore;
      declare const auths: Auths;
      declare const production: ProductionAuths;
      declare const code: AuthsErrorCode;
      declare const action: McpAction;
      declare const store: AtomicReservationStore;
      declare const signer: Signer;
      declare const report: DoctorReport;
      void auths; void production; void code; void action; void store; void signer; void report;
    `);
    await writeFile(join(directory, "tsconfig.json"), JSON.stringify({
      compilerOptions: {
        lib: ["DOM", "ES2022", "ESNext.Disposable"],
        module: "NodeNext",
        moduleResolution: "NodeNext",
        noEmit: true,
        strict: true,
        target: "ES2022",
      },
      include: ["consumer.ts"],
    }));
    compileConsumer(directory);
    execFileSync(process.execPath, ["consumer.mjs"], { cwd: directory, stdio: "pipe" });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

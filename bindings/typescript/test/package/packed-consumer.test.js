import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { compileConsumer, installPackedSdk } from "./helpers/packed-install.mjs";

// Derived from the declared topology rather than restated, so this test cannot
// agree with the package while both disagree with what was reviewed.
const entryPoints = JSON.parse(
  await readFile(new URL("../../../public-topology-v1.json", import.meta.url), "utf8"),
).layers.flatMap((layer) => layer.typescript);

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
      const { createGitHubAgentClient } = await import("@auths-dev/sdk/service");
      const names = Object.keys(root).sort();
      // Runtime values only; types erase. classifyErrorCode and isProductVerb
      // are the Rust-owned registry projection reaching a caller.
      const allowed = [
        "AuthsError", "ExecutionReference", "approval", "classifyErrorCode",
        "createAuths", "doctor", "isProductVerb",
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
      const githubResponses = [
        {
          schema: "auths-github-agent/v1",
          repository: "auths-dev/example",
          issue_number: 7,
          base_ref: "main",
          base_revision: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          allowed_paths: ["src/**"],
          denied_paths: [".github/**"],
          budgets: { branches: 1, draft_pull_requests: 1 },
          expiry: { minimum_seconds: 60, maximum_seconds: 900 },
          agent_credential_present: false,
        },
        {
          schema: "auths-github-agent/v1",
          session_id: "11111111111111111111111111111111",
          workflow_id: "demo-11111111111111111111111111111111",
          expires_at: 1_000,
          target_ref: "auths/issue-7-111111111111",
          agent_principal: "urn:auths:raw-key:agent",
          required_configuration: "2".repeat(64),
          executed_configuration: "2".repeat(64),
        },
        {
          schema: "auths-github-agent/v1",
          candidate: {
            status: "inspected",
            candidate_revision: "b".repeat(40),
            changed_paths: [{ path: "src/fix.ts" }],
            direct_push: { result: "refused-without-credential" },
            preview: { code: "authorized", credential_would_be_requested: true },
          },
        },
        {
          schema: "auths-github-agent/v1",
          decision: { class: "authorized", code: "authorized" },
          execution: { branch_ref: "auths/issue-7-111111111111", pull_request_number: 8, pull_request_url: "https://github.com/auths-dev/example/pull/8" },
          credential_requests: 2,
          mutations: 2,
        },
        {
          schema: "auths-github-agent/v1",
          workflow_id: "demo-11111111111111111111111111111111",
          receipts: [{ type: "decision" }, { type: "execution" }],
        },
        {
          schema: "auths-github-agent/v1",
          decision: { class: "authorized", code: "action-replay" },
          execution: { replay: "original-receipt-returned" },
          credential_requests: 0,
          mutations: 0,
        },
      ];
      const client = createGitHubAgentClient({
        endpoint: "https://operator.example",
        fetch: async () => new Response(JSON.stringify(githubResponses.shift()), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
      });
      const boundary = await client.boundary();
      if (boundary.branchBudget !== 1 || boundary.agentCredentialPresent !== false) {
        throw new Error("packed GitHub boundary widened");
      }
      const githubSession = await client.delegate({
        repository: boundary.repository,
        issueNumber: boundary.issueNumber,
        baseRef: boundary.baseRef,
        baseRevision: boundary.baseRevision,
        allowedPaths: boundary.allowedPaths,
        protectedPaths: boundary.protectedPaths,
        expiresInSeconds: boundary.maximumExpirySeconds,
        branchBudget: 1,
        draftPullRequestBudget: 1,
        agentLabel: "packed-consumer",
      });
      const inspected = await client.inspectFixture(githubSession, "exact");
      const completed = await client.execute(githubSession);
      const verified = await client.verifyReceipts(githubSession);
      const replayed = await client.replay(githubSession);
      if (inspected.kind !== "inspected" || completed.kind !== "completed" || verified.kind !== "verified") {
        throw new Error("packed GitHub journey did not complete");
      }
      if (replayed.kind !== "replayed" || replayed.credentialRequests !== 0 || replayed.mutations !== 0) {
        throw new Error("packed GitHub replay was not bounded");
      }
    `);
    await writeFile(join(directory, "consumer.ts"), `
      import { approval, createAuths, doctor, type Auths, type AuthsErrorCode, type DoctorReport, type EffectState, type Outcome, type RetryClass } from "@auths-dev/sdk";
      import { loadIdentity } from "@auths-dev/sdk/identity";
      import { inspectDecision, verifyReceipt } from "@auths-dev/sdk/verify";
      import { createServiceClient, githubIssueAddress, opentofuSavedPlanApply, postgresqlBoundedUpdate, type NextCall, type ServiceClient } from "@auths-dev/sdk/service";
      import { createGitHubAgentClient, type GitHubAgentClient, type GitHubAgentTask } from "@auths-dev/sdk/service";
      import { mcp, type McpAction } from "@auths-dev/sdk/profiles";
      import { development } from "@auths-dev/sdk/integrations";
      import type { AtomicReservationStore, Signer } from "@auths-dev/sdk/framework";
      import { certifyAtomicStore, fixtures } from "@auths-dev/sdk/testkit";
      void approval; void createAuths; void doctor; void loadIdentity; void inspectDecision; void verifyReceipt;
      void githubIssueAddress; void mcp; void opentofuSavedPlanApply; void postgresqlBoundedUpdate;
      void development; void certifyAtomicStore; void createServiceClient; void fixtures;
      void createGitHubAgentClient;
      declare const auths: Auths;
      declare const service: ServiceClient;
      declare const code: AuthsErrorCode;
      declare const action: McpAction;
      declare const store: AtomicReservationStore;
      declare const signer: Signer;
      declare const report: DoctorReport;
      // The two retry questions must stay separable at the packed surface.
      declare const retry: RetryClass;
      declare const next: NextCall;
      declare const effect: EffectState;
      declare const outcome: Outcome;
      declare const githubAgent: GitHubAgentClient;
      declare const githubTask: GitHubAgentTask;
      void auths; void service; void code; void action; void store; void signer; void report;
      void retry; void next; void effect; void outcome;
      void githubAgent; void githubTask;
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

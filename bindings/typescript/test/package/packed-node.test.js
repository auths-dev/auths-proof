import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { installPackedSdk } from "./helpers/packed-install.mjs";

test("packed package runs the sealed command path in native Node", async () => {
  const { directory } = await installPackedSdk("auths-typescript-node-");
  try {
    await writeFile(join(directory, "smoke.mjs"), `
      // The packaged loader must resolve its WASM from disk without any
      // network capability, so fail loudly if anything reaches for one.
      const forbid = (name) => () => { throw new Error(name + " was used during load"); };
      globalThis.fetch = forbid("fetch");
      globalThis.XMLHttpRequest = forbid("XMLHttpRequest");
      globalThis.WebSocket = forbid("WebSocket");

      const {
        approvalPolicy, commandsForGateway, loadAuths, prepareRawKeyAuthority,
      } = await import("@auths-dev/sdk");
      const {
        loadVerifier,
      } = await import("@auths-dev/sdk/verify");
      const { inspectDecision } = await import("@auths-dev/sdk/inspection");
      const { createDiagnosticVerifier } = await import("@auths-dev/sdk/diagnostics");
      const { mcp } = await import("@auths-dev/sdk/mcp");
      const { development } = await import("@auths-dev/sdk/testkit");

      const wasmUrl = import.meta.resolve("@auths-dev/sdk/verify");
      if (!wasmUrl.includes("/node_modules/@auths-dev/sdk/")) {
        throw new Error("verify entry resolved outside the installed package: " + wasmUrl);
      }

      const profile = mcp.profile({ service: "node-records" });
      const policy = await approvalPolicy.planOnce({ maxUses: 2, expiresInSeconds: 120 });
      const approval = development.approval(policy);
      const rootSigner = await development.ephemeralSigner();
      const agentSigner = await development.ephemeralSigner();
      const principal = await agentSigner.publicIdentity();
      const now = BigInt(Math.floor(Date.now() / 1000));
      const prepared = await prepareRawKeyAuthority({
        authorityId: "node.owner",
        rootSigner,
        subjectPrincipal: principal.principal,
        profile,
        permissions: [{ capability: "tools/call", resource: "mcp://node-records/tools/update" }],
        resourceNamespaces: ["mcp://node-records"],
        validity: { notBefore: now - 30n, expiresAt: now + 600n },
        audiences: ["mcp://node-records"],
        budget: { algebra: "numeric-ceiling-v1", value: 2n },
        remainingDepth: 0,
        approval,
      });

      const client = await loadAuths({ signer: agentSigner, trustedAuthority: prepared.trustedAuthority });
      let executed = 0;
      let planKind;
      let deniedKind;
      try {
        const agent = await client.attachAgent({
          name: "node-agent", profile, authority: prepared.authority, approval,
        });
        const plan = await profile.plan([
          profile.call("update", { record: "one" }),
          profile.call("update", { record: "two" }),
        ]);
        const planDecision = await agent.authorizePlan(plan);
        planKind = planDecision.kind;
        if (planDecision.kind === "authorized") {
          const gateway = profile.gateway(async () => { executed += 1; });
          for (const command of commandsForGateway(planDecision.command)) await gateway.execute(command);
          const inspection = await inspectDecision(planDecision.results[0]);
          if ("command" in inspection || "action" in inspection) {
            throw new Error("node inspection exposed a capability");
          }
        }
        const deniedDecision = await agent.authorize(profile.call("delete", { record: "one" }));
        deniedKind = deniedDecision.kind;
        if ("command" in deniedDecision) throw new Error("denied node decision carried a command");
      } finally {
        await client.dispose();
        await rootSigner.dispose();
      }

      // The published build must offer no engine injection anywhere.
      const raw = await loadVerifier();
      if (loadVerifier.length !== 0) throw new Error("packed loader accepted options");
      const forged = createDiagnosticVerifier({
        verifyV1: () => new Uint8Array([0]),
      });
      let rejectedForgedBytes = false;
      try {
        forged.verify(new Uint8Array([1]), new Uint8Array([1]), new Uint8Array([1]));
      } catch {
        rejectedForgedBytes = true;
      }
      if (!rejectedForgedBytes) throw new Error("packed diagnostic verifier accepted junk bytes");

      process.stdout.write(JSON.stringify({
        planKind, executed, deniedKind, raw: typeof raw.verify,
      }));
    `);

    const output = execFileSync(process.execPath, ["smoke.mjs"], {
      cwd: directory,
      encoding: "utf8",
      stdio: "pipe",
    });
    assert.deepEqual(JSON.parse(output), {
      planKind: "authorized",
      executed: 2,
      deniedKind: "denied",
      raw: "function",
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

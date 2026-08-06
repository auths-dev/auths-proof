import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { access, cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const packageRoot = new URL("../../", import.meta.url);
const packageRootPath = fileURLToPath(packageRoot);
const fixtureRoot = new URL("../../../../core/fixtures/v1/", import.meta.url);
const bindingRoot = new URL("../../../../target/binding-vectors/", import.meta.url);

function npmSync(arguments_, options) {
  const npmCli = process.env.npm_execpath;
  return npmCli === undefined
    ? execFileSync("npm", arguments_, options)
    : execFileSync(process.execPath, [npmCli, ...arguments_], options);
}

test("packed package installs and executes only through published entry points", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "auths-typescript-consumer-"));
  try {
    const npmEnvironment = { ...process.env, npm_config_cache: join(temporary, "npm-cache") };
    const packOutput = npmSync(
      ["pack", packageRootPath, "--json", "--pack-destination", temporary],
      { encoding: "utf8", env: npmEnvironment },
    );
    const [{ filename }] = JSON.parse(packOutput);
    await writeFile(join(temporary, "package.json"), JSON.stringify({ type: "module" }));
    npmSync(
      ["install", "--ignore-scripts", "--no-audit", "--no-fund", join(temporary, filename)],
      { cwd: temporary, stdio: "pipe", env: npmEnvironment },
    );
    await cp(new URL("valid/raw-key-chain.proof.cbor", fixtureRoot), join(temporary, "proof.cbor"));
    await cp(new URL("valid/raw-key-chain.action.cbor", fixtureRoot), join(temporary, "action.cbor"));
    await cp(new URL("authorized.context.cbor", bindingRoot), join(temporary, "authorized.context.cbor"));
    await cp(new URL("valid/raw-key-chain.context.cbor", fixtureRoot), join(temporary, "denied.context.cbor"));
    await cp(
      new URL("indeterminate/unsupported-budget-algebra.result.cbor", fixtureRoot),
      join(temporary, "indeterminate.result.cbor"),
    );
    await writeFile(join(temporary, "consumer.mjs"), `
      import { readFile } from "node:fs/promises";
      const {
        Auths, createDiagnosticVerifier, inspectDecision, loadPortableAuths,
      } = await import("@auths-dev/sdk/advanced");
      const sdk = await import("@auths-dev/sdk");
      for (const name of ["Auths", "loadPortableAuths", "inspectDecision", "commitCanonical"]) {
        if (name in sdk) throw new Error(name + " leaked onto the main entry point");
      }
      void inspectDecision;
      await import("@auths-dev/sdk/mcp");
      await import("@auths-dev/sdk/profile-kit");
      await import("@auths-dev/sdk/testkit");
      const bytes = (name) => readFile(new URL(name, import.meta.url));
      const action = await bytes("action.cbor");
      const verifier = await loadPortableAuths();
      const authorized = verifier.verify(
        await bytes("proof.cbor"), action, await bytes("authorized.context.cbor"),
      );
      const denied = verifier.verify(
        await bytes("proof.cbor"), action, await bytes("denied.context.cbor"),
      );
      const indeterminateBytes = await bytes("indeterminate.result.cbor");
      const indeterminate = createDiagnosticVerifier({ verifyV1: () => indeterminateBytes }).verify(
        new Uint8Array([1]), action, new Uint8Array([2]),
      );
      if (authorized.kind !== "authorized") throw new Error("authorized fixture drifted");
      if (denied.kind !== "denied") throw new Error("denied fixture drifted");
      if (indeterminate.kind !== "indeterminate") throw new Error("indeterminate fixture drifted");
      if (indeterminate.effectCapable !== false) throw new Error("diagnostic result claimed effect capability");
      if ("action" in indeterminate) throw new Error("diagnostic result carried a verified action");
      try {
        new Auths({ verifyV1: () => indeterminateBytes });
        throw new Error("installed package allowed engine injection");
      } catch (error) {
        if (!/sealed/.test(String(error?.message))) throw error;
      }
      const forged = createDiagnosticVerifier({ verifyV1: () => authorized.resultCbor }).verify(
        new Uint8Array([1]), action, new Uint8Array([2]),
      );
      if (forged.kind !== "authorized" || "action" in forged) {
        throw new Error("forged authorized bytes produced a verified action");
      }
      try {
        await import("@auths-dev/sdk/workflow");
        throw new Error("internal workflow subpath was importable");
      } catch (error) {
        if (error?.code !== "ERR_PACKAGE_PATH_NOT_EXPORTED") throw error;
      }
    `);
    await writeFile(join(temporary, "consumer.ts"), `
      import { approvalPolicy, loadAuths, type AuthorizationResult, type Signer } from "@auths-dev/sdk";
      import { createDiagnosticVerifier, inspectDecision, type DiagnosticResult } from "@auths-dev/sdk/advanced";
      import { mcp, type McpCommand } from "@auths-dev/sdk/mcp";
      import { defineProfile } from "@auths-dev/sdk/profile-kit";
      import { development } from "@auths-dev/sdk/testkit";
      import { loadPortableAuths } from "@auths-dev/sdk/advanced";
      void approvalPolicy; void loadAuths; void mcp; void defineProfile;
      void development; void loadPortableAuths; void createDiagnosticVerifier; void inspectDecision;
      declare const diagnostic: DiagnosticResult;
      void diagnostic;
      declare const result: AuthorizationResult<McpCommand>;
      declare const signer: Signer;
      void result; void signer;
    `);
    await writeFile(join(temporary, "tsconfig.json"), JSON.stringify({
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
    execFileSync(
      process.execPath,
      [join(packageRootPath, "node_modules", "typescript", "bin", "tsc"), "-p", "tsconfig.json"],
      { cwd: temporary, stdio: "pipe" },
    );
    execFileSync(process.execPath, ["consumer.mjs"], { cwd: temporary, stdio: "pipe" });

    const installedManifest = JSON.parse(await readFile(
      join(temporary, "node_modules", "@auths-dev", "sdk", "package.json"),
      "utf8",
    ));
    assert.equal(installedManifest.name, "@auths-dev/sdk");
    assert.equal(installedManifest.version, "1.0.0-rc.1");
    await assert.rejects(() => access(join(
      temporary,
      "node_modules",
      "@auths-dev",
      "sdk",
      "dist",
      "workflow",
      "runtime.js",
    )));
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

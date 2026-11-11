import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

/** Run the shipped controller's local approval proof against its real public SDK. */
export async function localWithdrawalContract() {
  const root = new URL("../control-room/public/", import.meta.url);
  const previousFetch = globalThis.fetch;
  let networkCalls = 0;
  const refuseNetwork = async () => {
    networkCalls++;
    throw new Error("local withdrawal evidence must not call an API or provider");
  };
  globalThis.fetch = refuseNetwork;
  let timer;
  try {
    // These are the public entrypoints copied by the maintained control-room
    // build. Their real packaged WASM loader uses local files under Node.
    const [selfHosted, testkit, verifier] = await Promise.all([
      import(new URL("vendor-v3/dist/self-hosted.js", root).href),
      import(new URL("vendor-v3/dist/testkit/index.js", root).href),
      import(new URL("vendor-v3/dist/verify.js", root).href),
    ]);
    const modules = new Map([
      ["@auths-dev/sdk/self-hosted", selfHosted],
      ["@auths-dev/sdk/testkit", testkit],
      ["@auths-dev/sdk/verify", verifier],
    ]);
    const bindings = {};
    const shipped = await readFile(new URL("app.js", root), "utf8");
    assert.match(shipped, /wire\(\);\s*await bootstrap\(\);\s*$/);
    const controller = shipped.replace(
      /^import\s*\{([^}]+)\}\s*from\s*["']([^"']+)["'];\r?\n/gm,
      (_statement, names, specifier) => {
        const namespace = modules.get(specifier);
        assert.ok(namespace, `unexpected controller import ${specifier}`);
        for (const name of names.split(",").map((item) => item.trim()).filter(Boolean)) {
          assert.equal(typeof namespace[name], "function", `missing public SDK function ${name}`);
          bindings[name] = namespace[name];
        }
        return "";
      },
    ).replace(/wire\(\);\s*await bootstrap\(\);\s*$/, "");
    assert.doesNotMatch(controller, /^import\s/m);
    // Evaluate the unmodified function bodies in the same JS realm as the SDK:
    // schema checks intentionally reject foreign-realm object prototypes.
    // Only browser bootstrap/network is excluded; cryptography, native approval
    // collection and verification are the actual shipped implementation.
    const load = new Function(...Object.keys(bindings), "sessionStorage", "fetch",
      `"use strict";\n${controller}\nreturn liveWithdrawalAttack;`);
    const prove = load(...Object.values(bindings), { getItem: () => null }, refuseNetwork);
    const deadline = new Promise((_resolve, reject) => {
      timer = setTimeout(() => reject(new Error("local withdrawal contract exceeded its diagnostic bound")), 20_000);
    });
    const result = await Promise.race([prove(), deadline]);
    assert.equal(result.blocked, true);
    assert.equal(result.stage, "approval");
    assert.equal(result.code, "approval.incomplete");
    assert.equal(result.evidence.firstDecision, "authorized");
    assert.equal(result.evidence.secondApproved, 0);
    assert.deepEqual(result.evidence.approvedSteps, ["firewall-eu-west-2"]);
    assert.deepEqual(result.evidence.unresolved, ["cache-eu-west-2"]);
    assert.equal(result.evidence.secondStatuses.length, 1);
    assert.equal(result.evidence.secondStatuses[0].status, "declined");
    assert.match(result.evidence.firstProof, /^[A-Za-z0-9_-]+$/);
    assert.match(result.evidence.decline, /^auths-as2-/);
    assert.equal(result.evidence.providerCalls, 0);
    assert.equal(networkCalls, 0);
  } finally {
    clearTimeout(timer);
    globalThis.fetch = previousFetch;
  }
}

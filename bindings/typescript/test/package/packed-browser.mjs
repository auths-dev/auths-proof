import { execFileSync } from "node:child_process";
import { createReadStream } from "node:fs";
import { cp, mkdtemp, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const temporary = await mkdtemp(join(tmpdir(), "auths-typescript-browser-"));
const npmEnvironment = { ...process.env, npm_config_cache: join(temporary, "npm-cache") };
let browser;
let server;
try {
  const [{ filename }] = JSON.parse(execFileSync(
    "npm",
    ["pack", fileURLToPath(new URL("../../", import.meta.url)), "--json", "--pack-destination", temporary],
    { encoding: "utf8", env: npmEnvironment },
  ));
  await writeFile(join(temporary, "package.json"), JSON.stringify({ type: "module" }));
  execFileSync(
    "npm",
    ["install", "--ignore-scripts", "--no-audit", "--no-fund", join(temporary, filename)],
    { cwd: temporary, env: npmEnvironment, stdio: "pipe" },
  );
  await mkdir(join(temporary, "fixtures"));
  const fixtures = new URL("../../../../core/fixtures/v1/", import.meta.url);
  const vectors = new URL("../../../../target/binding-vectors/", import.meta.url);
  await cp(new URL("valid/raw-key-chain.proof.cbor", fixtures), join(temporary, "fixtures/proof.cbor"));
  await cp(new URL("valid/raw-key-chain.action.cbor", fixtures), join(temporary, "fixtures/action.cbor"));
  await cp(new URL("authorized.context.cbor", vectors), join(temporary, "fixtures/context.cbor"));
  await writeFile(join(temporary, "worker.js"), `
    const started = performance.now();
    const { loadVerifier } = await import("/node_modules/@auths-dev/sdk/dist/verify.js");
    const bytes = async (name) => new Uint8Array(await (await fetch('/fixtures/' + name)).arrayBuffer());
    const verifier = await loadVerifier();
    const result = verifier.verify(
      await bytes('proof.cbor'), await bytes('action.cbor'), await bytes('context.cbor'),
    );
    postMessage({ kind: result.kind, coldStartMs: performance.now() - started });
  `);
  await writeFile(join(temporary, "index.html"), `<!doctype html>
    <meta charset="utf-8">
    <title>Auths packed browser conformance</title>
    <output id="result">starting</output>
    <script type="module">
      import { doctor } from "/node_modules/@auths-dev/sdk/dist/index.js";
      import { development } from "/node_modules/@auths-dev/sdk/dist/integrations.js";
      import { mcp } from "/node_modules/@auths-dev/sdk/dist/profiles.js";
      import { loadVerifier } from "/node_modules/@auths-dev/sdk/dist/verify.js";
      const bytes = async (name) => new Uint8Array(await (await fetch('/fixtures/' + name)).arrayBuffer());
      const proof = await bytes('proof.cbor');
      const actionBytes = await bytes('action.cbor');
      const context = await bytes('context.cbor');
      const verifier = await loadVerifier();
      const verified = verifier.verify(proof, actionBytes, context);
      const warmTimings = [];
      for (let index = 0; index < 30; index += 1) {
        const before = performance.now();
        verifier.verify(proof, actionBytes, context);
        warmTimings.push(performance.now() - before);
      }
      warmTimings.sort((left, right) => left - right);
      const workerResult = await new Promise((resolve, reject) => {
        const worker = new Worker('/worker.js', { type: 'module' });
        worker.onmessage = (event) => { worker.terminate(); resolve(event.data); };
        worker.onerror = reject;
      });
      let calls = 0;
      const provider = mcp.developmentProvider({ tools: {
        async update_record() { calls += 1; return { updated: true }; },
      } });
      const auths = await development.createAuths({
        authority: mcp.allowTools(['update_record']),
      });
      let execution;
      try {
        execution = await auths.execute({
          action: mcp.callTool({ name: 'update_record', arguments: { record: 'one' } }),
          provider,
        });
      } finally {
        await auths.close();
        await auths.close();
      }
      const report = await doctor({ mode: 'development', state: 'in-memory' });
      document.querySelector('#result').textContent = JSON.stringify({
        verified: verified.kind,
        worker: workerResult.kind,
        workerColdStartMs: workerResult.coldStartMs,
        warmVerificationP95Ms: warmTimings[Math.floor(warmTimings.length * 0.95)],
        execution: execution.kind,
        calls,
        doctor: report.status,
        runtime: report.runtime,
      });
    </script>`);

  server = createServer(async (request, response) => {
    const requested = request.url === "/" ? "/index.html" : request.url ?? "/index.html";
    const relative = normalize(decodeURIComponent(requested)).replace(/^[/\\]+/, "");
    const path = join(temporary, relative);
    if (!path.startsWith(temporary)) {
      response.writeHead(403).end();
      return;
    }
    try {
      const info = await stat(path);
      if (!info.isFile()) throw new Error("not a file");
      const type = new Map([
        [".html", "text/html; charset=utf-8"],
        [".js", "text/javascript; charset=utf-8"],
        [".wasm", "application/wasm"],
        [".cbor", "application/cbor"],
      ]).get(extname(path)) ?? "application/octet-stream";
      response.writeHead(200, { "content-type": type });
      createReadStream(path).pipe(response);
    } catch {
      response.writeHead(404).end();
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("browser server did not bind");
  browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  const failures = [];
  page.on("pageerror", (error) => failures.push(`page error: ${error.message}`));
  page.on("response", (response) => {
    if (!response.ok()) failures.push(`HTTP ${response.status()}: ${response.url()}`);
  });
  await page.goto(`http://127.0.0.1:${address.port}/`);
  try {
    await page.waitForFunction(() => document.querySelector("#result")?.textContent !== "starting");
  } catch (error) {
    throw new Error(`packed browser did not finish: ${failures.join("; ") || "no page error was reported"}`, { cause: error });
  }
  const outcome = JSON.parse(await page.textContent("#result"));
  for (const [key, value] of Object.entries({
    verified: "authorized",
    worker: "authorized",
    execution: "completed",
    calls: 1,
    doctor: "ready",
    runtime: "Browser",
  })) {
    if (outcome[key] !== value) throw new Error(`packed browser ${key} drifted: ${outcome[key]}`);
  }
  const baseline = JSON.parse(await readFile(new URL("../../performance-baseline.json", import.meta.url)));
  for (const [actual, budget] of [
    [outcome.warmVerificationP95Ms, baseline.measurements.chromiumWarmVerificationP95Ms],
    [outcome.workerColdStartMs, baseline.measurements.chromiumWorkerColdStartMs],
  ]) {
    if (!Number.isFinite(actual) || actual > budget * 1.1) {
      throw new Error(`packed browser performance exceeded budget: ${actual} > ${budget}`);
    }
  }
  process.stdout.write(`${JSON.stringify({ outcome })}\n`);
} finally {
  if (browser !== undefined) await browser.close();
  if (server !== undefined) await new Promise((resolve) => server.close(resolve));
  await rm(temporary, { recursive: true, force: true });
}

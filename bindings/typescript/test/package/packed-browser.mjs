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
    const { createVerifier } = await import("/node_modules/@auths-dev/sdk/dist/verify.js");
    const bytes = async (name) => new Uint8Array(await (await fetch('/fixtures/' + name)).arrayBuffer());
    const verifier = await createVerifier();
    const result = verifier.verify({
      proof: await bytes('proof.cbor'),
      action: await bytes('action.cbor'),
      trustedContext: await bytes('context.cbor'),
    });
    postMessage({ kind: result.kind, coldStartMs: performance.now() - started });
  `);
  await writeFile(join(temporary, "index.html"), `<!doctype html>
    <meta charset="utf-8">
    <title>Auths packed browser conformance</title>
    <output id="result">starting</output>
    <script type="module">
      import { runtimeInfo } from "/node_modules/@auths-dev/sdk/dist/index.js";
      import { createVerifier } from "/node_modules/@auths-dev/sdk/dist/verify.js";
      const bytes = async (name) => new Uint8Array(await (await fetch('/fixtures/' + name)).arrayBuffer());
      const proof = await bytes('proof.cbor');
      const actionBytes = await bytes('action.cbor');
      const context = await bytes('context.cbor');
      const verifier = await createVerifier();
      const input = { proof, action: actionBytes, trustedContext: context };
      const verified = verifier.verify(input);
      const warmTimings = [];
      for (let index = 0; index < 30; index += 1) {
        const before = performance.now();
        verifier.verify(input);
        warmTimings.push(performance.now() - before);
      }
      warmTimings.sort((left, right) => left - right);
      const runtime = await runtimeInfo();
      document.querySelector('#result').textContent = JSON.stringify({
        verified: verified.kind,
        warmVerificationP95Ms: warmTimings[Math.floor(warmTimings.length * 0.95)],
        runtime: runtime.host,
        profiles: runtime.profiles.length,
      });
    </script>`);
  await writeFile(join(temporary, "worker-harness.html"), `<!doctype html>
    <meta charset="utf-8">
    <title>Auths packed browser worker cold start</title>
    <output id="result">starting</output>
    <script type="module">
      const worker = new Worker('/worker.js', { type: 'module' });
      const outcome = await new Promise((resolve, reject) => {
        worker.onmessage = (event) => { worker.terminate(); resolve(event.data); };
        worker.onerror = reject;
      });
      document.querySelector('#result').textContent = JSON.stringify(outcome);
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

  const attachFailureListeners = (page) => {
    const failures = [];
    page.on("pageerror", (error) => failures.push(`page error: ${error.message}`));
    page.on("response", (response) => {
      if (!response.ok()) failures.push(`HTTP ${response.status()}: ${response.url()}`);
    });
    return failures;
  };
  const readResult = async (page, failures, label) => {
    try {
      await page.waitForFunction(() => document.querySelector("#result")?.textContent !== "starting");
    } catch (error) {
      throw new Error(`${label} did not finish: ${failures.join("; ") || "no page error was reported"}`, { cause: error });
    }
    return JSON.parse(await page.textContent("#result"));
  };

  browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  const failures = attachFailureListeners(page);
  await page.goto(`http://127.0.0.1:${address.port}/`);
  const outcome = await readResult(page, failures, "packed browser");
  for (const [key, value] of Object.entries({
    verified: "authorized",
    runtime: "browser",
    profiles: 0,
  })) {
    if (outcome[key] !== value) throw new Error(`packed browser ${key} drifted: ${outcome[key]}`);
  }

  // A single wall-clock cold start on a shared CI runner is noise, not signal. Each
  // sample gets its own browser context, not just a new page, because a shared context
  // lets Chromium reuse an earlier sample's HTTP and V8 code cache and hide the real
  // cold-start cost.
  const workerColdStartSampleCount = 5;
  const coldStartSamples = [];
  for (let index = 0; index < workerColdStartSampleCount; index += 1) {
    const context = await browser.newContext();
    try {
      const samplePage = await context.newPage();
      const sampleFailures = attachFailureListeners(samplePage);
      await samplePage.goto(`http://127.0.0.1:${address.port}/worker-harness.html`);
      const sample = await readResult(samplePage, sampleFailures, `packed browser worker sample ${index}`);
      if (sample.kind !== "authorized") {
        throw new Error(`packed browser worker sample ${index} drifted: ${sample.kind}`);
      }
      coldStartSamples.push(sample);
    } finally {
      await context.close();
    }
  }
  const coldStartTimingsMs = coldStartSamples.map((sample) => sample.coldStartMs);
  // The median of independent cold starts resists the single slow outlier that a mean
  // or a lone sample cannot, and is held to the same budget a lone sample was.
  const sortedColdStartTimingsMs = [...coldStartTimingsMs].sort((left, right) => left - right);
  const workerColdStartMedianMs = sortedColdStartTimingsMs[Math.floor(sortedColdStartTimingsMs.length / 2)];
  outcome.worker = coldStartSamples[0].kind;
  outcome.workerColdStartSamplesMs = coldStartTimingsMs;
  outcome.workerColdStartMedianMs = workerColdStartMedianMs;

  const baseline = JSON.parse(await readFile(new URL("../../performance-baseline.json", import.meta.url)));
  for (const { name, actual, budget, tolerance } of [
    {
      name: "warm verification p95",
      actual: outcome.warmVerificationP95Ms,
      budget: baseline.measurements.chromiumWarmVerificationP95Ms,
      tolerance: 1.1,
    },
    {
      name: "worker cold start median",
      actual: outcome.workerColdStartMedianMs,
      budget: baseline.measurements.chromiumWorkerColdStartMs,
      tolerance: 1.25,
    },
  ]) {
    const limit = budget * tolerance;
    if (!Number.isFinite(actual) || actual > limit) {
      throw new Error(`packed browser ${name} exceeded budget: ${actual} > ${limit}`);
    }
  }
  process.stdout.write(`${JSON.stringify({ outcome })}\n`);
} finally {
  if (browser !== undefined) await browser.close();
  if (server !== undefined) await new Promise((resolve) => server.close(resolve));
  await rm(temporary, { recursive: true, force: true });
}

#!/usr/bin/env node

import { spawn } from "node:child_process";
import {
  cp, mkdtemp, mkdir, readFile, readdir, rm, writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../../..");
const temporary = await mkdtemp(join(tmpdir(), "auths-local-agent-proof-"));
const artifacts = join(temporary, "artifacts");
const state = join(temporary, "agent-state");
const readyPath = join(temporary, "ready.json");
const expectedPath = join(temporary, "expected.json");
const python = process.env.PYTHON ?? join(root, "bindings/python/.venv/bin/python");
const maturin = process.env.MATURIN ?? "maturin";
const uv = process.env.UV ?? "uv";
let agent;

try {
  await mkdir(artifacts);
  await buildArtifacts();
  const installed = await installConsumers();

  let ready = await startAgent();
  await writeFile(readyPath, `${JSON.stringify(ready)}\n`, { mode: 0o600 });
  await command(installed.python, [
    installed.pythonConsumer, "--ready", readyPath, "--expected", expectedPath,
    "--mode", "fresh",
  ]);
  await command(process.execPath, [installed.typescriptConsumer, readyPath, expectedPath]);
  await stopAgent();

  const firstAnchors = JSON.stringify(ready.receiptTrustAnchors);
  ready = await startAgent();
  if (JSON.stringify(ready.receiptTrustAnchors) !== firstAnchors) {
    throw new Error("receipt trust anchors changed across agent restart");
  }
  await writeFile(readyPath, `${JSON.stringify(ready)}\n`, { mode: 0o600 });
  await command(installed.python, [
    installed.pythonConsumer, "--ready", readyPath, "--expected", expectedPath,
    "--mode", "replay",
  ]);
  const expected = JSON.parse(await readFile(expectedPath, "utf8"));
  console.log(JSON.stringify({
    schema: "auths.local-agent-installed-proof/1",
    status: "passed",
    provider: "synthetic-stripe-testkit",
    languages: ["python", "typescript"],
    operationId: expected.operationId,
    receiptIds: expected.receiptIds,
    assertions: [
      "fresh-generated-call",
      "cross-language-replay",
      "changed-input-conflict-preserves-possible-effect",
      "portable-receipt-pair-verifies-in-both-sdks",
      "restart-safe-replay",
    ],
  }));
} finally {
  await stopAgent();
  await rm(temporary, { recursive: true, force: true });
}

async function buildArtifacts() {
  await command("cargo", [
    "build", "-p", "auths-node", "--features", "testkit-agent", "--bin",
    "auths-testkit-agent",
  ]);

  const sdk = join(root, "bindings/typescript");
  await command("npm", ["run", "build"], { cwd: sdk });
  const sdkPack = JSON.parse(await command(
    "npm", ["pack", "--json", "--pack-destination", artifacts],
    { cwd: sdk, capture: true },
  ));
  const sdkTarball = join(artifacts, sdkPack[0].filename);

  const profileSource = join(temporary, "typescript-profile-source");
  await cp(join(root, "bindings/generated/stripe/typescript"), profileSource, {
    recursive: true,
  });
  await command("npm", [
    "install", "--ignore-scripts", "--no-audit", "--no-fund", sdkTarball,
    join(sdk, "node_modules/typescript"),
  ], { cwd: profileSource });
  await command("npm", ["run", "build"], { cwd: profileSource });
  const profilePack = JSON.parse(await command(
    "npm", ["pack", "--json", "--pack-destination", artifacts],
    { cwd: profileSource, capture: true },
  ));
  const profileTarball = join(artifacts, profilePack[0].filename);

  await command(maturin, [
    "build", "--profile", "python-extension", "--manifest-path",
    join(root, "bindings/python/Cargo.toml"),
    "--out", artifacts,
  ]);
  await command(uv, [
    "build", "--wheel", "--out-dir", artifacts,
    join(root, "bindings/generated/stripe/python"),
  ]);
  await writeFile(join(temporary, "typescript-artifacts.json"), JSON.stringify({
    sdkTarball, profileTarball,
  }));
}

async function installConsumers() {
  const typescriptArtifacts = JSON.parse(
    await readFile(join(temporary, "typescript-artifacts.json"), "utf8"),
  );
  const typescriptConsumerDirectory = join(temporary, "typescript-consumer");
  await mkdir(typescriptConsumerDirectory);
  await writeFile(join(typescriptConsumerDirectory, "package.json"), JSON.stringify({
    private: true,
    type: "module",
  }));
  await command("npm", [
    "install", "--ignore-scripts", "--no-audit", "--no-fund",
    typescriptArtifacts.sdkTarball, typescriptArtifacts.profileTarball,
  ], { cwd: typescriptConsumerDirectory });
  const typescriptConsumer = join(typescriptConsumerDirectory, "consumer.mjs");
  await cp(join(here, "typescript_consumer.mjs"), typescriptConsumer);

  const pythonConsumerDirectory = join(temporary, "python-consumer");
  await command(uv, ["venv", "--python", python, pythonConsumerDirectory]);
  const pythonExecutable = join(pythonConsumerDirectory, "bin/python");
  const wheels = (await readdir(artifacts))
    .filter((name) => name.endsWith(".whl"))
    .map((name) => join(artifacts, name));
  if (wheels.length !== 2) {
    throw new Error(`expected root and Stripe wheels, found ${wheels.length}`);
  }
  await command(uv, [
    "pip", "install", "--python", pythonExecutable, "--no-index", ...wheels,
  ]);
  const pythonConsumer = join(pythonConsumerDirectory, "consumer.py");
  await cp(join(here, "python_consumer.py"), pythonConsumer);
  return {
    python: pythonExecutable,
    pythonConsumer,
    typescriptConsumer,
  };
}

async function startAgent() {
  await mkdir(state, { recursive: true, mode: 0o700 });
  const binary = join(root, "target/debug/auths-testkit-agent");
  agent = spawn(binary, ["--state-directory", state], {
    cwd: root,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  agent.stderr.setEncoding("utf8");
  agent.stderr.on("data", (chunk) => {
    stderr += chunk;
    process.stderr.write(chunk);
  });
  const line = await new Promise((accept, reject) => {
    let output = "";
    const timer = setTimeout(() => reject(new Error("testkit agent readiness timed out")), 15_000);
    agent.once("error", reject);
    agent.once("exit", (code) => reject(new Error(
      `testkit agent exited before readiness (${code}): ${stderr}`,
    )));
    agent.stdout.setEncoding("utf8");
    agent.stdout.on("data", (chunk) => {
      output += chunk;
      const newline = output.indexOf("\n");
      if (newline >= 0) {
        clearTimeout(timer);
        accept(output.slice(0, newline));
      }
    });
  });
  const ready = JSON.parse(line);
  if (ready.status !== "ready" || ready.profile !== "auths.stripe.refund/1" ||
      !Array.isArray(ready.receiptTrustAnchors) || ready.receiptTrustAnchors.length !== 2) {
    throw new Error("testkit agent returned an invalid readiness projection");
  }
  return ready;
}

async function stopAgent() {
  if (agent === undefined) return;
  const current = agent;
  agent = undefined;
  if (current.exitCode !== null) return;
  await new Promise((accept, reject) => {
    const timer = setTimeout(() => {
      current.kill("SIGKILL");
      reject(new Error("testkit agent did not stop after SIGINT"));
    }, 10_000);
    current.once("exit", (code, signal) => {
      clearTimeout(timer);
      if (code === 0 || signal === "SIGINT") accept();
      else reject(new Error(`testkit agent exited unsuccessfully (${code ?? signal})`));
    });
    current.kill("SIGINT");
  });
}

function command(program, arguments_, options = {}) {
  return new Promise((accept, reject) => {
    const child = spawn(program, arguments_, {
      cwd: options.cwd ?? root,
      env: process.env,
      stdio: options.capture ? ["ignore", "pipe", "inherit"] : "inherit",
    });
    let output = "";
    if (options.capture) {
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", (chunk) => { output += chunk; });
    }
    child.once("error", reject);
    child.once("exit", (code) => {
      if (code === 0) accept(output);
      else reject(new Error(`${basename(program)} exited with ${code}`));
    });
  });
}

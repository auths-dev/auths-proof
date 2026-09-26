import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { before, test } from "node:test";
import { pathToFileURL } from "node:url";

import { installPackedSdk } from "./helpers/packed-install.mjs";

const seeds = { agent: 0x11, "manager-a": 0xa1, "manager-b": 0xb2 };
// Runs the CLI with its stdin on a pseudo-terminal and types `answer`.
const onTerminal = `
import os, pty, subprocess, sys
answer = sys.argv[1].encode()
controller, terminal = pty.openpty()
process = subprocess.Popen(sys.argv[2:], stdin=terminal, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
os.close(terminal)
os.write(controller, answer)
stdout, stderr = process.communicate(timeout=120)
sys.stdout.buffer.write(stdout)
sys.stderr.buffer.write(stderr)
sys.exit(process.returncode)
`;

// A pseudo-terminal needs POSIX; Windows runs the non-interactive cases.
const interactive = { skip: process.platform === "win32" ? "no pseudo-terminal on Windows" : false };

let directory;
let cli;
let sdk;
let testkit;

before(async () => {
  ({ directory } = await installPackedSdk("auths-typescript-approve-"));
  const root = join(directory, "node_modules", "@auths-dev", "sdk");
  cli = join(root, "tools", "profile-cli.mjs");
  sdk = await import(pathToFileURL(join(root, "dist", "self-hosted.js")).href);
  testkit = await import(pathToFileURL(join(root, "dist", "testkit", "index.js")).href);
});

test("packed CLI: the installed auths command runs approve --help", { skip: process.platform === "win32" ? "npm installs a .cmd shim on Windows" : false }, () => {
  const run = spawnSync(join(directory, "node_modules", ".bin", "auths"), ["approve", "--help"], { encoding: "utf8" });
  assert.equal(run.status, 0, run.stderr);
  assert.match(run.stdout, /^usage: auths approve <request-file-or-text> --signer <custody-config>/u);
});

async function principal(name) {
  return (await testkit.developmentEd25519Key(new Uint8Array(32).fill(seeds[name]))).principal;
}

async function workspace(label) {
  const contract = sdk.exactMcpTool({
    service: "payments",
    name: "refund_v1",
    fields: {
      amount: sdk.integerField({ minimum: 1, maximum: 10_000_000 }),
      payment_intent: sdk.stringField({ minBytes: 1, maxBytes: 64 }),
    },
  });
  const proposal = await sdk.proposeMcpApproval({
    contract,
    command: { amount: 1500, payment_intent: "pi_cli_0001" },
    required: 3,
    approvers: await Promise.all(Object.keys(seeds).map(async (name) => ({ principal: await principal(name) }))),
    requester: await principal("agent"),
    challenge: new Uint8Array(32).fill(0x63),
    evaluationTime: BigInt(Math.floor(Date.now() / 1000) - 5),
  });
  const manager = await principal("manager-a");
  const request = (await sdk.approvalRequests(proposal)).find((item) => item.approver === manager);
  const base = join(directory, label);
  await writeFile(`${base}.request`, `${request.text}\n`);
  await writeFile(`${base}.seed`, new Uint8Array(32).fill(seeds["manager-a"]));
  await writeFile(`${base}.signer.json`, JSON.stringify({
    schema: "auths.approval-signer/1", custody: "development-ed25519", seed_file: `${label}.seed`,
  }));
  return { base, proposal, request, manager };
}

function run(base, requestArgument, extra, { answer } = {}) {
  const command = [process.execPath, cli, "approve", requestArgument, "--signer", `${base}.signer.json`, ...extra];
  const result = answer === undefined
    ? spawnSync(command[0], command.slice(1), { cwd: directory, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] })
    : spawnSync("python3", ["-c", onTerminal, answer, ...command], { cwd: directory, encoding: "utf8" });
  return result;
}

async function statusOf(proposal, manager, responses) {
  const collection = await sdk.collectApprovals(proposal, responses);
  return collection.statuses.find((status) => status.approver === manager).status;
}

test("packed CLI: an interactive yes approves and prints only the review", interactive, async () => {
  const { base, proposal, manager } = await workspace("interactive");
  const out = `${base}.response`;
  const result = run(base, `${base}.request`, ["--out", out], { answer: "y\n" });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stderr, /Auths V1 · MCP approval/u);
  assert.ok(result.stderr.includes('  Arguments: {"amount":1500,"payment_intent":"pi_cli_0001"}'));
  assert.ok(result.stderr.includes(`  ${manager} (you)`));
  assert.match(result.stderr, /Signer: development custody/u);
  assert.match(result.stderr, /Approve this action\? \[y\/N\]/u);
  const response = await readFile(out, "utf8");
  assert.match(response, /^auths-as1-/u);
  assert.equal(await statusOf(proposal, manager, [response]), "approved");
});

test("packed CLI: an interactive default answer signs nothing", interactive, async () => {
  const { base } = await workspace("default");
  const out = `${base}.response`;
  const result = run(base, `${base}.request`, ["--out", out], { answer: "\n" });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /nothing was signed/u);
  assert.equal(existsSync(out), false);
});

test("packed CLI: --yes approves without a terminal", async () => {
  const { base, proposal, request, manager } = await workspace("yes");
  const result = run(base, request.text, ["--yes"]);
  assert.equal(result.status, 0, result.stderr);
  assert.doesNotMatch(result.stderr, /Approve this action\?/u);
  assert.equal(await statusOf(proposal, manager, [result.stdout]), "approved");
});

test("packed CLI: without a terminal or --yes nothing is signed", async () => {
  const { base, proposal, manager } = await workspace("refuse");
  const out = `${base}.response`;
  const result = run(base, `${base}.request`, ["--out", out]);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /pass --yes/u);
  assert.equal(existsSync(out), false);
  assert.equal(await statusOf(proposal, manager, []), "pending");
});

test("packed CLI: --decline --yes signs a decline", async () => {
  const { base, proposal, manager } = await workspace("decline");
  const result = run(base, `${base}.request`, ["--decline", "--yes"]);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(await statusOf(proposal, manager, [result.stdout]), "declined");
});

test("packed CLI: a tampered request is refused before anything is signed", async () => {
  const { base, request } = await workspace("tampered");
  const tampered = Buffer.from(request.data).toString("latin1").replace('"amount":1500', '"amount":9500');
  assert.notEqual(tampered, Buffer.from(request.data).toString("latin1"));
  await writeFile(`${base}.tampered`, Buffer.from(tampered, "latin1"));
  const out = `${base}.response`;
  const result = run(base, `${base}.tampered`, ["--yes", "--out", out]);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /approval\.action-mismatch/u);
  assert.doesNotMatch(result.stderr, /Approve this action\?/u);
  assert.equal(existsSync(out), false);
});

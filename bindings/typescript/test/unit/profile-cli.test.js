import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import {
  parseContract, profileDiff, renderAdapter, renderGenerated, renderLock, renderRun, renderVectors,
} from "../../tools/profile-cli.mjs";

const root = new URL("../../../fixtures/self-hosted-profile/", import.meta.url);
const profile = await readFile(new URL("profile.toml", root), "utf8");
const adversarial = JSON.parse(await readFile(new URL("adversarial-boundary-v1.json", root), "utf8"));

test("shared adversarial profile source decisions", () => {
  for (const item of adversarial.profileCases) {
    const source = item.prefix + adversarial.profileBaseLines.map(line =>
      line.replace('name = "probe"', `name = "${item.name}"`)).join(item.lineEnding) + item.lineEnding;
    if (item.decision === "reject") {
      assert.throws(() => parseContract(source), item.id);
    } else {
      assert.equal(parseContract(source).command, item.command, item.id);
    }
  }
});

test("generated exact tool binds the version", () => {
  const contract = parseContract(profile);
  assert.match(renderGenerated(contract), /name: TOOL_NAME/);
  assert.match(renderGenerated(contract), /set_value_v2/);
  assert.match(renderGenerated(contract), /retry_count: optionalField\(integerField/);
  assert.match(renderGenerated(contract), /labels: arrayField\(stringField/);
  assert.match(renderGenerated(contract), /payload: bytesField/);
  assert.match(renderGenerated(contract), /target: objectField/);
  assert.match(renderGenerated(contract), /status: enumField/);
  assert.match(renderVectors(contract), /"tool":"set_value_v2"/);
});

test("starter keeps provider mapping application-owned", () => {
  const contract = parseContract(profile);
  assert.match(renderAdapter(contract), /class ApplicationAdapter implements SelfHostedProviderAdapter/);
  assert.match(renderAdapter(contract), /throw new Error\("map the exact command/);
  assert.match(renderRun(contract), /runOnce\(\{ contract: CONTRACT, \.\.\.input \}\)/);
});

test("language-neutral vector fixture is byte-for-byte identical", async () => {
  const expected = await readFile(new URL("vectors.json", root), "utf8");
  assert.equal(renderVectors(parseContract(profile)), expected);
  assert.equal(renderLock(parseContract(profile)), await readFile(new URL("profile.lock.json", root), "utf8"));
});

test("malformed and widened profiles are rejected", () => {
  for (const invalid of [
    profile.replace("version = 2", "version = 0"),
    profile.replace("max_bytes = 32", "max_bytes = 32\nmax_bytes = 32"),
    profile.replace('type = "boolean"', 'type = "any"'),
    profile.replace('variants = ["open", "in_progress", "closed"]', 'variants = []'),
    profile.replace('variants = ["open", "in_progress", "closed"]', 'variants = ["open", "open"]'),
    profile.replace('variants = ["open", "in_progress", "closed"]', 'variants = ["open", "Open!"]'),
    profile.replace('variants = ["open", "in_progress", "closed"]', 'variants = ["open", "closed",]'),
    profile.replace("max_bytes = 32", "max_bytes = 99999"),
  ]) assert.throws(() => parseContract(invalid));
});

test("profile diff identifies the changed field and required version bump", async () => {
  const folder = await mkdtemp(join(tmpdir(), "auths-profile-diff-"));
  await writeFile(join(folder, "profile.lock.json"), renderLock(parseContract(profile)));
  await writeFile(join(folder, "profile.toml"), profile.replace("max_bytes = 32", "max_bytes = 31"));
  const result = await profileDiff(join(folder, "profile.toml"));
  assert.equal(result.code, "profile.contract.version-required");
  assert.ok(result.changed_fields.includes("arguments.fields.value.maximum"));
  assert.equal(result.action_identity_changed, true);
});

test("enum reorder is a versioned action change with an exact before/after", async () => {
  const folder = await mkdtemp(join(tmpdir(), "auths-enum-diff-"));
  await writeFile(join(folder, "profile.lock.json"), renderLock(parseContract(profile)));
  await writeFile(join(folder, "profile.toml"), profile.replace(
    'variants = ["open", "in_progress", "closed"]',
    'variants = ["closed", "in_progress", "open"]'));
  const result = await profileDiff(join(folder, "profile.toml"));
  assert.equal(result.code, "profile.contract.version-required");
  assert.deepEqual(result.changes.find(item => item.path === "arguments.fields.status.variants"), {
    path: "arguments.fields.status.variants",
    before: ["open", "in_progress", "closed"],
    after: ["closed", "in_progress", "open"],
  });
});

test("first profile edit after init can be generated at version one", async () => {
  const folder = await mkdtemp(join(tmpdir(), "auths-profile-first-edit-"));
  const cli = new URL("../../tools/profile-cli.mjs", import.meta.url);
  execFileSync(process.execPath, [fileURLToPath(cli), "init", "--language", "typescript",
    "--name", "local-demo", "--directory", folder]);
  await assert.rejects(() => readFile(join(folder, "profile.lock.json")));
  const source = await readFile(join(folder, "profile.toml"), "utf8");
  await writeFile(join(folder, "profile.toml"), source.replace("max_bytes = 256", "max_bytes = 32"));
  execFileSync(process.execPath, [fileURLToPath(cli), "generate", join(folder, "profile.toml")]);
  assert.match(await readFile(join(folder, "profile.lock.json"), "utf8"), /"version":1/);
});

test("diff before the first lock explains the new action identity", async () => {
  const folder = await mkdtemp(join(tmpdir(), "auths-profile-new-diff-"));
  const cli = fileURLToPath(new URL("../../tools/profile-cli.mjs", import.meta.url));
  execFileSync(process.execPath, [cli, "init", "--language", "typescript",
    "--name", "new-operation", "--directory", folder]);
  const output = execFileSync(process.execPath, [cli, "diff", join(folder, "profile.toml")],
    { encoding: "utf8" });
  assert.match(output, /no prior generated lock; this is a new action identity/);
  assert.doesNotMatch(output, /no field changes/);
});

test("production doctor describes only its actual TypeScript authority checks", async () => {
  const folder = await mkdtemp(join(tmpdir(), "auths-profile-doctor-"));
  const cli = new URL("../../tools/profile-cli.mjs", import.meta.url);
  execFileSync(process.execPath, [fileURLToPath(cli), "init", "--language", "typescript",
    "--name", "doctor-demo", "--directory", folder]);
  execFileSync(process.execPath, [fileURLToPath(cli), "generate", join(folder, "profile.toml")]);
  const grant = join(folder, "grant.cbor");
  const trust = join(folder, "trust.cbor");
  await writeFile(grant, "not-a-grant");
  await writeFile(trust, "not-a-context");
  const output = execFileSync(process.execPath, [fileURLToPath(cli), "doctor", join(folder, "profile.toml"),
    "--production", "--signer-adapter", "operator-signer", "--grant-file", grant,
    "--trust-file", trust], { encoding: "utf8" });
  assert.match(output, /grant\/trust bytes not parsed/);
  assert.doesNotMatch(output, /structurally present/);
});

test("production doctor names each missing authority input", async () => {
  const folder = await mkdtemp(join(tmpdir(), "auths-profile-missing-authority-"));
  const cli = fileURLToPath(new URL("../../tools/profile-cli.mjs", import.meta.url));
  execFileSync(process.execPath, [cli, "init", "--language", "typescript",
    "--name", "missing-authority", "--directory", folder]);
  execFileSync(process.execPath, [cli, "generate", join(folder, "profile.toml")]);
  for (const [flags, code] of [
    [[], "profile.authority.signer-missing"],
    [["--signer-adapter", "operator-signer"], "profile.authority.grant-missing"],
    [["--signer-adapter", "operator-signer", "--grant-file", join(folder, "grant.cbor")],
      "profile.trust.context-missing"],
  ]) {
    const result = spawnSync(process.execPath, [cli, "doctor", join(folder, "profile.toml"),
      "--production", ...flags, "--json"], { encoding: "utf8" });
    assert.equal(result.status, 1, code);
    assert.equal(JSON.parse(result.stdout).diagnostic.code, code);
  }
});

test("profile test refuses a suite that omits mandatory adapter cases", async () => {
  const folder = await mkdtemp(join(tmpdir(), "auths-profile-empty-suite-"));
  const cli = fileURLToPath(new URL("../../tools/profile-cli.mjs", import.meta.url));
  execFileSync(process.execPath, [cli, "init", "--language", "typescript",
    "--name", "empty-suite", "--directory", folder]);
  execFileSync(process.execPath, [cli, "generate", join(folder, "profile.toml")]);
  const suite = join(folder, "empty-suite.mjs");
  await writeFile(suite, "export async function run() { return { metadata: { suite: 'self-hosted-provider-adapter/1', assurance: 'test-results-only-not-security-certification' }, passed: true, cases: [] }; }\n");
  const result = spawnSync(process.execPath, [cli, "test", join(folder, "profile.toml"),
    "--suite", suite, "--json"], { encoding: "utf8" });
  assert.equal(result.status, 1);
  const diagnostic = JSON.parse(result.stdout).diagnostic;
  assert.equal(diagnostic.code, "profile.provider.adapter-test-failed");
  assert.match(diagnostic.message, /mandatory cases/);

  const manifest = JSON.parse(await readFile(new URL("../../../fixtures/self-hosted-profile/adapter-scenarios-v1.json", import.meta.url), "utf8"));
  const cases = [...manifest.mandatoryCaseIds, "provider-specific-read-back"].map(id => ({ id, status: "passed" }));
  await writeFile(suite, `export async function run() { return ${JSON.stringify({
    metadata: { suite: "self-hosted-provider-adapter/1", assurance: "test-results-only-not-security-certification" },
    passed: true, cases,
  })}; }\n`);
  const extraCaseResult = spawnSync(process.execPath, [cli, "test", join(folder, "profile.toml"),
    "--suite", suite, "--json"], { encoding: "utf8" });
  assert.equal(extraCaseResult.status, 0);
  assert.equal(JSON.parse(extraCaseResult.stdout).ok, true);
});

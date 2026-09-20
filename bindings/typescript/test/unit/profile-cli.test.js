import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  parseContract, profileDiff, renderAdapter, renderGenerated, renderLock, renderRun, renderVectors,
} from "../../tools/profile-cli.mjs";

const root = new URL("../../../fixtures/self-hosted-profile/", import.meta.url);
const profile = await readFile(new URL("profile.toml", root), "utf8");

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
  execFileSync(process.execPath, [cli.pathname, "profile", "init", "--language", "typescript",
    "--name", "local-demo", "--directory", folder]);
  await assert.rejects(() => readFile(join(folder, "profile.lock.json")));
  const source = await readFile(join(folder, "profile.toml"), "utf8");
  await writeFile(join(folder, "profile.toml"), source.replace("max_bytes = 256", "max_bytes = 32"));
  execFileSync(process.execPath, [cli.pathname, "profile", "generate", join(folder, "profile.toml")]);
  assert.match(await readFile(join(folder, "profile.lock.json"), "utf8"), /"version":1/);
});

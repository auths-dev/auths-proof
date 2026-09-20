import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import {
  parseContract, renderAdapter, renderGenerated, renderLock, renderRun, renderVectors,
} from "../../tools/profile-cli.mjs";

const root = new URL("../../../fixtures/self-hosted-profile/", import.meta.url);
const profile = await readFile(new URL("profile.toml", root), "utf8");

test("generated exact tool binds the version", () => {
  const contract = parseContract(profile);
  assert.match(renderGenerated(contract), /name: TOOL_NAME/);
  assert.match(renderGenerated(contract), /set_value_v1/);
  assert.match(renderGenerated(contract), /retry_count: optionalField\(integerField/);
  assert.match(renderGenerated(contract), /labels: arrayField\(stringField/);
  assert.match(renderGenerated(contract), /payload: bytesField/);
  assert.match(renderGenerated(contract), /target: objectField/);
  assert.match(renderVectors(contract), /"tool":"set_value_v1"/);
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
    profile.replace("version = 1", "version = 0"),
    profile.replace("max_bytes = 32", "max_bytes = 32\nmax_bytes = 32"),
    profile.replace('type = "boolean"', 'type = "any"'),
    profile.replace("max_bytes = 32", "max_bytes = 99999"),
  ]) assert.throws(() => parseContract(invalid));
});

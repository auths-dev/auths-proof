import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import { parseContract, renderGenerated, renderVectors } from "../../tools/profile-cli.mjs";

const profile = `[profile]
name = "example-set-value"
version = 1
service = "example-service"
tool = "set_value"

[fields]
value = "string:1:32"
enabled = "boolean"
retry_count = "optional-integer:0:3"
`;

test("generated exact tool binds the version", () => {
  const contract = parseContract(profile);
  assert.match(renderGenerated(contract), /name: TOOL_NAME/);
  assert.match(renderGenerated(contract), /set_value_v1/);
  assert.match(renderGenerated(contract), /retry_count: optionalField\(integerField/);
  assert.match(renderVectors(contract), /"tool":"set_value_v1"/);
});

test("language-neutral vector fixture is byte-for-byte identical", async () => {
  const root = new URL("../../../fixtures/self-hosted-profile/", import.meta.url);
  const source = await readFile(new URL("profile.toml", root), "utf8");
  const expected = await readFile(new URL("vectors.json", root), "utf8");
  assert.equal(renderVectors(parseContract(source)), expected);
});

test("malformed and widened profiles are rejected", () => {
  for (const invalid of [
    profile.replace("version = 1", "version = 0"),
    profile.replace('value = "string:1:32"', 'value = "string:1:32"\nvalue = "string:1:32"'),
    profile.replace('enabled = "boolean"', 'enabled = "object"'),
    profile.replace('value = "string:1:32"', 'value = "string:0:99999"'),
  ]) assert.throws(() => parseContract(invalid));
});

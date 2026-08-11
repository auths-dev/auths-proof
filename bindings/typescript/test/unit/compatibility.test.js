import assert from "node:assert/strict";
import test from "node:test";
import { SDK_COMPATIBILITY, negotiateCompatibility } from "../../dist/compatibility.js";

const subject = (overrides = {}) => ({
  authoringAbi: 1,
  identityAbi: 1,
  capabilities: SDK_COMPATIBILITY.capabilities,
  ...overrides,
});

test("the supported compatibility window is exact and fails closed", () => {
  assert.deepEqual(negotiateCompatibility(subject()), { compatible: true, missing: [] });
  assert.deepEqual(negotiateCompatibility(subject({ authoringAbi: 0 })).missing, ["authoring-abi:0"]);
  assert.deepEqual(negotiateCompatibility(subject({ identityAbi: 2 })).missing, ["identity-abi:2"]);
  const withoutBatch = SDK_COMPATIBILITY.capabilities.filter(
    (capability) => capability !== "verification.batch-v1",
  );
  assert.deepEqual(
    negotiateCompatibility(subject({ capabilities: withoutBatch })).missing,
    ["verification.batch-v1"],
  );
});

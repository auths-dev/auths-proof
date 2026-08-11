import assert from "node:assert/strict";
import test from "node:test";
import {
  SDK_RUNTIME_CONTRACT,
  evaluateRuntimeContract,
} from "../../dist/runtime-contract.js";

const subject = (overrides = {}) => ({
  authoringAbi: 1,
  identityAbi: 1,
  capabilities: SDK_RUNTIME_CONTRACT.capabilities,
  ...overrides,
});

test("the current runtime contract is exact and fails closed", () => {
  assert.deepEqual(evaluateRuntimeContract(subject()), { satisfied: true, missing: [] });
  assert.deepEqual(evaluateRuntimeContract(subject({ authoringAbi: 0 })).missing, ["authoring-abi:0"]);
  assert.deepEqual(evaluateRuntimeContract(subject({ identityAbi: 2 })).missing, ["identity-abi:2"]);
  const withoutBatch = SDK_RUNTIME_CONTRACT.capabilities.filter(
    (capability) => capability !== "verification.batch-v1",
  );
  assert.deepEqual(
    evaluateRuntimeContract(subject({ capabilities: withoutBatch })).missing,
    ["verification.batch-v1"],
  );
});

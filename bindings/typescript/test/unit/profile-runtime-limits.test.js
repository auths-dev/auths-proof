import assert from "node:assert/strict";
import { test } from "node:test";

import { PROFILE_CLIENT_RUNTIME, bindProfile } from "../../dist/profile-runtime.js";

const descriptor = {
  profileClientRuntime: PROFILE_CLIENT_RUNTIME,
  profileId: "auths.example.double",
  version: 1,
  collectionRoute: "/v1/profiles/example/double/1/operations",
  runtimeContractDigest: "00".repeat(32),
  errorProjectionDigest: "00".repeat(32),
  preparationEvidence: null,
  requestBytes: 4096,
  responseBytes: 4096,
  executionMilliseconds: 30_000,
  receiptCount: 4,
  receiptBytes: 1024,
  profileApi: {},
  inputType: "Input",
  successType: "Result",
};

test("generated profile descriptors fail closed on runtime and receipt limits", () => {
  assert.throws(
    () => bindProfile({}, { ...descriptor, profileClientRuntime: "auths.profile-client-runtime/0" }),
    /runtime mismatch/,
  );
  assert.throws(
    () => bindProfile({}, { ...descriptor, receiptCount: 65 }),
    /receiptCount is outside bounds/,
  );
  assert.throws(
    () => bindProfile({}, { ...descriptor, receiptBytes: 4097 }),
    /receiptBytes is outside bounds/,
  );
});

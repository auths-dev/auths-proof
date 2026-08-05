import assert from "node:assert/strict";
import { test } from "node:test";
import { defineProfile } from "../../dist/profile-kit.js";
import { profileConformance } from "../../dist/testkit/index.js";

const profile = defineProfile({
  id: "example.files/1",
  version: 1,
  canonicalize(input) {
    return {
      mediaType: "application/json",
      body: new TextEncoder().encode(JSON.stringify(input)),
      permission: { capability: "file/modify", resource: `repo://demo/${input.path}` },
      resourceNamespace: "repo://demo",
      audience: "repo://demo",
      display: [{ label: "Path", value: input.path }],
    };
  },
});

const paymentProfile = defineProfile({
  id: "example.payments/1",
  version: 1,
  canonicalize(input) {
    return {
      mediaType: "application/json",
      body: new TextEncoder().encode(JSON.stringify({
        account: input.account,
        processor: input.processor,
        amount: input.amount.toString(),
      })),
      permission: { capability: "payment/send", resource: `account://${input.account}` },
      resourceNamespace: `payments://${input.account}`,
      audience: `processor://${input.processor}`,
      budget: { algebra: "numeric-ceiling-v1", value: input.amount },
      display: [{ label: "Account", value: input.account }],
    };
  },
});

test("profile conformance catches omitted semantic dimensions", () => {
  const result = profileConformance(profile, {
    baseline: { path: "docs/a.md", value: "a" },
    mutations: { path: ["docs/b.md"], value: ["b"] },
  });
  assert.doesNotThrow(() => result.mustChange({
    path: ["resource", "canonicalAction"],
    value: ["canonicalAction"],
  }));
  assert.throws(
    () => result.mustChange({ value: ["resource"] }),
    /did not change resource/,
  );
});

test("profile conformance supports structurally different budgeted profiles", () => {
  const result = profileConformance(paymentProfile, {
    baseline: { account: "merchant-a", processor: "stripe", amount: 10n },
    mutations: {
      account: ["merchant-b"],
      processor: ["adyen"],
      amount: [20n],
    },
  });
  assert.doesNotThrow(() => result.mustChange({
    account: ["resource", "resourceNamespace", "canonicalAction"],
    processor: ["audience", "canonicalAction"],
    amount: ["budget", "canonicalAction"],
  }));
});

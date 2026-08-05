import assert from "node:assert/strict";
import { test } from "node:test";
import { approvalPolicy, commitCanonical } from "../../dist/index.js";

test("canonical commitments are deterministic and domain separated", async () => {
  const bytes = new TextEncoder().encode("canonical");
  const first = await commitCanonical("demo.a", bytes);
  const second = await commitCanonical("demo.a", bytes);
  const other = await commitCanonical("demo.b", bytes);
  assert.deepEqual(first.digest, second.digest);
  assert.notDeepEqual(first.digest, other.digest);
  bytes.fill(0);
  assert.notDeepEqual(first.digest, bytes);
});

test("approval policy builders commit exact bounded configuration", async () => {
  const first = await approvalPolicy.planOnce({ maxUses: 3, expiresInSeconds: 60 });
  const second = await approvalPolicy.planOnce({ maxUses: 3, expiresInSeconds: 60 });
  const changed = await approvalPolicy.planOnce({ maxUses: 4, expiresInSeconds: 60 });
  assert.deepEqual(first.configurationDigest, second.configurationDigest);
  assert.notDeepEqual(first.configurationDigest, changed.configurationDigest);
});

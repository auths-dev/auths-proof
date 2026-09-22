import assert from "node:assert/strict";
import { test } from "node:test";

import { authorProductionMcpProof, exactMcpTool, stringField } from "../../dist/self-hosted.js";

test("production authoring rejects ephemeral custody before signer access", async () => {
  let signCalls = 0;
  const signer = {
    descriptor: { contract: "signer-custody/2", lifecycle: "ephemeral", keyState: "active-current" },
    async sign() { signCalls++; throw new Error("must not sign"); },
  };
  const contract = exactMcpTool({
    service: "example-service", name: "set_value_v1",
    fields: { value: stringField({ minBytes: 1, maxBytes: 32 }) },
  });
  await assert.rejects(authorProductionMcpProof({
    contract, command: { value: "approved" },
    inputs: {
      grants: [], trustedContextTemplate: new Uint8Array([1]), signer,
      challenge: new Uint8Array(32), evaluationTime: 1n,
    },
  }), /durable custody/);
  assert.equal(signCalls, 0);
});

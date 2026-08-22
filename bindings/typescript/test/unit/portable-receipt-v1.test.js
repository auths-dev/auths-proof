import assert from "node:assert/strict";
import { test } from "node:test";

import { parsePortableReceipt } from "../../dist/internal/receipt.js";
import { loadPackagedWorkflowEngine } from "../../dist/verifier/wasm.js";

const portableId = `rcpt_${"A".repeat(43)}`;
const id = new Uint8Array(32);
const attested = new Uint8Array([1]);

test("portable receipt v1 uses the Rust projection and needs no companion input", () => {
  const engine = {
    decodePortableReceiptV1() {
      return {
        portableReceiptId: portableId,
        kind: "execution",
        decisionReceiptId: id,
        executionReceiptId: id,
        attestedDecision: attested,
        attestedExecution: attested,
      };
    },
  };
  const value = parsePortableReceipt(new Uint8Array([0xa4]), engine);
  assert.equal(value.kind, "execution");
  assert.equal(value.receipt.id, portableId);
  assert.deepEqual(value.attestedDecision, attested);
  assert.deepEqual(value.attestedExecution, attested);
});

test("portable receipt projection rejects ID and variant contradictions", () => {
  const contradictory = {
    decodePortableReceiptV1() {
      return {
        portableReceiptId: portableId,
        kind: "decision",
        decisionReceiptId: id,
        executionReceiptId: id,
        attestedDecision: attested,
        attestedExecution: attested,
      };
    },
  };
  assert.throws(
    () => parsePortableReceipt(new Uint8Array([0xa3]), contradictory),
    /contradictory portable receipt projection/,
  );
});

test("packaged WASM exposes the canonical portable receipt decoder", async () => {
  const engine = await loadPackagedWorkflowEngine();
  assert.throws(() => engine.decodePortableReceiptV1(new Uint8Array([0xa0])));
});

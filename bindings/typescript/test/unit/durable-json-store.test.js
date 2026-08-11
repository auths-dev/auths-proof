import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { DurableJsonExecutionStateStore } from "../../adapters/durable-json/index.js";

test("durable reference state store survives reopen and compares transitions", async () => {
  const directory = await mkdtemp(join(tmpdir(), "auths-runtime-store-"));
  const path = join(directory, "state.json");
  try {
    const first = new DurableJsonExecutionStateStore(path);
    assert.equal(await first.reserve({
      idempotencyKey: "request-1",
      challenge: new Uint8Array(32).fill(7),
      state: "pre-effect",
    }), "reserved");
    assert.equal(await first.transition("request-1", "reserved", "executing"), "transitioned");

    const reopened = new DurableJsonExecutionStateStore(path);
    assert.equal((await reopened.load("request-1")).state, "executing");
    assert.equal(await reopened.reserve({
      idempotencyKey: "request-1",
      challenge: new Uint8Array(32).fill(7),
      state: "pre-effect",
    }), "duplicate");
    assert.equal(await reopened.transition("request-1", "reserved", "failed"), "conflict");
    assert.equal(await reopened.reserve({
      idempotencyKey: "__proto__",
      challenge: new Uint8Array(32).fill(8),
      state: "pre-effect",
    }), "reserved");
    assert.equal((await reopened.load("__proto__")).state, "reserved");
    assert.doesNotMatch(await readFile(path, "utf8"), /private|signature|proof/i);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

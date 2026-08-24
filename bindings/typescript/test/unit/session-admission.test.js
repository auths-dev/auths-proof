import assert from "node:assert/strict";
import { test } from "node:test";

import { UnavailableError } from "../../dist/index.js";
import { SdkAdmissionGate, isReservedSdkRequest } from "../../dist/session.js";

test("SDK admission is bounded, FIFO, cancellable, and preserves safe control capacity", async () => {
  const gate = new SdkAdmissionGate(32);
  let release;
  const blocked = new Promise((resolve) => { release = resolve; });
  const started = [];
  const calls = [];
  for (let index = 0; index < 32; index += 1) {
    calls.push(gate.run(async () => { started.push(index); await blocked; }));
  }
  const controller = new AbortController();
  const cancelled = gate.run(async () => { started.push(32); await blocked; }, controller.signal);
  for (let index = 33; index < 288; index += 1) {
    calls.push(gate.run(async () => { started.push(index); await blocked; }));
  }
  controller.abort();
  await assert.rejects(cancelled, (error) => error instanceof DOMException && error.name === "AbortError");
  calls.push(gate.run(async () => { started.push(288); await blocked; }));
  await assert.rejects(
    gate.run(async () => undefined),
    (error) => error instanceof UnavailableError && error.issue.code === "operation.admission-exhausted" && error.effect === "not-applied",
  );
  release();
  await Promise.all(calls);
  assert.deepEqual(started, [...Array.from({ length: 32 }, (_, index) => index), ...Array.from({ length: 256 }, (_, index) => index + 33)]);
  assert.equal(isReservedSdkRequest("GET", "/v1/operations/pending"), true);
  assert.equal(isReservedSdkRequest("POST", "/v1/operations/recover"), true);
  assert.equal(isReservedSdkRequest("POST", "/v1/profiles/example/double/1/operations/op_AAAAAAAAAAAAAAAAAAAAAA/recover"), true);
  assert.equal(isReservedSdkRequest("POST", "/v1/profiles/example/double/1/operations"), false);
  assert.equal(isReservedSdkRequest("POST", "/v1/profiles/example/double/1/operations/op_A/execute"), false);
  assert.equal(isReservedSdkRequest("POST", "/v1/profiles/example/double/1/operations/op_A/recover"), false);
});

test("closing admission rejects queued work without starting it", async () => {
  const gate = new SdkAdmissionGate(1);
  let release;
  const active = gate.run(() => new Promise((resolve) => { release = resolve; }));
  let queuedStarted = false;
  const queued = gate.run(async () => { queuedStarted = true; });
  gate.close();
  await assert.rejects(queued, /auths client is closed/);
  assert.equal(queuedStarted, false);
  release();
  await active;
  await assert.rejects(gate.run(async () => undefined), /auths client is closed/);
});

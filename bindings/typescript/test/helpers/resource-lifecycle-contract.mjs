import assert from "node:assert/strict";

export const deferred = () => {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};
const disposed = (error) => error?.code === "disposed";
const cleanup = (reason) => (error) => error?.code === "signer-failed" && error.causeChain.includes(reason);
const until = async (predicate) => {
  for (let index = 0; index < 40 && !predicate(); index++) await Promise.resolve();
  assert.ok(predicate(), "owned transition did not settle");
};
function timing() {
  let now = 100;
  const jobs = new Map();
  return { now: () => now, schedule(callback, delay) {
    const key = Symbol(); jobs.set(key, { callback, due: now + delay });
    return () => jobs.delete(key);
  }, advance(delta) {
    now += delta;
    for (const [key, job] of [...jobs]) if (job.due <= now) { jobs.delete(key); job.callback(); }
  }, jobs };
}

/** Identical schedules against source-built and source-free installed owners. */
export async function resourceLifecycleContract(t, { ResourceLifecycle, openResource }) {
  await t.test("C1: concurrent opening shares work; cancelling one waiter detaches only it", async () => {
    const owner = new ResourceLifecycle("new");
    const gate = deferred(); let calls = 0;
    const abort = new AbortController();
    const first = owner.open(async () => { calls++; await gate.promise; }, { signal: abort.signal });
    const second = owner.open(async () => { throw new Error("duplicate opening"); });
    const rejected = assert.rejects(first, disposed); abort.abort(); await rejected;
    gate.resolve(); await second;
    assert.equal(calls, 1); assert.equal(owner.state, "open");
    await owner.close(); await assert.rejects(owner.open(async () => {}), disposed);
  });

  await t.test("C1/C3: close invalidates opening, retains late acquisition, and never reopens", async () => {
    const owner = new ResourceLifecycle("new"); const gate = deferred(); let destroyed = 0;
    const opening = owner.open(async () => { await gate.promise; owner.own({}, async () => { destroyed++; }); });
    const rejected = assert.rejects(opening, disposed);
    const closing = owner.close(); await rejected;
    assert.equal(owner.state, "closing"); assert.equal(destroyed, 0);
    gate.resolve(); await closing;
    assert.equal(owner.state, "closed"); assert.equal(destroyed, 1);
  });

  await t.test("C2: shared close, caller cancellation, and active ownership prevent premature destruction", async () => {
    const owner = new ResourceLifecycle(); const work = deferred(), destructor = deferred(), entered = deferred();
    let calls = 0;
    owner.own({}, async () => { calls++; entered.resolve(); await destructor.promise; });
    const operation = owner.run(() => work.promise);
    const controller = new AbortController();
    const first = owner.close({ signal: controller.signal }); const second = owner.close();
    const rejected = assert.rejects(first, disposed); controller.abort(); await rejected;
    assert.equal(calls, 0); assert.throws(() => owner.run(async () => {}), disposed);
    work.resolve("recorded-result"); assert.equal(await operation, "recorded-result");
    await entered.promise; assert.equal(calls, 1);
    destructor.resolve(); await second; await owner.close(); assert.equal(calls, 1);
  });

  await t.test("C3/C4: failed opening returns original failure and retains independent cleanup failures", async () => {
    const owner = new ResourceLifecycle("new"); const gate = deferred(), entered = deferred();
    const original = new Error("original opening failure"); let independent = 0;
    await assert.rejects(owner.open(async () => {
      owner.own({}, async () => { entered.resolve(); await gate.promise; throw new Error("private cleanup failure"); });
      owner.own({}, async () => { independent++; });
      throw original;
    }), (error) => error === original);
    const closed = assert.rejects(owner.close(), cleanup("cleanup-failed"));
    await entered.promise; gate.resolve(); await closed;
    assert.equal(independent, 1); assert.equal(owner.state, "cleanup-failed");
    await assert.rejects(owner.open(async () => {}), disposed);
  });

  await t.test("C4: explicit retry joins one generation, skips successes, and retains unsafe failures", async () => {
    const owner = new ResourceLifecycle(); const retried = deferred(), entered = deferred();
    let safe = 0, unsafe = 0, successful = 0;
    owner.own({}, async (retry) => { safe++; if (!retry) throw new Error(); entered.resolve(); await retried.promise; }, "idempotent");
    owner.own({}, async () => { unsafe++; throw new Error(); });
    owner.own({}, async () => { successful++; });
    await assert.rejects(owner.close(), cleanup("cleanup-failed"));
    await assert.rejects(owner.close(), cleanup("cleanup-failed"));
    assert.deepEqual([safe, unsafe, successful], [1, 1, 1]);
    const first = assert.rejects(owner.retryCleanup(), cleanup("cleanup-failed"));
    await entered.promise;
    const joined = assert.rejects(owner.close(), cleanup("cleanup-failed"));
    const otherRetry = assert.rejects(owner.retryCleanup(), cleanup("cleanup-failed"));
    retried.resolve(); await Promise.all([first, joined, otherRetry]);
    assert.deepEqual([safe, unsafe, successful], [2, 1, 1]);
  });

  await t.test("C5: private shorter timeout cannot replace the cleanup generation deadline", async () => {
    const clock = timing(); const owner = new ResourceLifecycle("open", clock); const gate = deferred(), entered = deferred();
    owner.own({}, async () => { entered.resolve(); await gate.promise; });
    const first = assert.rejects(owner.close({ timeoutMs: 20 }), cleanup("cleanup-incomplete"));
    await entered.promise;
    const short = assert.rejects(owner.close({ timeoutMs: 5 }), disposed);
    const shared = assert.rejects(owner.close(), cleanup("cleanup-incomplete"));
    clock.advance(5); await short; assert.equal(owner.state, "closing");
    clock.advance(15); await Promise.all([first, shared]); assert.equal(owner.state, "closing-overdue");
    await assert.rejects(owner.close(), cleanup("cleanup-incomplete"));
    await assert.rejects(owner.retryCleanup(), cleanup("cleanup-incomplete"));
    gate.resolve(); await until(() => owner.state === "closed");
    await owner.close(); assert.equal(clock.jobs.size, 0);
  });

  for (const event of ["close", "cancel", "timeout"]) await t.test(`C6: attachment racing ${event} cannot publish or lose a late child`, async () => {
    const clock = timing(); const owner = new ResourceLifecycle("open", clock); const created = deferred(), cleaned = deferred(); const controller = new AbortController();
    let calls = 0;
    const pending = owner.publish(() => created.promise, async () => { calls++; cleaned.resolve(); }, { signal: controller.signal, ...(event === "timeout" ? { timeoutMs: 5 } : {}) });
    const rejected = assert.rejects(pending, disposed);
    let closing;
    if (event === "close") closing = owner.close(); else if (event === "timeout") clock.advance(5); else controller.abort();
    await rejected; assert.equal(calls, 0);
    created.resolve({ child: true }); await cleaned.promise;
    if (closing !== undefined) await closing; else await owner.close();
    assert.equal(calls, 1); assert.equal(owner.state, "closed");
  });

  await t.test("C6: successful publication registers ownership before a caller can close", async () => {
    const owner = new ResourceLifecycle(); let calls = 0;
    const child = await owner.publish(async () => ({}), async () => { calls++; });
    assert.ok(child); await owner.close(); assert.equal(calls, 1);
  });

  await t.test("C3: an active operation survives the cleanup deadline before zeroization", async () => {
    const clock = timing(); const owner = new ResourceLifecycle("open", clock);
    const gate = deferred(); const bytes = new Uint8Array([7, 8, 9]); let destroyed = 0;
    owner.own(bytes, async () => { bytes.fill(0); destroyed++; });
    const active = owner.run(async () => { await gate.promise; assert.deepEqual(bytes, new Uint8Array([7, 8, 9])); return "recorded-result"; });
    const close = assert.rejects(owner.close({ timeoutMs: 10 }), cleanup("cleanup-incomplete"));
    clock.advance(10); await close;
    assert.equal(destroyed, 0); assert.equal(owner.state, "closing-overdue");
    gate.resolve(); assert.equal(await active, "recorded-result");
    await until(() => owner.state === "closed");
    assert.deepEqual(bytes, new Uint8Array(3)); assert.equal(destroyed, 1);
  });

  await t.test("C4: one and then all opening waiters time out without cancelling initialization", async () => {
    const clock = timing(); const owner = new ResourceLifecycle("new", clock); const gate = deferred(); let calls = 0;
    const first = assert.rejects(owner.open(async () => { calls++; await gate.promise; }, { timeoutMs: 5 }), disposed);
    const second = assert.rejects(owner.open(async () => { throw new Error("duplicate"); }, { timeoutMs: 10 }), disposed);
    clock.advance(5); await first; assert.equal(owner.state, "opening");
    clock.advance(5); await second; assert.equal(owner.state, "opening");
    gate.resolve(); await until(() => owner.state === "open");
    assert.equal(calls, 1); await owner.close();
  });

  await t.test("C5: abort after attachment publication does not retroactively abandon the child", async () => {
    const owner = new ResourceLifecycle(); const caller = new AbortController(); let destroyed = 0;
    const child = await owner.publish(async () => ({}), async () => { destroyed++; }, { signal: caller.signal });
    caller.abort(); assert.ok(child); assert.equal(destroyed, 0);
    await owner.close(); assert.equal(destroyed, 1);
  });

  await t.test("C7: a late cleanup failure settles overdue ownership and permits only explicit safe retry", async () => {
    const clock = timing(); const owner = new ResourceLifecycle("open", clock); const gate = deferred(); let calls = 0;
    owner.own({}, async (retry) => { calls++; if (!retry) await gate.promise; }, "idempotent");
    const closing = assert.rejects(owner.close({ timeoutMs: 10 }), cleanup("cleanup-incomplete"));
    clock.advance(10); await closing; assert.equal(owner.state, "closing-overdue");
    gate.reject(new Error("private cleanup failure")); await until(() => owner.state === "cleanup-failed");
    await assert.rejects(owner.close(), cleanup("cleanup-failed")); assert.equal(calls, 1);
    await owner.retryCleanup(); assert.equal(calls, 2); assert.equal(owner.state, "closed");
  });

  await t.test("C1/C7: an abandoned factory owns and closes its late result", async () => {
    const gate = deferred(), entered = deferred(), cleaned = deferred(); const controller = new AbortController(); let calls = 0;
    const factory = openResource(async (owner) => {
      entered.resolve(); await gate.promise;
      owner.own({}, async () => { calls++; cleaned.resolve(); });
      return { owner };
    }, { signal: controller.signal });
    await entered.promise;
    const rejected = assert.rejects(factory, disposed); controller.abort(); await rejected;
    gate.resolve(); await cleaned.promise; assert.equal(calls, 1);
  });

  await t.test("C7: pre-abort and invalid timeouts do not start opening, attachment, or cleanup", async () => {
    const owner = new ResourceLifecycle("new"); let calls = 0;
    assert.throws(() => owner.open(async () => { calls++; }, { signal: AbortSignal.abort() }), disposed);
    for (const timeoutMs of [0, -1, NaN, Infinity]) assert.throws(() => owner.close({ timeoutMs }), TypeError);
    assert.equal(calls, 0); assert.equal(owner.state, "new");
    await assert.rejects(owner.retryCleanup(), disposed);
    await owner.close();
  });
}

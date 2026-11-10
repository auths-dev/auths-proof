import assert from "node:assert/strict";

const deferred = () => {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};
const context = () => ({ signal: new AbortController().signal });
const kind = (expected) => (error) => error?.kind === expected;
const response = (request, decision = "approved") => ({
  requestId: request.requestId,
  transactionDigest: request.transactionDigest.slice(),
  policy: { ...request.policy, configurationDigest: request.policy.configurationDigest.slice() },
  decision,
});

function fixture(BoundedApprovalSession, provider, count = 2) {
  let now = 100n;
  const jobs = new Map();
  const scheduler = {
    schedule(callback, delayMs) {
      assert.ok(delayMs > 0 && delayMs <= 2147483647);
      const id = Symbol(); jobs.set(id, callback);
      return () => jobs.delete(id);
    },
  };
  const policy = { mode: "plan-once", maxUses: count, expiresInSeconds: 10, requirements: [],
    reference: { policyId: "plan", evaluatorVersion: "1", configurationDigest: new Uint8Array(32).fill(7) } };
  const members = Array.from({ length: count }, (_, i) => new Uint8Array(32).fill(i + 1));
  const session = new BoundedApprovalSession({ planCommitment: new Uint8Array(32).fill(9), memberCommitments: members,
    policy, provider, display: [], now: () => now, scheduler });
  const request = (expiresAt = 110n) => ({ requestId: "member", objectKind: "action", transactionDigest: new Uint8Array(32).fill(3),
    policy: { ...policy.reference, configurationDigest: policy.reference.configurationDigest.slice() }, expiresAt,
    display: [{ label: "Action", value: "exact" }] });
  return { session, members, request, time(value) { now = value; }, wake() {
    const [id, callback] = jobs.entries().next().value;
    jobs.delete(id); callback();
  }, jobs };
}

/** Run unchanged against built source and the installed, source-free package. */
export async function approvalStateContract(t, { BoundedApprovalSession, noApproval, thresholdApproval }) {
  await t.test("A1: one pending request owns the member; successful acceptance advances once", async () => {
    const entered = deferred(), completion = deferred(); let calls = 0;
    const f = fixture(BoundedApprovalSession, { approve(request, ctx) {
      calls++; assert.equal(ctx.signal.aborted, false); entered.resolve(request); return completion.promise;
    } });
    const first = f.session.providerFor(0, f.members[0]);
    const second = f.session.providerFor(1, f.members[1]);
    const pending = first.approve(f.request(), context());
    const visible = await entered.promise;
    await assert.rejects(first.approve(f.request(), context()), kind("rejected"));
    await assert.rejects(second.approve(f.request(), context()), kind("rejected"));
    completion.resolve(response(visible));
    assert.equal((await pending).decision, "approved");
    assert.equal((await second.approve(f.request(), context())).decision, "approved");
    await assert.rejects(first.approve(f.request(), context()), kind("rejected"));
    assert.equal(calls, 1);
    await f.session.dispose();
  });

  for (const reason of ["dispose", "abort", "session-expiry", "request-expiry"]) {
    await t.test(`A2/A5: ${reason} settles an uncooperative provider and invalidates late completion`, async () => {
      const entered = deferred(), completion = deferred(); let providerSignal;
      const f = fixture(BoundedApprovalSession, { approve(request, ctx) { providerSignal = ctx.signal; entered.resolve(request); return completion.promise; } });
      const caller = new AbortController();
      const member = f.session.providerFor(0, f.members[0]);
      const pending = member.approve(f.request(reason === "request-expiry" ? 105n : 120n), { signal: caller.signal });
      const visible = await entered.promise;
      const rejected = assert.rejects(pending, kind(reason.includes("expiry") ? "timeout" : "cancelled"));
      if (reason === "dispose") await f.session.dispose();
      if (reason === "abort") caller.abort();
      if (reason.includes("expiry")) { f.time(reason === "request-expiry" ? 106n : 111n); f.wake(); }
      await rejected;
      assert.equal(providerSignal.aborted, true);
      assert.equal(f.jobs.size, 0);
      completion.resolve(response(visible));
      f.time(100n);
      await assert.rejects(member.approve(f.request(), context()), kind(reason.includes("expiry") ? "timeout" : "cancelled"));
    });
  }

  await t.test("A3: refusal, malformed response and provider errors are terminal and typed", async () => {
    for (const mode of ["refusal", "mismatch", "invalid-decision", "error", "typed-error"]) {
      const f = fixture(BoundedApprovalSession, { async approve(request) {
        if (mode === "error") throw new Error("unavailable");
        if (mode === "typed-error") return noApproval.approve(request, { signal: AbortSignal.abort() });
        if (mode === "mismatch") return { ...response(request), requestId: "other" };
        if (mode === "invalid-decision") return { ...response(request), decision: "maybe" };
        return response(request, "rejected");
      } });
      const member = f.session.providerFor(0, f.members[0]);
      if (mode === "refusal") assert.equal((await member.approve(f.request(), context())).decision, "rejected");
      else await assert.rejects(member.approve(f.request(), context()), kind(mode === "typed-error" ? "cancelled" : mode === "error" ? "unavailable" : "rejected"));
      await assert.rejects(member.approve(f.request(), context()), kind("rejected"));
      assert.equal(f.jobs.size, 0);
    }
  });

  await t.test("A4: caller and provider mutation cannot rewrite retained approval bindings", async () => {
    const entered = deferred(), completion = deferred(); let saved;
    const f = fixture(BoundedApprovalSession, { approve(visible) {
      saved = response(visible);
      visible.transactionDigest.fill(44); visible.policy.configurationDigest.fill(45);
      entered.resolve(); return completion.promise;
    } });
    const member = f.session.providerFor(0, f.members[0]);
    f.members[0].fill(40); // closure and constructor both own a separate commitment.
    const request = f.request();
    const pending = member.approve(request, context());
    await entered.promise;
    request.transactionDigest.fill(46); request.policy.configurationDigest.fill(47);
    request.display[0].value = "changed"; request.requestId = "changed";
    completion.resolve(saved);
    const accepted = await pending;
    assert.equal(accepted.requestId, "member");
    assert.deepEqual(accepted.transactionDigest, new Uint8Array(32).fill(3));
    assert.deepEqual(accepted.policy.configurationDigest, new Uint8Array(32).fill(7));
    await f.session.dispose();
  });

  await t.test("A4: shared or detached decision bytes cannot enter pending state", async () => {
    const f = fixture(BoundedApprovalSession, { approve: async (request) => response(request) });
    const member = f.session.providerFor(0, f.members[0]);
    const shared = f.request(); shared.transactionDigest = new Uint8Array(new SharedArrayBuffer(32));
    await assert.rejects(member.approve(shared, context()), kind("rejected"));
    assert.throws(() => f.session.providerFor(0, new Uint8Array(new SharedArrayBuffer(32))), TypeError);
    const detached = new Uint8Array(32); structuredClone(detached, { transfer: [detached.buffer] });
    assert.throws(() => f.session.providerFor(0, detached), TypeError);
    assert.equal((await member.approve(f.request(), context())).decision, "approved");
    await f.session.dispose();
  });

  await t.test("A5: pre-abort does not poison the session; post-acceptance abort does not undo acceptance", async () => {
    const f = fixture(BoundedApprovalSession, { approve: async (request) => response(request) });
    const first = f.session.providerFor(0, f.members[0]), second = f.session.providerFor(1, f.members[1]);
    const cancelled = new AbortController(); cancelled.abort();
    await assert.rejects(first.approve(f.request(), { signal: cancelled.signal }), kind("cancelled"));
    const caller = new AbortController();
    assert.equal((await first.approve(f.request(), { signal: caller.signal })).decision, "approved");
    caller.abort();
    assert.equal((await second.approve(f.request(), context())).decision, "approved");
    await f.session.dispose();
  });

  await t.test("A5: threshold abort stops unscheduled children and consumes late rejections", async () => {
    const caller = new AbortController(); let started = 0;
    const provider = thresholdApproval({ threshold: 1, providers: [
      { approve() { started++; caller.abort(); return Promise.reject(new Error("late")); } },
      { approve(request) { started++; return Promise.resolve(response(request)); } },
    ] });
    const f = fixture(BoundedApprovalSession, provider);
    await assert.rejects(provider.approve(f.request(), { signal: caller.signal }), kind("cancelled"));
    assert.equal(started, 1);
  });

  await t.test("A6: equality is valid; effective time does not roll back; pre-admission expiry rejects only its request", async () => {
    const entered = deferred(), completion = deferred();
    const f = fixture(BoundedApprovalSession, { approve(request) { entered.resolve(request); return completion.promise; } });
    const member = f.session.providerFor(0, f.members[0]);
    await assert.rejects(member.approve(f.request(99n), context()), kind("timeout"));
    const pending = member.approve(f.request(105n), context());
    const visible = await entered.promise;
    f.time(105n); f.wake(); assert.equal(f.jobs.size, 1);
    f.time(104n); f.wake(); assert.equal(f.jobs.size, 1);
    completion.resolve(response(visible));
    assert.equal((await pending).decision, "approved");
    f.time(110n);
    assert.equal((await f.session.providerFor(1, f.members[1]).approve(f.request(), context())).decision, "approved");
    await f.session.dispose();
    const expiry = fixture(BoundedApprovalSession, noApproval);
    const oldMember = expiry.session.providerFor(0, expiry.members[0]);
    expiry.time(111n);
    await assert.rejects(oldMember.approve(expiry.request(), context()), kind("timeout"));
    expiry.time(100n);
    await assert.rejects(oldMember.approve(expiry.request(), context()), kind("timeout"));
  });
}

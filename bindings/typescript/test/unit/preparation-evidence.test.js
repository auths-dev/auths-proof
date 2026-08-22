import assert from "node:assert/strict";
import { test } from "node:test";
import { chmod, mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { RecoveryRequiredError, connect, recoveryHandleFromBytes } from "../../dist/index.js";
import { decodeDeterministic, encodeDeterministic } from "../../dist/internal/cbor.js";
import { PROFILE_CLIENT_RUNTIME, bindProfile } from "../../dist/profile-runtime.js";
import {
  beginProfileInvocation, finishProfileInvocation, profileInvocationStatus,
  publishProfileInvocation,
} from "../../dist/session.js";

const operation = "op_AAAAAAAAAAAAAAAAAAAAAA";
const digest = new Uint8Array(32).fill(12);
const descriptor = {
  profileClientRuntime: PROFILE_CLIENT_RUNTIME,
  profileId: "auths.example.double",
  version: 1,
  collectionRoute: "/v1/profiles/example/double/1/operations",
  runtimeContractDigest: Buffer.from(digest).toString("hex"),
  errorProjectionDigest: Buffer.from(digest).toString("hex"),
  preparationEvidence: "protected-lease",
  requestBytes: 4096,
  responseBytes: 4096,
  executionMilliseconds: 30_000,
  receiptCount: 4,
  receiptBytes: 1024,
  profileApi: {
    schema: "auths.profile-api/1",
    types: {
      Input: { kind: "record", fields: [{ name: "value", value: { kind: "uint", minimum: "0", maximum: "100" }, sensitive: false }] },
      Result: { kind: "record", fields: [{ name: "doubled", value: { kind: "uint", minimum: "0", maximum: "200" }, sensitive: false }] },
    },
  },
  inputType: "Input",
  successType: "Result",
};

function recoveryForOperation(operationId = operation) {
  return recoveryHandleFromBytes(encodeDeterministic(new Map([
    [1, 1], [2, operationId], [3, descriptor.profileId], [4, descriptor.version],
    [5, new Uint8Array(32)], [6, 1], [7, null], [8, new Uint8Array(32)],
    [9, "Ed25519"], [10, "recovery-test"], [11, new Uint8Array(64)],
  ])));
}

function pendingEntry(operationId, updatedAt, state = "ready", effect = "not-applied") {
  return new Map([
    [1, operationId], [2, descriptor.profileId], [3, descriptor.version], [4, state],
    [5, effect], [6, false], [7, updatedAt], [8, []],
    [9, recoveryForOperation(operationId).toBytes()], [10, "primary"],
  ]);
}

function completed(request) {
  return new Map([
    [1, 1], [2, "completed"], [3, request], [4, operation],
    [5, encodeDeterministic(new Map([["doubled", 14]]))], [6, []],
    [7, "replayed"], [8, "primary"],
  ]);
}

function conflictIssue() {
  return encodeDeterministic(new Map([
    ["schema", "auths.error/1"], ["family", "state"], ["code", "operation.idempotency-conflict"],
    ["operation", "execute"], ["stage", "reservation"], ["summary", "the idempotency key names a different operation"],
    ["correlationId", operation], ["retry", "unknown"], ["effect", "possible"],
    ["entered", new Map([["approval", true], ["signer", true], ["state", true], ["credential", true], ["provider", true]])],
    ["recommendedAction", "resume-and-reconcile"], ["executionReference", operation],
    ["decisionReference", null], ["receiptReference", null], ["causes", ["conflict"]],
  ]));
}

function conflict(request) {
  return new Map([
    [1, 1], [2, "conflict"], [3, request], [4, operation], [5, conflictIssue()],
    [6, recoveryForOperation().toBytes()], [7, []], [8, "primary"],
  ]);
}

function inProgress(request, effect) {
  return new Map([
    [1, 1], [2, "in-progress"], [3, request], [4, operation], [5, "executing"],
    [6, effect], [7, []], [8, recoveryForOperation().toBytes()], [9, "primary"],
  ]);
}

function notApplied(request) {
  const issue = encodeDeterministic(new Map([
    ["schema", "auths.error/1"], ["family", "runtime"], ["code", "operation.timed-out"],
    ["operation", "execute"], ["stage", "pre-provider"], ["summary", "the operation timed out before provider entry"],
    ["correlationId", operation], ["retry", "safe"], ["effect", "not-applied"],
    ["entered", new Map([["approval", true], ["signer", true], ["state", true], ["credential", false], ["provider", false]])],
    ["recommendedAction", "retry-execution"], ["executionReference", operation],
    ["decisionReference", null], ["receiptReference", null], ["causes", ["timeout"]],
  ]));
  return new Map([
    [1, 1], [2, "not-applied"], [3, request], [4, operation], [5, issue],
    [6, []], [7, "fresh"], [8, "primary"],
  ]);
}

async function withCompanion(initial, action, options = {}) {
  const directory = await mkdtemp(join(tmpdir(), "auths-preparation-evidence-"));
  const socketPath = join(directory, "agent.sock");
  const paths = [];
  let operationRequest;
  let companionRequests = 0;
  let prepareRequests = 0;
  const server = createServer((socket) => {
    let buffered = Buffer.alloc(0);
    socket.on("data", (chunk) => {
      buffered = Buffer.concat([buffered, chunk]);
      const marker = buffered.indexOf("\r\n\r\n");
      if (marker < 0) return;
      const header = buffered.subarray(0, marker).toString("ascii");
      const contentLength = Number(/^Content-Length: (\d+)$/mi.exec(header)?.[1]);
      if (!Number.isSafeInteger(contentLength) || buffered.length !== marker + 4 + contentLength) return;
      const [method, path] = header.split("\r\n", 1)[0].split(" ");
      paths.push(path);
      const request = contentLength === 0 ? null : decodeDeterministic(buffered.subarray(marker + 4));
      let response;
      if (method === "POST" && path === "/v1/session") {
        response = new Map([
          [1, 1], [2, request.get(2)], [3, options.sessionId ?? "ses_AQEBAQEBAQEBAQEBAQEBAQ"], [4, options.principal ?? "raw:test-agent"], [5, options.recoveryOnly === true ? new Uint8Array(32).fill(99) : request.get(5)],
          [6, [new Map([[1, options.profileId ?? descriptor.profileId], [2, options.profileVersion ?? descriptor.version], [3, options.profileDigestMismatch === true ? new Uint8Array(32).fill(88) : digest], [4, "auths.profile-operation/1"], [5, options.profileDigestMismatch === true ? new Uint8Array(32).fill(88) : digest], [6, options.connectionProjection ?? null], [7, options.nullQualification === true ? null : new Map([[1, `qlf_${"A".repeat(43)}`], [2, "linux-x86_64"], [3, new Uint8Array(32).fill(4)]])]])]],
          [7, 16], [8, options.recoveryOnly === true ? "recovery-only" : "full"],
        ]);
      } else if (method === "DELETE") {
        response = new Map([[1, 1]]);
      } else if (path === "/v1/operations/pending") {
        response = new Map([[1, 1], [2, options.pendingRows ?? []]]);
      } else if (path.endsWith("/preparation-evidence")) {
        operationRequest = request.get(2);
        companionRequests += 1;
        if (companionRequests === 1 && options.cancelCompanion !== undefined) {
          options.cancelCompanion();
          return;
        }
        if (companionRequests === 1 && options.malformedCompanion === true) {
          response = new Map();
        } else
        if (initial === null) {
          response = new Map([[1, 1], [2, request.get(2)], [3, "lease"], [4, new Uint8Array(32).fill(1)], [5, new Uint8Array(32).fill(2)], [6, 4_000_000_000]]);
        } else {
          const nested = initial(request.get(2));
          response = new Map([[1, 1], [2, request.get(2)], [3, "outcome"], [4, encodeDeterministic(nested)]]);
        }
      } else if (method === "POST" && path === descriptor.collectionRoute) {
        prepareRequests += 1;
        options.onPrepare?.(request, prepareRequests);
        if (prepareRequests === 1 && options.cancelPrepare !== undefined) {
          options.cancelPrepare();
          return;
        }
        if (prepareRequests === 1 && options.timeoutPrepare === true) return;
        response = prepareRequests === 1 && options.malformedPrepare === true
          ? new Map()
          : (options.prepareOutcome ?? completed)(request.get(2), request, prepareRequests);
      } else if (path.endsWith("/recover") && options.dropRecovery === true) {
        socket.destroy();
        return;
      } else if (path.endsWith("/recover") && options.unavailableRecovery === true) {
        response = new Map([[1, 1], [2, "unavailable"], [3, request.get(2)], [4, operation], [5, notApplied(request.get(2)).get(5)], [6, []], [7, "primary"]]);
      } else if (path.endsWith("/recover") && options.unknownRecovery === true) {
        response = new Map([[1, 1], [2, "future-terminal"], [3, request.get(2)], [4, operation]]);
      } else if (path.endsWith("/recover")) {
        response = (options.recoverOutcome ?? completed)(request.get(2));
      } else {
        const requestId = request instanceof Map ? request.get(2) : operationRequest;
        response = completed(requestId);
      }
      const body = Buffer.from(encodeDeterministic(response));
      const send = () => socket.end(Buffer.concat([
        Buffer.from(`HTTP/1.1 200 OK\r\nContent-Type: application/auths+cbor;version=1\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n`, "ascii"), body,
      ]));
      if (method === "POST" && path === descriptor.collectionRoute && prepareRequests === 1 && options.delayFirstPrepareMs !== undefined) setTimeout(send, options.delayFirstPrepareMs);
      else send();
    });
  });
  try {
    await new Promise((resolve, reject) => { server.once("error", reject); server.listen(socketPath, resolve); });
    await chmod(socketPath, 0o600);
    const client = await connect({ agentSocket: socketPath });
    try {
      await action(bindProfile(client, descriptor, "primary"), paths, client);
    } finally {
      await client.close();
    }
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(directory, { recursive: true, force: true });
  }
}

test("profile invocation coordination is bounded, uses fresh conflict IDs, and promotes after a prewrite failure", async () => {
  await withCompanion(null, async (_profile, _paths, client) => {
    const requestA = new Uint8Array(16).fill(1);
    const requestB = new Uint8Array(16).fill(2);
    const scope = "auths.example.double/1:coordinated";
    const leader = beginProfileInvocation(client, scope, "fingerprint-a", requestA);
    assert.equal(leader.role, "leader");
    const conflictProbe = beginProfileInvocation(client, scope, "fingerprint-b", requestB);
    assert.equal(conflictProbe.role, "conflict-probe");
    assert.deepEqual(conflictProbe.requestId, requestB);
    finishProfileInvocation(client, conflictProbe);

    const followers = Array.from({ length: 256 }, () => beginProfileInvocation(client, scope, "fingerprint-a", new Uint8Array(16).fill(3)));
    assert.ok(followers.every((ticket) => ticket.role === "follower"));
    const observer = beginProfileInvocation(client, scope, "fingerprint-a", new Uint8Array(16).fill(4));
    assert.equal(observer.role, "observer");
    let statusReads = 0;
    let releaseStatus;
    const pendingStatus = new Promise((resolve) => { releaseStatus = resolve; });
    const statuses = [...followers, observer].map((ticket) => profileInvocationStatus(client, ticket, async () => {
      statusReads += 1;
      return await pendingStatus;
    }));
    assert.equal(statusReads, 1);
    releaseStatus(new Uint8Array([7]));
    assert.ok((await Promise.all(statuses)).every((value) => value[0] === 7));

    publishProfileInvocation(client, leader, operation);
    const identities = await Promise.all([...followers, observer].map((ticket) => ticket.identity));
    assert.ok(identities.every((identity) => identity?.operationId === operation && Buffer.from(identity.requestId).equals(Buffer.from(requestA))));
    finishProfileInvocation(client, leader);
    for (const ticket of followers) finishProfileInvocation(client, ticket);
    finishProfileInvocation(client, observer);

    const failed = beginProfileInvocation(client, `${scope}:promotion`, "fingerprint-a", requestA);
    const firstFollower = beginProfileInvocation(client, `${scope}:promotion`, "fingerprint-a", requestB);
    const secondFollower = beginProfileInvocation(client, `${scope}:promotion`, "fingerprint-a", new Uint8Array(16).fill(5));
    finishProfileInvocation(client, failed);
    assert.equal(await firstFollower.identity, null);
    assert.equal(await secondFollower.identity, null);
    const promoted = beginProfileInvocation(client, `${scope}:promotion`, "fingerprint-a", requestB);
    const attached = beginProfileInvocation(client, `${scope}:promotion`, "fingerprint-a", requestA);
    assert.equal(promoted.role, "leader");
    assert.equal(attached.role, "follower");
    finishProfileInvocation(client, firstFollower);
    finishProfileInvocation(client, secondFollower);
    finishProfileInvocation(client, promoted);
    finishProfileInvocation(client, attached);

    const boundedLeader = beginProfileInvocation(client, `${scope}:conflicts`, "leader", requestA);
    const probes = Array.from({ length: 256 }, (_, index) => beginProfileInvocation(
      client, `${scope}:conflicts`, `changed-${index}`, new Uint8Array(16).fill(index & 0xff),
    ));
    assert.ok(probes.every((ticket) => ticket.role === "conflict-probe"));
    assert.throws(
      () => beginProfileInvocation(client, `${scope}:conflicts`, "changed-overflow", requestB),
      (error) => error?.issue?.code === "operation.admission-exhausted",
    );
    for (const ticket of probes) finishProfileInvocation(client, ticket);
    finishProfileInvocation(client, boundedLeader);
  });
});

test("generated invocations coalesce exact keys, preserve follower cancellation truth, and probe changed input with a fresh request", async () => {
  const prepareIds = [];
  await withCompanion(null, async (profile, paths) => {
    const leader = profile.invokeOutcome({ value: 7 }, { idempotencyKey: "same-key", timeoutMs: 1_000, recoveryWaitMs: 100 });
    while (!paths.includes(descriptor.collectionRoute)) await new Promise((resolve) => setTimeout(resolve, 1));
    const followerAbort = new AbortController();
    const follower = profile.invokeOutcome({ value: 7 }, { idempotencyKey: "same-key", timeoutMs: 1_000, recoveryWaitMs: 100, signal: followerAbort.signal });
    followerAbort.abort();
    const changed = profile.invokeOutcome({ value: 8 }, { idempotencyKey: "same-key", timeoutMs: 1_000, recoveryWaitMs: 100 });
    const [first, second, mismatch] = await Promise.all([leader, follower, changed]);
    assert.equal(first.kind, "completed");
    assert.equal(second.kind, "completed");
    assert.equal(mismatch.kind, "conflict");
    assert.equal(first.value.auths.completion, "fresh");
    assert.equal(second.value.auths.completion, "replayed");
    assert.equal(paths.filter((path) => path.endsWith("/preparation-evidence")).length, 2);
    assert.equal(paths.filter((path) => path === descriptor.collectionRoute).length, 2);
    assert.equal(paths.some((path) => path.endsWith("/execute")), false);
    assert.equal(prepareIds.length, 2);
    assert.notDeepEqual(prepareIds[0], prepareIds[1]);
  }, {
    delayFirstPrepareMs: 40,
    onPrepare: (request) => prepareIds.push(Buffer.from(request.get(2))),
    prepareOutcome: (requestId, _request, count) => {
      if (count !== 1) return conflict(requestId);
      const value = completed(requestId); value.set(7, "fresh"); return value;
    },
  });
});

test("a null qualification advertisement remains usable for the isolated testkit", async () => {
  await withCompanion(null, async (profile, paths) => {
    const outcome = await profile.invokeOutcome({ value: 7 });
    assert.equal(outcome.kind, "completed");
    assert.equal(paths.filter((path) => path.endsWith("/preparation-evidence")).length, 1);
  }, { nullQualification: true });
});

test("session negotiation rejects malformed binding and unrelated profile rows", async () => {
  const hostile = [
    { sessionId: "test-session" },
    { sessionId: "ses_AAAAAAAAAAAAAAAAAAAAAA" },
    { principal: "DID:key:noncanonical" },
    { profileId: "auths.Bad.profile" },
    { profileVersion: true },
    { connectionProjection: new Map([[1, "Stripe"], [2, "auths.stripe.connection/1"], [3, "auths.stripe.connection-descriptor/1"]]) },
    { connectionProjection: new Map([[1, "stripe"], [2, "invalid semantic id"], [3, "auths.stripe.connection-descriptor/1"]]) },
  ];
  for (const options of hostile) {
    let dispatched = false;
    await assert.rejects(withCompanion(null, async () => { dispatched = true; }, options));
    assert.equal(dispatched, false);
  }
});

test("recovery-only sessions block new effects but conservatively preserve root recovery", async () => {
  await withCompanion(null, async (profile, paths) => {
    const outcome = await profile.recoverOutcome(recoveryForOperation());
    assert.equal(outcome.kind, "completed");
    assert.equal(paths.filter((path) => path.endsWith("/recover")).length, 1);
  }, { recoveryOnly: true });

  await withCompanion(null, async (profile, paths) => {
    const recovery = recoveryForOperation();
    const outcome = await profile.recoverOutcome(recovery);
    assert.equal(outcome.kind, "recovery-required");
    assert.equal(outcome.issue.code, "operation.recovery-unavailable");
    assert.equal(outcome.operationId, operation);
    assert.equal(outcome.recovery, recovery);
    assert.equal(paths.filter((path) => path.endsWith("/recover")).length, 1);
  }, { recoveryOnly: true, unknownRecovery: true });

  await withCompanion(null, async (profile, paths) => {
    const outcome = await profile.recoverOutcome(recoveryForOperation());
    assert.equal(outcome.kind, "recovery-required");
    assert.equal(outcome.issue.code, "operation.recovery-unavailable");
    assert.equal(paths.filter((path) => path.endsWith("/recover")).length, 1);
  }, { recoveryOnly: true, profileDigestMismatch: true });

  await withCompanion(null, async (profile, paths, client) => {
    await assert.rejects(profile.invokeOutcome({ value: 7 }), (error) => error?.code === "client.profile-unavailable");
    assert.equal(paths.some((path) => path.endsWith("/preparation-evidence")), false);
    const recovery = recoveryForOperation();
    await assert.rejects(
      client.operations.recover(recovery),
      (error) => error instanceof RecoveryRequiredError && error.code === "operation.recovery-unavailable" && error.operationId === operation && error.recovery === recovery,
    );
  }, { recoveryOnly: true, unknownRecovery: true });
});

test("generated recovery never accepts a foreign operation response", async () => {
  const foreign = `op_${"B".repeat(22)}`;
  await withCompanion(null, async (profile) => {
    const recovery = recoveryForOperation();
    const outcome = await profile.recoverOutcome(recovery);
    assert.equal(outcome.kind, "recovery-required");
    assert.equal(outcome.operationId, operation);
    assert.equal(outcome.recovery, recovery);
  }, {
    recoverOutcome: (request) => new Map([
      [1, 1], [2, "completed"], [3, request], [4, foreign],
      [5, encodeDeterministic(new Map([["doubled", 14]]))], [6, []],
      [7, "replayed"], [8, "primary"],
    ]),
  });

  await withCompanion(null, async (profile) => {
    const recovery = recoveryForOperation();
    const outcome = await profile.recoverOutcome(recovery);
    assert.equal(outcome.kind, "recovery-required");
    assert.equal(outcome.operationId, operation);
    assert.equal(outcome.recovery, recovery);
  }, {
    recoverOutcome: (request) => new Map([
      [1, 1], [2, "in-progress"], [3, request], [4, operation], [5, "executing"],
      [6, "possible"], [7, []], [8, recoveryForOperation(foreign).toBytes()], [9, "primary"],
    ]),
  });
});

test("pending rows are exact, identity-bound, and strictly ordered", async () => {
  const second = `op_${"B".repeat(22)}`;
  await withCompanion(null, async (_profile, _paths, client) => {
    const rows = await client.operations.pending();
    assert.deepEqual(rows.map((row) => row.operationId), [operation, second]);
    assert.ok(rows.every((row) => row.terminal === false && row.state === "ready"));
  }, { pendingRows: [pendingEntry(operation, 10), pendingEntry(second, 10)] });

  const extra = pendingEntry(operation, 10); extra.set(11, null);
  const wrongTruth = pendingEntry(operation, 10, "ready", "possible");
  const wrongHandle = pendingEntry(second, 10); wrongHandle.set(9, recoveryForOperation(operation).toBytes());
  for (const rows of [
    [extra], [wrongTruth], [wrongHandle],
    [pendingEntry(second, 10), pendingEntry(operation, 10)],
  ]) {
    await withCompanion(null, async (_profile, _paths, client) => {
      await assert.rejects(client.operations.pending(), TypeError);
    }, { pendingRows: rows });
  }
});

test("unavailable is a terminal not-applied recovery status", async () => {
  await withCompanion(null, async (_profile, _paths, client) => {
    const status = await client.operations.recover(recoveryForOperation());
    assert.equal(status.state, "unavailable");
    assert.equal(status.effect, "not-applied");
    assert.equal(status.terminal, true);
  }, { unavailableRecovery: true });
});

test("root recovery validates every status field and returned handle identity", async () => {
  const foreign = `op_${"B".repeat(22)}`;
  const hostile = [
    (request) => { const value = inProgress(request, "not-applied"); value.set(5, "future"); return value; },
    (request) => { const value = inProgress(request, "possible"); value.set(8, recoveryForOperation(foreign).toBytes()); return value; },
    (request) => { const value = completed(request); value.set(7, "future"); return value; },
    (request) => new Map([[1, 1], [2, "unavailable"], [3, request], [4, operation], [5, conflictIssue()], [6, []], [7, "primary"]]),
  ];
  for (const recoverOutcome of hostile) {
    await withCompanion(null, async (_profile, _paths, client) => {
      const recovery = recoveryForOperation();
      await assert.rejects(
        client.operations.recover(recovery),
        (error) => error instanceof RecoveryRequiredError && error.operationId === operation && error.recovery === recovery,
      );
    }, { recoverOutcome });
  }
});

test("root recovery preserves the original handle after a written response is lost", async () => {
  for (const recoveryOnly of [false, true]) {
    await withCompanion(null, async (_profile, _paths, client) => {
      const recovery = recoveryForOperation();
      await assert.rejects(
        client.operations.recover(recovery, { timeoutMs: 100, recoveryWaitMs: 50 }),
        (error) => error instanceof RecoveryRequiredError && error.code === "operation.recovery-unavailable" && error.operationId === operation && error.recovery === recovery,
      );
    }, { dropRecovery: true, recoveryOnly });
  }
});

test("companion outcomes re-enter the ordinary TypeScript state machine", async () => {
  for (const [initial, expectedKind, expectedPath] of [
    [(request) => inProgress(request, "not-applied"), "completed", `/${operation}`],
    [(request) => inProgress(request, "possible"), "completed", "/recover"],
    [(request) => completed(request), "completed", null],
    [(request) => conflict(request), "conflict", null],
  ]) {
    await withCompanion(initial, async (profile, paths) => {
      const outcome = await profile.invokeOutcome({ value: 7 });
      assert.equal(outcome.kind, expectedKind);
      assert.equal(paths.filter((path) => path.endsWith("/preparation-evidence")).length, 1);
      if (expectedPath === null) assert.equal(paths.some((path) => path.endsWith(`/${operation}`) || path.endsWith("/recover")), false);
      else assert.equal(paths.some((path) => path.endsWith(expectedPath)), true);
    });
  }
});

test("post-write cancellation never advances a not-applied TypeScript operation", async () => {
  const companionAbort = new AbortController();
  await withCompanion(null, async (profile, paths) => {
    await assert.rejects(
      profile.invokeOutcome({ value: 7 }, { signal: companionAbort.signal }),
      (error) => error instanceof DOMException && error.name === "AbortError",
    );
    assert.equal(paths.filter((path) => path.endsWith("/preparation-evidence")).length, 2);
    assert.equal(paths.some((path) => path === descriptor.collectionRoute), false);
  }, { cancelCompanion: () => companionAbort.abort() });

  const prepareAbort = new AbortController();
  await withCompanion(null, async (profile, paths) => {
    await assert.rejects(
      profile.invokeOutcome({ value: 7 }, { signal: prepareAbort.signal }),
      (error) => error instanceof DOMException && error.name === "AbortError",
    );
    assert.equal(paths.filter((path) => path === descriptor.collectionRoute).length, 2);
    assert.equal(paths.some((path) => path.endsWith("/execute")), false);
    assert.equal(paths.filter((path) => path.endsWith("/recover")).length, 1);
  }, {
    cancelPrepare: () => prepareAbort.abort(),
    prepareOutcome: (request) => inProgress(request, "not-applied"),
    recoverOutcome: notApplied,
  });
});

test("post-write cancellation preserves coalesced applied and possible truth", async () => {
  for (const [prepareOutcome, recoverOutcome, expected] of [
    [completed, undefined, "completed"],
    [(request) => inProgress(request, "possible"), (request) => inProgress(request, "possible"), "recovery-required"],
  ]) {
    const controller = new AbortController();
    await withCompanion(null, async (profile, paths) => {
      const outcome = await profile.invokeOutcome({ value: 7 }, { signal: controller.signal });
      assert.equal(outcome.kind, expected);
      assert.equal(paths.some((path) => path.endsWith("/execute")), false);
    }, { cancelPrepare: () => controller.abort(), prepareOutcome, recoverOutcome });
  }
});

test("malformed companion and prepare responses are exactly replayed", async () => {
  await withCompanion(null, async (profile, paths) => {
    assert.equal((await profile.invokeOutcome({ value: 7 })).kind, "completed");
    assert.equal(paths.filter((path) => path.endsWith("/preparation-evidence")).length, 2);
  }, { malformedCompanion: true });

  await withCompanion(null, async (profile, paths) => {
    assert.equal((await profile.invokeOutcome({ value: 7 })).kind, "completed");
    assert.equal(paths.filter((path) => path === descriptor.collectionRoute).length, 2);
  }, { malformedPrepare: true });
});

test("post-write timeout uses the reserved cleanup budget and never executes", async () => {
  await withCompanion(null, async (profile, paths) => {
    const outcome = await profile.invokeOutcome(
      { value: 7 },
      { timeoutMs: 100, recoveryWaitMs: 50 },
    );
    assert.equal(outcome.kind, "not-applied");
    assert.equal(paths.filter((path) => path === descriptor.collectionRoute).length, 2);
    assert.equal(paths.some((path) => path.endsWith("/execute")), false);
    assert.equal(paths.filter((path) => path.endsWith("/recover")).length, 1);
  }, { timeoutPrepare: true, prepareOutcome: (request) => inProgress(request, "not-applied"), recoverOutcome: notApplied });
});

import assert from "node:assert/strict";
import test from "node:test";
import { renameWithWindowsGracePeriod } from "../../dist/internal/development-store-node.js";

const fileError = (code) => Object.assign(new Error(code), { code });

test("Windows checkpoint replacement waits through transient destination locks", async () => {
  let attempts = 0;
  const waits = [];
  await renameWithWindowsGracePeriod("checkpoint.tmp", "checkpoint.json", {
    operatingSystem: "win32",
    async operation() {
      attempts += 1;
      if (attempts < 3) throw fileError("EPERM");
    },
    async wait(milliseconds) {
      waits.push(milliseconds);
    },
  });

  assert.equal(attempts, 3);
  assert.deepEqual(waits, [25, 50]);
});

test("checkpoint replacement never retries a permanent or non-Windows error", async () => {
  for (const [operatingSystem, code] of [["win32", "ENOENT"], ["linux", "EPERM"]]) {
    let attempts = 0;
    const error = fileError(code);
    await assert.rejects(
      renameWithWindowsGracePeriod("checkpoint.tmp", "checkpoint.json", {
        operatingSystem,
        async operation() {
          attempts += 1;
          throw error;
        },
        async wait() {
          assert.fail("a permanent rename error must not wait");
        },
      }),
      (received) => received === error,
    );
    assert.equal(attempts, 1);
  }
});

test("Windows checkpoint replacement retry budget is bounded", async () => {
  let attempts = 0;
  let waits = 0;
  const error = fileError("EBUSY");
  await assert.rejects(
    renameWithWindowsGracePeriod("checkpoint.tmp", "checkpoint.json", {
      operatingSystem: "win32",
      async operation() {
        attempts += 1;
        throw error;
      },
      async wait() {
        waits += 1;
      },
    }),
    (received) => received === error,
  );
  assert.equal(attempts, 9);
  assert.equal(waits, 8);
});

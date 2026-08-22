import assert from "node:assert/strict";
import fs, { constants } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { readBoundedProfileFile } from "../../dist/internal/profile-file-node.js";

const { mkdtemp, mkdir, rename, rm, symlink, writeFile } = fs.promises;

test("profile files are nofollow, regular, and bounded to maximum plus one", async () => {
  const directory = await mkdtemp(join(tmpdir(), "auths-profile-file-"));
  const selected = join(directory, "selected.bin");
  const linked = join(directory, "linked.bin");
  const folder = join(directory, "folder");
  const raceSelected = join(directory, "race-selected.bin");
  const replacement = join(directory, "replacement.bin");
  const originalOpen = fs.promises.open;
  let observedFlags = 0;
  let observedReadLength = 0;
  let beforeOpen = async () => {};
  fs.promises.open = async (path, flags, mode) => {
    observedFlags = Number(flags);
    await beforeOpen(path);
    const handle = await originalOpen(path, flags, mode);
    const originalRead = handle.read.bind(handle);
    handle.read = async (buffer, offset, length, position) => {
      observedReadLength = length;
      return originalRead(buffer, offset, length, position);
    };
    return handle;
  };
  try {
    await writeFile(selected, Uint8Array.of(1, 2, 3));
    assert.deepEqual(await readBoundedProfileFile(selected, 3), Uint8Array.of(1, 2, 3));
    assert.notEqual(observedFlags & constants.O_NOFOLLOW, 0);
    assert.equal(observedReadLength, 4);
    await assert.rejects(readBoundedProfileFile(selected, 2), /generated bound/);

    await symlink(selected, linked);
    await assert.rejects(readBoundedProfileFile(linked, 3), /regular non-symlink/);
    await mkdir(folder);
    await assert.rejects(readBoundedProfileFile(folder, 3), /regular non-symlink/);

    await writeFile(raceSelected, Uint8Array.of(1, 2, 3));
    await writeFile(replacement, Uint8Array.of(4, 5, 6));
    beforeOpen = async (path) => {
      if (path === raceSelected) await rename(replacement, raceSelected);
    };
    await assert.rejects(
      readBoundedProfileFile(raceSelected, 3),
      /changed during bounded read/,
    );
  } finally {
    fs.promises.open = originalOpen;
    await rm(directory, { recursive: true, force: true });
  }
});

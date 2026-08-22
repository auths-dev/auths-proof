type FileSnapshot = Readonly<{
  dev: bigint;
  ino: bigint;
  mode: bigint;
  nlink: bigint;
  size: bigint;
  mtimeNs: bigint;
  ctimeNs: bigint;
  isFile(): boolean;
  isSymbolicLink(): boolean;
}>;

/** Reads a generated-profile file without following or racing a path swap. */
export async function readBoundedProfileFile(path: string, maximum: number): Promise<Uint8Array> {
  if (!Number.isSafeInteger(maximum) || maximum < 0 || maximum > 64 * 1024 * 1024) {
    throw new RangeError("profile file maximum is outside bounds");
  }
  const { constants } = await import("node:fs");
  const { lstat, open } = await import("node:fs/promises");
  if (typeof constants.O_NOFOLLOW !== "number" || constants.O_NOFOLLOW === 0) {
    throw new TypeError("this runtime cannot safely open profile files");
  }

  let pathBefore: FileSnapshot;
  try {
    pathBefore = await lstat(path, { bigint: true });
  } catch {
    throw new TypeError("profile file is unavailable");
  }
  requireRegular(pathBefore);

  const flags = constants.O_RDONLY | constants.O_NOFOLLOW | (constants.O_NONBLOCK ?? 0);
  let handle;
  try {
    handle = await open(path, flags);
  } catch {
    throw new TypeError("profile file could not be opened safely");
  }

  let opened: FileSnapshot;
  let afterDescriptor: FileSnapshot;
  let output: Uint8Array;
  let bytesRead: number;
  let closeFailed = false;
  try {
    opened = await handle.stat({ bigint: true });
    requireRegular(opened);
    if (!sameSnapshot(pathBefore, opened)) throw new TypeError("profile file changed during bounded read");
    if (opened.size > BigInt(maximum)) throw new RangeError("profile file exceeds its generated bound");
    output = new Uint8Array(maximum + 1);
    ({ bytesRead } = await handle.read(output, 0, output.length, 0));
    afterDescriptor = await handle.stat({ bigint: true });
  } catch (error) {
    if (error instanceof TypeError || error instanceof RangeError) throw error;
    throw new TypeError("profile file could not be read safely");
  } finally {
    try { await handle.close(); } catch { closeFailed = true; }
  }
  if (closeFailed) throw new TypeError("profile file could not be closed safely");

  let pathAfter: FileSnapshot;
  try {
    pathAfter = await lstat(path, { bigint: true });
  } catch {
    throw new TypeError("profile file changed during bounded read");
  }
  requireRegular(pathAfter);
  if (!sameSnapshot(opened, afterDescriptor) || !sameSnapshot(afterDescriptor, pathAfter)) {
    throw new TypeError("profile file changed during bounded read");
  }
  if (bytesRead > maximum) throw new RangeError("profile file exceeds its generated bound");
  if (BigInt(bytesRead) !== afterDescriptor.size) throw new TypeError("profile file changed during bounded read");
  return output.slice(0, bytesRead);
}

function requireRegular(value: FileSnapshot): void {
  if (value.isSymbolicLink() || !value.isFile()) {
    throw new TypeError("profile file must be a regular non-symlink file");
  }
}

function sameSnapshot(left: FileSnapshot, right: FileSnapshot): boolean {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.nlink === right.nlink
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

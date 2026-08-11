import { readdir } from "node:fs/promises";
import { spawn } from "node:child_process";
import { join } from "node:path";

const roots = Object.freeze({
  integration: "test/integration",
  package: "test/package",
  unit: "test/unit",
});

const suite = process.argv[2];
const root = roots[suite];

if (root === undefined) {
  throw new Error(`unknown test suite: ${suite ?? "<missing>"}`);
}

const collectTests = async (directory) => {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = await Promise.all(
    entries.map(async (entry) => {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) return collectTests(path);
      return entry.isFile() && entry.name.endsWith(".test.js") ? [path] : [];
    }),
  );
  return files.flat();
};

const tests = (await collectTests(root)).sort();

if (tests.length === 0) {
  throw new Error(`no tests found for suite: ${suite}`);
}

const child = spawn(process.execPath, ["--test", ...tests], { stdio: "inherit" });
child.on("error", (error) => {
  throw error;
});
child.on("exit", (code, signal) => {
  if (signal !== null) process.kill(process.pid, signal);
  process.exitCode = code ?? 1;
});

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const snapshot = fs.readFileSync(path.join(root, "api/public-api.txt"), "utf8");
const symbols = snapshot
  .split("\n")
  .filter((line) => line && !line.startsWith("#"))
  .map((line) => {
    const [entrypoint, name, kind] = line.split("\t");
    if (!entrypoint || !name || !kind) throw new TypeError(`invalid public API line: ${line}`);
    return { entrypoint, name, kind };
  })
  .sort((left, right) => `${left.entrypoint}\0${left.name}`.localeCompare(`${right.entrypoint}\0${right.name}`));

process.stdout.write(`${JSON.stringify({ schema: "auths.docs.typescript-surface/1", package: "@auths-dev/sdk", symbols }, null, 2)}\n`);

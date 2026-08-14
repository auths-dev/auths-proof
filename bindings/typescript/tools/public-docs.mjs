import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const product = fs.readFileSync(path.join(root, "src/product.ts"), "utf8");
const required = [
  ["create", /\/\*\*[\s\S]*?@scenario auths\.scenario\.rest-effect\/1[\s\S]*?\*\/\s*export async function createAuths/],
  ["delegate", /\/\*\*[\s\S]*?@scenario auths\.scenario\.delegation\/1[\s\S]*?\*\/\s*delegate\(/],
  ["execute", /\/\*\*[\s\S]*?@scenario auths\.scenario\.rest-effect\/1[\s\S]*?\*\/\s*execute\(/],
  ["resume", /\/\*\*[\s\S]*?@security[\s\S]*?\*\/\s*resume\(/],
];

const missing = required.filter(([, pattern]) => !pattern.test(product)).map(([name]) => name);
if (missing.length > 0) {
  throw new Error(`TypeScript P0 documentation missing: ${missing.join(", ")}`);
}

process.stdout.write(JSON.stringify({ schema: "auths.public-docs.typescript/1", p0: required.length, missing: [] }));

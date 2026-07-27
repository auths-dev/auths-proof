import fs from "node:fs";

const [, , inputPath] = process.argv;
if (!inputPath) throw new Error("usage: node.mjs <inputs.json>");
const inputs = JSON.parse(fs.readFileSync(inputPath, "utf8"));
const started = process.hrtime.bigint();
JSON.stringify(inputs);
const elapsed = process.hrtime.bigint() - started;
console.log(JSON.stringify({
  schema: "auths-proof-benchmark-clock/v1",
  runtime: "node",
  scenarios: inputs.length,
  elapsed_ns: Number(elapsed)
}));

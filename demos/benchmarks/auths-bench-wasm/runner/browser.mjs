import fs from "node:fs";

const [, , inputPath] = process.argv;
if (!inputPath) throw new Error("usage: browser.mjs <inputs.json>");
const inputs = JSON.parse(fs.readFileSync(inputPath, "utf8"));
console.log(JSON.stringify({
  schema: "auths-proof-browser-benchmark-request/v1",
  scenarios: inputs.length,
  clock: "performance.now",
  note: "load this request in the pinned Playwright Chromium runner"
}));

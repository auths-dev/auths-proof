import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const recipes = resolve(fileURLToPath(new URL("..", import.meta.url)));
const root = resolve(recipes, "../..");
const manifest = JSON.parse(readFileSync(join(recipes, "manifest.json"), "utf8"));
const python = process.env.AUTHS_RECIPE_PYTHON ?? "python3";
const fixture = process.env.AUTHS_RECIPE_FIXTURE ?? join(root, manifest.fixture.root);
const timings = [];
const outputs = new Map();

for (const recipe of manifest.recipes) {
  run("typescript", recipe.id, process.execPath, [
    join(recipes, "typescript/build", `${recipe.typescript.slice("typescript/".length, -3)}.js`),
  ], recipe.expected);
  run("python", recipe.id, python, [join(recipes, recipe.python)], recipe.expected);
}

const typescriptOutput = outputs.get("typescript/05-cross-organization-plan");
const pythonOutput = outputs.get("python/05-cross-organization-plan");
if (typescriptOutput === undefined || pythonOutput === undefined) throw new Error("recipe five output is missing");
run("python", "05-verify-typescript-receipt", python, [
  join(recipes, "python/05_cross_organization_plan.py"),
  "verify",
  join(typescriptOutput, "typescript-recovered-receipt.json"),
], "verified-portable-receipt");
run("typescript", "05-verify-python-receipt", process.execPath, [
  join(recipes, "typescript/build/05-cross-organization-plan.js"),
  "verify",
  join(pythonOutput, "python-recovered-receipt.json"),
], "verified-portable-receipt");

console.log(JSON.stringify({ schema: "auths.recipe-run/1", timings }, null, 2));

function run(language, id, command, args, expected) {
  const output = mkdtempSync(join(tmpdir(), `auths-${language}-${id}-`));
  const started = performance.now();
  const result = spawnSync(command, args, {
    cwd: output,
    encoding: "utf8",
    env: {
      ...process.env,
      AUTHS_RECIPE_FIXTURE: fixture,
      AUTHS_RECIPE_OUTPUT: output,
    },
  });
  const elapsedMs = Math.round(performance.now() - started);
  if (result.status !== 0) throw new Error(`${language}/${id}: ${result.stderr || result.stdout}`);
  const lines = result.stdout.trim().split("\n");
  const observed = JSON.parse(lines.at(-1));
  if (observed.outcome !== expected) {
    throw new Error(`${language}/${id}: expected ${expected}, got ${observed.outcome}`);
  }
  timings.push({ language, id, elapsedMs });
  outputs.set(`${language}/${id}`, output);
}

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { deriveOperation, parseContract, renderLock } from "../../tools/profile-cli.mjs";

// Every derived byte comes from the Rust mapper through the packaged WASM
// module; these tests prove the TypeScript route returns it unchanged.
const corpus = fileURLToPath(new URL("../../../fixtures/openapi-derivation/", import.meta.url));
const vendors = JSON.parse(await readFile(new URL("../../../fixtures/openapi-corpus/cases.json", import.meta.url), "utf8"));
const { cases } = JSON.parse(await readFile(join(corpus, "cases.json"), "utf8"));
const cli = fileURLToPath(new URL("../../tools/profile-cli.mjs", import.meta.url));

async function documentFor(item) {
  if (item.document.file) {
    return { bytes: new Uint8Array(await readFile(join(corpus, item.document.file))),
      name: item.document.file.split("/").pop() };
  }
  const directory = process.env.AUTHS_OPENAPI_CORPUS_DIR;
  if (!directory) return undefined;
  const pinned = vendors.cases.find(entry => entry.vendor === item.document.vendor);
  const name = `${item.document.vendor.toLowerCase()}.json`;
  const bytes = await readFile(join(directory, name));
  assert.equal(createHash("sha256").update(bytes).digest("hex"), pinned.source.sha256);
  return { bytes: new Uint8Array(bytes), name };
}

test("the WASM route reproduces every derivation corpus case", async () => {
  let skipped = 0;
  for (const item of cases) {
    const document = await documentFor(item);
    if (!document) { skipped += 1; continue; }
    const expected = join(corpus, "expected", item.id);
    const result = await deriveOperation(document.bytes, document.name, item.arguments);
    assert.equal(`${result.lines.join("\n")}\n`, await readFile(join(expected, "report.txt"), "utf8"), item.id);
    if (item.outcome === "derived") {
      assert.equal(result.ok, true, item.id);
      for (const [name, contents] of Object.entries(result.files)) {
        assert.equal(contents, await readFile(join(expected, name), "utf8"), `${item.id} ${name}`);
      }
      const lock = renderLock(parseContract(result.files["profile.toml"]));
      assert.equal(lock, await readFile(join(expected, "profile.lock.json"), "utf8"), `${item.id} lock`);
      assert.equal(JSON.parse(lock).schema_digest, JSON.parse(result.files["recipe.json"]).profile_schema_digest);
    } else {
      assert.equal(result.ok, false, item.id);
      assert.deepEqual(result.diagnostics.map(({ code, pointer, overrides }) => ({ code, pointer, overrides })),
        JSON.parse(await readFile(join(expected, "rejections.json"), "utf8")), item.id);
    }
  }
  assert.ok(skipped <= 7, "only vendor cases may be skipped");
});

function run(...args) {
  return spawnSync(process.execPath, [cli, ...args], { encoding: "utf8" });
}

function derive(directory, id, ...extra) {
  const item = cases.find(entry => entry.id === id);
  return run("derive", "--openapi", join(corpus, item.document.file), "--directory", directory, ...item.arguments, ...extra);
}

test("derive, generate, check, and a hand edit through the packaged command", async () => {
  const directory = await mkdtemp(join(tmpdir(), "auths-derive-"));
  try {
    const target = join(directory, "notes");
    const expected = join(corpus, "expected", "minimal-create-note");
    const first = derive(target, "minimal-create-note");
    assert.equal(first.status, 0, first.stderr);
    assert.equal(first.stdout, await readFile(join(expected, "report.txt"), "utf8"));
    for (const name of ["profile.toml", "recipe.json", "derivation.json"]) {
      assert.deepEqual(await readFile(join(target, name)), await readFile(join(expected, name)));
    }
    const manifest = join(target, "profile.toml");
    assert.equal(run("generate", manifest).status, 0);
    assert.equal(run("check", manifest).status, 0);
    assert.equal(derive(target, "minimal-create-note").status, 0);

    const item = cases.find(entry => entry.id === "minimal-create-note");
    const narrowed = item.arguments.map(value => value.replace("title=240", "title=200"));
    const changed = ["derive", "--openapi", join(corpus, "documents/minimal.json"), "--directory", target, ...narrowed];
    const refused = run(...changed);
    assert.equal(refused.status, 1);
    assert.match(refused.stderr, /contract\.derive\.version-required/);
    assert.equal(run(...changed, "--version", "2").status, 0);
    assert.equal(run("check", manifest).status, 1);
    assert.equal(run("generate", manifest).status, 0);
    assert.equal(run("check", manifest).status, 0);

    await writeFile(manifest, (await readFile(manifest, "utf8")).replace("max_bytes = 200", "max_bytes = 199"));
    const edited = run("check", manifest);
    assert.equal(edited.status, 1);
    assert.match(edited.stderr, /profile\.toml: derived file edited by hand/);
    const report = JSON.parse(run("--json", "check", manifest).stdout);
    assert.equal(report.diagnostic.code, "profile.contract.derived-edited");
    const diff = run("diff", manifest);
    assert.equal(diff.status, 0);
    assert.match(diff.stdout, /profile\.toml: derived file edited by hand/);
    assert.match(diff.stdout, /profile\.contract\.version-required/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("rejected, hand-owned, and unsafe derivations write nothing", async () => {
  const directory = await mkdtemp(join(tmpdir(), "auths-derive-reject-"));
  try {
    const hostile = derive(join(directory, "hostile"), "hostile-object-union");
    assert.equal(hostile.status, 1);
    assert.equal(hostile.stderr, await readFile(join(corpus, "expected/hostile-object-union/report.txt"), "utf8"));
    const unmodified = cases.find(entry => entry.id === "minimal-create-note-unmodified");
    const json = run("--json", "derive", "--openapi", join(corpus, "documents/minimal.json"),
      "--directory", join(directory, "json"), ...unmodified.arguments);
    assert.equal(json.status, 1);
    assert.equal(JSON.parse(json.stdout).diagnostic.code, "contract.derive.query-parameter");
    const owned = join(directory, "owned");
    await mkdir(owned);
    await writeFile(join(owned, "profile.toml"), "# hand-owned\n");
    const refused = derive(owned, "minimal-create-note");
    assert.equal(refused.status, 1);
    assert.match(refused.stderr, /contract\.derive\.directory-not-derived/);
    assert.equal(await readFile(join(owned, "profile.toml"), "utf8"), "# hand-owned\n");
    const link = join(directory, "linked.json");
    await symlink(join(corpus, "documents/minimal.json"), link);
    const item = cases.find(entry => entry.id === "minimal-create-note");
    const unsafe = run("derive", "--openapi", link, "--directory", join(directory, "out"), ...item.arguments);
    assert.equal(unsafe.status, 1);
    assert.match(unsafe.stderr, /contract\.derive\.document-unreadable/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

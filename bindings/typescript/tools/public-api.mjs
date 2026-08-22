import { readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import ts from "typescript";

const normalizeText = (value) => value.replaceAll("\r\n", "\n").replaceAll("\r", "\n");
const normalizedPath = (value) => value.replaceAll("\\", "/");
const compareText = (left, right) => left < right ? -1 : left > right ? 1 : 0;
const comparePublicNames = (left, right) => {
  const folded = compareText(left.toLowerCase(), right.toLowerCase());
  return folded === 0 ? -compareText(left, right) : folded;
};

const packageJson = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
const topology = JSON.parse(await readFile(new URL("../../public-topology-v1.json", import.meta.url), "utf8"));
const expectedPackages = topology.layers.flatMap((layer) => layer.typescript);
const expectedSubpaths = expectedPackages.map((value) => value === packageJson.name
  ? "."
  : `.${value.slice(packageJson.name.length)}`);
if (JSON.stringify(Object.keys(packageJson.exports)) !== JSON.stringify(expectedSubpaths)) {
  throw new Error("TypeScript package exports drifted from bindings/public-topology-v1.json");
}
const declarationPath = (value) => {
  if (typeof value === "string") return undefined;
  if (typeof value.types === "string") return value.types;
  for (const nested of Object.values(value)) {
    const found = declarationPath(nested);
    if (found !== undefined) return found;
  }
  return undefined;
};
const entries = new Map(Object.entries(packageJson.exports).map(([subpath, value]) => {
  const types = declarationPath(value);
  if (types === undefined) throw new Error(`package export ${subpath} has no types condition`);
  return [subpath, types.replace(/^\.\//, "")];
}));

const program = ts.createProgram([...entries.values()], {
  module: ts.ModuleKind.NodeNext,
  moduleResolution: ts.ModuleResolutionKind.NodeNext,
  skipLibCheck: true,
  target: ts.ScriptTarget.ES2022,
});
const checker = program.getTypeChecker();
const declarationDigest = createHash("sha256");
for (const source of program.getSourceFiles()
  .filter((item) => normalizedPath(item.fileName).includes("/dist/") || item.fileName.startsWith("dist/"))
  .sort((left, right) => compareText(normalizedPath(left.fileName), normalizedPath(right.fileName)))) {
  declarationDigest.update(
    normalizedPath(source.fileName).replace(/^.*?dist\//, "dist/"),
  );
  declarationDigest.update("\0");
  declarationDigest.update(normalizeText(source.text));
  declarationDigest.update("\0");
}
const lines = [
  "# Installed @auths-dev/sdk public API v1",
  `# declaration-sha256 ${declarationDigest.digest("hex")}`,
];
const records = [];
for (const [subpath, filename] of entries) {
  const source = program.getSourceFile(filename);
  if (source === undefined) throw new Error(`missing built declaration ${filename}`);
  const moduleSymbol = checker.getSymbolAtLocation(source);
  if (moduleSymbol === undefined) throw new Error(`missing module symbol ${filename}`);
  for (const exported of checker.getExportsOfModule(moduleSymbol).sort((a, b) => comparePublicNames(a.name, b.name))) {
    const symbol = exported.flags & ts.SymbolFlags.Alias
      ? checker.getAliasedSymbol(exported)
      : exported;
    const kinds = [];
    if (symbol.flags & ts.SymbolFlags.Value) kinds.push("value");
    if (symbol.flags & ts.SymbolFlags.Type) kinds.push("type");
    if (symbol.flags & ts.SymbolFlags.Namespace) kinds.push("namespace");
    lines.push(`${subpath}\t${exported.name}\t${kinds.join("+") || "alias"}`);
    const declaration = symbol.declarations?.[0];
    records.push({
      subpath,
      name: exported.name,
      kinds: kinds.join("+") || "alias",
      // Declaration identity: two exports sharing this are the same thing
      // re-exported, which is legitimate. Differing identity under one name is not.
      declaration: declaration
        ? `${normalizedPath(declaration.getSourceFile().fileName).replace(/^.*?dist\//, "dist/")}:${declaration.pos}`
        : "unknown",
    });
  }
}
const actual = `${lines.join("\n")}\n`;
if (process.argv.includes("--update")) {
  await writeFile(new URL("../api/public-api.txt", import.meta.url), actual);
  process.exit(0);
}
if (process.argv.includes("--print")) {
  process.stdout.write(actual);
  process.exit(0);
}

// --shape: structural duplication checks.
//
// The snapshot comparison below proves the surface has not CHANGED. It cannot
// notice that the surface was wrong to begin with. These two rules catch the
// duplication classes that a name-and-kind snapshot is blind to:
//
//   mirror   one entry point exporting both `X` and `<Prefix>X` of the same kind
//            -- a second parallel API grown alongside the first
//   homonym  one name exported from two entry points resolving to DIFFERENT
//            declarations -- two things wearing one name
//
// Legitimate cases are declared in api/public-api-allowances.json with a reason.
// An allowance that no longer matches anything fails as loudly as a violation,
// so stale exemptions cannot accumulate.
if (process.argv.includes("--shape")) {
  const allowances = JSON.parse(
    await readFile(new URL("../api/public-api-allowances.json", import.meta.url), "utf8"),
  );
  const used = new Set();
  const allowed = (kind, key) => {
    const hit = allowances[kind]?.find((item) => item.key === key);
    if (hit) used.add(`${kind}:${key}`);
    return hit !== undefined;
  };
  const violations = [];

  const byName = new Map(records.map((item) => [`${item.subpath}\t${item.name}`, item]));
  for (const record of records) {
    for (const other of records) {
      if (other.subpath !== record.subpath) continue;
      if (other.name === record.name || !other.name.endsWith(record.name)) continue;
      const prefix = other.name.slice(0, -record.name.length);
      // A prefix must be a capitalised word, or `Foo` matches every `*Foo`.
      if (!/^[A-Z][A-Za-z]*$/.test(prefix)) continue;
      if (byName.get(`${record.subpath}\t${record.name}`)?.kinds !== other.kinds) continue;
      const key = `${record.subpath}\t${prefix}${record.name}`;
      if (allowed("mirror", key)) continue;
      violations.push(
        `mirror: ${record.subpath} exports both '${record.name}' and '${other.name}' as ${other.kinds}. ` +
        `A prefixed twin of an existing export is a second API, not a variant. ` +
        `Give it a distinct entry point and an unprefixed name, or declare it in api/public-api-allowances.json.`,
      );
    }
  }

  const byBareName = new Map();
  for (const record of records) {
    const list = byBareName.get(record.name) ?? [];
    list.push(record);
    byBareName.set(record.name, list);
  }
  for (const [name, list] of byBareName) {
    const declarations = new Set(list.map((item) => item.declaration));
    if (declarations.size < 2) continue;   // one declaration re-exported is fine
    if (allowed("homonym", name)) continue;
    violations.push(
      `homonym: '${name}' is exported from ${list.map((item) => item.subpath).join(", ")} ` +
      `resolving to ${declarations.size} different declarations. One name must mean one thing.`,
    );
  }

  for (const [kind, items] of Object.entries(allowances)) {
    if (kind.startsWith("_")) continue;   // `_comment` and friends are documentation
    for (const item of items) {
      if (!used.has(`${kind}:${item.key}`)) {
        violations.push(
          `stale allowance: ${kind} '${item.key}' no longer matches any export. Remove it from ` +
          `api/public-api-allowances.json.`,
        );
      }
    }
  }

  if (violations.length > 0) {
    process.stderr.write(`${violations.join("\n")}\n`);
    throw new Error(`TypeScript public API shape: ${violations.length} violation(s)`);
  }
  process.stdout.write("TypeScript public API shape: no mirrored or homonymous exports\n");
  process.exit(0);
}
const expected = normalizeText(
  await readFile(new URL("../api/public-api.txt", import.meta.url), "utf8"),
);
if (actual !== expected) {
  throw new Error("installed TypeScript public API drifted; review declarations and update api/public-api.txt");
}

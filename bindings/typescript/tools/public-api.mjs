import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import ts from "typescript";

const normalizeText = (value) => value.replaceAll("\r\n", "\n").replaceAll("\r", "\n");
const normalizedPath = (value) => value.replaceAll("\\", "/");
const compareText = (left, right) => left < right ? -1 : left > right ? 1 : 0;
const comparePublicNames = (left, right) => {
  const folded = compareText(left.toLowerCase(), right.toLowerCase());
  return folded === 0 ? -compareText(left, right) : folded;
};

const entries = new Map([
  [".", "dist/index.d.ts"],
  ["./advanced", "dist/advanced.d.ts"],
  ["./identity", "dist/identity.d.ts"],
  ["./authority", "dist/authority.d.ts"],
  ["./approvals", "dist/approvals.d.ts"],
  ["./profiles", "dist/profiles.d.ts"],
  ["./trust", "dist/trust.d.ts"],
  ["./lifecycle", "dist/lifecycle.d.ts"],
  ["./runtime", "dist/runtime.d.ts"],
  ["./custody", "dist/custody.d.ts"],
  ["./mcp", "dist/mcp.d.ts"],
  ["./profile-kit", "dist/profile-kit.d.ts"],
  ["./testkit", "dist/testkit/index.d.ts"],
]);

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
  }
}
const actual = `${lines.join("\n")}\n`;
if (process.argv.includes("--print")) {
  process.stdout.write(actual);
  process.exit(0);
}
const expected = normalizeText(
  await readFile(new URL("../api/public-api.txt", import.meta.url), "utf8"),
);
if (actual !== expected) {
  throw new Error("installed TypeScript public API drifted; review declarations and update api/public-api.txt");
}

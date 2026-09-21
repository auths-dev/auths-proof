#!/usr/bin/env node

/** Bounded generator for application-owned exact MCP contracts. */

import { createHash } from "node:crypto";
import { lstat, mkdir, readFile, realpath, writeFile } from "node:fs/promises";
import { realpathSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const identity = /^[a-z][a-z0-9._-]{0,63}$/;
const key = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
const tool = /^[A-Za-z][A-Za-z0-9._-]{0,111}$/;
const quoted = /^"([A-Za-z0-9_.:-]+)"$/;
const integer = /^-?(0|[1-9][0-9]{0,15})$/;
const reserved = new Set(["__proto__", "prototype", "constructor"]);
const mandatoryAdapterCases = new Set([
  "authorized-one-write-and-replay", "denied-before-credential",
  "mutated-action-before-credential", "invalid-trust-before-credential",
  "credential-unavailable-before-provider", "competing-claim",
  "definite-no-effect-rejection", "unknown-no-blind-retry",
  "timeout-no-blind-retry", "unavailable-observation",
]);

export function parseContract(source) {
  if (new TextEncoder().encode(source).length > 16_384) throw new Error("profile.toml exceeds 16 KiB");
  if (/\r(?!\n)|[\u000b\u000c\u001c-\u001e\u0085\u2028\u2029\ufeff]/u.test(source)) {
    throw new Error("profile.toml has an unsupported line ending or BOM");
  }
  const tables = new Map();
  let current;
  for (const original of source.split(/\r?\n/)) {
    const line = original.trim();
    if (line === "" || line.startsWith("#")) continue;
    if (line.startsWith("[") && line.endsWith("]")) {
      current = line.slice(1, -1);
      if (!current || tables.has(current) || current.split(".").some(part => !key.test(part))) {
        throw new Error("invalid or duplicate profile table");
      }
      tables.set(current, new Map());
      continue;
    }
    const separator = line.indexOf("=");
    if (current === undefined || separator < 0) throw new Error("invalid profile.toml line");
    const name = line.slice(0, separator).trim();
    const raw = line.slice(separator + 1).trim();
    const entries = tables.get(current);
    if (!key.test(name) || reserved.has(name) || entries.has(name)) {
      throw new Error("invalid or duplicate profile key");
    }
    const match = quoted.exec(raw);
    if (name === "variants" && raw.startsWith("[")) {
      if (!/^\[\s*(?:"[A-Za-z0-9_.:-]+"(?:\s*,\s*"[A-Za-z0-9_.:-]+")*)?\s*\]$/.test(raw)) {
        throw new Error("invalid single-line enum variants");
      }
      entries.set(name, [...raw.matchAll(/"([A-Za-z0-9_.:-]+)"/g)].map(item => item[1]));
    } else if (match) entries.set(name, match[1]);
    else if (integer.test(raw)) {
      const value = Number(raw);
      if (!Number.isSafeInteger(value)) throw new Error("profile integer is unsafe");
      entries.set(name, value);
    } else throw new Error("unsupported profile.toml value");
  }
  const profile = tables.get("profile");
  if (!profile || ["name", "version", "service", "tool"].some(name => !profile.has(name)) ||
      [...profile.keys()].some(name => !["name", "version", "service", "tool", "command"].includes(name))) {
    throw new Error("profile identity fields are invalid");
  }
  const name = profile.get("name");
  const version = profile.get("version");
  const service = profile.get("service");
  const baseTool = profile.get("tool");
  const command = profile.get("command") ?? name.split(/[-_.]/).filter(Boolean)
    .map(part => part[0].toUpperCase() + part.slice(1)).join("");
  const versionedTool = `${baseTool}_v${version}`;
  if (typeof name !== "string" || !identity.test(name) ||
      !Number.isInteger(version) || version < 1 || version > 9999 ||
      typeof service !== "string" || !identity.test(service) ||
      typeof baseTool !== "string" || !tool.test(baseTool) ||
      new TextEncoder().encode(versionedTool).length > 128 ||
      typeof command !== "string" || !key.test(command) || reserved.has(command)) {
    throw new Error("profile identity or version is invalid");
  }
  const used = new Set(["profile"]);
  const root = nodeAt(tables, used, "arguments", "arguments", 1);
  if (root.kind !== "object" || root.fields.length === 0 ||
      [...tables.keys()].some(table => !used.has(table))) {
    throw new Error("root arguments must be a closed object with no unknown tables");
  }
  if (fieldCount(root) > 32 || maxDepth(root) > 4) {
    throw new Error("command schema exceeds field or depth bounds");
  }
  if (maximumJsonBytes(root) > 4096) {
    throw new Error("worst-case canonical arguments exceed 4 KiB");
  }
  return { name, version, service, tool: versionedTool, command, fields: root.fields };
}

function nodeAt(tables, used, path, name, depth) {
  const table = tables.get(path);
  if (!table || used.has(path) || depth > 4) throw new Error(`missing, duplicate, or over-deep schema node: ${path}`);
  used.add(path);
  const kind = table.get("type");
  if (["string", "bytes", "integer"].includes(kind)) {
    const keys = kind === "integer" ? ["type", "minimum", "maximum"] : ["type", "min_bytes", "max_bytes"];
    if (table.size !== keys.length || keys.some(item => !table.has(item))) {
      throw new Error(`schema bounds are incomplete: ${path}`);
    }
    const minimum = table.get(kind === "integer" ? "minimum" : "min_bytes");
    const maximum = table.get(kind === "integer" ? "maximum" : "max_bytes");
    if (!Number.isSafeInteger(minimum) || !Number.isSafeInteger(maximum) || minimum > maximum ||
        (kind === "string" && (minimum < 0 || maximum > 4096)) ||
        (kind === "bytes" && (minimum < 0 || maximum > 3072))) {
      throw new Error(`invalid schema bounds: ${path}`);
    }
    return { name, kind, minimum, maximum };
  }
  if (kind === "boolean") {
    if (table.size !== 1) throw new Error(`unknown boolean schema key: ${path}`);
    return { name, kind };
  }
  if (kind === "enum") {
    const variants = table.get("variants");
    if (table.size !== 2 || !Array.isArray(variants) || variants.length < 1 || variants.length > 32 ||
        variants.some(item => typeof item !== "string" || !/^[A-Za-z0-9_.-]{1,64}$/.test(item)) ||
        new Set(variants).size !== variants.length) {
      throw new Error(`enum variants are invalid: ${path}`);
    }
    return { name, kind, variants };
  }
  if (kind === "object") {
    if (table.size !== 1) throw new Error(`unknown object schema key: ${path}`);
    const prefix = `${path}.fields.`;
    const names = [...tables.keys()].filter(candidate => candidate.startsWith(prefix) &&
      !candidate.slice(prefix.length).includes(".")).map(candidate => candidate.slice(prefix.length));
    if (names.length < 1 || names.length > 32 || names.some(item => reserved.has(item))) {
      throw new Error(`object field count or name is invalid: ${path}`);
    }
    return { name, kind, fields: names.map(item => nodeAt(tables, used, `${prefix}${item}`, item, depth + 1)) };
  }
  if (kind === "array") {
    if (table.size !== 3 || !table.has("min_items") || !table.has("max_items")) {
      throw new Error(`array bounds are incomplete: ${path}`);
    }
    const minimum = table.get("min_items");
    const maximum = table.get("max_items");
    if (!Number.isInteger(minimum) || !Number.isInteger(maximum) || minimum < 0 ||
        minimum > maximum || maximum > 32) throw new Error(`invalid array bounds: ${path}`);
    const inner = nodeAt(tables, used, `${path}.items`, "items", depth + 1);
    if (inner.kind === "nullable") throw new Error("array items cannot be nullable");
    return { name, kind, minimum, maximum, inner };
  }
  if (kind === "nullable") {
    if (table.size !== 1) throw new Error(`unknown nullable schema key: ${path}`);
    const inner = nodeAt(tables, used, `${path}.value`, "value", depth);
    if (inner.kind === "nullable") throw new Error("nested nullable fields are unsupported");
    return { name, kind, inner };
  }
  throw new Error(`unsupported command field schema: ${path}`);
}

function fieldCount(node) {
  if (node.kind === "object") return node.fields.reduce((count, item) => count + fieldCount(item), 0);
  if (node.inner) return fieldCount(node.inner);
  return 1;
}

function maxDepth(node) {
  if (node.kind === "object") return 1 + Math.max(0, ...node.fields.map(maxDepth));
  if (node.kind === "array") return 1 + maxDepth(node.inner);
  if (node.inner) return maxDepth(node.inner);
  return 0;
}

function maximumJsonBytes(node) {
  switch (node.kind) {
    case "object": return 2 + node.fields.reduce((sum, item) =>
      sum + 2 + item.name.length + 1 + maximumJsonBytes(item), 0) + Math.max(0, node.fields.length - 1);
    case "array": return 2 + node.maximum * maximumJsonBytes(node.inner) + Math.max(0, node.maximum - 1);
    case "nullable": return Math.max(4, maximumJsonBytes(node.inner));
    case "string": return 2 + 6 * node.maximum;
    case "bytes": return 2 + 4 * Math.ceil(node.maximum / 3);
    case "integer": return Math.max(String(node.minimum).length, String(node.maximum).length);
    case "enum": return 2 + Math.max(...node.variants.map(item => item.length));
    default: return 5;
  }
}

function nodeJson(node) {
  if (node.kind === "enum") return { type: "enum", variants: node.variants };
  const value = { kind: node.kind };
  if (node.minimum !== undefined) value.minimum = node.minimum;
  if (node.maximum !== undefined) value.maximum = node.maximum;
  if (node.kind === "object") value.fields = Object.fromEntries(node.fields.map(item => [item.name, nodeJson(item)]));
  if (node.inner) value.inner = nodeJson(node.inner);
  return value;
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value).sort().map(name => `${JSON.stringify(name)}:${stableJson(value[name])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function schemaDigest(contract) {
  const root = { name: "arguments", kind: "object", fields: contract.fields };
  return createHash("sha256").update(stableJson(nodeJson(root)), "utf8").digest("hex");
}

function fieldSource(node) {
  switch (node.kind) {
    case "enum": return `enumField(${stableJson(node.variants)})`;
    case "string": return `stringField({ minBytes: ${node.minimum}, maxBytes: ${node.maximum} })`;
    case "bytes": return `bytesField({ minBytes: ${node.minimum}, maxBytes: ${node.maximum} })`;
    case "integer": return `integerField({ minimum: ${node.minimum}, maximum: ${node.maximum} })`;
    case "boolean": return "booleanField()";
    case "nullable": return `optionalField(${fieldSource(node.inner)})`;
    case "array": return `arrayField(${fieldSource(node.inner)}, { minItems: ${node.minimum}, maxItems: ${node.maximum} })`;
    case "object": return `objectField({ ${node.fields.map(item => `${item.name}: ${fieldSource(item)}`).join(", ")} })`;
    default: throw new Error("unsupported field source");
  }
}

function usedBuilders(node) {
  const name = {
    string: "stringField", bytes: "bytesField", integer: "integerField",
    boolean: "booleanField", enum: "enumField", nullable: "optionalField",
    array: "arrayField", object: "objectField",
  }[node.kind];
  const found = new Set([name]);
  for (const child of node.fields ?? []) for (const item of usedBuilders(child)) found.add(item);
  if (node.inner) for (const item of usedBuilders(node.inner)) found.add(item);
  return found;
}

export function renderGenerated(contract) {
  const fields = contract.fields.map(field => `  ${field.name}: ${fieldSource(field)},`).join("\n");
  const builders = new Set(["exactMcpTool"]);
  for (const field of contract.fields) for (const item of usedBuilders(field)) builders.add(item);
  const imports = [...builders].sort().join(", ");
  return `/** Generated by auths-profile; edit profile.toml, then regenerate. */\n` +
    `import { ${imports}, type CommandOf } from "@auths-dev/sdk/self-hosted";\n\n` +
    `export const PROFILE_NAME = "${contract.name}";\n` +
    `export const PROFILE_VERSION = ${contract.version};\n` +
    `export const TOOL_NAME = "${contract.tool}";\n` +
    `export const SCHEMA_DIGEST = "${schemaDigest(contract)}";\n\n` +
    `export const FIELDS = {\n${fields}\n} as const;\n` +
    `export type ${contract.command} = CommandOf<typeof FIELDS>;\n` +
    `export const CONTRACT = exactMcpTool({ service: "${contract.service}", name: TOOL_NAME, fields: FIELDS });\n`;
}

function example(node) {
  switch (node.kind) {
    case "enum": return node.variants[0];
    case "nullable": return null;
    case "object": return Object.fromEntries(node.fields.map(item => [item.name, example(item)]));
    case "array": return Array.from({ length: node.minimum }, () => example(node.inner));
    case "bytes": return Buffer.alloc(node.minimum).toString("base64url");
    case "string": return "x".repeat(node.minimum);
    case "integer": return node.minimum;
    default: return false;
  }
}

export function renderVectors(contract) {
  const valid = Object.fromEntries(contract.fields.map(field => [field.name, example(field)]));
  return stableJson({
    schema: "auths.self-hosted-profile-vectors/2", profile: contract.name,
    version: contract.version, service: contract.service, tool: contract.tool,
    schema_digest: schemaDigest(contract), valid_arguments_json: stableJson(valid),
  }) + "\n";
}

export function renderLock(contract) {
  const root = { name: "arguments", kind: "object", fields: contract.fields };
  return stableJson({
    schema: "auths.self-hosted-profile-lock/1", profile: contract.name,
    version: contract.version, service: contract.service, tool: contract.tool,
    schema_digest: schemaDigest(contract), command_schema: nodeJson(root), generator_format: 2,
  }) + "\n";
}

function schemaChanges(before, after, path = "arguments") {
  if (stableJson(before) === stableJson(after)) return [];
  if (before && after && typeof before === "object" && typeof after === "object" &&
      !Array.isArray(before) && !Array.isArray(after)) {
    return [...new Set([...Object.keys(before), ...Object.keys(after)])].sort()
      .flatMap(name => schemaChanges(before[name], after[name], `${path}.${name}`));
  }
  return [path];
}

function schemaAt(schema, path) {
  for (const component of path.split(".").slice(1)) {
    if (schema === null || typeof schema !== "object") return null;
    schema = schema[component];
  }
  return schema ?? null;
}

export async function profileDiff(path) {
  const contract = parseContract(await sourceAt(path));
  const target = join(dirname(path), "profile.lock.json");
  const current = JSON.parse(renderLock(contract));
  let old;
  try {
    const metadata = await lstat(target);
    if (!metadata.isFile() || metadata.isSymbolicLink()) throw new Error("profile lock is invalid");
    old = JSON.parse(await readFile(target, "utf8"));
  } catch (error) {
    if (error.code === "ENOENT") return { status: "new", stage: "contract", code: "profile.contract.new",
      changed_fields: [], changes: [], action_identity_changed: true, next_action: "Run profile generate." };
    throw error;
  }
  if (!old || old.schema !== "auths.self-hosted-profile-lock/1") throw new Error("profile lock is invalid");
  const changed = schemaChanges(old.command_schema, current.command_schema).slice(0, 64);
  const changes = changed.map(path => ({ path,
    before: schemaAt(old.command_schema, path), after: schemaAt(current.command_schema, path) }));
  const identityChanged = ["service", "tool", "version"].some(name => old[name] !== current[name]);
  const different = stableJson(old) !== stableJson(current);
  const status = different && old.version === current.version ? "version-required" : different ? "changed" : "current";
  return { status, stage: "contract", code: `profile.contract.${status}`,
    old_version: old.version, new_version: current.version, changed_fields: changed, changes,
    action_identity_changed: identityChanged || changed.length > 0,
    next_action: status === "version-required" ? "Increase profile.version before generation."
      : status === "changed" ? "Run profile generate and review new proof identity."
      : "No version change required." };
}

export function renderAdapter(contract) {
  return `/** Application-owned provider mapping; Auths does not qualify these effects. */\n` +
    `import type { Observation, ProviderOutcome, SelfHostedProviderAdapter } from "@auths-dev/sdk/self-hosted";\n` +
    `import type { ${contract.command} } from "./generated.js";\n\n` +
    `export class ApplicationAdapter implements SelfHostedProviderAdapter<${contract.command}, string, string> {\n` +
    `  credential(): string {\n` +
    `    // Load the app's existing token only after Auths claims the attempt.\n` +
    `    throw new Error("supply an application-owned credential");\n` +
    `  }\n\n` +
    `  async invoke(command: ${contract.command}, credential: string): Promise<ProviderOutcome<string>> {\n` +
    `    // Derive one closed provider write from command. Timeouts are unknown.\n` +
    `    void command; void credential;\n` +
    `    throw new Error("map the exact command to one provider write");\n` +
    `  }\n\n` +
    `  async observe(command: ${contract.command}): Promise<Observation> {\n` +
    `    // Read-only reconciliation; never repeat invoke here.\n` +
    `    void command;\n` +
    `    throw new Error("read back the provider effect");\n` +
    `  }\n` +
    `}\n`;
}

export function renderRun(contract) {
  return `/** Exact local execution order: verify, claim, credential, provider. */\n` +
    `import { runOnce, type AttemptStore, type RunResult } from "@auths-dev/sdk/self-hosted";\n` +
    `import { CONTRACT, type ${contract.command} } from "./generated.js";\n` +
    `import type { ApplicationAdapter } from "./adapter.js";\n\n` +
    `export async function execute(input: Readonly<{\n` +
    `  proof: Uint8Array; action: Uint8Array; trustedContext: Uint8Array;\n` +
    `  attempts: AttemptStore; operationKey: string;\n` +
    `  expectedCommand: ${contract.command}; adapter: ApplicationAdapter;\n` +
    `}>): Promise<RunResult<${contract.command}, string>> {\n` +
    `  return runOnce({ contract: CONTRACT, ...input });\n` +
    `}\n`;
}

export function renderConformance(contract) {
  const exampleArguments = stableJson(Object.fromEntries(
    contract.fields.map(field => [field.name, example(field)]),
  ));
  return `/** Wire the real adapter to a scripted provider before running this suite. */\n` +
    `import { runSelfHostedAdapterConformance, type ScriptedProvider } from "@auths-dev/sdk/testkit";\n` +
    `import { CONTRACT, type ${contract.command} } from "./generated.js";\n` +
    `import { ApplicationAdapter } from "./adapter.js";\n\n` +
    `export async function run(input?: Readonly<{\n` +
    `  artifacts: { proof: Uint8Array; action: Uint8Array; trustedContext: Uint8Array };\n` +
    `  adapterFactory: (provider: ScriptedProvider) => ApplicationAdapter;\n` +
    `}>) {\n` +
    `  // Supply signed local artifacts and an adapter wired to the scripted provider.\n` +
    `  const command: ${contract.command} = CONTRACT.decode(${exampleArguments});\n` +
    `  if (input === undefined) throw new Error("supply signed artifacts and a scripted-provider adapter");\n` +
    `  return runSelfHostedAdapterConformance({ contract: CONTRACT, command, ...input });\n` +
    `}\n`;
}

async function sourceAt(path) {
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > 16_384) {
    throw new Error("profile.toml must be a bounded regular file");
  }
  return readFile(path, "utf8");
}

async function lockState(directory, contract) {
  const target = join(directory, "profile.lock.json");
  let content;
  try {
    const metadata = await lstat(target);
    if (!metadata.isFile() || metadata.isSymbolicLink()) throw new Error("profile lock is invalid");
    content = await readFile(target, "utf8");
  } catch (error) {
    if (error.code === "ENOENT") return;
    throw error;
  }
  let old;
  try { old = JSON.parse(content); } catch { throw new Error("profile lock is invalid"); }
  if (old === null || typeof old !== "object" || old.schema !== "auths.self-hosted-profile-lock/1") {
    throw new Error("profile lock is invalid");
  }
  const current = JSON.parse(renderLock(contract));
  if (old.version === contract.version && stableJson(old) !== stableJson(current)) {
    throw new Error("profile identity or schema changed without a version bump");
  }
  if (!Number.isInteger(old.version) || old.version > contract.version) {
    throw new Error("profile version cannot move backward");
  }
}

async function writeProfile(directory, contract, options = {}) {
  await mkdir(directory, { recursive: true });
  const folder = await lstat(directory);
  if (!folder.isDirectory() || folder.isSymbolicLink()) throw new Error("profile directory cannot be a symlink");
  if (options.seal !== false) await lockState(directory, contract);
  const generated = [
    ["generated.ts", renderGenerated(contract)],
    ["vectors.json", renderVectors(contract)],
  ];
  if (options.seal !== false) generated.push(["profile.lock.json", renderLock(contract)]);
  for (const [name, contents] of generated) {
    const target = join(directory, name);
    try { if ((await lstat(target)).isSymbolicLink()) throw new Error("generated profile target cannot be a symlink"); }
    catch (error) { if (error.code !== "ENOENT") throw error; }
    await writeFile(target, contents);
  }
}

async function checkProfile(path) {
  const contract = parseContract(await sourceAt(path));
  const directory = dirname(path);
  const problems = [];
  for (const [name, expected] of [
    ["generated.ts", renderGenerated(contract)],
    ["vectors.json", renderVectors(contract)],
    ["profile.lock.json", renderLock(contract)],
  ]) {
    let actual;
    try { actual = await readFile(join(directory, name), "utf8"); } catch { actual = undefined; }
    if (actual !== expected) problems.push(`${name} has drifted`);
  }
  return problems;
}

async function mainText(args) {
  const action = args[0];
  if (action === "init") {
    const languageAt = args.indexOf("--language");
    const nameAt = args.indexOf("--name");
    const directoryAt = args.indexOf("--directory");
    if (languageAt < 0 || args[languageAt + 1] !== "typescript" || nameAt < 0 ||
        !identity.test(args[nameAt + 1] ?? "")) throw new Error("init requires --language typescript and bounded --name");
    const name = args[nameAt + 1];
    const directory = directoryAt < 0 ? "." : args[directoryAt + 1];
    if (!directory) throw new Error("--directory needs a path");
    const source = `[profile]\nname = "${name}"\nversion = 1\nservice = "${name}"\ntool = "invoke"\n\n` +
      `[arguments]\ntype = "object"\n\n[arguments.fields.value]\ntype = "string"\nmin_bytes = 1\nmax_bytes = 256\n`;
    await mkdir(directory, { recursive: true });
    for (const filename of ["profile.toml", "generated.ts", "vectors.json", "profile.lock.json", "adapter.ts", "run.ts", "conformance.ts"]) {
      try { await lstat(join(directory, filename)); throw new Error("profile files already exist"); }
      catch (error) { if (error.code !== "ENOENT") throw error; }
    }
    await writeFile(join(directory, "profile.toml"), source, { flag: "wx" });
    const contract = parseContract(source);
    await writeProfile(directory, contract, { seal: false });
    await writeFile(join(directory, "adapter.ts"), renderAdapter(contract), { flag: "wx" });
    await writeFile(join(directory, "run.ts"), renderRun(contract), { flag: "wx" });
    await writeFile(join(directory, "conformance.ts"), renderConformance(contract), { flag: "wx" });
    process.stdout.write(`created ${join(directory, "profile.toml")}; edit schema, then run profile generate; self-hosted, provider behavior unqualified\n`);
    return;
  }
  const path = args[1] && !args[1].startsWith("--") ? args[1] : "profile.toml";
  if (action === "generate") {
    await writeProfile(dirname(path), parseContract(await sourceAt(path)));
    process.stdout.write(`generated ${dirname(path)}; self-hosted, provider behavior unqualified\n`);
  } else if (action === "check") {
    const problems = await checkProfile(path);
    if (problems.length) throw new Error(problems.join("; "));
    process.stdout.write("profile current; self-hosted, provider behavior unqualified\n");
  } else if (action === "diff") {
    const result = await profileDiff(path);
    process.stdout.write(`${result.code}\n`);
    for (const change of result.changes) {
      process.stdout.write(`${change.path}: ${stableJson(change.before)} -> ${stableJson(change.after)}\n`);
    }
    if (!result.changes.length) process.stdout.write("no field changes\n");
    process.stdout.write(`action identity changed: ${result.action_identity_changed}\n${result.next_action}\n`);
  } else if (action === "test") {
    const suiteAt = args.indexOf("--suite");
    const suitePath = suiteAt < 0 ? undefined : args[suiteAt + 1];
    if (!suitePath) throw new Error("profile test needs --suite path/to/compiled-conformance.js");
    const problems = await checkProfile(path);
    if (problems.length) throw new Error(problems.join("; "));
    const suite = await import(pathToFileURL(resolve(suitePath)).href);
    if (typeof suite.run !== "function") throw new Error("adapter suite must export run()");
    const report = await suite.run();
    if (report?.metadata?.suite !== "self-hosted-provider-adapter/1" || !Array.isArray(report.cases)) {
      throw new Error("adapter suite returned an invalid conformance report");
    }
    const caseIds = report.cases.map(item => item?.id);
    if (caseIds.length !== mandatoryAdapterCases.size ||
        new Set(caseIds).size !== mandatoryAdapterCases.size ||
        caseIds.some(id => !mandatoryAdapterCases.has(id)) ||
        report.metadata.assurance !== "test-results-only-not-security-certification") {
      throw new Error("adapter suite omitted or duplicated mandatory cases");
    }
    if (report.passed !== report.cases.every(item => item.status === "passed")) {
      throw new Error("adapter suite summary disagrees with mandatory cases");
    }
    for (const item of report.cases) process.stdout.write(`${item.status.toUpperCase()} ${item.id}\n`);
    process.stdout.write("local adapter tests only; provider behavior remains unqualified\n");
    if (!report.passed) process.exitCode = 1;
  } else if (action === "doctor") {
    const problems = await checkProfile(path);
    if (problems.length) throw new Error(problems.join("; "));
    process.stdout.write("contract: current; provider adapter: application-owned, unqualified\n");
    if (args.includes("--production")) {
      const option = name => { const at = args.indexOf(name); return at < 0 ? undefined : args[at + 1]; };
      const signer = option("--signer-adapter");
      const grant = option("--grant-file");
      const trust = option("--trust-file");
      if (!identity.test(signer ?? "")) throw new Error("production signer-adapter is missing or invalid");
      if (!grant) throw new Error("production grant-file is missing");
      if (!trust) throw new Error("production trust-file is missing");
      for (const filename of [grant, trust]) {
        const metadata = await lstat(filename);
        if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size < 1 || metadata.size > 262_144) {
          throw new Error("production authority file is unavailable or outside bounds");
        }
      }
      if (await realpath(grant) === await realpath(trust)) throw new Error("grant and trusted context need separate files");
      process.stdout.write("production input files: present, bounded, and distinct; grant/trust bytes not parsed; signer connectivity and trust provenance not checked\n");
    } else process.stdout.write("local testkit authority is development-only\n");
    process.stdout.write("profile doctor does not verify provider credentials or qualify adapter behavior\n");
  } else throw new Error("usage: auths-profile init|generate|check|diff|doctor|test");
}

function diagnostic(action, status, message) {
  if (status === 0) return [action === "check" ? "profile.generated.current" : "profile.operation.ok",
    action === "check" ? "generated" : "contract", "No action required."];
  if (/without a version bump|version cannot move backward/.test(message)) return [
    "profile.contract.version-required", "contract", "Increase profile.version, then review profile diff."];
  if (/has drifted/.test(message)) return ["profile.generated.stale", "generated",
    "Run profile generate after reviewing the source and version."];
  if (/Cannot find module|ERR_MODULE_NOT_FOUND/.test(message)) return [
    "profile.provider.suite-import-failed", "provider", "Compile or install the suite, then rerun profile test."];
  if (/signer/.test(message)) return ["profile.authority.signer-missing", "authority",
    "Supply an explicit custody signer adapter."];
  if (/grant/.test(message) && !/trust/.test(message)) return ["profile.authority.grant-missing", "authority",
    "Supply a bounded signed grant file."];
  if (/trust/.test(message)) return ["profile.trust.context-missing", "trust",
    "Supply an independently provisioned trusted context."];
  if (/suite|adapter/.test(message)) return ["profile.provider.adapter-test-failed", "provider",
    "Wire the adapter to the scripted provider and rerun profile test."];
  return ["profile.contract.schema-invalid", "contract", "Correct the bounded profile.toml schema."];
}

async function main(args) {
  if (!args.includes("--json")) return mainText(args);
  const filtered = args.filter(value => value !== "--json");
  const action = filtered[0] ?? "unknown";
  const original = process.stdout.write;
  let captured = "";
  let status = 0;
  let diff = null;
  process.stdout.write = function (chunk) { captured += String(chunk).slice(0, 4096); return true; };
  try {
    await mainText(filtered);
    if (process.exitCode && process.exitCode !== 0) status = 1;
    if (status === 0 && action === "diff") diff = await profileDiff(filtered[1] ?? "profile.toml");
  } catch (error) {
    status = 1;
    captured = error instanceof Error ? error.message : "unknown failure";
  } finally {
    process.stdout.write = original;
  }
  const message = captured.trim().slice(0, 2048);
  let [code, stage, nextAction] = diagnostic(action, status, message);
  if (diff) ({ code, stage, next_action: nextAction } = diff);
  original.call(process.stdout, stableJson({ schema: "auths.profile-diagnostic/1", ok: status === 0,
    action, diagnostic: { code, stage, message, next_action: nextAction }, diff }) + "\n");
  if (status !== 0) process.exitCode = 1;
}

if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch(error => {
    process.stderr.write(`auths-profile: ${error instanceof Error ? error.message : "unknown failure"}\n`);
    process.exitCode = 1;
  });
}

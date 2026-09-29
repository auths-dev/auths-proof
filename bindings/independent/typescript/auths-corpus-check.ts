// Independent bounded deterministic-CBOR corpus auditor for Node, and the
// runner of the independent semantic verifier. This file intentionally has no
// Rust/WASM bridge and runs with Node's type stripping.

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { type AuditVector, semanticAudit } from "./semantic-verifier.ts";

const USAGE = "usage: auths-corpus-check.ts [--semantic [--report <file>]] <manifest.json>";
const MAX_BYTES = 16 * 1024 * 1024;
const MAX_DEPTH = 64;
const MAX_ITEMS = 1_000_000;

type Artifact = { path: string; sha256: string; encoding?: unknown };
type Fixture = {
  name: string;
  proof: Artifact;
  context: Artifact;
  canonical_action: Artifact;
  canonical_body: Artifact;
  expected_result: Artifact & { stage?: unknown };
  expected_code: string;
};
type Manifest = { protocol_major: number; fixtures: Fixture[] };
type Input = "proof" | "context" | "canonical_action" | "canonical_body" | "expected_result";

class Parser {
  private offset = 0;
  private items = 0;
  private readonly data: Uint8Array;

  constructor(data: Uint8Array) {
    this.data = data;
  }

  get position(): number {
    return this.offset;
  }

  item(depth: number): Uint8Array {
    if (depth > MAX_DEPTH || this.items >= MAX_ITEMS || this.offset >= this.data.length) {
      throw new Error("CBOR resource limit or truncation");
    }
    this.items += 1;
    const start = this.offset;
    const initial = this.data[this.offset++]!;
    const major = initial >>> 5;
    const additional = initial & 31;
    const value = this.argument(additional);
    switch (major) {
      case 0:
      case 1:
        break;
      case 2:
      case 3: {
        const length = this.boundedLength(value, this.data.length - this.offset);
        const valueBytes = this.data.subarray(this.offset, this.offset + length);
        if (major === 3) {
          new TextDecoder("utf-8", { fatal: true }).decode(valueBytes);
        }
        this.offset += length;
        break;
      }
      case 4: {
        const length = this.boundedLength(value, MAX_ITEMS - this.items);
        for (let index = 0; index < length; index += 1) {
          this.item(depth + 1);
        }
        break;
      }
      case 5: {
        const length = this.boundedLength(value, Math.floor((MAX_ITEMS - this.items) / 2));
        let previous: Uint8Array | undefined;
        for (let index = 0; index < length; index += 1) {
          const key = this.item(depth + 1);
          if (previous !== undefined && canonicalCompare(previous, key) >= 0) {
            throw new Error("duplicate or non-canonical CBOR map key");
          }
          previous = key.slice();
          this.item(depth + 1);
        }
        break;
      }
      case 7:
        if (additional !== 20 && additional !== 21 && additional !== 22) {
          throw new Error("unsupported CBOR simple or floating value");
        }
        break;
      default:
        throw new Error("CBOR tags are not admitted");
    }
    return this.data.subarray(start, this.offset);
  }

  private argument(additional: number): bigint {
    if (additional < 24) return BigInt(additional);
    const width = additional === 24 ? 1 : additional === 25 ? 2 : additional === 26 ? 4 : additional === 27 ? 8 : 0;
    if (width === 0) throw new Error("indefinite or reserved CBOR argument");
    if (this.offset + width > this.data.length) throw new Error("truncated CBOR argument");
    let value = 0n;
    for (const octet of this.data.subarray(this.offset, this.offset + width)) {
      value = (value << 8n) | BigInt(octet);
    }
    this.offset += width;
    if (
      (width === 1 && value < 24n) ||
      (width === 2 && value <= 0xffn) ||
      (width === 4 && value <= 0xffffn) ||
      (width === 8 && value <= 0xffffffffn)
    ) {
      throw new Error("non-minimal CBOR argument");
    }
    return value;
  }

  private boundedLength(value: bigint, maximum: number): number {
    if (value > BigInt(maximum)) throw new Error("CBOR length exceeds bound");
    return Number(value);
  }
}

function canonicalCompare(left: Uint8Array, right: Uint8Array): number {
  if (left.length !== right.length) return left.length < right.length ? -1 : 1;
  return Buffer.compare(left, right);
}

function sha256(bytes: Uint8Array): Buffer {
  return createHash("sha256").update(bytes).digest();
}

// The major type, argument, and head length of the CBOR item at `offset` in
// bytes that already parsed as deterministic CBOR.
function head(data: Uint8Array, offset: number): [number, number, number] {
  const initial = data[offset]!;
  const additional = initial & 31;
  const width = additional < 24 ? 0 : 1 << (additional - 24);
  let value = additional < 24 ? additional : 0;
  for (let index = 1; index <= width; index += 1) value = value * 256 + data[offset + index]!;
  return [initial >>> 5, value, 1 + width];
}

// The body, key 2, of a canonical action that parsed as one deterministic
// CBOR item.
function actionBody(action: Uint8Array): Uint8Array {
  const [major, entries, headLength] = head(action, 0);
  if (major !== 5) throw new Error("canonical action is not a map");
  let offset = headLength;
  for (let index = 0; index < entries; index += 1) {
    const key = new Parser(action.subarray(offset)).item(1);
    offset += key.length;
    const value = new Parser(action.subarray(offset)).item(1);
    offset += value.length;
    if (key.length === 1 && key[0] === 0x02) {
      const [valueMajor, length, valueHead] = head(value, 0);
      if (valueMajor !== 2) throw new Error("canonical action body is not a byte string");
      return value.subarray(valueHead, valueHead + length);
    }
  }
  throw new Error("canonical action has no body");
}

// An absent encoding is canonical. Only the canonical action may be raw: its
// bytes are then a decode-stage fault carried as they are.
function encoding(fixture: Fixture, input: Input): "canonical" | "raw" {
  const value = fixture[input].encoding;
  if (value === undefined || value === "canonical") return "canonical";
  if (value === "raw" && input === "canonical_action") return "raw";
  throw new Error(`${fixture.name}: ${input} encoding ${JSON.stringify(value)} is not admitted`);
}

function wireAudit(manifestPath: string): void {
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as Manifest;
  if (manifest.protocol_major !== 1 || !Array.isArray(manifest.fixtures) ||
      manifest.fixtures.length === 0) {
    throw new Error("unsupported or empty Auths corpus");
  }
  const root = dirname(manifestPath);
  const summary = createHash("sha256");
  let count = 0;
  for (const fixture of manifest.fixtures) {
    if (!fixture.name || !fixture.expected_code) throw new Error("manifest fixture is incomplete");
    const inputs: Input[] = ["proof", "context", "canonical_action", "canonical_body", "expected_result"];
    inputs.forEach((input) => encoding(fixture, input));
    const rawAction = encoding(fixture, "canonical_action") === "raw";
    if (rawAction && fixture.expected_result.stage !== "decode") {
      throw new Error(`${fixture.name}: a raw canonical action requires the decode stage`);
    }
    const contents: Buffer[] = [];
    for (const [index, input] of inputs.entries()) {
      const artifact = fixture[input];
      if (!artifact.path || !artifact.sha256) throw new Error("manifest artifact is incomplete");
      const body = readFileSync(join(root, artifact.path));
      if (body.length === 0 || body.length > MAX_BYTES) {
        throw new Error(`${artifact.path} exceeds corpus byte bounds`);
      }
      const digest = sha256(body);
      if (digest.toString("hex") !== artifact.sha256) {
        throw new Error(`${artifact.path} digest mismatch`);
      }
      // The canonical body remains profile-owned opaque bytes, and a raw
      // canonical action need not parse. Every other protocol input and
      // expected output is deterministic CBOR.
      if (index !== 3 && !(index === 2 && rawAction)) {
        const parser = new Parser(body);
        let parseError: unknown;
        try {
          parser.item(1);
          if (parser.position !== body.length) throw new Error("trailing CBOR bytes");
        } catch (error: unknown) {
          parseError = error;
        }
        // A vector whose fault is in a raw input carries a proof that parses.
        const expectMalformedProof =
          index === 0 && !rawAction &&
          (fixture.expected_code === "malformed-proof" ||
            fixture.expected_code === "non-canonical-proof");
        if (expectMalformedProof && parseError === undefined) {
          throw new Error(`${artifact.path} should be rejected as ${fixture.expected_code}`);
        }
        if (!expectMalformedProof && parseError !== undefined) {
          const detail = parseError instanceof Error ? parseError.message : String(parseError);
          throw new Error(`${artifact.path}: ${detail}`);
        }
      }
      contents.push(body);
      summary.update(artifact.path);
      summary.update(Uint8Array.of(0));
      summary.update(digest);
      count += 1;
    }
    // A canonical action binds the canonical body; a raw one is not compared.
    if (!rawAction && Buffer.compare(actionBody(contents[2]!), contents[3]!) !== 0) {
      throw new Error(`${fixture.name} canonical action/body mismatch`);
    }
  }
  process.stdout.write(`${count}:${summary.digest("hex")}\n`);
}

// One line of the per-vector report, in the runner contract's format.
function reportLine(vector: AuditVector): string {
  const { verdict } = vector;
  const fields: Array<[string, string | null | string[]]> = [
    ["name", vector.name],
    ["implementation", "typescript-independent"],
    ["decision", verdict.decision],
    ["code", verdict.code],
    ["stage", verdict.stage],
    ["proof_digest", verdict.proofDigest],
    ["action_digest", verdict.actionDigest],
    ["context_digest", verdict.contextDigest],
    ["plan_digest", verdict.planDigest],
    ["mismatched_fields", vector.mismatches.map((mismatch) => mismatch.field)],
  ];
  const json = (value: string | null | string[]): string => Array.isArray(value)
    ? `[${value.map((item) => JSON.stringify(item)).join(", ")}]`
    : JSON.stringify(value);
  return `{${fields.map(([key, value]) => `${JSON.stringify(key)}: ${json(value)}`).join(", ")}}\n`;
}

// Compares every vector before failing, and writes the report, when asked
// for, whether or not any vector mismatches.
function semanticRun(manifestPath: string, reportPath: string | undefined): void {
  const audit = semanticAudit(manifestPath);
  if (reportPath !== undefined) writeFileSync(reportPath, audit.vectors.map(reportLine).join(""));
  const failing = audit.vectors.filter((vector) => vector.mismatches.length > 0);
  if (failing.length === 0) {
    process.stdout.write(`${audit.summary}\n`);
    return;
  }
  const show = (value: string | null): string => value ?? "absent";
  for (const vector of failing) {
    for (const mismatch of vector.mismatches) {
      process.stderr.write(
        `${vector.name}: ${mismatch.field} is ${show(mismatch.got)}, ` +
        `manifest requires ${show(mismatch.expected)}\n`,
      );
    }
  }
  process.stderr.write(
    `${failing.length} of ${audit.vectors.length} vectors disagree with the manifest\n`,
  );
  process.exitCode = 1;
}

function main(): void {
  const args = process.argv.slice(2);
  const manifestPath = args.at(-1);
  if (manifestPath === undefined || manifestPath.startsWith("--")) throw new Error(USAGE);
  if (args.length === 1) {
    wireAudit(manifestPath);
  } else if (args.length === 2 && args[0] === "--semantic") {
    semanticRun(manifestPath, undefined);
  } else if (args.length === 4 && args[0] === "--semantic" && args[1] === "--report") {
    semanticRun(manifestPath, args[2]!);
  } else {
    throw new Error(USAGE);
  }
}

main();

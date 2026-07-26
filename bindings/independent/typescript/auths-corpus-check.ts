// Independent bounded deterministic-CBOR corpus auditor for Node. This file
// intentionally has no Rust/WASM bridge and runs with Node's type stripping.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { semanticAudit } from "./semantic-verifier.ts";

const MAX_BYTES = 16 * 1024 * 1024;
const MAX_DEPTH = 64;
const MAX_ITEMS = 1_000_000;

type Artifact = { path: string; sha256: string };
type Fixture = {
  name: string;
  proof: Artifact;
  context: Artifact;
  canonical_action: Artifact;
  canonical_body: Artifact;
  expected_result: Artifact;
  expected_code: string;
};
type Manifest = { protocol_major: number; fixtures: Fixture[] };

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

function main(): void {
  if (process.argv.length !== 3 &&
      !(process.argv.length === 4 && process.argv[2] === "--semantic")) {
    throw new Error("usage: auths-corpus-check.ts [--semantic] <manifest.json>");
  }
  const manifestPath = process.argv.at(-1)!;
  if (process.argv[2] === "--semantic") {
    process.stdout.write(`${semanticAudit(manifestPath)}\n`);
    return;
  }
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as Manifest;
  if (manifest.protocol_major !== 1 || manifest.fixtures.length === 0) {
    throw new Error("unsupported or empty Auths corpus");
  }
  const root = dirname(manifestPath);
  const summary = createHash("sha256");
  let count = 0;
  for (const fixture of manifest.fixtures) {
    if (!fixture.name || !fixture.expected_code) throw new Error("manifest fixture is incomplete");
    for (const [index, artifact] of [
      fixture.proof,
      fixture.context,
      fixture.canonical_action,
      fixture.canonical_body,
      fixture.expected_result,
    ].entries()) {
      if (!artifact.path || !artifact.sha256) throw new Error("manifest artifact is incomplete");
      const body = readFileSync(join(root, artifact.path));
      if (body.length === 0 || body.length > MAX_BYTES) {
        throw new Error(`${artifact.path} exceeds corpus byte bounds`);
      }
      const digest = sha256(body);
      if (digest.toString("hex") !== artifact.sha256) {
        throw new Error(`${artifact.path} digest mismatch`);
      }
      // The canonical body remains profile-owned opaque bytes. Every protocol
      // input and expected output is deterministic CBOR.
      if (index !== 3) {
        const parser = new Parser(body);
        let parseError: unknown;
        try {
          parser.item(1);
          if (parser.position !== body.length) throw new Error("trailing CBOR bytes");
        } catch (error: unknown) {
          parseError = error;
        }
        const expectMalformedProof =
          index === 0 &&
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
      summary.update(artifact.path);
      summary.update(Uint8Array.of(0));
      summary.update(digest);
      count += 1;
    }
  }
  process.stdout.write(`${count}:${summary.digest("hex")}\n`);
}

main();

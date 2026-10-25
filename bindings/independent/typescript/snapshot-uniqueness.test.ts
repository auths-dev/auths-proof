import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { verify } from "./semantic-verifier.ts";

type Head = { major: number; argument: bigint; next: number };
function head(input: Uint8Array, position: number): Head {
  const first = input[position++]!;
  const major = first >>> 5;
  const tag = first & 31;
  if (tag < 24) return { major, argument: BigInt(tag), next: position };
  const width = tag === 24 ? 1 : tag === 25 ? 2 : tag === 26 ? 4 : tag === 27 ? 8 : 0;
  assert.notEqual(width, 0);
  let argument = 0n;
  for (let index = 0; index < width; index += 1) argument = (argument << 8n) | BigInt(input[position++]!);
  return { major, argument, next: position };
}
function endOf(input: Uint8Array, position: number): number {
  const value = head(input, position);
  if (value.major === 2 || value.major === 3) return value.next + Number(value.argument);
  if (value.major === 4 || value.major === 5) {
    let next = value.next;
    const count = Number(value.argument) * (value.major === 5 ? 2 : 1);
    for (let index = 0; index < count; index += 1) next = endOf(input, next);
    return next;
  }
  return value.next;
}
function replaceSnapshot(context: Uint8Array, key: bigint, replacement: Uint8Array): Uint8Array {
  const root = head(context, 0);
  assert.equal(root.major, 5);
  let position = root.next;
  for (let index = 0; index < Number(root.argument); index += 1) {
    const field = head(context, position);
    assert.equal(field.major, 0);
    const finish = endOf(context, field.next);
    if (field.argument === key) {
      return Buffer.concat([context.subarray(0, field.next), replacement, context.subarray(finish)]);
    }
    position = finish;
  }
  throw new Error("snapshot field missing from valid baseline context");
}

test("shared snapshot uniqueness vectors through the public independent verifier", () => {
  const fixtures = new URL("../../../core/fixtures/", import.meta.url);
  const corpus = JSON.parse(readFileSync(new URL("codec/snapshot-uniqueness-v1.json", fixtures), "utf8"));
  const manifest = JSON.parse(readFileSync(new URL("v1/manifest.json", fixtures), "utf8"));
  const read = (name: string) => readFileSync(new URL(`v1/valid/raw-key-chain.${name}.cbor`, fixtures));
  const proof = read("proof");
  const action = read("action");
  const context = read("context");
  assert.equal(verify(proof, action, context, manifest.adapter_context).decision, "authorized");
  assert.equal(corpus.schema, "auths-proof-status-snapshot-uniqueness/v1");
  assert.ok(corpus.cases.length > 0);
  for (const vector of corpus.cases) {
    assert.ok(vector.kind === "principal" || vector.kind === "grant");
    const edited = replaceSnapshot(context, vector.kind === "principal" ? 9n : 10n,
      Buffer.from(vector.snapshot_cbor_hex, "hex"));
    const result = verify(proof, action, edited, manifest.adapter_context);
    if (vector.accepts) assert.notEqual(result.stage, "decode", vector.name);
    else {
      assert.equal(result.stage, "decode", vector.name);
      assert.equal(result.decision, "denied", vector.name);
      assert.equal(result.code, "malformed-proof", vector.name);
    }
  }
});

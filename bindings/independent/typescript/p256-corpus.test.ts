import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { verifySignature } from "./semantic-verifier.ts";

test("published P-256 vectors and strict Auths derivations", () => {
  const corpus = readFileSync(new URL("../../../core/fixtures/crypto/p256-sha256-v1.tsv", import.meta.url), "utf8");
  let cases = 0;
  let accepted = 0;
  const keys = new Set<string>();
  for (const line of corpus.trimEnd().split("\n")) {
    if (line.startsWith("#") || line.startsWith("id\t")) continue;
    const fields = line.split("\t");
    assert.equal(fields.length, 6, "fixture fields");
    const [name, keyHex, messageHex, signatureHex, result] = fields;
    assert.ok(["ok", "invalid-key", "invalid-signature-encoding", "verification-failed"].includes(result!));
    const decode = (hex: string): Uint8Array => {
      assert.match(hex, /^(?:[0-9a-f]{2})*$/, "fixture hex");
      return Buffer.from(hex, "hex");
    };
    assert.equal(verifySignature("p256-sha256-v1", decode(keyHex!), decode(messageHex!), decode(signatureHex!)),
      result === "ok", name);
    cases += 1;
    if (result === "ok") { accepted += 1; keys.add(keyHex!); }
  }
  assert.equal(cases, 653);
  assert.equal(accepted, 173);
  assert.ok(keys.size === 98, "positive coverage spans distinct keys");
});

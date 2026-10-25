import assert from "node:assert/strict";
import test from "node:test";
import { canonicalEd25519Encoding, strictEd25519PointEncoding } from "./ed25519-encoding.ts";

function coordinate(value: bigint, negative = false): Uint8Array {
  const bytes = new Uint8Array(32);
  for (let index = 0; index < 32; index += 1) {
    bytes[index] = Number(value & 255n);
    value >>= 8n;
  }
  if (negative) bytes[31] = bytes[31]! | 128;
  return bytes;
}

test("RFC 8032 field and negative-zero boundaries", () => {
  const prime = (1n << 255n) - 19n;
  for (let offset = 0n; offset < 19n; offset += 1n) {
    for (const negative of [false, true]) {
      assert.equal(canonicalEd25519Encoding(coordinate(prime + offset, negative)), false);
    }
  }
  for (const value of [1n, prime - 1n]) {
    assert.equal(canonicalEd25519Encoding(coordinate(value)), true);
    assert.equal(canonicalEd25519Encoding(coordinate(value, true)), false);
  }
  assert.equal(canonicalEd25519Encoding(coordinate(0n, true)), true);
  for (const length of [0, 31, 33]) assert.equal(canonicalEd25519Encoding(new Uint8Array(length)), false);
  assert.equal(canonicalEd25519Encoding(new Uint8Array([
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
    0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
    0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
  ])), true);
});

test("Auths strict verification excludes canonical small-order points", () => {
  const prime = (1n << 255n) - 19n;
  for (const value of [0n, 1n, prime - 1n]) {
    for (const negative of [false, true]) {
      assert.equal(strictEd25519PointEncoding(coordinate(value, negative)), false);
    }
  }
  const publicKey = Uint8Array.from([
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
    0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
    0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
  ]);
  assert.equal(strictEd25519PointEncoding(publicKey), true);
});

test("order-eight points are excluded for both sign choices", () => {
  const prime = (1n << 255n) - 19n;
  // Public torsion coordinate of Edwards25519, defined by RFC 8032's curve
  // parameters. The two ordinates and two signs give its four order-eight points.
  const y = 55188659117513257062467267217118295137698188065244968500265048394206261417927n;
  for (const value of [y, prime - y]) for (const negative of [false, true]) {
    const encoded = coordinate(value, negative);
    assert.equal(canonicalEd25519Encoding(encoded), true);
    assert.equal(strictEd25519PointEncoding(encoded), false);
  }
});

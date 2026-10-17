// RFC 8032 §5.1.3 compressed-coordinate/sign form. Curve and signature
// verification remain the selected cryptographic primitive's responsibility.
export function canonicalEd25519Encoding(raw: Uint8Array): boolean {
  if (raw.length !== 32) return false;
  const bigEndian = Uint8Array.from(raw).reverse();
  const negative = (bigEndian[0]! & 0x80) !== 0;
  bigEndian[0] = bigEndian[0]! & 0x7f;
  const ordinate = BigInt(`0x${Buffer.from(bigEndian).toString("hex")}`);
  const prime = (1n << 255n) - 19n;
  return ordinate < prime && (!negative || (ordinate !== 1n && ordinate !== prime - 1n));
}

// For a valid Edwards25519 point, y = 0, ±1 has order dividing four.
// The y-coordinate of [2]P is zero precisely when d*y^4 + 2*y^2 - 1 = 0.
// With d = -121665/121666, the polynomial below therefore identifies the
// remaining order-eight points. Point recovery and the signature equation
// still belong to the crypto primitive; this enforces Auths' strict rule.
export function strictEd25519PointEncoding(raw: Uint8Array): boolean {
  if (!canonicalEd25519Encoding(raw)) return false;
  const bigEndian = Uint8Array.from(raw).reverse();
  bigEndian[0] = bigEndian[0]! & 0x7f;
  const y = BigInt(`0x${Buffer.from(bigEndian).toString("hex")}`);
  const prime = (1n << 255n) - 19n;
  if (y === 0n || y === 1n || y === prime - 1n) return false;
  const square = y * y % prime;
  return (121665n * square * square - 243332n * square + 121666n) % prime !== 0n;
}

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

function head(major: number, value: number | bigint): Uint8Array {
  const input = typeof value === "bigint" ? value : BigInt(value);
  if (input < 0n) throw new RangeError("CBOR length cannot be negative");
  if (input < 24n) return Uint8Array.of((major << 5) | Number(input));
  if (input <= 0xffn) return Uint8Array.of((major << 5) | 24, Number(input));
  const size = input <= 0xffffn ? 2 : input <= 0xffff_ffffn ? 4 : 8;
  const output = new Uint8Array(1 + size);
  output[0] = (major << 5) | ({ 2: 25, 4: 26, 8: 27 }[size] ?? 27);
  let remaining = input;
  for (let index = size; index > 0; index -= 1) {
    output[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return output;
}

function concat(values: readonly Uint8Array[]): Uint8Array {
  const output = new Uint8Array(values.reduce((total, value) => total + value.length, 0));
  let offset = 0;
  for (const value of values) { output.set(value, offset); offset += value.length; }
  return output;
}

export function encodeDeterministic(value: unknown): Uint8Array {
  if (value === null) return Uint8Array.of(0xf6);
  if (value === false) return Uint8Array.of(0xf4);
  if (value === true) return Uint8Array.of(0xf5);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new TypeError("CBOR accepts only safe integers");
    if (value >= 0) return head(0, value);
    return head(1, BigInt(-1 - value));
  }
  if (typeof value === "bigint") {
    if (value >= 0n) return head(0, value);
    return head(1, -1n - value);
  }
  if (value instanceof Uint8Array) return concat([head(2, value.length), value]);
  if (typeof value === "string") {
    const encoded = textEncoder.encode(value); return concat([head(3, encoded.length), encoded]);
  }
  if (Array.isArray(value)) return concat([head(4, value.length), ...value.map(encodeDeterministic)]);
  const entries = value instanceof Map
    ? [...value.entries()]
    : value !== null && typeof value === "object"
      ? Object.entries(value as Record<string, unknown>)
      : undefined;
  if (!entries) throw new TypeError("unsupported CBOR value");
  const encoded = entries.map(([key, item]) => ({ key: encodeDeterministic(key), value: encodeDeterministic(item) }));
  encoded.sort((left, right) => left.key.length - right.key.length || compare(left.key, right.key));
  return concat([head(5, encoded.length), ...encoded.flatMap((item) => [item.key, item.value])]);
}

function compare(left: Uint8Array, right: Uint8Array): number {
  for (let index = 0; index < Math.min(left.length, right.length); index += 1) {
    const difference = (left[index] ?? 0) - (right[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return left.length - right.length;
}

export function decodeDeterministic(bytes: Uint8Array): unknown {
  let offset = 0;
  const read = (): unknown => {
    const initial = bytes[offset++];
    if (initial === undefined) throw new TypeError("truncated CBOR");
    const major = initial >> 5; const additional = initial & 31;
    if (major === 7 && additional === 20) return false;
    if (major === 7 && additional === 21) return true;
    if (major === 7 && additional === 22) return null;
    let length: bigint;
    if (additional < 24) length = BigInt(additional);
    else {
      const size = additional === 24 ? 1 : additional === 25 ? 2 : additional === 26 ? 4 : additional === 27 ? 8 : 0;
      if (size === 0 || offset + size > bytes.length) throw new TypeError("unsupported CBOR length");
      length = 0n;
      for (let index = 0; index < size; index += 1) length = (length << 8n) | BigInt(bytes[offset++] ?? 0);
    }
    if (major === 0) return length <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(length) : length;
    if (major === 1) { const value = -1n - length; return value >= BigInt(Number.MIN_SAFE_INTEGER) ? Number(value) : value; }
    if (length > BigInt(Number.MAX_SAFE_INTEGER)) throw new RangeError("CBOR collection is too large");
    const count = Number(length);
    if (major === 2 || major === 3) {
      if (offset + count > bytes.length) throw new TypeError("truncated CBOR bytes");
      const value = bytes.slice(offset, offset + count); offset += count;
      return major === 2 ? value : textDecoder.decode(value);
    }
    if (major === 4) return Array.from({ length: count }, read);
    if (major === 5) {
      const map = new Map<unknown, unknown>();
      for (let index = 0; index < count; index += 1) {
        const key = read(); if (map.has(key)) throw new TypeError("duplicate CBOR key"); map.set(key, read());
      }
      return map;
    }
    throw new TypeError("unsupported CBOR value");
  };
  const result = read();
  if (offset !== bytes.length) throw new TypeError("trailing CBOR bytes");
  const canonical = encodeDeterministic(result);
  if (canonical.length !== bytes.length || canonical.some((value, index) => value !== bytes[index])) {
    throw new TypeError("non-canonical CBOR");
  }
  return result;
}

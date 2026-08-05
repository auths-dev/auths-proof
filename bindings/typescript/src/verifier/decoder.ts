import type {
  VerificationMetrics,
  VerificationStage,
  VerdictKind,
} from "./result.js";

const MAX_RESULT_BYTES = 16 * 1024 * 1024;
const MAX_DEPTH = 64;

export type DecodedResult = {
  kind: VerdictKind;
  code: string;
  stage: VerificationStage;
  metrics: VerificationMetrics;
  requiredConfiguration: Uint8Array | undefined;
  localConfiguration: Uint8Array;
};

class Reader {
  readonly #bytes: Uint8Array;
  #offset = 0;

  constructor(bytes: Uint8Array) {
    if (bytes.length === 0 || bytes.length > MAX_RESULT_BYTES) throw new RangeError("Auths result exceeds byte bounds");
    this.#bytes = bytes;
  }

  get complete(): boolean { return this.#offset === this.#bytes.length; }

  head(): [number, bigint] {
    const initial = this.#take();
    const major = initial >>> 5;
    const additional = initial & 31;
    if (additional < 24) return [major, BigInt(additional)];
    const width = additional === 24 ? 1 : additional === 25 ? 2 : additional === 26 ? 4 : additional === 27 ? 8 : 0;
    if (width === 0) throw new TypeError("indefinite CBOR is not canonical");
    let value = 0n;
    for (let index = 0; index < width; index += 1) value = (value << 8n) | BigInt(this.#take());
    if ((width === 1 && value < 24n) || (width === 2 && value <= 0xffn) || (width === 4 && value <= 0xffffn) || (width === 8 && value <= 0xffff_ffffn)) {
      throw new TypeError("non-minimal CBOR integer");
    }
    return [major, value];
  }

  uint(): bigint {
    const [major, value] = this.head();
    if (major !== 0) throw new TypeError("expected CBOR unsigned integer");
    return value;
  }

  text(): string {
    const [major, length] = this.head();
    if (major !== 3 || length > BigInt(this.#bytes.length - this.#offset)) throw new TypeError("invalid CBOR text");
    const size = Number(length);
    const value = new TextDecoder("utf-8", { fatal: true }).decode(this.#bytes.subarray(this.#offset, this.#offset + size));
    this.#offset += size;
    return value;
  }

  nullableBytes(expectedLength: number): Uint8Array | undefined {
    const [major, length] = this.head();
    if (major === 7 && length === 22n) return undefined;
    if (major !== 2 || length !== BigInt(expectedLength) || length > BigInt(this.#bytes.length - this.#offset)) throw new TypeError("invalid CBOR bytes");
    const size = Number(length);
    const value = this.#bytes.slice(this.#offset, this.#offset + size);
    this.#offset += size;
    return value;
  }

  bytes(expectedLength: number): Uint8Array {
    const value = this.nullableBytes(expectedLength);
    if (value === undefined) throw new TypeError("unexpected CBOR null");
    return value;
  }

  map(): number {
    const [major, length] = this.head();
    if (major !== 5 || length > 1_000_000n) throw new TypeError("invalid CBOR map");
    return Number(length);
  }

  skip(depth = 0): void {
    if (depth > MAX_DEPTH) throw new RangeError("CBOR depth exceeded");
    const [major, argument] = this.head();
    if (major === 0 || major === 1) return;
    if (major === 2 || major === 3) {
      if (argument > BigInt(this.#bytes.length - this.#offset)) throw new TypeError("truncated CBOR value");
      this.#offset += Number(argument);
      return;
    }
    if (major === 4) {
      for (let index = 0; index < Number(argument); index += 1) this.skip(depth + 1);
      return;
    }
    if (major === 5) {
      for (let index = 0; index < Number(argument); index += 1) {
        this.skip(depth + 1);
        this.skip(depth + 1);
      }
      return;
    }
    if (major === 7 && [20n, 21n, 22n].includes(argument)) return;
    throw new TypeError("unsupported CBOR result value");
  }

  #take(): number {
    const value = this.#bytes[this.#offset];
    if (value === undefined) throw new TypeError("truncated CBOR result");
    this.#offset += 1;
    return value;
  }
}

export function decodeResult(bytes: Uint8Array): DecodedResult {
  const reader = new Reader(bytes);
  if (reader.map() !== 16) throw new TypeError("invalid Auths result shape");
  let decision = -1;
  let stage = -1;
  let code = "";
  let metrics: bigint[] = [];
  let requiredConfiguration: Uint8Array | undefined;
  let localConfiguration: Uint8Array | undefined;
  let abiVersion = -1n;
  for (let index = 0; index < 16; index += 1) {
    const key = Number(reader.uint());
    if (key !== index) throw new TypeError("result map keys are not the exact canonical sequence");
    if (key === 0) decision = Number(reader.uint());
    else if (key === 1) stage = Number(reader.uint());
    else if (key === 2) {
      if (reader.map() !== 2 || reader.uint() !== 0n) throw new TypeError("invalid Auths result code");
      reader.uint();
      if (reader.uint() !== 1n) throw new TypeError("invalid result code key");
      code = reader.text();
    } else if (key === 11) {
      if (reader.map() !== 7) throw new TypeError("invalid result metrics");
      metrics = [];
      for (let metric = 0; metric < 7; metric += 1) {
        if (reader.uint() !== BigInt(metric)) throw new TypeError("non-canonical result metrics");
        metrics.push(reader.uint());
      }
    } else if (key === 13) requiredConfiguration = reader.nullableBytes(32);
    else if (key === 14) localConfiguration = reader.bytes(32);
    else if (key === 15) abiVersion = reader.uint();
    else reader.skip();
  }
  if (!reader.complete) throw new TypeError("trailing CBOR result bytes");
  if (abiVersion !== 2n) throw new TypeError("unsupported Auths result ABI version");
  if (!code || metrics.length !== 7 || localConfiguration === undefined) throw new TypeError("incomplete Auths result");
  const kinds: VerdictKind[] = ["authorized", "denied", "indeterminate"];
  const stages: VerificationStage[] = ["decode", "resolve", "principal-control", "authority", "complete"];
  const kind = kinds[decision];
  const stageName = stages[stage];
  if (kind === undefined || stageName === undefined) throw new TypeError("unknown Auths result discriminator");
  return {
    kind,
    code,
    stage: stageName,
    requiredConfiguration,
    localConfiguration,
    metrics: {
      proofBytes: metrics[0]!, actionBytes: metrics[1]!, contextBytes: metrics[2]!,
      objectCount: metrics[3]!, planLeaves: metrics[4]!, planDepth: metrics[5]!, workUnits: metrics[6]!,
    },
  };
}

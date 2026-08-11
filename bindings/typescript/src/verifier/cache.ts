export interface ImmutableArtifactCacheOptions {
  readonly maximumEntries?: number;
  readonly maximumBytes?: number;
}

interface CacheEntry {
  readonly bytes: Uint8Array;
  readonly size: number;
}

/** A bounded LRU cache for immutable values addressed by exact 32-byte commitments. */
export class ImmutableArtifactCache {
  readonly #maximumEntries: number;
  readonly #maximumBytes: number;
  readonly #entries = new Map<string, CacheEntry>();
  #bytes = 0;

  constructor(options: ImmutableArtifactCacheOptions = {}) {
    this.#maximumEntries = boundedLimit(options.maximumEntries ?? 256, 1, 4_096, "entries");
    this.#maximumBytes = boundedLimit(
      options.maximumBytes ?? 16_777_216,
      1,
      268_435_456,
      "bytes",
    );
  }

  get size(): number {
    return this.#entries.size;
  }

  get byteLength(): number {
    return this.#bytes;
  }

  get(commitment: Uint8Array): Uint8Array | undefined {
    const key = commitmentKey(commitment);
    const entry = this.#entries.get(key);
    if (entry === undefined) return undefined;
    this.#entries.delete(key);
    this.#entries.set(key, entry);
    return entry.bytes.slice();
  }

  put(commitment: Uint8Array, bytes: Uint8Array): void {
    const key = commitmentKey(commitment);
    if (!(bytes instanceof Uint8Array) || bytes.length > this.#maximumBytes) {
      throw new RangeError("immutable artifact is outside cache bounds");
    }
    const previous = this.#entries.get(key);
    if (previous !== undefined) {
      this.#entries.delete(key);
      this.#bytes -= previous.size;
    }
    const entry = Object.freeze({ bytes: bytes.slice(), size: bytes.length });
    this.#entries.set(key, entry);
    this.#bytes += entry.size;
    this.#evict();
  }

  invalidate(commitment: Uint8Array): boolean {
    const key = commitmentKey(commitment);
    const entry = this.#entries.get(key);
    if (entry === undefined) return false;
    this.#entries.delete(key);
    this.#bytes -= entry.size;
    return true;
  }

  clear(): void {
    this.#entries.clear();
    this.#bytes = 0;
  }

  #evict(): void {
    while (this.#entries.size > this.#maximumEntries || this.#bytes > this.#maximumBytes) {
      const oldest = this.#entries.entries().next().value as [string, CacheEntry] | undefined;
      if (oldest === undefined) return;
      this.#entries.delete(oldest[0]);
      this.#bytes -= oldest[1].size;
    }
  }
}

function commitmentKey(commitment: Uint8Array): string {
  if (!(commitment instanceof Uint8Array) || commitment.length !== 32) {
    throw new TypeError("artifact commitment must contain 32 bytes");
  }
  return Array.from(commitment, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function boundedLimit(value: number, minimum: number, maximum: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new RangeError(`cache ${name} limit is outside bounds`);
  }
  return value;
}

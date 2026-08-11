import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

export class DurableJsonExecutionStateStore {
  #path;
  #pending = Promise.resolve();

  constructor(path) {
    if (typeof path !== "string" || path.length === 0) throw new TypeError("store path is required");
    this.#path = path;
  }

  reserve(record) {
    return this.#serialized(async () => {
      const records = await this.#read();
      if (Object.hasOwn(records, record.idempotencyKey)) return "duplicate";
      records[record.idempotencyKey] = encodeRecord({ ...record, state: "reserved" });
      await this.#write(records);
      return "reserved";
    });
  }

  transition(idempotencyKey, expected, next) {
    return this.#serialized(async () => {
      const records = await this.#read();
      const current = Object.hasOwn(records, idempotencyKey) ? records[idempotencyKey] : undefined;
      if (current === undefined || current.state !== expected) return "conflict";
      records[idempotencyKey] = { ...current, state: next };
      await this.#write(records);
      return "transitioned";
    });
  }

  load(idempotencyKey) {
    return this.#serialized(async () => {
      const records = await this.#read();
      const record = Object.hasOwn(records, idempotencyKey) ? records[idempotencyKey] : undefined;
      return record === undefined ? undefined : decodeRecord(idempotencyKey, record);
    });
  }

  #serialized(operation) {
    const result = this.#pending.then(operation, operation);
    this.#pending = result.then(() => undefined, () => undefined);
    return result;
  }

  async #read() {
    try {
      const parsed = JSON.parse(await readFile(this.#path, "utf8"));
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new TypeError("durable Auths store is malformed");
      }
      return Object.assign(Object.create(null), parsed);
    } catch (error) {
      if (error?.code === "ENOENT") return Object.create(null);
      throw error;
    }
  }

  async #write(records) {
    await mkdir(dirname(this.#path), { recursive: true });
    const temporary = `${this.#path}.next`;
    await writeFile(temporary, `${JSON.stringify(records)}\n`, { mode: 0o600 });
    await rename(temporary, this.#path);
  }
}

function encodeRecord(record) {
  if (!(record.challenge instanceof Uint8Array) || record.challenge.length !== 32) {
    throw new TypeError("runtime challenge is invalid");
  }
  return { challenge: Buffer.from(record.challenge).toString("base64url"), state: record.state };
}

function decodeRecord(idempotencyKey, record) {
  if (record === null || typeof record !== "object" || Array.isArray(record) ||
      typeof record.challenge !== "string" || !EXECUTION_STATES.has(record.state)) {
    throw new TypeError("durable Auths store record is malformed");
  }
  const challenge = new Uint8Array(Buffer.from(record.challenge, "base64url"));
  if (challenge.length !== 32) {
    throw new TypeError("durable Auths store record is malformed");
  }
  return Object.freeze({ idempotencyKey, challenge, state: record.state });
}

const EXECUTION_STATES = new Set([
  "pre-effect", "reserved", "executing", "executed", "failed", "cancelled",
  "exhausted", "unavailable", "outcome-unknown",
]);

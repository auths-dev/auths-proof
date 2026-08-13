import type { McpExecutionState, McpReceiptSink, McpRecoveryCheckpoint } from "../profiles/mcp/index.js";
import { mkdir, open, readFile, rename, unlink } from "node:fs/promises";
import { platform } from "node:os";
import { dirname, join, resolve } from "node:path";

const MANIFEST = "auths-development-v2.json";

export interface RecoverableDevelopmentResources {
  readonly resources: McpExecutionState & McpReceiptSink;
  readonly sessionKey: Uint8Array;
  readonly authorityNotBefore: bigint;
}

export async function openRecoverableDevelopmentResources(directory: string): Promise<RecoverableDevelopmentResources> {
  const root = resolve(directory);
  await mkdir(root, { recursive: true });
  const manifestPath = join(root, MANIFEST);
  let sessionKey: Uint8Array;
  let authorityNotBefore: bigint;
  try {
    const parsed: unknown = JSON.parse(await readFile(manifestPath, "utf8"));
    ({ sessionKey, authorityNotBefore } = parseManifest(parsed));
  } catch (error) {
    if (isMissing(error)) {
      sessionKey = crypto.getRandomValues(new Uint8Array(32));
      authorityNotBefore = BigInt(Math.floor(Date.now() / 1000));
      try {
        const handle = await open(manifestPath, "wx", 0o600);
        try {
          await handle.writeFile(JSON.stringify({
            schema: "auths.recoverable-development/2",
            authorityNotBefore: Number(authorityNotBefore),
            sessionKey: toHex(sessionKey),
          }));
          await handle.sync();
        } finally {
          await handle.close();
        }
        await syncDirectory(root);
      } catch (creationError) {
        if (!isExists(creationError)) throw creationError;
        const parsed: unknown = JSON.parse(await readFile(manifestPath, "utf8"));
        ({ sessionKey, authorityNotBefore } = parseManifest(parsed));
      }
    } else {
      throw new TypeError("recoverable development manifest is corrupt");
    }
  }
  return Object.freeze({ resources: new FileMcpResources(root), sessionKey, authorityNotBefore });
}

class FileMcpResources implements McpExecutionState, McpReceiptSink {
  readonly #root: string;

  constructor(root: string) {
    this.#root = root;
  }

  async reserve(executionId: string, recovery: McpRecoveryCheckpoint): Promise<"acquired" | "exact-replay" | "conflict"> {
    assertRecovery(executionId, recovery);
    await this.#writeRecovery(recovery);
    const path = this.#path("execution", executionId);
    try {
      const handle = await open(path, "wx", 0o600);
      try {
        await handle.writeFile(executionRecord("reserved", recovery.reference));
        await handle.sync();
      } finally {
        await handle.close();
      }
      await syncDirectory(this.#root);
      return "acquired";
    } catch (error) {
      if (!isExists(error)) throw error;
      parseExecutionRecord(await readFile(path, "utf8"));
      return "exact-replay";
    }
  }

  async markProviderEntry(executionId: string, recovery: McpRecoveryCheckpoint): Promise<void> {
    assertRecovery(executionId, recovery);
    const path = this.#path("execution", executionId);
    const existing = parseExecutionRecord(await readFile(path, "utf8"));
    if (existing.stage !== "reserved") {
      throw new TypeError("invalid recoverable development provider-entry transition");
    }
    await this.#writeRecovery(recovery);
    await atomicWrite(path, executionRecord("provider", recovery.reference));
  }

  async saveRecovery(recovery: McpRecoveryCheckpoint): Promise<void> {
    assertRecovery(recovery.executionId, recovery);
    const path = this.#path("execution", recovery.executionId);
    const existing = parseExecutionRecord(await readFile(path, "utf8"));
    if (existing.stage === "completed") throw new TypeError("invalid recoverable development recovery transition");
    await this.#writeRecovery(recovery);
    await atomicWrite(path, executionRecord(existing.stage, recovery.reference));
  }

  async loadRecovery(reference: string): Promise<Uint8Array | undefined> {
    const executionId = executionIdForReference(reference);
    try {
      const execution = parseExecutionRecord(await readFile(this.#path("execution", executionId), "utf8"));
      if (execution.stage === "completed" || execution.recoveryReference !== reference) return undefined;
      return new Uint8Array(await readFile(this.#path("recovery", await digest(reference))));
    } catch (error) {
      if (isMissing(error)) return undefined;
      throw error;
    }
  }

  async loadPending(executionId: string): Promise<McpRecoveryCheckpoint | undefined> {
    try {
      const execution = parseExecutionRecord(await readFile(this.#path("execution", executionId), "utf8"));
      if (execution.stage === "completed" || execution.recoveryReference === undefined) return undefined;
      const recordJson = new Uint8Array(await readFile(
        this.#path("recovery", await digest(execution.recoveryReference)),
      ));
      return Object.freeze({ executionId, reference: execution.recoveryReference, recordJson });
    } catch (error) {
      if (isMissing(error)) return undefined;
      throw error;
    }
  }

  async clearPending(executionId: string): Promise<void> {
    const path = this.#path("execution", executionId);
    const execution = parseExecutionRecord(await readFile(path, "utf8"));
    if (execution.stage === "completed") return;
    await atomicWrite(path, executionRecord("completed"));
    if (execution.recoveryReference !== undefined) {
      await unlink(this.#path("recovery", await digest(execution.recoveryReference))).catch((error: unknown) => {
        if (!isMissing(error)) throw error;
      });
      await syncDirectory(this.#root);
    }
  }

  async persist(executionId: string, receiptJson: Uint8Array): Promise<void> {
    const path = this.#path("receipt", executionId);
    try {
      const handle = await open(path, "wx", 0o600);
      try {
        await handle.writeFile(receiptJson);
        await handle.sync();
      } finally {
        await handle.close();
      }
      await syncDirectory(this.#root);
    } catch (error) {
      if (isExists(error)) {
        const existing = new Uint8Array(await readFile(path));
        if (!equalBytes(existing, receiptJson)) {
          throw new TypeError("development receipt conflicts with persisted bytes");
        }
        return;
      }
      throw error;
    }
  }

  async #writeRecovery(recovery: McpRecoveryCheckpoint): Promise<void> {
    await atomicWrite(this.#path("recovery", await digest(recovery.reference)), recovery.recordJson);
  }

  #path(kind: "execution" | "receipt" | "recovery", id: string): string {
    if (!/^[0-9a-f]{64}$/u.test(id)) throw new TypeError("invalid recoverable development record identity");
    return join(this.#root, `${kind}-${id}.json`);
  }
}

async function atomicWrite(path: string, bytes: Uint8Array): Promise<void> {
  const temporary = `${path}.${crypto.randomUUID()}.tmp`;
  const handle = await open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    await rename(temporary, path);
    await syncDirectory(dirname(path));
  } catch (error) {
    await unlink(temporary).catch(() => undefined);
    throw error;
  }
}

async function syncDirectory(path: string): Promise<void> {
  if (platform() === "win32") return;
  const handle = await open(path, "r");
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

type ExecutionRecord = Readonly<{
  stage: "reserved" | "provider" | "completed";
  recoveryReference?: string;
}>;

function executionRecord(stage: ExecutionRecord["stage"], recoveryReference?: string): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({
    schema: "auths.development-execution/2",
    stage,
    ...(recoveryReference === undefined ? {} : { recoveryReference }),
  }));
}

function parseExecutionRecord(value: string): ExecutionRecord {
  const parsed: unknown = JSON.parse(value);
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new TypeError();
  const record = parsed as Record<string, unknown>;
  const keys = Object.keys(record).sort().join(",");
  if (record.schema !== "auths.development-execution/2") throw new TypeError();
  if (record.stage === "completed") {
    if (keys !== "schema,stage") throw new TypeError();
    return Object.freeze({ stage: "completed" });
  }
  if ((record.stage !== "reserved" && record.stage !== "provider")
    || keys !== "recoveryReference,schema,stage"
    || typeof record.recoveryReference !== "string") {
    throw new TypeError();
  }
  executionIdForReference(record.recoveryReference);
  return Object.freeze({ stage: record.stage, recoveryReference: record.recoveryReference });
}

function assertRecovery(executionId: string, recovery: McpRecoveryCheckpoint): void {
  if (recovery.executionId !== executionId || executionIdForReference(recovery.reference) !== executionId) {
    throw new TypeError("recovery checkpoint does not match execution");
  }
  if (!(recovery.recordJson instanceof Uint8Array) || recovery.recordJson.length === 0) {
    throw new TypeError("recovery checkpoint is empty");
  }
}

function executionIdForReference(reference: string): string {
  const match = /^mcp1\.([0-9a-f]{64})\.[0-9a-f]{64}$/u.exec(reference);
  if (match === null) throw new TypeError("invalid recoverable development reference");
  return match[1];
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function parseManifest(value: unknown): Readonly<{ sessionKey: Uint8Array; authorityNotBefore: bigint }> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new TypeError();
  const record = value as Record<string, unknown>;
  if (Object.keys(record).sort().join(",") !== "authorityNotBefore,schema,sessionKey"
    || record.schema !== "auths.recoverable-development/2"
    || typeof record.sessionKey !== "string"
    || !Number.isSafeInteger(record.authorityNotBefore)
    || (record.authorityNotBefore as number) < 0) throw new TypeError();
  const key = fromHex(record.sessionKey);
  if (key.length !== 32) throw new TypeError();
  return Object.freeze({ sessionKey: key, authorityNotBefore: BigInt(record.authorityNotBefore as number) });
}

async function digest(value: string): Promise<string> {
  return toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))));
}

function toHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function fromHex(value: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/u.test(value)) throw new TypeError();
  return Uint8Array.from(value.match(/.{2}/gu) ?? [], (part) => Number.parseInt(part, 16));
}

function isMissing(value: unknown): boolean {
  return value !== null && typeof value === "object" && "code" in value && value.code === "ENOENT";
}

function isExists(value: unknown): boolean {
  return value !== null && typeof value === "object" && "code" in value && value.code === "EEXIST";
}

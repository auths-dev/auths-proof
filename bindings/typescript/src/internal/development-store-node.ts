import type { McpExecutionState, McpReceiptSink } from "../profiles/mcp/index.js";
import { mkdir, open, readFile, rename, unlink } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";

const MANIFEST = "auths-development-v1.json";

export interface RecoverableDevelopmentResources {
  readonly resources: McpExecutionState & McpReceiptSink;
  readonly sessionKey: Uint8Array;
}

export async function openRecoverableDevelopmentResources(directory: string): Promise<RecoverableDevelopmentResources> {
  const root = resolve(directory);
  await mkdir(root, { recursive: true });
  const manifestPath = join(root, MANIFEST);
  let sessionKey: Uint8Array;
  try {
    const parsed: unknown = JSON.parse(await readFile(manifestPath, "utf8"));
    sessionKey = parseManifest(parsed);
  } catch (error) {
    if (isMissing(error)) {
      sessionKey = crypto.getRandomValues(new Uint8Array(32));
      try {
        const handle = await open(manifestPath, "wx", 0o600);
        try {
          await handle.writeFile(JSON.stringify({
            schema: "auths.recoverable-development/1",
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
        sessionKey = parseManifest(parsed);
      }
    } else {
      throw new TypeError("recoverable development manifest is corrupt");
    }
  }
  return Object.freeze({ resources: new FileMcpResources(root), sessionKey });
}

class FileMcpResources implements McpExecutionState, McpReceiptSink {
  readonly #root: string;

  constructor(root: string) {
    this.#root = root;
  }

  async reserve(executionId: string): Promise<"acquired" | "exact-replay" | "conflict"> {
    const path = this.#path("execution", executionId);
    try {
      const handle = await open(path, "wx", 0o600);
      try {
        await handle.writeFile('{"schema":"auths.development-execution/1","stage":"reserved"}');
        await handle.sync();
      } finally {
        await handle.close();
      }
      await syncDirectory(this.#root);
      return "acquired";
    } catch (error) {
      if (!isExists(error)) throw error;
      const existing = await readFile(path, "utf8");
      if (!isExecutionRecord(existing)) {
        throw new TypeError("recoverable development execution is corrupt");
      }
      return "exact-replay";
    }
  }

  async markProviderEntry(executionId: string): Promise<void> {
    const path = this.#path("execution", executionId);
    const existing = await readFile(path, "utf8");
    if (existing !== reservedExecutionRecord()) {
      throw new TypeError("invalid recoverable development provider-entry transition");
    }
    await atomicWrite(path, new TextEncoder().encode('{"schema":"auths.development-execution/1","stage":"provider"}'));
  }

  async saveRecovery(reference: string, recordJson: Uint8Array): Promise<void> {
    await atomicWrite(this.#path("recovery", await digest(reference)), recordJson);
  }

  async loadRecovery(reference: string): Promise<Uint8Array | undefined> {
    try {
      return new Uint8Array(await readFile(this.#path("recovery", await digest(reference))));
    } catch (error) {
      if (isMissing(error)) return undefined;
      throw error;
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
      if (isExists(error)) throw new TypeError("development receipt already exists");
      throw error;
    }
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
  const handle = await open(path, "r");
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

function reservedExecutionRecord(): string {
  return '{"schema":"auths.development-execution/1","stage":"reserved"}';
}

function isExecutionRecord(value: string): boolean {
  return value === reservedExecutionRecord()
    || value === '{"schema":"auths.development-execution/1","stage":"provider"}';
}

function parseManifest(value: unknown): Uint8Array {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new TypeError();
  const record = value as Record<string, unknown>;
  if (record.schema !== "auths.recoverable-development/1" || typeof record.sessionKey !== "string") throw new TypeError();
  const key = fromHex(record.sessionKey);
  if (key.length !== 32) throw new TypeError();
  return key;
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

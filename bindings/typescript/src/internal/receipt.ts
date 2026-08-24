import type { Receipt } from "../index.js";
import type { WorkflowWasmEngine } from "../workflow/contracts.js";

const receipts = new WeakSet<object>();
const RECEIPT_ID = /^rcpt_[A-Za-z0-9_-]{43}$/u;

class OpaqueReceipt {
  readonly id: string;
  readonly #bytes: Uint8Array;

  constructor(id: string, bytes: Uint8Array) {
    if (!RECEIPT_ID.test(id)) throw new TypeError("invalid receipt identifier");
    if (!(bytes instanceof Uint8Array) || bytes.length === 0 || bytes.length > 1024 * 1024) {
      throw new RangeError("receipt is outside the portable byte bound");
    }
    this.id = id;
    this.#bytes = bytes.slice();
    receipts.add(this);
    Object.freeze(this);
  }

  toBytes(): Uint8Array {
    return this.#bytes.slice();
  }

  toJSON(): never {
    throw new TypeError("Auths receipts have no raw JSON representation");
  }
}

export function mintReceipt(id: string, bytes: Uint8Array): Receipt {
  return new OpaqueReceipt(id, bytes) as unknown as Receipt;
}

export function receiptBytes(value: Receipt | Uint8Array): Uint8Array {
  if (value instanceof Uint8Array) {
    if (value.length === 0 || value.length > 1024 * 1024) {
      throw new RangeError("receipt is outside the portable byte bound");
    }
    return value.slice();
  }
  if (!receipts.has(value as object)) throw new TypeError("unsealed Auths receipt");
  return value.toBytes();
}

export interface PortableReceiptParts {
  readonly kind: "decision" | "execution";
  readonly portableReceiptId: string;
  readonly decisionReceiptId: Uint8Array;
  readonly executionReceiptId?: Uint8Array;
  readonly attestedDecision: Uint8Array;
  readonly attestedExecution?: Uint8Array;
}

/**
 * Decodes through the Rust-owned canonical `auths.portable-receipt/1`
 * implementation. This establishes container identity and linkage, but not
 * signer trust; callers must verify both embedded attestations.
 */
export function parsePortableReceipt(
  value: Receipt | Uint8Array,
  engine: WorkflowWasmEngine,
): PortableReceiptParts & Readonly<{ receipt: Receipt }> {
  const bytes = receiptBytes(value);
  const projected = engine.decodePortableReceiptV1(bytes);
  try {
    const kind = projected.kind;
    if (kind !== "decision" && kind !== "execution") throw new TypeError("malformed portable receipt projection");
    const portableReceiptId = projected.portableReceiptId;
    if (!RECEIPT_ID.test(portableReceiptId)) throw new TypeError("malformed portable receipt identity");
    const decisionReceiptId = fixedBytes(projected.decisionReceiptId, "decision receipt ID");
    const projectedExecutionId = projected.executionReceiptId;
    const executionReceiptId = projectedExecutionId === undefined
      ? undefined
      : fixedBytes(projectedExecutionId, "execution receipt ID");
    const attestedDecision = boundedBytes(projected.attestedDecision, "decision attestation");
    const projectedExecution = projected.attestedExecution;
    const attestedExecution = projectedExecution === undefined
      ? undefined
      : boundedBytes(projectedExecution, "execution attestation");
    if ((kind === "decision") !== (executionReceiptId === undefined && attestedExecution === undefined)) {
      throw new TypeError("contradictory portable receipt projection");
    }
    const receipt = value instanceof Uint8Array
      ? mintReceipt(portableReceiptId, bytes)
      : value;
    if (receipt.id !== portableReceiptId) throw new TypeError("portable receipt ID mismatch");
    return Object.freeze({
      kind,
      portableReceiptId,
      decisionReceiptId,
      ...(executionReceiptId === undefined ? {} : { executionReceiptId }),
      attestedDecision,
      ...(attestedExecution === undefined ? {} : { attestedExecution }),
      receipt,
    });
  } finally {
    projected.free?.();
  }
}

function fixedBytes(value: unknown, label: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== 32) throw new TypeError(`invalid ${label}`);
  return value.slice();
}

function boundedBytes(value: unknown, label: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length === 0 || value.length > 1024 * 1024) {
    throw new TypeError(`invalid ${label}`);
  }
  return value.slice();
}

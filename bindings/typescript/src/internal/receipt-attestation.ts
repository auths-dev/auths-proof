import type {
  ApplicationReceiptAttestor,
  ApplicationReceiptSigner,
  AttestedApplicationReceipt,
} from "../profiles/application/index.js";
import type { VerifiedArtifactView } from "./authorization.js";
import type { WorkflowWasmEngine } from "../workflow/contracts.js";
import { loadPackagedWorkflowEngine } from "../verifier/wasm.js";

export interface LinkedAttestedReceipt {
  readonly decision: AttestedApplicationReceipt;
  readonly execution: AttestedApplicationReceipt;
}

export async function attestAuthorizedDecision(
  engine: WorkflowWasmEngine,
  artifacts: VerifiedArtifactView,
  attestor: ApplicationReceiptAttestor,
  observedAt = BigInt(Math.floor(Date.now() / 1000)),
): Promise<AttestedApplicationReceipt> {
  const signer = receiptSigner(attestor.signer);
  const preparation = engine.prepareAuthorizedDecisionReceiptV1(
    artifacts.proofCbor.slice(),
    artifacts.canonicalActionCbor.slice(),
    artifacts.trustedContextCbor.slice(),
    observedAt,
    signer.principal,
    signer.verificationMethod,
    signer.suite,
  );
  try {
    const signature = await attestor.sign(preparation.signingPreimage.slice());
    return attestedReceipt({
      kind: "decision",
      receiptId: preparation.receiptId,
      bytes: engine.attestDecisionReceiptV1(
        preparation.canonical.slice(),
        signer.principal,
        signer.verificationMethod,
        signer.suite,
        signature.slice(),
      ),
      signer,
    });
  } finally {
    preparation.free?.();
  }
}

export async function attestExecution(
  engine: WorkflowWasmEngine,
  input: Readonly<{
    attestor: ApplicationReceiptAttestor;
    decisionReceiptId: Uint8Array;
    idempotencyKey: string;
    commandBytes: Uint8Array;
    result?: Uint8Array;
    planCommitment?: Uint8Array;
    memberIndex?: number;
    memberCount?: number;
    outcome?: "succeeded" | "failed";
    observedAt?: bigint;
  }>,
): Promise<AttestedApplicationReceipt> {
  const signer = receiptSigner(input.attestor.signer);
  const preparation = engine.prepareApplicationExecutionReceiptV1(
    input.decisionReceiptId.slice(),
    input.idempotencyKey,
    input.planCommitment !== undefined,
    input.planCommitment?.slice() ?? new Uint8Array(),
    input.memberIndex ?? 0,
    input.memberCount ?? 0,
    input.commandBytes.slice(),
    input.outcome ?? "succeeded",
    input.result !== undefined,
    input.result?.slice() ?? new Uint8Array(),
    input.observedAt ?? BigInt(Math.floor(Date.now() / 1000)),
    signer.principal,
    signer.verificationMethod,
    signer.suite,
  );
  try {
    const signature = await input.attestor.sign(preparation.signingPreimage.slice());
    return attestedReceipt({
      kind: "execution",
      receiptId: preparation.receiptId,
      bytes: engine.attestExecutionReceiptV1(
        preparation.canonical.slice(),
        signer.principal,
        signer.verificationMethod,
        signer.suite,
        signature.slice(),
      ),
      signer,
    });
  } finally {
    preparation.free?.();
  }
}

export function verifyAttestedReceipt(
  engine: WorkflowWasmEngine,
  receipt: AttestedApplicationReceipt,
): void {
  const value = attestedReceipt(receipt);
  engine.verifyRawKeyReceiptV1(
    value.kind,
    value.bytes,
    value.receiptId,
    value.signer.principal,
    value.signer.verificationMethod,
    value.signer.suite,
    value.signer.evidence,
  );
}

export function attestedReceipt(value: AttestedApplicationReceipt): AttestedApplicationReceipt {
  if (
    (value.kind !== "decision" && value.kind !== "execution") ||
    !(value.receiptId instanceof Uint8Array) ||
    value.receiptId.length !== 32 ||
    !(value.bytes instanceof Uint8Array) ||
    value.bytes.length === 0
  ) {
    throw new TypeError("invalid Auths receipt");
  }
  return Object.freeze({
    kind: value.kind,
    receiptId: value.receiptId.slice(),
    bytes: value.bytes.slice(),
    signer: receiptSigner(value.signer),
  });
}

export function encodeLinkedReceipt(receipt: LinkedAttestedReceipt): Uint8Array {
  const value = linkedReceipt(receipt);
  return new TextEncoder().encode(JSON.stringify({
    schema: "auths.portable-receipt/1",
    decision: receiptProjection(value.decision),
    execution: receiptProjection(value.execution),
  }));
}

export function decodeLinkedReceipt(input: Uint8Array): LinkedAttestedReceipt {
  if (!(input instanceof Uint8Array) || input.length === 0 || input.length > 1024 * 1024) {
    throw new TypeError("portable Auths receipt is outside bounds");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(input));
  } catch {
    throw new TypeError("portable Auths receipt is malformed");
  }
  if (!isRecord(parsed) || parsed.schema !== "auths.portable-receipt/1") {
    throw new TypeError("unsupported portable Auths receipt");
  }
  return linkedReceipt({
    decision: parseReceiptProjection(parsed.decision, "decision"),
    execution: parseReceiptProjection(parsed.execution, "execution"),
  });
}

export async function verifyLinkedReceipt(receipt: LinkedAttestedReceipt): Promise<void> {
  const value = linkedReceipt(receipt);
  const engine = await loadPackagedWorkflowEngine();
  verifyAttestedReceipt(engine, value.decision);
  verifyAttestedReceipt(engine, value.execution);
  engine.verifyReceiptLinkV1(
    value.decision.bytes,
    value.decision.receiptId,
    value.execution.bytes,
    value.execution.receiptId,
  );
}

function linkedReceipt(value: LinkedAttestedReceipt): LinkedAttestedReceipt {
  if (value === null || typeof value !== "object") throw new TypeError("Auths receipt is required");
  const decision = attestedReceipt(value.decision);
  const execution = attestedReceipt(value.execution);
  if (decision.kind !== "decision" || execution.kind !== "execution") {
    throw new TypeError("Auths receipt pair has invalid kinds");
  }
  return Object.freeze({ decision, execution });
}

function receiptProjection(receipt: AttestedApplicationReceipt): Readonly<Record<string, unknown>> {
  return Object.freeze({
    receiptId: base64Url(receipt.receiptId),
    bytes: base64Url(receipt.bytes),
    signer: Object.freeze({
      principal: receipt.signer.principal,
      verificationMethod: receipt.signer.verificationMethod,
      suite: receipt.signer.suite,
      evidence: base64Url(receipt.signer.evidence),
    }),
  });
}

function parseReceiptProjection(
  value: unknown,
  kind: "decision" | "execution",
): AttestedApplicationReceipt {
  if (!isRecord(value) || !isRecord(value.signer)) {
    throw new TypeError("portable Auths receipt member is malformed");
  }
  return attestedReceipt({
    kind,
    receiptId: decodeBase64Url(value.receiptId, 32, 32),
    bytes: decodeBase64Url(value.bytes, 1, 768 * 1024),
    signer: {
      principal: boundedText(value.signer.principal),
      verificationMethod: boundedText(value.signer.verificationMethod),
      suite: boundedText(value.signer.suite),
      evidence: decodeBase64Url(value.signer.evidence, 1, 128 * 1024),
    },
  });
}

function boundedText(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 1024) {
    throw new TypeError("portable Auths receipt text is outside bounds");
  }
  return value;
}

function base64Url(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function decodeBase64Url(value: unknown, minimum: number, maximum: number): Uint8Array {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum * 2) {
    throw new TypeError("portable Auths receipt bytes are outside bounds");
  }
  const padding = "=".repeat((4 - (value.length % 4)) % 4);
  let binary: string;
  try {
    binary = atob(value.replaceAll("-", "+").replaceAll("_", "/") + padding);
  } catch {
    throw new TypeError("portable Auths receipt bytes are malformed");
  }
  const decoded = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (decoded.length < minimum || decoded.length > maximum || base64Url(decoded) !== value) {
    throw new TypeError("portable Auths receipt bytes are not canonical");
  }
  return decoded;
}

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function receiptSigner(value: ApplicationReceiptSigner): ApplicationReceiptSigner {
  if (
    value === null || typeof value !== "object" ||
    typeof value.principal !== "string" || value.principal.length === 0 ||
    typeof value.verificationMethod !== "string" || value.verificationMethod.length === 0 ||
    typeof value.suite !== "string" || value.suite.length === 0 ||
    !(value.evidence instanceof Uint8Array) || value.evidence.length === 0
  ) {
    throw new TypeError("invalid Auths receipt signer");
  }
  return Object.freeze({
    principal: value.principal,
    verificationMethod: value.verificationMethod,
    suite: value.suite,
    evidence: value.evidence.slice(),
  });
}

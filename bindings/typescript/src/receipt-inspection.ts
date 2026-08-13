import type { LinkedAttestedReceipt } from "./internal/receipt-attestation.js";
import { loadPackagedWorkflowEngine } from "./verifier/wasm.js";

export type ReceiptViewMode = "opaque" | "summary" | "full";

export interface ReceiptInspectionSigner {
  readonly principal: string;
  readonly verificationMethod: string;
  readonly suite: string;
}

export interface ReceiptInspectionProfile {
  readonly id: string;
  readonly version: number;
}

export interface ReceiptInspectionCommitments {
  readonly proof: string;
  readonly action: string;
  readonly context: string;
  readonly principalStatus: string;
  readonly grantStatus: string;
  readonly executionLease: string;
  readonly command: string;
  readonly result?: string;
}

export interface ReceiptInspectionMetadata {
  readonly decisionReceiptId: string;
  readonly executionReceiptId: string;
  readonly profile: ReceiptInspectionProfile;
  readonly decision: "authorized" | "denied" | "indeterminate";
  readonly reasons: readonly string[];
  readonly outcome: "succeeded" | "failed";
  readonly decidedAt: bigint;
  readonly completedAt: bigint;
  readonly decisionSigner: ReceiptInspectionSigner;
  readonly executionSigner: ReceiptInspectionSigner;
  readonly commitments: ReceiptInspectionCommitments;
}

export interface ReceiptSummaryField {
  readonly label: string;
  readonly value: string;
}

export interface ReceiptSummary {
  readonly title: string;
  readonly fields: readonly ReceiptSummaryField[];
}

export interface ReceiptDisclosureMaterial {
  readonly command: Uint8Array;
  readonly result?: Uint8Array;
}

export interface VerifiedOpaqueReceipt {
  readonly kind: "verified-opaque";
  readonly mode: "opaque";
  readonly receipt: ReceiptInspectionMetadata;
}

export interface VerifiedDisclosedReceipt {
  readonly kind: "verified-disclosed";
  readonly mode: "summary" | "full";
  readonly receipt: ReceiptInspectionMetadata;
  readonly summary: ReceiptSummary;
  readonly disclosure?: ReceiptDisclosureMaterial;
}

export interface InvalidReceiptInspection {
  readonly kind: "invalid";
  readonly mode: string;
  readonly code: string;
}

export type ReceiptInspectionResult =
  | VerifiedOpaqueReceipt
  | VerifiedDisclosedReceipt
  | InvalidReceiptInspection;

export interface ReceiptDisclosureProtector {
  protect(tenant: string, receiptId: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array>;
  reveal(tenant: string, receiptId: Uint8Array, protectedBytes: Uint8Array): Promise<Uint8Array>;
}

export interface ReceiptDisclosureStore {
  put(tenant: string, receiptId: Uint8Array, protectedBytes: Uint8Array): Promise<void>;
  get(tenant: string, receiptId: Uint8Array): Promise<Uint8Array | undefined>;
  delete(tenant: string, receiptId: Uint8Array): Promise<void>;
}

export async function createReceiptDisclosure(input: Readonly<{
  receipt: LinkedAttestedReceipt;
  profileId: string;
  profileVersion: number;
  command: Uint8Array;
  result?: Uint8Array;
}>): Promise<Uint8Array> {
  const receipt = receiptPair(input.receipt);
  const engine = await loadPackagedWorkflowEngine();
  return engine.prepareReceiptDisclosureV1(
    receipt.execution.receiptId.slice(),
    input.profileId,
    input.profileVersion,
    bytes(input.command, "receipt disclosure command"),
    input.result !== undefined,
    input.result === undefined ? new Uint8Array() : bytes(input.result, "receipt disclosure result"),
  );
}

export async function inspectReceipt(input: Readonly<{
  receipt: LinkedAttestedReceipt;
  mode?: ReceiptViewMode;
  disclosure?: Uint8Array;
}>): Promise<ReceiptInspectionResult> {
  const receipt = receiptPair(input.receipt);
  const mode = input.mode ?? "opaque";
  const disclosure = input.disclosure?.slice() ?? new Uint8Array();
  const engine = await loadPackagedWorkflowEngine();
  const encoded = engine.inspectRawKeyReceiptV1(
    receipt.decision.receiptId.slice(),
    receipt.decision.bytes.slice(),
    receipt.decision.signer.evidence.slice(),
    receipt.execution.receiptId.slice(),
    receipt.execution.bytes.slice(),
    receipt.execution.signer.evidence.slice(),
    mode,
    input.disclosure !== undefined,
    disclosure,
  );
  return inspectionResult(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(encoded)));
}

function inspectionResult(value: unknown): ReceiptInspectionResult {
  const item = value as NativeInspection;
  if (item.kind === "invalid") {
    return Object.freeze({ kind: "invalid", mode: item.mode, code: item.code });
  }
  const receipt = inspectionMetadata(item.receipt);
  if (item.kind === "verified-opaque") {
    return Object.freeze({ kind: "verified-opaque", mode: "opaque", receipt });
  }
  const summary = Object.freeze({
    title: item.summary.title,
    fields: Object.freeze(item.summary.fields.map((field) => Object.freeze({ ...field }))),
  });
  const base = {
    kind: "verified-disclosed",
    mode: item.mode,
    receipt,
    summary,
  } as const;
  if (item.disclosure === null) return Object.freeze(base);
  const disclosure = item.disclosure.resultHex === null
    ? Object.freeze({ command: hexBytes(item.disclosure.commandHex) })
    : Object.freeze({
        command: hexBytes(item.disclosure.commandHex),
        result: hexBytes(item.disclosure.resultHex),
      });
  return Object.freeze({ ...base, disclosure });
}

function inspectionMetadata(value: NativeMetadata): ReceiptInspectionMetadata {
  const commitments = value.commitments.result === null
    ? Object.freeze({
        proof: value.commitments.proof,
        action: value.commitments.action,
        context: value.commitments.context,
        principalStatus: value.commitments.principalStatus,
        grantStatus: value.commitments.grantStatus,
        executionLease: value.commitments.executionLease,
        command: value.commitments.command,
      })
    : Object.freeze({ ...value.commitments, result: value.commitments.result });
  return Object.freeze({
    ...value,
    reasons: Object.freeze(value.reasons.slice()),
    decidedAt: BigInt(value.decidedAt),
    completedAt: BigInt(value.completedAt),
    profile: Object.freeze({ ...value.profile }),
    decisionSigner: Object.freeze({ ...value.decisionSigner }),
    executionSigner: Object.freeze({ ...value.executionSigner }),
    commitments,
  });
}

function receiptPair(value: LinkedAttestedReceipt): LinkedAttestedReceipt {
  if (
    value === null ||
    typeof value !== "object" ||
    value.decision?.kind !== "decision" ||
    value.execution?.kind !== "execution"
  ) {
    throw new TypeError("Auths receipt is required");
  }
  return value;
}

function bytes(value: Uint8Array, label: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length === 0) throw new TypeError(`${label} is required`);
  return value.slice();
}

function hexBytes(value: string): Uint8Array {
  return Uint8Array.from(value.match(/../g) ?? [], (pair) => Number.parseInt(pair, 16));
}

type NativeInspection =
  | Readonly<{ kind: "invalid"; mode: string; code: string }>
  | Readonly<{ kind: "verified-opaque"; mode: "opaque"; receipt: NativeMetadata }>
  | Readonly<{
      kind: "verified-disclosed";
      mode: "summary" | "full";
      receipt: NativeMetadata;
      summary: ReceiptSummary;
      disclosure: null | Readonly<{ commandHex: string; resultHex: string | null }>;
    }>;

type NativeMetadata = Omit<
  ReceiptInspectionMetadata,
  "decidedAt" | "completedAt" | "commitments"
> & Readonly<{
  decidedAt: string | number;
  completedAt: string | number;
  commitments: Omit<ReceiptInspectionCommitments, "result"> & Readonly<{ result: string | null }>;
}>;

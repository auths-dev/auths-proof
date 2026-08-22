import type { AuthsIssue, Receipt } from "./index.js";
import { issue } from "./internal/issues.js";
import { parsePortableReceipt } from "./internal/receipt.js";
import { loadPackagedWorkflowEngine, type PackagedWorkflowEngine } from "./verifier/wasm.js";
import {
  loadVerifier,
  type VerificationResult as NativeVerificationResult,
  type Verifier as NativeVerifier,
} from "./verifier/client.js";

export type VerificationStage = "decode" | "resolve" | "principal-control" | "authority" | "complete";

export interface VerificationInput {
  readonly proof: Uint8Array;
  readonly action: Uint8Array;
  readonly trustedContext: Uint8Array;
}

export interface VerificationMetrics {
  readonly proofBytes: bigint;
  readonly actionBytes: bigint;
  readonly contextBytes: bigint;
  readonly objectCount: bigint;
  readonly planLeaves: bigint;
  readonly planDepth: bigint;
  readonly workUnits: bigint;
}

interface VerificationCommon {
  readonly code: string;
  readonly stage: VerificationStage;
  readonly correlationId: string;
  readonly metrics: VerificationMetrics;
  readonly requiredConfiguration?: Uint8Array;
  readonly executedConfiguration: Uint8Array;
  readonly decisionBytes: Uint8Array;
}

export type VerificationResult =
  | (VerificationCommon & Readonly<{ kind: "authorized" }>)
  | (VerificationCommon & Readonly<{ kind: "denied"; issue: AuthsIssue & Readonly<{ effect: "not-applied" }> }>)
  | (VerificationCommon & Readonly<{ kind: "indeterminate"; issue: AuthsIssue & Readonly<{ effect: "not-applied" }> }>);

export interface VerificationInspection {
  readonly kind: VerificationResult["kind"];
  readonly code: string;
  readonly stage: VerificationStage;
  readonly resultCommitment: Uint8Array;
  readonly actionCommitment?: Uint8Array;
  readonly requiredConfigurationCommitment?: Uint8Array;
  readonly executedConfigurationCommitment: Uint8Array;
  readonly metrics: VerificationMetrics;
  readonly approval?: Readonly<{
    policyId: string;
    evaluatorVersion: string;
    decision: "approved" | "rejected";
    commitment: Uint8Array;
  }>;
}

export interface ReceiptProfile { readonly id: string; readonly version: number }
export interface ReceiptTrustAnchor {
  readonly role: "decision" | "execution";
  readonly principal: string;
  readonly verificationMethod: string;
  readonly suite: "ed25519-v1" | "p256-sha256-v1";
  readonly publicKey: Uint8Array;
}

declare const receiptTrustPolicyBrand: unique symbol;
export interface ReceiptTrustPolicy {
  readonly [receiptTrustPolicyBrand]: true;
  readonly allowedProfiles: readonly ReceiptProfile[];
  readonly anchorCount: number;
}

interface InternalReceiptTrustPolicy extends ReceiptTrustPolicy {
  readonly anchors: readonly ReceiptTrustAnchor[];
  readonly verificationTimeUnixSeconds?: bigint;
  readonly maximumReceiptAgeSeconds: bigint;
  readonly engine: PackagedWorkflowEngine;
}

const trustPolicies = new WeakSet<object>();

export async function pinnedReceiptTrust(options: Readonly<{
  anchors: readonly ReceiptTrustAnchor[];
  allowedProfiles: readonly ReceiptProfile[];
  verificationTimeUnixSeconds?: bigint;
  maximumReceiptAgeSeconds?: bigint;
}>): Promise<ReceiptTrustPolicy> {
  if (options.anchors.length < 1 || options.anchors.length > 32 ||
      !options.anchors.some((anchor) => anchor.role === "decision")) {
    throw new RangeError("receipt trust requires 1..32 anchors including a decision anchor");
  }
  if (options.allowedProfiles.length < 1 || options.allowedProfiles.length > 16) {
    throw new RangeError("receipt trust requires 1..16 profiles");
  }
  const maximumReceiptAgeSeconds = options.maximumReceiptAgeSeconds ?? 86_400n;
  if (maximumReceiptAgeSeconds < 1n || maximumReceiptAgeSeconds > 31_536_000n) {
    throw new RangeError("maximum receipt age is outside bounds");
  }
  if (options.verificationTimeUnixSeconds !== undefined && options.verificationTimeUnixSeconds < 0n) {
    throw new RangeError("verification time is invalid");
  }
  const engine = await loadPackagedWorkflowEngine();
  const profiles = Object.freeze(options.allowedProfiles.map(parseProfile));
  if (new Set(profiles.map((profile) => `${profile.id}/${profile.version}`)).size !== profiles.length) {
    throw new TypeError("duplicate receipt profile");
  }
  const anchors = Object.freeze(options.anchors.map((anchor) => {
    const parsed = parseAnchor(anchor);
    engine.validateReceiptAnchorV1(parsed.suite, parsed.publicKey);
    return parsed;
  }));
  if (new Set(anchors.map((anchor) => `${anchor.role}\0${anchor.principal}\0${anchor.verificationMethod}\0${anchor.suite}`)).size !== anchors.length) {
    throw new TypeError("duplicate receipt trust anchor");
  }
  const value = Object.freeze({
    allowedProfiles: profiles,
    anchorCount: anchors.length,
    anchors,
    engine,
    maximumReceiptAgeSeconds,
    ...(options.verificationTimeUnixSeconds === undefined
      ? {}
      : { verificationTimeUnixSeconds: options.verificationTimeUnixSeconds }),
  }) as unknown as InternalReceiptTrustPolicy;
  trustPolicies.add(value);
  return value;
}

export interface DecisionReceiptDetails {
  readonly kind: "decision";
  readonly receiptId: string;
  readonly profile: ReceiptProfile;
  readonly decision: "authorized" | "denied" | "indeterminate";
  readonly reasons: readonly string[];
  readonly decidedAtUnixSeconds: bigint;
  readonly decisionSigner: Readonly<{ principal: string; verificationMethod: string; suite: string }>;
  readonly commitments: Readonly<{ proof: string; action: string; context: string; principalStatus: string; grantStatus: string }>;
}

export interface ExecutionReceiptDetails {
  readonly kind: "execution";
  readonly decisionReceiptId: string;
  readonly executionReceiptId: string;
  readonly profile: ReceiptProfile;
  readonly decision: "authorized" | "denied" | "indeterminate";
  readonly outcome: "succeeded" | "failed" | "indeterminate";
  readonly reasons: readonly string[];
  readonly decidedAtUnixSeconds: bigint;
  readonly completedAtUnixSeconds: bigint;
  readonly decisionSigner: Readonly<{ principal: string; verificationMethod: string; suite: string }>;
  readonly executionSigner: Readonly<{ principal: string; verificationMethod: string; suite: string }>;
  readonly commitments: Readonly<{ proof: string; action: string; context: string; principalStatus: string; grantStatus: string; executionLease: string; command: string; result?: string }>;
}

export type ReceiptEnvelopeDetails = DecisionReceiptDetails | ExecutionReceiptDetails;
declare const verifiedReceiptBrand: unique symbol;
export interface VerifiedReceipt {
  readonly [verifiedReceiptBrand]: true;
  readonly kind: "verified";
  readonly receipt: Receipt;
  readonly details: ReceiptEnvelopeDetails;
}

export type ReceiptVerification =
  | VerifiedReceipt
  | Readonly<{ kind: "rejected"; issue: AuthsIssue & Readonly<{ effect: "not-applied" }> }>
  | Readonly<{ kind: "indeterminate"; issue: AuthsIssue & Readonly<{ effect: "not-applied" }> }>;

export interface VerificationOptions { readonly correlationId?: string }
export interface VerificationBatchOptions {
  readonly signal?: AbortSignal;
  readonly chunkSize?: number;
  readonly correlationId?: () => string;
}
export interface ReceiptVerificationInput {
  readonly receipt: Receipt | Uint8Array;
  readonly trust: ReceiptTrustPolicy;
}

export class Verifier {
  readonly #native: NativeVerifier;
  private constructor(native: NativeVerifier) { this.#native = native; }

  static async create(): Promise<Verifier> { return new Verifier(await loadVerifier()); }

  verify(input: VerificationInput, options: VerificationOptions = {}): VerificationResult {
    validateInput(input);
    return projectResult(this.#native.verify(input.proof, input.action, input.trustedContext, options));
  }

  async verifyMany(inputs: readonly VerificationInput[], options: VerificationBatchOptions = {}): Promise<readonly VerificationResult[]> {
    inputs.forEach(validateInput);
    const results = await this.#native.verifyMany(inputs.map((input) => ({
      proofCbor: input.proof,
      canonicalActionCbor: input.action,
      trustedContextCbor: input.trustedContext,
    })), options);
    return Object.freeze(results.map(projectResult));
  }

  inspect(result: VerificationResult): VerificationInspection {
    return Object.freeze({
      kind: result.kind,
      code: result.code,
      stage: result.stage,
      resultCommitment: commitment("result", result.decisionBytes),
      ...(result.kind === "authorized" ? { actionCommitment: commitment("action", result.decisionBytes) } : {}),
      ...(result.requiredConfiguration === undefined ? {} : { requiredConfigurationCommitment: commitment("required", result.requiredConfiguration) }),
      executedConfigurationCommitment: commitment("executed", result.executedConfiguration),
      metrics: result.metrics,
    });
  }

  verifyReceipt(input: ReceiptVerificationInput): ReceiptVerification {
    if (!trustPolicies.has(input.trust as object)) throw new TypeError("unsealed receipt trust policy");
    try {
      const trust = input.trust as InternalReceiptTrustPolicy;
      const receipt = parsePortableReceipt(input.receipt, trust.engine);
      const decision = verifyWithAnchors(
        trust,
        "decision",
        receipt.attestedDecision,
        receipt.decisionReceiptId,
      );
      let metadata = decision;
      if (receipt.kind === "execution") {
        if (receipt.attestedExecution === undefined || receipt.executionReceiptId === undefined) {
          throw new TypeError("execution receipt omitted its execution attestation");
        }
        metadata = verifyWithAnchors(
          trust,
          "execution",
          receipt.attestedExecution,
          receipt.executionReceiptId,
        );
        trust.engine.verifyReceiptLinkV1(
          receipt.attestedDecision,
          receipt.decisionReceiptId,
          receipt.attestedExecution,
          receipt.executionReceiptId,
        );
        if (metadata.decisionReceiptId !== hex(receipt.decisionReceiptId)) throw new TypeError("receipt chain mismatch");
      }
      const profile = parseProfile(decision.profile as ReceiptProfile);
      if (!trust.allowedProfiles.some((allowed) => allowed.id === profile.id && allowed.version === profile.version)) {
        return Object.freeze({ kind: "rejected", issue: notAppliedIssue("core.receipt-profile-denied") });
      }
      const now = trust.verificationTimeUnixSeconds ?? BigInt(Math.floor(Date.now() / 1000));
      const decidedAt = BigInt(String(decision.decidedAtUnixSeconds));
      const completedAt = receipt.kind === "execution" ? BigInt(String(metadata.completedAtUnixSeconds)) : decidedAt;
      if (decidedAt > now + 300n || completedAt > now + 300n || now - decidedAt > trust.maximumReceiptAgeSeconds) {
        return Object.freeze({ kind: "rejected", issue: notAppliedIssue("core.receipt-expired") });
      }
      const common = decision.commitments as Record<string, string>;
      const detailsValue: Record<string, unknown> = receipt.kind === "decision"
        ? {
            kind: "decision", receiptId: hex(receipt.decisionReceiptId), profile,
            decision: decision.decision, reasons: Object.freeze([...decision.reasons]),
            decidedAtUnixSeconds: decidedAt, decisionSigner: Object.freeze({ ...decision.decisionSigner }),
            commitments: Object.freeze({ proof: common.proof!, action: common.action!, context: common.context!, principalStatus: common.principalStatus!, grantStatus: common.grantStatus! }),
          }
        : {
            kind: "execution", decisionReceiptId: String(metadata.decisionReceiptId), executionReceiptId: hex(receipt.executionReceiptId!), profile,
            decision: decision.decision, outcome: metadata.outcome, reasons: Object.freeze([...decision.reasons]),
            decidedAtUnixSeconds: decidedAt, completedAtUnixSeconds: completedAt,
            decisionSigner: Object.freeze({ ...decision.decisionSigner }), executionSigner: Object.freeze({ ...metadata.executionSigner }),
            commitments: Object.freeze({ proof: common.proof!, action: common.action!, context: common.context!, principalStatus: common.principalStatus!, grantStatus: common.grantStatus!, executionLease: metadata.commitments.executionLease, command: metadata.commitments.command, ...(metadata.commitments.result === null ? {} : { result: metadata.commitments.result }) }),
          };
      const details = Object.freeze(detailsValue) as unknown as ReceiptEnvelopeDetails;
      return Object.freeze({ kind: "verified", receipt: receipt.receipt, details }) as VerifiedReceipt;
    } catch {
      return Object.freeze({ kind: "rejected", issue: notAppliedIssue("core.receipt-malformed") });
    }
  }
}

export async function createVerifier(): Promise<Verifier> { return Verifier.create(); }

function projectResult(result: NativeVerificationResult): VerificationResult {
  const common = {
    code: result.code,
    stage: result.stage,
    correlationId: result.correlationId,
    metrics: result.metrics,
    ...(result.requiredConfiguration === undefined ? {} : { requiredConfiguration: result.requiredConfiguration.slice() }),
    executedConfiguration: result.localConfiguration.slice(),
    decisionBytes: result.resultCbor.slice(),
  };
  if (result.kind === "authorized") return Object.freeze({ ...common, kind: "authorized" });
  const projectedIssue = notAppliedIssue(
    result.kind === "denied" ? "core.authorization-denied" : "core.authorization-indeterminate",
    { correlationId: result.correlationId, summary: result.explanation.message },
  );
  return result.kind === "denied"
    ? Object.freeze({ ...common, kind: "denied", issue: projectedIssue })
    : Object.freeze({ ...common, kind: "indeterminate", issue: projectedIssue });
}

function notAppliedIssue(
  code: Parameters<typeof issue>[0],
  options?: Parameters<typeof issue>[1],
): AuthsIssue & Readonly<{ effect: "not-applied" }> {
  const value = issue(code, options);
  if (value.effect !== "not-applied") throw new TypeError("expected a not-applied registry code");
  return value as AuthsIssue & Readonly<{ effect: "not-applied" }>;
}

function validateInput(input: VerificationInput): void {
  if (!(input.proof instanceof Uint8Array) || !(input.action instanceof Uint8Array) || !(input.trustedContext instanceof Uint8Array)) throw new TypeError("verification input must contain bytes");
}

function parseProfile(value: ReceiptProfile): ReceiptProfile {
  if (!/^[a-z][a-z0-9._:/-]{0,127}$/u.test(value.id) || !Number.isSafeInteger(value.version) || value.version < 1 || value.version > 0x7fffffff) throw new TypeError("invalid receipt profile");
  return Object.freeze({ id: value.id, version: value.version });
}

function parseAnchor(anchor: ReceiptTrustAnchor): ReceiptTrustAnchor {
  if (!/^[a-z][a-z0-9._:/-]{0,127}$/u.test(anchor.suite) || anchor.principal.length < 1 || anchor.principal.length > 512 || anchor.verificationMethod.length < 1 || anchor.verificationMethod.length > 512) throw new TypeError("invalid receipt anchor");
  const expected = anchor.suite === "ed25519-v1" ? 32 : 33;
  if (!(anchor.publicKey instanceof Uint8Array) || anchor.publicKey.length !== expected) throw new TypeError("invalid receipt public key");
  return Object.freeze({ ...anchor, publicKey: anchor.publicKey.slice() });
}

function commitment(domain: string, bytes: Uint8Array): Uint8Array {
  const output = new Uint8Array(32);
  let state = 0x811c9dc5;
  for (const byte of new TextEncoder().encode(domain)) { state ^= byte; state = Math.imul(state, 0x01000193); }
  for (const byte of bytes) { state ^= byte; state = Math.imul(state, 0x01000193); }
  for (let index = 0; index < output.length; index += 1) { state ^= index; state = Math.imul(state, 0x01000193); output[index] = state >>> ((index % 4) * 8); }
  return output;
}

function verifyWithAnchors(
  trust: InternalReceiptTrustPolicy,
  kind: "decision" | "execution",
  attested: Uint8Array,
  receiptId: Uint8Array,
): any {
  const role = kind;
  for (const anchor of trust.anchors) {
    if (anchor.role !== role) continue;
    try {
      const encoded = trust.engine.verifyPinnedReceiptV1(kind, attested, receiptId, anchor.principal, anchor.verificationMethod, anchor.suite, anchor.publicKey);
      return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(encoded));
    } catch {
      continue;
    }
  }
  throw new TypeError("receipt signer is not pinned or its signature is invalid");
}

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

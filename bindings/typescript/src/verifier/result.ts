import { decodeResult } from "./decoder.js";
import { explain } from "./explanation.js";

const AUTHORIZED_TOKEN: unique symbol = Symbol("auths-authorized");
let mintVerifiedAction: (canonicalAction: Uint8Array) => VerifiedAction;

export type VerdictKind = "authorized" | "denied" | "indeterminate";
export type VerificationStage =
  | "decode"
  | "resolve"
  | "principal-control"
  | "authority"
  | "complete";

export interface Explanation {
  readonly code: string;
  readonly message: string;
  readonly retryable: boolean;
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

export class VerifiedAction {
  readonly #canonicalAction: Uint8Array;

  private constructor(token: typeof AUTHORIZED_TOKEN, canonicalAction: Uint8Array) {
    if (token !== AUTHORIZED_TOKEN) throw new TypeError("sealed Auths action");
    this.#canonicalAction = canonicalAction.slice();
  }

  private static fromEngine(
    token: typeof AUTHORIZED_TOKEN,
    canonicalAction: Uint8Array,
  ): VerifiedAction {
    return new VerifiedAction(token, canonicalAction);
  }

  static {
    mintVerifiedAction = (canonicalAction) =>
      VerifiedAction.fromEngine(AUTHORIZED_TOKEN, canonicalAction);
  }

  canonicalBytes(): Uint8Array {
    return this.#canonicalAction.slice();
  }
}

interface CommonResult {
  readonly code: string;
  readonly stage: VerificationStage;
  readonly explanation: Explanation;
  readonly metrics: VerificationMetrics;
  readonly requiredConfiguration: Uint8Array | undefined;
  readonly localConfiguration: Uint8Array;
  readonly resultCbor: Uint8Array;
}

export interface AuthorizedResult extends CommonResult {
  readonly kind: "authorized";
  readonly action: VerifiedAction;
}

export interface DeniedResult extends CommonResult {
  readonly kind: "denied";
}

export interface IndeterminateResult extends CommonResult {
  readonly kind: "indeterminate";
}

export type VerificationResult = AuthorizedResult | DeniedResult | IndeterminateResult;

export interface PortableWasmEngine {
  verifyV1(
    proofCbor: Uint8Array,
    canonicalActionCbor: Uint8Array,
    trustedContextCbor: Uint8Array,
  ): Uint8Array;
}

/** Advanced raw verifier result; it is not an effect-capable profile command. */
export class Auths {
  readonly #engine: PortableWasmEngine;

  constructor(engine: PortableWasmEngine) {
    this.#engine = engine;
  }

  verify(
    proofCbor: Uint8Array,
    canonicalActionCbor: Uint8Array,
    trustedContextCbor: Uint8Array,
  ): VerificationResult {
    const bytes = this.#engine.verifyV1(proofCbor, canonicalActionCbor, trustedContextCbor);
    const decoded = decodeResult(bytes);
    const explanation = explain(decoded.kind, decoded.code);
    const common = {
      code: decoded.code,
      stage: decoded.stage,
      explanation,
      metrics: decoded.metrics,
      requiredConfiguration: decoded.requiredConfiguration?.slice(),
      localConfiguration: decoded.localConfiguration.slice(),
      resultCbor: bytes.slice(),
    };
    if (decoded.kind === "authorized") {
      return {
        ...common,
        kind: "authorized",
        action: mintVerifiedAction(canonicalActionCbor),
      };
    }
    return { ...common, kind: decoded.kind };
  }
}

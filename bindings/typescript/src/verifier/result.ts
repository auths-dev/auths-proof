import { interpretVerification } from "./decode-common.js";
import { isPackagedEngine } from "./packaged-registry.js";

const AUTHORIZED_TOKEN: unique symbol = Symbol("auths-authorized");
const PACKAGED_VERIFIER_TOKEN: unique symbol = Symbol("auths-packaged-verifier");
let mintVerifiedAction: (canonicalAction: Uint8Array) => VerifiedAction;
let mintPackagedVerifier: (engine: PortableWasmEngine) => Auths;

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

/**
 * Capability-minting verifier bound to the SDK-packaged WASM subject.
 *
 * Application code cannot construct one and cannot supply the engine whose
 * output selects the authorized branch. Caller-supplied engines belong on
 * `createDiagnosticVerifier`, whose results are never effect-capable.
 */
export class Auths {
  readonly #engine: PortableWasmEngine;

  private constructor(token: typeof PACKAGED_VERIFIER_TOKEN, engine: PortableWasmEngine) {
    if (token !== PACKAGED_VERIFIER_TOKEN) throw new TypeError("sealed Auths verifier");
    if (!isPackagedEngine(engine)) {
      throw new TypeError("Auths verification requires the packaged WASM engine");
    }
    this.#engine = engine;
    Object.freeze(this);
  }

  private static create(
    token: typeof PACKAGED_VERIFIER_TOKEN,
    engine: PortableWasmEngine,
  ): Auths {
    return new Auths(token, engine);
  }

  static {
    mintPackagedVerifier = (engine) => Auths.create(PACKAGED_VERIFIER_TOKEN, engine);
  }

  verify(
    proofCbor: Uint8Array,
    canonicalActionCbor: Uint8Array,
    trustedContextCbor: Uint8Array,
  ): VerificationResult {
    const bytes = this.#engine.verifyV1(proofCbor, canonicalActionCbor, trustedContextCbor);
    const { kind, ...common } = interpretVerification(bytes);
    if (kind === "authorized") {
      return {
        ...common,
        kind: "authorized",
        action: mintVerifiedAction(canonicalActionCbor),
      };
    }
    return { ...common, kind };
  }
}

/**
 * Package-private constructor for the capability-minting verifier.
 *
 * It is intentionally absent from every published entry point, and it refuses
 * any engine that the packaged loader did not produce.
 */
export function mintPackagedVerifierEngine(engine: PortableWasmEngine): Auths {
  return mintPackagedVerifier(engine);
}

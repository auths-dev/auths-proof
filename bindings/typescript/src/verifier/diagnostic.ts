import { interpretVerification } from "./decode-common.js";
import type {
  Explanation,
  PortableWasmEngine,
  VerdictKind,
  VerificationMetrics,
  VerificationStage,
} from "./result.js";

const DIAGNOSTIC_TOKEN: unique symbol = Symbol("auths-diagnostic-verifier");

let mintDiagnosticVerifier: (engine: PortableWasmEngine) => DiagnosticVerifier;

/**
 * Inert verifier evidence produced by a caller-supplied engine.
 *
 * A diagnostic result never carries a `VerifiedAction` and can never be
 * promoted into a profile command, whatever bytes the engine returned.
 */
export interface DiagnosticResult {
  readonly effectCapable: false;
  readonly kind: VerdictKind;
  readonly code: string;
  readonly stage: VerificationStage;
  readonly explanation: Explanation;
  readonly metrics: VerificationMetrics;
  readonly requiredConfiguration: Uint8Array | undefined;
  readonly localConfiguration: Uint8Array;
  readonly resultCbor: Uint8Array;
  /** Copy of the action bytes submitted to the engine; not a verified action. */
  readonly submittedActionCbor: Uint8Array;
}

/**
 * Advanced raw verifier bound to an explicitly supplied engine.
 *
 * It exists for differential testing, offline inspection, and hostile-engine
 * analysis. It is deliberately incapable of minting an effect capability.
 */
export class DiagnosticVerifier {
  readonly #engine: PortableWasmEngine;

  private constructor(token: typeof DIAGNOSTIC_TOKEN, engine: PortableWasmEngine) {
    if (token !== DIAGNOSTIC_TOKEN) throw new TypeError("sealed Auths diagnostic verifier");
    this.#engine = engine;
    Object.freeze(this);
  }

  private static create(
    token: typeof DIAGNOSTIC_TOKEN,
    engine: PortableWasmEngine,
  ): DiagnosticVerifier {
    return new DiagnosticVerifier(token, engine);
  }

  static {
    mintDiagnosticVerifier = (engine) => DiagnosticVerifier.create(DIAGNOSTIC_TOKEN, engine);
  }

  verify(
    proofCbor: Uint8Array,
    canonicalActionCbor: Uint8Array,
    trustedContextCbor: Uint8Array,
  ): DiagnosticResult {
    const bytes = this.#engine.verifyV1(proofCbor, canonicalActionCbor, trustedContextCbor);
    if (!(bytes instanceof Uint8Array)) {
      throw new TypeError("diagnostic engine returned a non-byte verification result");
    }
    return Object.freeze({
      effectCapable: false as const,
      ...interpretVerification(bytes),
      submittedActionCbor: canonicalActionCbor.slice(),
    });
  }
}

/** Wraps an explicitly supplied engine in a non-effect-capable verifier. */
export function createDiagnosticVerifier(engine: PortableWasmEngine): DiagnosticVerifier {
  if (engine === null || typeof engine !== "object" || typeof engine.verifyV1 !== "function") {
    throw new TypeError("diagnostic engine must expose verifyV1");
  }
  return mintDiagnosticVerifier(engine);
}

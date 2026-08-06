import { decodeResult } from "./decoder.js";
import { explain } from "./explanation.js";
import type {
  Explanation,
  VerdictKind,
  VerificationMetrics,
  VerificationStage,
} from "./result.js";

/** Engine-independent interpretation of one verification-result encoding. */
export interface InterpretedVerification {
  readonly kind: VerdictKind;
  readonly code: string;
  readonly stage: VerificationStage;
  readonly explanation: Explanation;
  readonly metrics: VerificationMetrics;
  readonly requiredConfiguration: Uint8Array | undefined;
  readonly localConfiguration: Uint8Array;
  readonly resultCbor: Uint8Array;
}

/** Decodes verifier bytes without granting any effect capability. */
export function interpretVerification(bytes: Uint8Array): InterpretedVerification {
  const decoded = decodeResult(bytes);
  return {
    kind: decoded.kind,
    code: decoded.code,
    stage: decoded.stage,
    explanation: explain(decoded.kind, decoded.code),
    metrics: decoded.metrics,
    requiredConfiguration: decoded.requiredConfiguration?.slice(),
    localConfiguration: decoded.localConfiguration.slice(),
    resultCbor: bytes.slice(),
  };
}

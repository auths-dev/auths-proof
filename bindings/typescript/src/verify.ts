/** Deterministic, effect-free verification over the packaged Rust/WASM engine. */
export {
  Auths as Verifier,
  VerifiedAction,
  loadVerifier,
  type AuthorizedResult,
  type DeniedResult,
  type Explanation,
  type IndeterminateResult,
  type VerificationBatchOptions,
  type VerificationInput,
  type VerificationMetrics,
  type VerificationOptions,
  type VerificationResult,
  type VerificationStage,
  type VerdictKind,
} from "./verifier/client.js";
export {
  ImmutableArtifactCache,
  type ImmutableArtifactCacheOptions,
} from "./verifier/cache.js";
export {
  decodeLinkedReceipt as decodeReceipt,
  encodeLinkedReceipt as encodeReceipt,
  verifyLinkedReceipt as verifyReceipt,
  type LinkedAttestedReceipt as Receipt,
} from "./internal/receipt-attestation.js";
export {
  inspectDecision,
  type DecisionInspection,
} from "./inspection.js";
export {
  createReceiptDisclosure,
  inspectReceipt,
  type InvalidReceiptInspection,
  type ReceiptDisclosureMaterial,
  type ReceiptDisclosureProtector,
  type ReceiptDisclosureStore,
  type ReceiptInspectionCommitments,
  type ReceiptInspectionMetadata,
  type ReceiptInspectionProfile,
  type ReceiptInspectionResult,
  type ReceiptInspectionSigner,
  type ReceiptSummary,
  type ReceiptSummaryField,
  type ReceiptViewMode,
  type VerifiedDisclosedReceipt,
  type VerifiedOpaqueReceipt,
} from "./receipt-inspection.js";

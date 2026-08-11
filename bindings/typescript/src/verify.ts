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

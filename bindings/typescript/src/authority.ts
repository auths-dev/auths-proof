/**
 * Effect-free delegated-authority verification.
 *
 * This entry point does not initialize approval providers, profile gateways, execution effects,
 * receipts, or lifecycle orchestration. It accepts already-canonical proof inputs and returns a
 * sealed verified action only from the package-owned Rust/WASM verifier.
 */
export {
  Auths,
  loadPortableAuths,
  type AuthorizedResult,
  type DeniedResult,
  type Explanation,
  type VerificationResult,
  type VerifiedAction,
} from "./advanced.js";
export {
  AuthorizationPlan,
  AuthorizationPlanBuilder,
  ProofReference,
  loadAuthorizationPlanBuilder,
  proofReference,
  type AuthorizationPlanKind,
  type AuthorizationPlanSummary,
} from "./authorization-plans.js";

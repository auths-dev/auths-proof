/**
 * Delegated-authority authoring and proof-plan composition.
 *
 * This entry point does not initialize approval providers, profile gateways, execution effects,
 * receipts, or lifecycle orchestration. Raw proof verification lives under the independent
 * `@auths-dev/sdk/verify` entry point.
 */
export {
  AuthorizationPlan,
  AuthorizationPlanBuilder,
  ProofReference,
  loadAuthorizationPlanBuilder,
  proofReference,
  type AuthorizationPlanKind,
  type AuthorizationPlanSummary,
} from "./authorization-plans.js";

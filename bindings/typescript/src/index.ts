/**
 * The local Auths product facade.
 *
 * One vocabulary, one entry point per operation. The remote service client is a
 * separate product and lives at `@auths-dev/sdk/service`; this entry point
 * publishes no mirror of it and holds no import edge to it.
 */
export { approval } from "./approvals.js";
export type { ApprovalPolicy } from "./workflow.js";
export {
  doctor,
  type DoctorMode,
  type DoctorOptions,
  type DoctorReport,
  type DoctorState,
} from "./doctor.js";
export {
  AuthsError,
  classifyErrorCode,
  isProductVerb,
  type AuthsErrorCode,
  type AuthsErrorDetails,
  type CauseCategory,
  type CodeClassification,
  type EnteredBoundaries,
  type EffectState,
  type ErrorFamily,
  type ProductStage,
  type ProductVerb,
  type RecommendedAction,
  type RetryClass,
} from "./product-errors.js";
export {
  createAuths,
  type Actor,
  type Auths,
  type AuthsConfiguration,
  type Authority,
  type Completed,
  type Denied,
  ExecutionReference,
  type ExecutionResult,
  type Indeterminate,
  type Outcome,
  type Receipt,
  type RecoveryResult,
} from "./product.js";

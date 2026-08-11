import { createWorkflowClient, type LoadWorkflowOptions } from "../workflow.js";
import { mintPackagedVerifierEngine, type Auths } from "./result.js";
import { loadPackagedWorkflowEngine } from "./wasm.js";

export * from "./authority.js";
export {
  Auths,
  VerifiedAction,
  type AuthorizedResult,
  type DeniedResult,
  type Explanation,
  type IndeterminateResult,
  type PortableWasmEngine,
  type VerdictKind,
  type VerificationMetrics,
  type VerificationBatchOptions,
  type VerificationInput,
  type VerificationOptions,
  type VerificationResult,
  type VerificationStage,
} from "./result.js";
export {
  AuthsClient,
  AuthsWorkflowError,
  AttachedAgent,
  ProviderOperationError,
  SignedGrantSource,
  TrustedContextSource,
  type AgentIdentity,
  type ApprovalConfiguration,
  type ApprovalExecutionSummary,
  type ApprovalMode,
  type ApprovalPolicy,
  type ApprovalPolicyReference,
  type ApprovalProvider,
  type ApprovalRequest,
  type ApprovalResponse,
  type AttachAgentOptions,
  type AuthorizationResult,
  type AuthorizedCommandResult,
  type AuthorityDiffSummary,
  type ControlEvidence,
  type DelegatedActionConstraint,
  type DelegatedAuthorityRequest,
  type DelegatedBudget,
  type DelegatedStatus,
  type DelegationOptions,
  type DelegationReview,
  type EffectState,
  type EffectiveAuthoritySummary,
  type ErrorContext,
  type ErrorFamily,
  type OverGrantingWarning,
  type PermissionSummary,
  type PlanAuthorizationResult,
  type PrincipalDescriptor,
  type Profile,
  type ProviderFailureKind,
  type RetryClass,
  type ReviewField,
  type SignedGrantLoadRequest,
  type SignedGrantMaterial,
  type SignedGrantProvider,
  type SignedGrantSourceOptions,
  type Signer,
  type SignerLifecycle,
  type SigningObjectKind,
  type SigningRequest,
  type SigningResponse,
  type TrustedAuthority,
  type TrustedAuthoritySnapshot,
  type TrustedContextLoadRequest,
  type TrustedContextProvider,
  type TrustedContextSourceOptions,
  type WorkflowErrorCode,
  type WorkflowVerificationResult,
  signedGrantSource,
  trustedContextSource,
} from "../workflow.js";

/**
 * Loads the raw verifier over the SDK-packaged WASM subject.
 *
 * It accepts no module URL, WASM input, or engine: the capability-minting
 * path resolves only the reviewed implementation shipped with this package.
 */
export async function loadVerifier(): Promise<Auths> {
  return mintPackagedVerifierEngine(await loadPackagedWorkflowEngine());
}

export type LoadAuthsOptions = LoadWorkflowOptions;

export async function loadAuths(options: LoadAuthsOptions) {
  return createWorkflowClient(options, await loadPackagedWorkflowEngine());
}

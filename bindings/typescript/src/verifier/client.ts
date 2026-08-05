import { createWorkflowClient, type LoadWorkflowOptions } from "../workflow.js";
import { Auths, type PortableWasmEngine } from "./result.js";
import { loadPackagedWorkflowEngine } from "./wasm.js";

export * from "./authority.js";
export * from "./result.js";
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
  type EffectiveAuthoritySummary,
  type OverGrantingWarning,
  type PermissionSummary,
  type PlanAuthorizationResult,
  type PrincipalDescriptor,
  type Profile,
  type ProviderFailureKind,
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

export interface LoadPortableAuthsOptions {
  readonly moduleUrl?: string;
  readonly wasmInput?: RequestInfo | URL | Response | BufferSource | WebAssembly.Module;
}

export async function loadPortableAuths(
  options: LoadPortableAuthsOptions = {},
): Promise<Auths> {
  if (options.moduleUrl === undefined && options.wasmInput === undefined) {
    const packaged = await loadPackagedWorkflowEngine();
    return new Auths({ verifyV1: packaged.verifyV1 });
  }
  const moduleUrl = options.moduleUrl ?? new URL("../../wasm/auths_proof_wasm.js", import.meta.url).href;
  const loaded = (await import(moduleUrl)) as {
    default?: (input?: { module_or_path: LoadPortableAuthsOptions["wasmInput"] }) => Promise<unknown>;
    verifyV1: PortableWasmEngine["verifyV1"];
  };
  if (loaded.default !== undefined) {
    if (options.wasmInput === undefined) await loaded.default();
    else await loaded.default({ module_or_path: options.wasmInput });
  }
  if (typeof loaded.verifyV1 !== "function") throw new TypeError("Auths WASM module omitted verifyV1");
  return new Auths({ verifyV1: loaded.verifyV1 });
}

export type LoadAuthsOptions = LoadWorkflowOptions;

export async function loadAuths(options: LoadAuthsOptions) {
  return createWorkflowClient(options, await loadPackagedWorkflowEngine());
}

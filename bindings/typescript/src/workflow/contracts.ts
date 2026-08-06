import type { AuthsClient, AttachedAgent } from "./internal/orchestrator.js";
import type { SignedGrantSource } from "./authority-source.js";
import type { TrustedContextSource } from "./trusted-context.js";
import type {
  AuthorizedResult,
  DeniedResult,
  IndeterminateResult,
  VerificationResult,
} from "../verifier/client.js";
import type { VerifiedPlanCommand } from "../plans.js";

export type SignerLifecycle = "durable" | "ephemeral";
export type SigningObjectKind =
  | "grant"
  | "action"
  | "principal-status"
  | "grant-status";
export type ApprovalMode =
  | "grant-only"
  | "risk-based"
  | "every-action"
  | "plan-once"
  | "headless"
  | "custom";

export interface PrincipalDescriptor {
  readonly principal: string;
  readonly principalMethod: string;
  readonly verificationMethod: string;
  readonly suite: string;
}

export interface ReviewField {
  readonly label: string;
  readonly value: string;
}

export interface SigningRequest {
  readonly requestId: string;
  readonly objectKind: SigningObjectKind;
  readonly objectId: Uint8Array;
  readonly principal: PrincipalDescriptor;
  readonly transactionDigest: Uint8Array;
  readonly signingPreimage: Uint8Array;
  readonly expiresAt: bigint;
  readonly display: readonly ReviewField[];
}

export interface SigningResponse {
  readonly requestId: string;
  readonly principal: PrincipalDescriptor;
  readonly transactionDigest: Uint8Array;
  readonly signature: Uint8Array;
  readonly evidence?: readonly ControlEvidence[];
}

export interface ControlEvidence {
  readonly evidenceType: string;
  readonly mediaType: string;
  readonly bytes: Uint8Array;
}

export interface Signer {
  readonly kind: string;
  readonly lifecycle: SignerLifecycle;
  publicIdentity(): Promise<PrincipalDescriptor>;
  sign(request: SigningRequest): Promise<SigningResponse>;
  dispose?(): Promise<void>;
}

export interface ApprovalPolicyReference {
  readonly policyId: string;
  readonly evaluatorVersion: string;
  readonly configurationDigest: Uint8Array;
}

export interface ApprovalPolicy {
  readonly reference: ApprovalPolicyReference;
  readonly mode: ApprovalMode;
  readonly maxUses: number;
  readonly expiresInSeconds: number;
  readonly requirements: readonly string[];
}

export interface ApprovalRequest {
  readonly requestId: string;
  readonly objectKind: SigningObjectKind;
  readonly transactionDigest: Uint8Array;
  readonly policy: ApprovalPolicyReference;
  readonly expiresAt: bigint;
  readonly display: readonly ReviewField[];
}

export interface ApprovalResponse {
  readonly requestId: string;
  readonly transactionDigest: Uint8Array;
  readonly policy: ApprovalPolicyReference;
  readonly decision: "approved" | "rejected";
}

export interface ApprovalProvider {
  approve(request: ApprovalRequest): Promise<ApprovalResponse>;
}

export interface ApprovalConfiguration {
  readonly policy: ApprovalPolicy;
  readonly provider: ApprovalProvider;
}

export interface TrustedAuthority {
  readonly authorityId: string;
  readonly rootPrincipal: string;
  readonly verifierConfiguration: Uint8Array;
  readonly context: TrustedContextSource;
  readonly requiredApproval: ApprovalPolicyReference;
}

export interface AgentIdentity {
  readonly principal: PrincipalDescriptor;
  readonly signerKind: string;
  readonly signerLifecycle: SignerLifecycle;
}

export interface TrustedAuthoritySnapshot {
  readonly authorityId: string;
  readonly rootPrincipal: string;
  readonly verifierConfiguration: Uint8Array;
  readonly contextSourceId: string;
  readonly requiredApproval: ApprovalPolicyReference;
}

export interface Profile<Action = unknown, Command = unknown> {
  readonly id: string;
  readonly version: number;
  readonly __action?: Action;
  readonly __command?: Command;
}

export interface ApprovalExecutionSummary {
  readonly policyId: string;
  readonly evaluatorVersion: string;
  readonly requiredConfiguration: Uint8Array;
  readonly executedConfiguration: Uint8Array;
  readonly executedMode: ApprovalMode;
  readonly executedMaxUses: number;
  readonly executedExpiresInSeconds: number;
  readonly executedRequirements: readonly string[];
}

export type WorkflowVerificationResult = VerificationResult & Readonly<{
  approval: ApprovalExecutionSummary;
}>;

export type AuthorizedCommandResult<Command> = AuthorizedResult & Readonly<{
  command: Command;
  approval: ApprovalExecutionSummary;
}>;

export type AuthorizationResult<Command> =
  | AuthorizedCommandResult<Command>
  | (DeniedResult & Readonly<{ approval: ApprovalExecutionSummary }>)
  | (IndeterminateResult & Readonly<{ approval: ApprovalExecutionSummary }>);

export type PlanAuthorizationResult<Command> =
  | Readonly<{
      kind: "authorized";
      command: VerifiedPlanCommand<Command>;
      results: readonly AuthorizedCommandResult<Command>[];
    }>
  | Readonly<{
      kind: "denied" | "indeterminate";
      failedIndex: number;
      result: DeniedResult | IndeterminateResult;
      results: readonly VerificationResult[];
    }>;

export interface SignedGrantLoadRequest {
  readonly sourceId: string;
  readonly authorityId: string;
  readonly subject: string;
  readonly profile: Readonly<{ id: string; version: number }>;
}

export interface SignedGrantProvider {
  loadSignedGrant(request: SignedGrantLoadRequest): Promise<SignedGrantMaterial>;
}

export interface SignedGrantMaterial {
  readonly signedGrant: Uint8Array;
  readonly evidence: readonly ControlEvidence[];
}

export interface SignedGrantSourceOptions {
  readonly sourceId: string;
  readonly provider: SignedGrantProvider;
}

export interface TrustedContextLoadRequest {
  readonly sourceId: string;
  readonly authorityId: string;
  readonly rootPrincipal: string;
  readonly verifierConfiguration: Uint8Array;
}

export interface TrustedContextProvider {
  loadTrustedContext(request: TrustedContextLoadRequest): Promise<Uint8Array>;
}

export interface TrustedContextSourceOptions {
  readonly sourceId: string;
  readonly provider: TrustedContextProvider;
}

export interface PermissionSummary {
  readonly capability: string;
  readonly resource: string;
}

export interface EffectiveAuthoritySummary {
  readonly grantId: Uint8Array;
  readonly issuer: string;
  readonly subject: string;
  readonly profile: Readonly<{ id: string; version: number }>;
  readonly permissions: readonly PermissionSummary[];
  readonly validity: Readonly<{ notBefore: bigint; expiresAt: bigint }>;
  readonly audiences: readonly string[];
  readonly actionConstraint: Readonly<{
    kind: "any-body" | "exact-body" | "allowed-bodies";
    digestCount: number;
  }>;
  readonly budget:
    | Readonly<{ algebra: string; value: bigint }>
    | undefined;
  readonly remainingDepth: number;
  readonly status: Readonly<{
    policy: "expiry-only" | "snapshot-required";
    method: string | undefined;
    maxAge: bigint | undefined;
  }>;
  readonly assuranceFloor: string;
  readonly criticalExtensions: readonly string[];
  readonly signature: Readonly<{
    principalMethod: string;
    verificationMethod: string;
    suite: string;
  }>;
  readonly explanation: Readonly<{
    stage: "attach";
    code:
      | "root-authority-structurally-bound"
      | "delegated-authority-structurally-bound";
    verification: "pending-authorization";
    message: string;
  }>;
}

export interface AttachAgentOptions<P extends Profile> {
  readonly name: string;
  readonly profile: P;
  readonly authority: SignedGrantSource;
  readonly approval: ApprovalConfiguration;
}

export type DelegatedActionConstraint =
  | Readonly<{ kind: "inherit" }>
  | Readonly<{ kind: "any-body" }>
  | Readonly<{ kind: "exact-body"; digest: Uint8Array }>
  | Readonly<{ kind: "allowed-bodies"; digests: readonly Uint8Array[] }>;

export type DelegatedBudget =
  | Readonly<{ kind: "inherit" }>
  | Readonly<{ kind: "none" }>
  | Readonly<{ kind: "ceiling"; algebra: string; value: bigint }>;

export type DelegatedStatus =
  | Readonly<{ kind: "inherit" }>
  | Readonly<{ kind: "expiry-only" }>
  | Readonly<{
      kind: "snapshot-required";
      method: string;
      maxAge: bigint;
    }>;

export interface DelegatedAuthorityRequest {
  readonly permissions: readonly PermissionSummary[];
  readonly validity: Readonly<{ notBefore: bigint; expiresAt: bigint }>;
  readonly audiences: readonly string[];
  readonly actionConstraint?: DelegatedActionConstraint;
  readonly budget?: DelegatedBudget;
  readonly remainingDepth: number;
  readonly status?: DelegatedStatus;
  readonly assuranceFloor?: string;
}

export interface DelegationOptions<P extends Profile> {
  readonly name: string;
  readonly authority: DelegatedAuthorityRequest;
  readonly signer: Signer;
  readonly profile?: P;
}

export type OverGrantingWarning =
  | "any-body"
  | "multiple-permissions"
  | "multiple-audiences"
  | "delegation-allowed"
  | "no-budget-ceiling"
  | "long-validity";

export interface AuthorityDiffSummary {
  readonly removedPermissions: number;
  readonly removedAudiences: number;
  readonly validityShortened: boolean;
  readonly actionNarrowed: boolean;
  readonly budgetNarrowed: boolean;
  readonly statusNarrowed: boolean;
  readonly parentDepth: number;
  readonly childDepth: number;
}

export interface DelegationReview {
  readonly diff: AuthorityDiffSummary;
  readonly warnings: readonly OverGrantingWarning[];
}

export interface WorkflowWasmEngine {
  authoringAbiVersionV1(): number;
  canonicalPrincipalV1(principal: string): string;
  configurationV1(): Uint8Array;
  validateTrustedContextV1(
    trustedContext: Uint8Array,
    rootPrincipal: string,
    verifierConfiguration: Uint8Array,
  ): Uint8Array;
  prepareMcpActionV1(
    service: string,
    name: string,
    argumentsJson: Uint8Array,
    actor: string,
    terminalGrant: Uint8Array,
    challenge: Uint8Array,
    evaluationTime: bigint,
  ): WorkflowMcpActionPreparation;
  prepareProfileActionV1(
    profileId: string,
    profileVersion: number,
    mediaType: string,
    body: Uint8Array,
    capability: string,
    resource: string,
    hasBudget: boolean,
    budgetAlgebra: string,
    budgetValue: bigint,
    audience: string,
    actor: string,
    terminalGrant: Uint8Array,
    challenge: Uint8Array,
    evaluationTime: bigint,
  ): WorkflowProfileActionPreparation;
  prepareRawKeyAuthorityV1(
    root: string,
    subject: string,
    profileId: string,
    profileVersion: number,
    permissionCapabilities: readonly string[],
    permissionResources: readonly string[],
    resourceNamespaces: readonly string[],
    notBefore: bigint,
    expiresAt: bigint,
    audiences: readonly string[],
    hasBudget: boolean,
    budgetAlgebra: string,
    budgetValue: bigint,
    remainingDepth: number,
  ): WorkflowRawKeyAuthorityPreparation;
  WorkflowProofBuilderV1: new () => WorkflowProofBuilder;
  verifyV1(
    proofCbor: Uint8Array,
    canonicalActionCbor: Uint8Array,
    trustedContextCbor: Uint8Array,
  ): Uint8Array;
  inspectSignedGrantV1(
    signedGrant: Uint8Array,
  ): WorkflowSignedGrantAuthority;
  validateRootAuthorityV1(
    signedGrant: Uint8Array,
    rootPrincipal: string,
    subjectPrincipal: string,
    profileId: string,
    profileVersion: number,
  ): WorkflowSignedGrantAuthority;
  planChildGrantFieldsV1(
    parentGrant: Uint8Array,
    subject: string,
    permissionCapabilities: readonly string[],
    permissionResources: readonly string[],
    notBefore: bigint,
    expiresAt: bigint,
    audiences: readonly string[],
    actionMode: string,
    actionDigests: Uint8Array,
    budgetMode: string,
    budgetAlgebra: string,
    budgetValue: bigint,
    remainingDepth: number,
    statusMode: string,
    statusMethod: string,
    statusMaxAge: bigint,
    assuranceFloor: string,
  ): WorkflowGrantPlan;
  prepareGrantSigningV1(
    statement: Uint8Array,
    principalMethod: string,
    verificationMethod: string,
    suite: string,
  ): WorkflowNativeSigningRequest;
  prepareActionSigningV1(
    action: Uint8Array,
    principalMethod: string,
    verificationMethod: string,
    suite: string,
  ): WorkflowNativeSigningRequest;
  preparePrincipalStatusSigningV1(
    statement: Uint8Array,
    principalMethod: string,
    verificationMethod: string,
    suite: string,
  ): WorkflowNativeSigningRequest;
  prepareGrantStatusSigningV1(
    statement: Uint8Array,
    principalMethod: string,
    verificationMethod: string,
    suite: string,
  ): WorkflowNativeSigningRequest;
  completeGrantSigningV1(
    statement: Uint8Array,
    principalMethod: string,
    verificationMethod: string,
    suite: string,
    signature: Uint8Array,
  ): Uint8Array;
  completeActionSigningV1(
    action: Uint8Array,
    principalMethod: string,
    verificationMethod: string,
    suite: string,
    signature: Uint8Array,
  ): Uint8Array;
  completePrincipalStatusSigningV1(
    statement: Uint8Array,
    principalMethod: string,
    verificationMethod: string,
    suite: string,
    signature: Uint8Array,
  ): Uint8Array;
  completeGrantStatusSigningV1(
    statement: Uint8Array,
    principalMethod: string,
    verificationMethod: string,
    suite: string,
    signature: Uint8Array,
  ): Uint8Array;
}

export interface WorkflowMcpActionPreparation {
  readonly canonicalActionCbor: Uint8Array;
  readonly actionEnvelopeCbor: Uint8Array;
  readonly audience: string;
  readonly resource: string;
  readonly displayDigestHex: string;
  free?(): void;
}

export interface WorkflowActionPreparation {
  readonly canonicalActionCbor: Uint8Array;
  readonly actionEnvelopeCbor: Uint8Array;
  readonly audience: string;
  readonly resource: string;
  free?(): void;
}

export type WorkflowProfileActionPreparation = WorkflowActionPreparation;

export interface WorkflowRawKeyAuthorityPreparation {
  readonly statementCbor: Uint8Array;
  readonly trustedContextCbor: Uint8Array;
  readonly verifierConfiguration: Uint8Array;
  free?(): void;
}

export interface WorkflowAuthorizationArtifacts {
  readonly proofCbor: Uint8Array;
  readonly trustedContextCbor: Uint8Array;
  free?(): void;
}

export interface WorkflowProofBuilder {
  pushGrant(signedGrant: Uint8Array): number;
  bindGrantEvidence(
    grantIndex: number,
    evidenceType: string,
    mediaType: string,
    bytes: Uint8Array,
  ): void;
  bindActionEvidence(
    evidenceType: string,
    mediaType: string,
    bytes: Uint8Array,
  ): void;
  finish(
    signedAction: Uint8Array,
    canonicalAction: Uint8Array,
    trustedContext: Uint8Array,
  ): WorkflowAuthorizationArtifacts;
  free?(): void;
}

export interface WorkflowSignedGrantAuthority {
  readonly statementCbor: Uint8Array;
  readonly grantId: Uint8Array;
  readonly issuer: string;
  readonly subject: string;
  readonly profileId: string;
  readonly profileVersion: number;
  readonly permissionCapabilities: readonly string[];
  readonly permissionResources: readonly string[];
  readonly notBefore: bigint;
  readonly expiresAt: bigint;
  readonly audiences: readonly string[];
  readonly actionConstraint: string;
  readonly actionDigestCount: number;
  readonly hasBudget: boolean;
  readonly budgetAlgebra: string;
  readonly budgetValue: bigint;
  readonly remainingDepth: number;
  readonly hasParent: boolean;
  readonly parentId: Uint8Array;
  readonly statusPolicy: string;
  readonly statusMethod: string;
  readonly statusMaxAge: bigint;
  readonly assuranceFloor: string;
  readonly criticalExtensions: readonly string[];
  readonly signaturePrincipalMethod: string;
  readonly signatureVerificationMethod: string;
  readonly signatureSuite: string;
  free?(): void;
}

export interface WorkflowGrantPlan {
  readonly statementCbor: Uint8Array;
  readonly removedPermissions: number;
  readonly removedAudiences: number;
  readonly validityShortened: boolean;
  readonly actionNarrowed: boolean;
  readonly budgetNarrowed: boolean;
  readonly statusNarrowed: boolean;
  readonly parentDepth: number;
  readonly childDepth: number;
  readonly warningMask: number;
  free?(): void;
}

export interface WorkflowNativeSigningRequest {
  readonly objectKind: string;
  readonly objectId: Uint8Array;
  readonly signingPreimage: Uint8Array;
  /** SHA-256 transaction binding stated by auths-codec, carried by the ABI. */
  readonly transactionDigest: Uint8Array;
  free?(): void;
}

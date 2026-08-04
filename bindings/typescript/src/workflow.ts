import type { VerificationResult } from "./index.js";

const MAX_IDENTIFIER_BYTES = 128;
const DIGEST_BYTES = 32;

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
  readonly mode: ApprovalMode;
  readonly policy: ApprovalPolicyReference;
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

export type WorkflowErrorCode =
  | "disposed"
  | "invalid-provider"
  | "invalid-principal"
  | "invalid-agent-name"
  | "invalid-profile"
  | "invalid-authority-source"
  | "authority-source-failed"
  | "trusted-context-source-failed"
  | "invalid-trusted-context"
  | "invalid-authority"
  | "authority-mismatch"
  | "invalid-delegation"
  | "delegation-expanded"
  | "configuration-mismatch"
  | "approval-policy-mismatch"
  | "approval-failed"
  | "approval-cancelled"
  | "approval-timeout"
  | "approval-unsupported"
  | "approval-rejected"
  | "approval-response-mismatch"
  | "signer-failed"
  | "signer-rejected"
  | "signer-cancelled"
  | "signer-timeout"
  | "signer-unsupported"
  | "signer-response-mismatch"
  | "transaction-expired"
  | "transaction-consumed";

export class AuthsWorkflowError extends Error {
  readonly code: WorkflowErrorCode;

  constructor(code: WorkflowErrorCode, message: string) {
    super(message);
    this.name = "AuthsWorkflowError";
    this.code = code;
  }
}

export type ProviderFailureKind =
  | "unavailable"
  | "rejected"
  | "cancelled"
  | "timeout"
  | "unsupported";

export class ProviderOperationError extends Error {
  readonly kind: ProviderFailureKind;

  constructor(kind: ProviderFailureKind) {
    super("external provider operation failed");
    this.name = "ProviderOperationError";
    this.kind = kind;
  }
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
  free?(): void;
}

interface ClientResources {
  readonly signer: Signer;
  readonly engine: WorkflowWasmEngine;
  readonly identity: AgentIdentity;
  readonly trustedAuthority: TrustedAuthoritySnapshot;
  readonly trustedContext: Uint8Array;
  readonly attachedAgents: Set<AttachedAgent<Profile>>;
}

const clientResources = new WeakMap<AuthsClient, ClientResources>();
const CLIENT_TOKEN: unique symbol = Symbol("auths-workflow-client");

export class AuthsClient implements AsyncDisposable {
  readonly #identity: AgentIdentity;
  readonly #trustedAuthority: TrustedAuthoritySnapshot;
  #disposed = false;

  private constructor(
    token: typeof CLIENT_TOKEN,
    identity: AgentIdentity,
    trustedAuthority: TrustedAuthoritySnapshot,
    signer: Signer,
    engine: WorkflowWasmEngine,
    trustedContext: Uint8Array,
  ) {
    if (token !== CLIENT_TOKEN) {
      throw new TypeError("sealed Auths workflow client");
    }
    this.#identity = identity;
    this.#trustedAuthority = trustedAuthority;
    clientResources.set(this, {
      signer,
      engine,
      identity,
      trustedAuthority,
      trustedContext: trustedContext.slice(),
      attachedAgents: new Set(),
    });
  }

  static create(
    token: typeof CLIENT_TOKEN,
    identity: AgentIdentity,
    trustedAuthority: TrustedAuthoritySnapshot,
    signer: Signer,
    engine: WorkflowWasmEngine,
    trustedContext: Uint8Array,
  ): AuthsClient {
    if (token !== CLIENT_TOKEN) {
      throw new TypeError("sealed Auths workflow client");
    }
    return new AuthsClient(
      token,
      identity,
      trustedAuthority,
      signer,
      engine,
      trustedContext,
    );
  }

  get disposed(): boolean {
    return this.#disposed;
  }

  get identity(): AgentIdentity {
    return this.#identity;
  }

  get trustedAuthority(): TrustedAuthoritySnapshot {
    return copyTrustedAuthoritySnapshot(this.#trustedAuthority);
  }

  assertActive(): void {
    if (this.#disposed) {
      throw new AuthsWorkflowError("disposed", "Auths client is disposed");
    }
  }

  async attachAgent<P extends Profile>(
    options: AttachAgentOptions<P>,
  ): Promise<AttachedAgent<P>> {
    return attachAgent(this, options);
  }

  async dispose(): Promise<void> {
    if (this.#disposed) return;
    this.#disposed = true;
    const resources = clientResources.get(this);
    let cleanupFailed = false;
    if (resources !== undefined) {
      for (const agent of Array.from(resources.attachedAgents)) {
        try {
          await agent.dispose();
        } catch {
          cleanupFailed = true;
        }
      }
    }
    if (resources?.signer.dispose !== undefined) {
      try {
        await resources.signer.dispose();
      } catch {
        cleanupFailed = true;
      }
    }
    resources?.trustedContext.fill(0);
    clientResources.delete(this);
    if (cleanupFailed) {
      throw new AuthsWorkflowError(
        "signer-failed",
        "one or more signer providers failed during cleanup",
      );
    }
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.dispose();
  }
}

interface SignedGrantSourceResources {
  readonly provider: SignedGrantProvider;
}

const signedGrantSourceResources = new WeakMap<
  SignedGrantSource,
  SignedGrantSourceResources
>();
const SIGNED_GRANT_SOURCE_TOKEN: unique symbol = Symbol(
  "auths-signed-grant-source",
);

export class SignedGrantSource {
  readonly sourceId: string;

  private constructor(
    token: typeof SIGNED_GRANT_SOURCE_TOKEN,
    sourceId: string,
    provider: SignedGrantProvider,
  ) {
    if (token !== SIGNED_GRANT_SOURCE_TOKEN) {
      throw new TypeError("sealed Auths signed-grant source");
    }
    this.sourceId = sourceId;
    signedGrantSourceResources.set(this, { provider });
    Object.freeze(this);
  }

  static create(
    token: typeof SIGNED_GRANT_SOURCE_TOKEN,
    sourceId: string,
    provider: SignedGrantProvider,
  ): SignedGrantSource {
    if (token !== SIGNED_GRANT_SOURCE_TOKEN) {
      throw new TypeError("sealed Auths signed-grant source");
    }
    return new SignedGrantSource(token, sourceId, provider);
  }
}

export function signedGrantSource(
  options: SignedGrantSourceOptions,
): SignedGrantSource {
  if (
    options === null ||
    typeof options !== "object" ||
    options.provider === null ||
    typeof options.provider !== "object" ||
    typeof options.provider.loadSignedGrant !== "function"
  ) {
    throw new AuthsWorkflowError(
      "invalid-authority-source",
      "signed-grant provider does not implement the Auths source port",
    );
  }
  return SignedGrantSource.create(
    SIGNED_GRANT_SOURCE_TOKEN,
    boundedIdentifier(options.sourceId, "signed-grant source"),
    options.provider,
  );
}

interface TrustedContextSourceResources {
  readonly provider: TrustedContextProvider;
}

const trustedContextSourceResources = new WeakMap<
  TrustedContextSource,
  TrustedContextSourceResources
>();
const TRUSTED_CONTEXT_SOURCE_TOKEN: unique symbol = Symbol(
  "auths-trusted-context-source",
);

export class TrustedContextSource {
  readonly sourceId: string;

  private constructor(
    token: typeof TRUSTED_CONTEXT_SOURCE_TOKEN,
    sourceId: string,
    provider: TrustedContextProvider,
  ) {
    if (token !== TRUSTED_CONTEXT_SOURCE_TOKEN) {
      throw new TypeError("sealed Auths trusted-context source");
    }
    this.sourceId = sourceId;
    trustedContextSourceResources.set(this, { provider });
    Object.freeze(this);
  }

  static create(
    token: typeof TRUSTED_CONTEXT_SOURCE_TOKEN,
    sourceId: string,
    provider: TrustedContextProvider,
  ): TrustedContextSource {
    if (token !== TRUSTED_CONTEXT_SOURCE_TOKEN) {
      throw new TypeError("sealed Auths trusted-context source");
    }
    return new TrustedContextSource(token, sourceId, provider);
  }
}

export function trustedContextSource(
  options: TrustedContextSourceOptions,
): TrustedContextSource {
  if (
    options === null ||
    typeof options !== "object" ||
    options.provider === null ||
    typeof options.provider !== "object" ||
    typeof options.provider.loadTrustedContext !== "function"
  ) {
    throw new AuthsWorkflowError(
      "invalid-trusted-context",
      "trusted-context provider does not implement the Auths source port",
    );
  }
  return TrustedContextSource.create(
    TRUSTED_CONTEXT_SOURCE_TOKEN,
    boundedIdentifier(options.sourceId, "trusted-context source"),
    options.provider,
  );
}

export interface AttachedAgentResources {
  readonly client: AuthsClient;
  readonly approval: ApprovalConfiguration;
  readonly signer: Signer;
  readonly ownsSigner: boolean;
  readonly signedGrant: Uint8Array;
  readonly grantChain: readonly GrantControlMaterial[];
  readonly grantStatement: Uint8Array;
  readonly review: DelegationReview | undefined;
}

export interface GrantControlMaterial {
  readonly signedGrant: Uint8Array;
  readonly evidence: readonly ControlEvidence[];
}

interface ProfileRuntime {
  authorize(
    agent: AttachedAgent<Profile>,
    action: unknown,
  ): Promise<VerificationResult>;
}

const profileRuntimes = new WeakMap<object, ProfileRuntime>();

export function registerProfileRuntime(
  profile: Profile,
  runtime: ProfileRuntime,
): void {
  if (profileRuntimes.has(profile as object)) {
    throw new TypeError("Auths profile runtime is already registered");
  }
  profileRuntimes.set(profile as object, runtime);
}

const attachedAgentResources = new WeakMap<
  AttachedAgent<Profile>,
  AttachedAgentResources
>();
const ATTACHED_AGENT_TOKEN: unique symbol = Symbol("auths-attached-agent");

export class AttachedAgent<P extends Profile> implements AsyncDisposable {
  readonly #name: string;
  readonly #identity: AgentIdentity;
  readonly #profile: P;
  readonly #authority: EffectiveAuthoritySummary;
  #disposed = false;

  private constructor(
    token: typeof ATTACHED_AGENT_TOKEN,
    client: AuthsClient,
    name: string,
    identity: AgentIdentity,
    profile: P,
    authority: EffectiveAuthoritySummary,
    approval: ApprovalConfiguration,
    signer: Signer,
    ownsSigner: boolean,
    signedGrant: Uint8Array,
    grantChain: readonly GrantControlMaterial[],
    grantStatement: Uint8Array,
    review: DelegationReview | undefined,
  ) {
    if (token !== ATTACHED_AGENT_TOKEN) {
      throw new TypeError("sealed Auths attached agent");
    }
    this.#name = name;
    this.#identity = identity;
    this.#profile = profile;
    this.#authority = authority;
    attachedAgentResources.set(this as AttachedAgent<Profile>, {
      client,
      approval,
      signer,
      ownsSigner,
      signedGrant: signedGrant.slice(),
      grantChain: copyGrantChain(grantChain),
      grantStatement: grantStatement.slice(),
      review,
    });
    clientResources
      .get(client)
      ?.attachedAgents.add(this as AttachedAgent<Profile>);
  }

  static create<P extends Profile>(
    token: typeof ATTACHED_AGENT_TOKEN,
    client: AuthsClient,
    name: string,
    identity: AgentIdentity,
    profile: P,
    authority: EffectiveAuthoritySummary,
    approval: ApprovalConfiguration,
    signer: Signer,
    ownsSigner: boolean,
    signedGrant: Uint8Array,
    grantChain: readonly GrantControlMaterial[],
    grantStatement: Uint8Array,
    review: DelegationReview | undefined,
  ): AttachedAgent<P> {
    if (token !== ATTACHED_AGENT_TOKEN) {
      throw new TypeError("sealed Auths attached agent");
    }
    return new AttachedAgent(
      token,
      client,
      name,
      identity,
      profile,
      authority,
      approval,
      signer,
      ownsSigner,
      signedGrant,
      grantChain,
      grantStatement,
      review,
    );
  }

  get name(): string {
    this.assertActive();
    return this.#name;
  }

  get identity(): AgentIdentity {
    this.assertActive();
    return this.#identity;
  }

  get profile(): P {
    this.assertActive();
    return this.#profile;
  }

  get authority(): EffectiveAuthoritySummary {
    this.assertActive();
    return copyEffectiveAuthority(this.#authority);
  }

  get disposed(): boolean {
    return this.#disposed;
  }

  get delegation(): DelegationReview | undefined {
    this.assertActive();
    const review = resourcesForAttachedAgent(this).review;
    return review === undefined ? undefined : copyDelegationReview(review);
  }

  async delegate(options: DelegationOptions<P>): Promise<AttachedAgent<P>> {
    this.assertActive();
    const { delegateAttachedAgent } = await import(
      "./internal/delegation.js"
    );
    return delegateAttachedAgent(this, options);
  }

  async authorize(action: P["__action"]): Promise<VerificationResult> {
    this.assertActive();
    const runtime = profileRuntimes.get(this.#profile as object);
    if (runtime === undefined) {
      throw new AuthsWorkflowError(
        "invalid-profile",
        "attached profile does not provide a package-owned authorization runtime",
      );
    }
    return runtime.authorize(this as AttachedAgent<Profile>, action);
  }

  assertActive(): void {
    const resources = attachedAgentResources.get(
      this as AttachedAgent<Profile>,
    );
    if (this.#disposed || resources === undefined) {
      throw new AuthsWorkflowError("disposed", "attached agent is disposed");
    }
    resources.client.assertActive();
  }

  async dispose(): Promise<void> {
    if (this.#disposed) return;
    this.#disposed = true;
    const resources = attachedAgentResources.get(
      this as AttachedAgent<Profile>,
    );
    attachedAgentResources.delete(this as AttachedAgent<Profile>);
    if (resources !== undefined) {
      clientResources
        .get(resources.client)
        ?.attachedAgents.delete(this as AttachedAgent<Profile>);
    }
    resources?.signedGrant.fill(0);
    resources?.grantStatement.fill(0);
    for (const material of resources?.grantChain ?? []) {
      material.signedGrant.fill(0);
      for (const evidence of material.evidence) evidence.bytes.fill(0);
    }
    if (resources?.ownsSigner && resources.signer.dispose !== undefined) {
      try {
        await resources.signer.dispose();
      } catch {
        throw new AuthsWorkflowError(
          "signer-failed",
          "child signer provider cleanup failed",
        );
      }
    }
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.dispose();
  }
}

export interface LoadWorkflowOptions {
  readonly signer: Signer;
  readonly trustedAuthority: TrustedAuthority;
}

export async function createWorkflowClient(
  options: LoadWorkflowOptions,
  engine: WorkflowWasmEngine,
): Promise<AuthsClient> {
  validateSignerShape(options.signer);
  let trustedAuthority: TrustedAuthoritySnapshot;
  let trustedContext: Uint8Array;
  try {
    trustedAuthority = copyTrustedAuthority(options.trustedAuthority);
    if (engine.authoringAbiVersionV1() !== 1) {
      throw new AuthsWorkflowError(
        "invalid-provider",
        "Auths WASM authoring ABI is unsupported",
      );
    }
    const engineConfiguration = copyExactBytes(
      engine.configurationV1(),
      DIGEST_BYTES,
      "verifier configuration",
    );
    if (
      !bytesEqual(
        engineConfiguration,
        trustedAuthority.verifierConfiguration,
      )
    ) {
      throw new AuthsWorkflowError(
        "configuration-mismatch",
        "trusted authority requires a different verifier configuration",
      );
    }
    trustedAuthority = Object.freeze({
      ...trustedAuthority,
      rootPrincipal: engine.canonicalPrincipalV1(
        trustedAuthority.rootPrincipal,
      ),
    });
    const source = options.trustedAuthority.context;
    const sourceResources =
      source instanceof TrustedContextSource
        ? trustedContextSourceResources.get(source)
        : undefined;
    if (sourceResources === undefined) {
      throw new AuthsWorkflowError(
        "invalid-trusted-context",
        "trusted authority must use a package-created context source",
      );
    }
    let loadedContext: Uint8Array;
    try {
      loadedContext = await sourceResources.provider.loadTrustedContext({
        sourceId: source.sourceId,
        authorityId: trustedAuthority.authorityId,
        rootPrincipal: trustedAuthority.rootPrincipal,
        verifierConfiguration:
          trustedAuthority.verifierConfiguration.slice(),
      });
    } catch {
      throw new AuthsWorkflowError(
        "trusted-context-source-failed",
        "trusted-context provider operation failed",
      );
    }
    if (!(loadedContext instanceof Uint8Array)) {
      throw new AuthsWorkflowError(
        "invalid-trusted-context",
        "trusted-context provider returned an invalid value",
      );
    }
    try {
      trustedContext = boundedBytes(
        engine.validateTrustedContextV1(
          loadedContext.slice(),
          trustedAuthority.rootPrincipal,
          trustedAuthority.verifierConfiguration.slice(),
        ),
        "trusted context",
      );
    } catch {
      throw new AuthsWorkflowError(
        "invalid-trusted-context",
        "trusted context does not bind the configured root and verifier",
      );
    }
  } catch (error) {
    await cleanupAfterFailedLoad(options.signer);
    if (error instanceof AuthsWorkflowError) throw error;
    throw new AuthsWorkflowError(
      "invalid-provider",
      "trusted authority or packaged WASM configuration is invalid",
    );
  }

  try {
    let descriptor = copyPrincipal(await options.signer.publicIdentity());
    descriptor = {
      ...descriptor,
      principal: engine.canonicalPrincipalV1(descriptor.principal),
    };

    const identity = Object.freeze({
      principal: Object.freeze(descriptor),
      signerKind: options.signer.kind,
      signerLifecycle: options.signer.lifecycle,
    });
    return AuthsClient.create(
      CLIENT_TOKEN,
      identity,
      trustedAuthority,
      options.signer,
      engine,
      trustedContext,
    );
  } catch (error) {
    await cleanupAfterFailedLoad(options.signer);
    if (error instanceof AuthsWorkflowError) throw error;
    throw new AuthsWorkflowError(
      "invalid-principal",
      "signer returned an invalid principal descriptor",
    );
  }
}

async function attachAgent<P extends Profile>(
  client: AuthsClient,
  options: AttachAgentOptions<P>,
): Promise<AttachedAgent<P>> {
  client.assertActive();
  if (options === null || typeof options !== "object") {
    throw new AuthsWorkflowError(
      "invalid-authority",
      "attach options are missing",
    );
  }
  const name = copyAgentName(options.name);
  const profile = copyProfile(options.profile) as P;
  const approval = validateApprovalConfiguration(
    options.approval,
    trustedAuthorityForClient(client).requiredApproval,
  );
  const source = options.authority;
  const sourceResources =
    source instanceof SignedGrantSource
      ? signedGrantSourceResources.get(source)
      : undefined;
  if (sourceResources === undefined) {
    throw new AuthsWorkflowError(
      "invalid-authority-source",
      "authority must be a package-created signed-grant source",
    );
  }

  const identity = identityForClient(client);
  const trustedAuthority = trustedAuthorityForClient(client);
  const request = Object.freeze({
    sourceId: source.sourceId,
    authorityId: trustedAuthority.authorityId,
    subject: identity.principal.principal,
    profile: Object.freeze({ id: profile.id, version: profile.version }),
  });
  let loadedMaterial: SignedGrantMaterial;
  try {
    loadedMaterial = await sourceResources.provider.loadSignedGrant(request);
  } catch {
    throw new AuthsWorkflowError(
      "authority-source-failed",
      "signed-grant provider operation failed",
    );
  }
  const material = copySignedGrantMaterial(loadedMaterial);
  const signedGrant = material.signedGrant.slice();

  const engine = engineForClient(client);
  let inspection: WorkflowSignedGrantAuthority | undefined;
  let validated: WorkflowSignedGrantAuthority | undefined;
  try {
    try {
      inspection = engine.inspectSignedGrantV1(signedGrant);
    } catch {
      throw new AuthsWorkflowError(
        "invalid-authority",
        "signed-grant source returned malformed or non-canonical authority",
      );
    }
    try {
      validated = engine.validateRootAuthorityV1(
        signedGrant,
        trustedAuthority.rootPrincipal,
        identity.principal.principal,
        profile.id,
        profile.version,
      );
    } catch {
      throw new AuthsWorkflowError(
        "authority-mismatch",
        "signed grant does not bind the trusted root, agent, and profile",
      );
    }
    return AttachedAgent.create(
      ATTACHED_AGENT_TOKEN,
      client,
      name,
      identity,
      profile,
      authoritySummary(validated),
      approval,
      signerForClient(client),
      false,
      signedGrant,
      [material],
      validated.statementCbor,
      undefined,
    );
  } finally {
    inspection?.free?.();
    validated?.free?.();
    signedGrant.fill(0);
  }
}

export function signerForClient(client: AuthsClient): Signer {
  client.assertActive();
  const resources = clientResources.get(client);
  if (resources === undefined) {
    throw new AuthsWorkflowError("disposed", "Auths client is disposed");
  }
  return resources.signer;
}

export function engineForClient(client: AuthsClient): WorkflowWasmEngine {
  client.assertActive();
  const resources = clientResources.get(client);
  if (resources === undefined) {
    throw new AuthsWorkflowError("disposed", "Auths client is disposed");
  }
  return resources.engine;
}

export function identityForClient(client: AuthsClient): AgentIdentity {
  client.assertActive();
  const resources = clientResources.get(client);
  if (resources === undefined) {
    throw new AuthsWorkflowError("disposed", "Auths client is disposed");
  }
  return resources.identity;
}

export function trustedAuthorityForClient(
  client: AuthsClient,
): TrustedAuthoritySnapshot {
  client.assertActive();
  const resources = clientResources.get(client);
  if (resources === undefined) {
    throw new AuthsWorkflowError("disposed", "Auths client is disposed");
  }
  return resources.trustedAuthority;
}

export function trustedContextForClient(client: AuthsClient): Uint8Array {
  client.assertActive();
  const resources = clientResources.get(client);
  if (resources === undefined) {
    throw new AuthsWorkflowError("disposed", "Auths client is disposed");
  }
  return resources.trustedContext.slice();
}

export function resourcesForAttachedAgent<P extends Profile>(
  agent: AttachedAgent<P>,
): AttachedAgentResources {
  agent.assertActive();
  const resources = attachedAgentResources.get(
    agent as AttachedAgent<Profile>,
  );
  if (resources === undefined) {
    throw new AuthsWorkflowError("disposed", "attached agent is disposed");
  }
  return resources;
}

export function createDelegatedAttachedAgent<P extends Profile>(options: {
  readonly parent: AttachedAgent<P>;
  readonly name: string;
  readonly identity: AgentIdentity;
  readonly profile: P;
  readonly authority: EffectiveAuthoritySummary;
  readonly signer: Signer;
  readonly signedGrant: Uint8Array;
  readonly evidence: readonly ControlEvidence[];
  readonly grantStatement: Uint8Array;
  readonly review: DelegationReview;
}): AttachedAgent<P> {
  const parentResources = resourcesForAttachedAgent(options.parent);
  return AttachedAgent.create(
    ATTACHED_AGENT_TOKEN,
    parentResources.client,
    options.name,
    options.identity,
    options.profile,
    options.authority,
    parentResources.approval,
    options.signer,
    true,
    options.signedGrant,
    [
      ...parentResources.grantChain,
      { signedGrant: options.signedGrant, evidence: options.evidence },
    ],
    options.grantStatement,
    options.review,
  );
}

export function copyPrincipal(value: PrincipalDescriptor): PrincipalDescriptor {
  if (value === null || typeof value !== "object") {
    throw new AuthsWorkflowError(
      "invalid-principal",
      "principal descriptor is missing",
    );
  }
  return {
    principal: boundedIdentifier(value.principal, "principal"),
    principalMethod: boundedIdentifier(
      value.principalMethod,
      "principal method",
    ),
    verificationMethod: boundedIdentifier(
      value.verificationMethod,
      "verification method",
    ),
    suite: boundedIdentifier(value.suite, "signature suite"),
  };
}

export function copyPolicy(
  value: ApprovalPolicyReference,
): ApprovalPolicyReference {
  if (value === null || typeof value !== "object") {
    throw new AuthsWorkflowError(
      "invalid-provider",
      "approval policy is missing",
    );
  }
  return Object.freeze({
    policyId: boundedIdentifier(value.policyId, "approval policy"),
    evaluatorVersion: boundedIdentifier(
      value.evaluatorVersion,
      "approval evaluator version",
    ),
    configurationDigest: copyExactBytes(
      value.configurationDigest,
      DIGEST_BYTES,
      "approval configuration digest",
    ),
  });
}

export function policiesEqual(
  left: ApprovalPolicyReference,
  right: ApprovalPolicyReference,
): boolean {
  if (
    left === null ||
    right === null ||
    typeof left !== "object" ||
    typeof right !== "object" ||
    !(left.configurationDigest instanceof Uint8Array) ||
    !(right.configurationDigest instanceof Uint8Array)
  ) {
    return false;
  }
  return (
    left.policyId === right.policyId &&
    left.evaluatorVersion === right.evaluatorVersion &&
    bytesEqual(left.configurationDigest, right.configurationDigest)
  );
}

export function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (!(left instanceof Uint8Array) || !(right instanceof Uint8Array)) {
    return false;
  }
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

export function copyExactBytes(
  value: Uint8Array,
  length: number,
  label: string,
): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    throw new AuthsWorkflowError(
      "invalid-provider",
      `${label} must contain exactly ${length} bytes`,
    );
  }
  return value.slice();
}

export function boundedBytes(value: Uint8Array, label: string): Uint8Array {
  if (
    !(value instanceof Uint8Array) ||
    value.length === 0 ||
    value.length > 16 * 1024 * 1024
  ) {
    throw new AuthsWorkflowError(
      "invalid-provider",
      `${label} must be a non-empty bounded byte array`,
    );
  }
  return value.slice();
}

export function boundedIdentifier(value: string, label: string): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    new TextEncoder().encode(value).length > MAX_IDENTIFIER_BYTES ||
    !/^[\x21-\x7e]+$/.test(value)
  ) {
    throw new AuthsWorkflowError(
      "invalid-provider",
      `${label} is outside the supported identifier bound`,
    );
  }
  return value;
}

function copyTrustedAuthority(
  value: TrustedAuthority,
): TrustedAuthoritySnapshot {
  if (value === null || typeof value !== "object") {
    throw new AuthsWorkflowError(
      "invalid-provider",
      "trusted authority is missing",
    );
  }
  return Object.freeze({
    authorityId: boundedIdentifier(value.authorityId, "trusted authority"),
    rootPrincipal: boundedIdentifier(value.rootPrincipal, "trusted root"),
    verifierConfiguration: copyExactBytes(
      value.verifierConfiguration,
      DIGEST_BYTES,
      "verifier configuration",
    ),
    contextSourceId:
      value.context instanceof TrustedContextSource
        ? value.context.sourceId
        : (() => {
            throw new AuthsWorkflowError(
              "invalid-trusted-context",
              "trusted authority must use a package-created context source",
            );
          })(),
    requiredApproval: copyPolicy(value.requiredApproval),
  });
}

function copyTrustedAuthoritySnapshot(
  value: TrustedAuthoritySnapshot,
): TrustedAuthoritySnapshot {
  return Object.freeze({
    authorityId: value.authorityId,
    rootPrincipal: value.rootPrincipal,
    verifierConfiguration: value.verifierConfiguration.slice(),
    contextSourceId: value.contextSourceId,
    requiredApproval: copyPolicy(value.requiredApproval),
  });
}

function copyControlEvidence(value: ControlEvidence): ControlEvidence {
  if (
    value === null ||
    typeof value !== "object" ||
    !(value.bytes instanceof Uint8Array) ||
    value.bytes.length === 0
  ) {
    throw new AuthsWorkflowError(
      "invalid-authority",
      "control evidence is malformed",
    );
  }
  return Object.freeze({
    evidenceType: boundedIdentifier(value.evidenceType, "evidence type"),
    mediaType: boundedIdentifier(value.mediaType, "evidence media type"),
    bytes: value.bytes.slice(),
  });
}

function copySignedGrantMaterial(
  value: SignedGrantMaterial,
): SignedGrantMaterial {
  if (
    value === null ||
    typeof value !== "object" ||
    !(value.signedGrant instanceof Uint8Array) ||
    value.signedGrant.length === 0 ||
    value.signedGrant.length > 16 * 1024 * 1024 ||
    !Array.isArray(value.evidence)
  ) {
    throw new AuthsWorkflowError(
      "invalid-authority",
      "signed-grant provider returned invalid proof material",
    );
  }
  if (value.evidence.length > 32) {
    throw new AuthsWorkflowError(
      "invalid-authority",
      "signed-grant control evidence exceeds the supported count",
    );
  }
  const evidence = value.evidence.map(copyControlEvidence);
  if (
    evidence.reduce((total, item) => total + item.bytes.length, 0) >
    64 * 1024
  ) {
    throw new AuthsWorkflowError(
      "invalid-authority",
      "signed-grant control evidence exceeds the supported byte bound",
    );
  }
  return Object.freeze({
    signedGrant: value.signedGrant.slice(),
    evidence: Object.freeze(evidence),
  });
}

function copyGrantChain(
  value: readonly GrantControlMaterial[],
): readonly GrantControlMaterial[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 64) {
    throw new AuthsWorkflowError(
      "invalid-authority",
      "grant chain exceeds the supported count",
    );
  }
  return Object.freeze(
    value.map((material) => copySignedGrantMaterial(material)),
  );
}

function copyAgentName(value: string): string {
  try {
    return boundedIdentifier(value, "agent name");
  } catch {
    throw new AuthsWorkflowError(
      "invalid-agent-name",
      "agent name is outside the supported identifier bound",
    );
  }
}

function copyProfile(value: Profile): Readonly<{ id: string; version: number }> {
  if (
    value === null ||
    typeof value !== "object" ||
    !Number.isInteger(value.version) ||
    value.version < 1 ||
    value.version > 0xffff
  ) {
    throw new AuthsWorkflowError(
      "invalid-profile",
      "profile is outside the supported version bound",
    );
  }
  try {
    const copied = Object.freeze({
      id: boundedIdentifier(value.id, "profile"),
      version: value.version,
    });
    const runtime = profileRuntimes.get(value as object);
    if (runtime !== undefined) profileRuntimes.set(copied, runtime);
    return copied;
  } catch {
    throw new AuthsWorkflowError(
      "invalid-profile",
      "profile is outside the supported identifier bound",
    );
  }
}

function validateApprovalConfiguration(
  value: ApprovalConfiguration,
  required: ApprovalPolicyReference,
): ApprovalConfiguration {
  if (
    value === null ||
    typeof value !== "object" ||
    !["grant-only", "risk-based", "every-action", "custom"].includes(
      value.mode,
    ) ||
    value.provider === null ||
    typeof value.provider !== "object" ||
    typeof value.provider.approve !== "function"
  ) {
    throw new AuthsWorkflowError(
      "invalid-provider",
      "approval configuration does not implement the Auths approval port",
    );
  }
  const policy = copyPolicy(value.policy);
  if (!policiesEqual(policy, required)) {
    throw new AuthsWorkflowError(
      "approval-policy-mismatch",
      "attach approval policy does not match trusted authority",
    );
  }
  return Object.freeze({
    mode: value.mode,
    policy,
    provider: value.provider,
  });
}

export function authoritySummary(
  value: WorkflowSignedGrantAuthority,
  binding: "root" | "delegated" = "root",
): EffectiveAuthoritySummary {
  if (
    value.permissionCapabilities.length !== value.permissionResources.length ||
    !["any-body", "exact-body", "allowed-bodies"].includes(
      value.actionConstraint,
    ) ||
    !["expiry-only", "snapshot-required"].includes(value.statusPolicy)
  ) {
    throw new AuthsWorkflowError(
      "invalid-authority",
      "native authority projection violated the workflow ABI",
    );
  }
  const permissions = value.permissionCapabilities.map((capability, index) =>
    Object.freeze({
      capability,
      resource: value.permissionResources[index]!,
    }),
  );
  return Object.freeze({
    grantId: value.grantId.slice(),
    issuer: value.issuer,
    subject: value.subject,
    profile: Object.freeze({
      id: value.profileId,
      version: value.profileVersion,
    }),
    permissions: Object.freeze(permissions),
    validity: Object.freeze({
      notBefore: value.notBefore,
      expiresAt: value.expiresAt,
    }),
    audiences: Object.freeze(Array.from(value.audiences)),
    actionConstraint: Object.freeze({
      kind: value.actionConstraint as
        | "any-body"
        | "exact-body"
        | "allowed-bodies",
      digestCount: value.actionDigestCount,
    }),
    budget: value.hasBudget
      ? Object.freeze({
          algebra: value.budgetAlgebra,
          value: value.budgetValue,
        })
      : undefined,
    remainingDepth: value.remainingDepth,
    status: Object.freeze({
      policy: value.statusPolicy as "expiry-only" | "snapshot-required",
      method:
        value.statusPolicy === "snapshot-required"
          ? value.statusMethod
          : undefined,
      maxAge:
        value.statusPolicy === "snapshot-required"
          ? value.statusMaxAge
          : undefined,
    }),
    assuranceFloor: value.assuranceFloor,
    criticalExtensions: Object.freeze(Array.from(value.criticalExtensions)),
    signature: Object.freeze({
      principalMethod: value.signaturePrincipalMethod,
      verificationMethod: value.signatureVerificationMethod,
      suite: value.signatureSuite,
    }),
    explanation: Object.freeze({
      stage: "attach",
      code:
        binding === "root"
          ? "root-authority-structurally-bound"
          : "delegated-authority-structurally-bound",
      verification: "pending-authorization",
      message:
        binding === "root"
          ? "Canonical root authority is bound; cryptographic and live checks remain pending authorization."
          : "Canonical delegated authority is bound; cryptographic and live checks remain pending authorization.",
    }),
  });
}

function copyDelegationReview(value: DelegationReview): DelegationReview {
  return Object.freeze({
    diff: Object.freeze({ ...value.diff }),
    warnings: Object.freeze(Array.from(value.warnings)),
  });
}

function copyEffectiveAuthority(
  value: EffectiveAuthoritySummary,
): EffectiveAuthoritySummary {
  return Object.freeze({
    ...value,
    grantId: value.grantId.slice(),
    profile: Object.freeze({ ...value.profile }),
    permissions: Object.freeze(
      value.permissions.map((permission) => Object.freeze({ ...permission })),
    ),
    validity: Object.freeze({ ...value.validity }),
    audiences: Object.freeze(Array.from(value.audiences)),
    actionConstraint: Object.freeze({ ...value.actionConstraint }),
    budget:
      value.budget === undefined
        ? undefined
        : Object.freeze({ ...value.budget }),
    status: Object.freeze({ ...value.status }),
    criticalExtensions: Object.freeze(Array.from(value.criticalExtensions)),
    signature: Object.freeze({ ...value.signature }),
    explanation: Object.freeze({ ...value.explanation }),
  });
}

function validateSignerShape(signer: Signer): void {
  if (
    signer === null ||
    typeof signer !== "object" ||
    typeof signer.publicIdentity !== "function" ||
    typeof signer.sign !== "function" ||
    !["durable", "ephemeral"].includes(signer.lifecycle)
  ) {
    throw new AuthsWorkflowError(
      "invalid-provider",
      "signer does not implement the Auths signer port",
    );
  }
  boundedIdentifier(signer.kind, "signer kind");
}

async function cleanupAfterFailedLoad(signer: Signer): Promise<void> {
  if (signer.dispose === undefined) return;
  try {
    await signer.dispose();
  } catch {
    // Preserve the fail-closed construction error and do not expose provider data.
  }
}

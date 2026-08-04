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
  readonly evidence?: readonly Uint8Array[];
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
  loadSignedGrant(request: SignedGrantLoadRequest): Promise<Uint8Array>;
}

export interface SignedGrantSourceOptions {
  readonly sourceId: string;
  readonly provider: SignedGrantProvider;
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
    code: "root-authority-structurally-bound";
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

export type WorkflowErrorCode =
  | "disposed"
  | "invalid-provider"
  | "invalid-principal"
  | "invalid-agent-name"
  | "invalid-profile"
  | "invalid-authority-source"
  | "authority-source-failed"
  | "invalid-authority"
  | "authority-mismatch"
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

export interface WorkflowSignedGrantAuthority {
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
    });
  }

  static create(
    token: typeof CLIENT_TOKEN,
    identity: AgentIdentity,
    trustedAuthority: TrustedAuthoritySnapshot,
    signer: Signer,
    engine: WorkflowWasmEngine,
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
    );
  }

  get disposed(): boolean {
    return this.#disposed;
  }

  get identity(): AgentIdentity {
    return this.#identity;
  }

  get trustedAuthority(): TrustedAuthoritySnapshot {
    return copyTrustedAuthority(this.#trustedAuthority);
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
    clientResources.delete(this);
    if (resources?.signer.dispose !== undefined) {
      try {
        await resources.signer.dispose();
      } catch {
        throw new AuthsWorkflowError(
          "signer-failed",
          "signer provider cleanup failed",
        );
      }
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

interface AttachedAgentResources {
  readonly client: AuthsClient;
  readonly approval: ApprovalConfiguration;
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
    });
  }

  static create<P extends Profile>(
    token: typeof ATTACHED_AGENT_TOKEN,
    client: AuthsClient,
    name: string,
    identity: AgentIdentity,
    profile: P,
    authority: EffectiveAuthoritySummary,
    approval: ApprovalConfiguration,
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
    attachedAgentResources.delete(this as AttachedAgent<Profile>);
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
  let loadedGrant: Uint8Array;
  try {
    loadedGrant = await sourceResources.provider.loadSignedGrant(request);
  } catch {
    throw new AuthsWorkflowError(
      "authority-source-failed",
      "signed-grant provider operation failed",
    );
  }
  if (!(loadedGrant instanceof Uint8Array)) {
    throw new AuthsWorkflowError(
      "invalid-authority",
      "signed-grant provider returned an invalid value",
    );
  }
  const signedGrant = loadedGrant.slice();

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
    requiredApproval: copyPolicy(value.requiredApproval),
  });
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
    return Object.freeze({
      id: boundedIdentifier(value.id, "profile"),
      version: value.version,
    });
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

function authoritySummary(
  value: WorkflowSignedGrantAuthority,
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
      code: "root-authority-structurally-bound",
      verification: "pending-authorization",
      message:
        "Canonical root authority is bound; cryptographic and live checks remain pending authorization.",
    }),
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

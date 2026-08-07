import type {
  AuthorizedResult,
  DeniedResult,
  IndeterminateResult,
  VerificationResult,
} from "../../verifier/client.js";
import {
  actionsForPlan,
  createVerifiedPlanCommand,
  memberCommitmentsForPlan,
  type ProfilePlan,
  type VerifiedPlanCommand,
} from "../../plans.js";
import { BoundedApprovalSession } from "../../approvals.js";
export {
  AuthsWorkflowError,
  ProviderOperationError,
  type ProviderFailureKind,
  type WorkflowErrorCode,
} from "../errors.js";
import { AuthsWorkflowError, ProviderOperationError } from "../errors.js";

const MAX_IDENTIFIER_BYTES = 128;
const DIGEST_BYTES = 32;

export * from "../contracts.js";
import type {
  SignerLifecycle,
  SigningObjectKind,
  ApprovalMode,
  PrincipalDescriptor,
  ReviewField,
  SigningRequest,
  SigningResponse,
  ControlEvidence,
  Signer,
  ApprovalPolicyReference,
  ApprovalPolicy,
  ApprovalRequest,
  ApprovalResponse,
  ApprovalProvider,
  ApprovalConfiguration,
  TrustedAuthority,
  AgentIdentity,
  TrustedAuthoritySnapshot,
  Profile,
  ApprovalExecutionSummary,
  WorkflowVerificationResult,
  AuthorizedCommandResult,
  AuthorizationResult,
  PlanAuthorizationResult,
  SignedGrantLoadRequest,
  SignedGrantProvider,
  SignedGrantMaterial,
  SignedGrantSourceOptions,
  TrustedContextLoadRequest,
  TrustedContextProvider,
  TrustedContextSourceOptions,
  PermissionSummary,
  EffectiveAuthoritySummary,
  AttachAgentOptions,
  DelegatedActionConstraint,
  DelegatedBudget,
  DelegatedStatus,
  DelegatedAuthorityRequest,
  DelegationOptions,
  OverGrantingWarning,
  AuthorityDiffSummary,
  DelegationReview,
  WorkflowWasmEngine,
  WorkflowMcpActionPreparation,
  WorkflowActionPreparation,
  WorkflowProfileActionPreparation,
  WorkflowRawKeyAuthorityPreparation,
  WorkflowAuthorizationArtifacts,
  WorkflowProofBuilder,
  WorkflowSignedGrantAuthority,
  WorkflowGrantPlan,
  WorkflowNativeSigningRequest,
} from "../contracts.js";
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
let mintAuthsClient: (
  identity: AgentIdentity,
  trustedAuthority: TrustedAuthoritySnapshot,
  signer: Signer,
  engine: WorkflowWasmEngine,
  trustedContext: Uint8Array,
) => AuthsClient;

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

  private static create(
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

  static {
    mintAuthsClient = (identity, trustedAuthority, signer, engine, trustedContext) =>
      AuthsClient.create(
        CLIENT_TOKEN,
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

import {
  SignedGrantSource,
  signedGrantProviderFor,
  signedGrantSource,
} from "../authority-source.js";
import {
  TrustedContextSource,
  trustedContextProviderFor,
  trustedContextSource,
} from "../trusted-context.js";
export { SignedGrantSource, signedGrantSource } from "../authority-source.js";
export { TrustedContextSource, trustedContextSource } from "../trusted-context.js";
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

import {
  bindProfileRuntimeCopy,
  profileRuntimeFor,
  registerProfileRuntime,
} from "./profile-runtime.js";
export { registerProfileRuntime } from "./profile-runtime.js";

const attachedAgentResources = new WeakMap<
  AttachedAgent<Profile>,
  AttachedAgentResources
>();
const ATTACHED_AGENT_TOKEN: unique symbol = Symbol("auths-attached-agent");
interface MintAttachedAgentOptions<P extends Profile> {
  readonly client: AuthsClient;
  readonly name: string;
  readonly identity: AgentIdentity;
  readonly profile: P;
  readonly authority: EffectiveAuthoritySummary;
  readonly approval: ApprovalConfiguration;
  readonly signer: Signer;
  readonly ownsSigner: boolean;
  readonly signedGrant: Uint8Array;
  readonly grantChain: readonly GrantControlMaterial[];
  readonly grantStatement: Uint8Array;
  readonly review: DelegationReview | undefined;
}
let mintAttachedAgent: <P extends Profile>(
  options: MintAttachedAgentOptions<P>,
) => AttachedAgent<P>;

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

  private static create<P extends Profile>(
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

  static {
    mintAttachedAgent = (options) => AttachedAgent.create(
      ATTACHED_AGENT_TOKEN,
      options.client,
      options.name,
      options.identity,
      options.profile,
      options.authority,
      options.approval,
      options.signer,
      options.ownsSigner,
      options.signedGrant,
      options.grantChain,
      options.grantStatement,
      options.review,
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
      "../../internal/delegation.js"
    );
    return delegateAttachedAgent(this, options);
  }

  async authorize(
    action: P["__action"],
  ): Promise<AuthorizationResult<NonNullable<P["__command"]>>> {
    this.assertActive();
    const runtime = profileRuntimeFor(this.#profile);
    if (runtime === undefined) {
      throw new AuthsWorkflowError(
        "invalid-profile",
        "attached profile does not provide a package-owned authorization runtime",
      );
    }
    return runtime.authorize(
      this as AttachedAgent<Profile>,
      action,
    ) as Promise<AuthorizationResult<NonNullable<P["__command"]>>>;
  }

  async authorizePlan(
    plan: ProfilePlan<NonNullable<P["__action"]>>,
    options: Readonly<{ approvalProvider?: ApprovalProvider }> = {},
  ): Promise<PlanAuthorizationResult<NonNullable<P["__command"]>>> {
    this.assertActive();
    const actions = actionsForPlan(plan, this.#profile);
    const memberCommitments = memberCommitmentsForPlan(plan, this.#profile);
    const resources = resourcesForAttachedAgent(this);
    const startedAt = BigInt(Math.floor(Date.now() / 1000));
    const expiresAt = startedAt + BigInt(resources.approval.policy.expiresInSeconds);
    // What one approval covered is committed by auths-author, not framed here.
    const approvedPlan = engineForClient(resources.client).commitPlanApprovalV1(
      plan.commitment,
      resources.approval.policy.reference.configurationDigest,
      resources.approval.policy.maxUses,
      expiresAt,
    );
    const session = new BoundedApprovalSession({
      planCommitment: approvedPlan.slice(),
      memberCommitments,
      policy: resources.approval.policy,
      provider: options.approvalProvider ?? resources.approval.provider,
      startedAt,
      display: Object.freeze([
        Object.freeze({ label: "Profile", value: `${this.#profile.id}/${this.#profile.version}` }),
        Object.freeze({ label: "Actions", value: String(actions.length) }),
      ]),
    });
    const results: AuthorizationResult<NonNullable<P["__command"]>>[] = [];
    try {
      const runtime = profileRuntimeFor(this.#profile);
      if (runtime === undefined) {
        throw new AuthsWorkflowError("invalid-profile", "attached profile runtime is missing");
      }
      for (let index = 0; index < actions.length; index += 1) {
        const memberCommitment = memberCommitments[index];
        if (memberCommitment === undefined) {
          throw new AuthsWorkflowError("invalid-profile", "plan member commitment is missing");
        }
        const memberApproval: ApprovalConfiguration = Object.freeze({
          policy: resources.approval.policy,
          provider: session.providerFor(index, memberCommitment),
        });
        const result = await runtime.authorize(
          this as AttachedAgent<Profile>,
          actions[index],
          memberApproval,
        ) as AuthorizationResult<NonNullable<P["__command"]>>;
        results.push(result);
        if (result.kind !== "authorized") {
          return Object.freeze({
            kind: result.kind,
            failedIndex: index,
            result,
            results: Object.freeze(results.map(stripPlanCommand)),
          });
        }
      }
      const authorized = results as AuthorizedCommandResult<NonNullable<P["__command"]>>[];
      return Object.freeze({
        kind: "authorized" as const,
        command: createVerifiedPlanCommand(
          authorized.map((result) => result.command),
          plan.commitment,
        ),
        results: Object.freeze([...authorized]),
      });
    } finally {
      await session.dispose();
    }
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

function stripPlanCommand<Command>(
  result: AuthorizationResult<Command>,
): VerificationResult {
  if (result.kind !== "authorized") return result;
  const { command: _command, ...verification } = result;
  return Object.freeze(verification);
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
    const contextProvider =
      source instanceof TrustedContextSource
        ? trustedContextProviderFor(source)
        : undefined;
    if (contextProvider === undefined) {
      throw new AuthsWorkflowError(
        "invalid-trusted-context",
        "trusted authority must use a package-created context source",
      );
    }
    let loadedContext: Uint8Array;
    try {
      loadedContext = await contextProvider.loadTrustedContext({
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
    return mintAuthsClient(
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
  const grantProvider =
    source instanceof SignedGrantSource
      ? signedGrantProviderFor(source)
      : undefined;
  if (grantProvider === undefined) {
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
    loadedMaterial = await grantProvider.loadSignedGrant(request);
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
    return mintAttachedAgent({
      client,
      name,
      identity,
      profile,
      authority: authoritySummary(validated),
      approval,
      signer: signerForClient(client),
      ownsSigner: false,
      signedGrant,
      grantChain: [material],
      grantStatement: validated.statementCbor,
      review: undefined,
    });
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
  return mintAttachedAgent({
    client: parentResources.client,
    name: options.name,
    identity: options.identity,
    profile: options.profile,
    authority: options.authority,
    approval: parentResources.approval,
    signer: options.signer,
    ownsSigner: true,
    signedGrant: options.signedGrant,
    grantChain: [
      ...parentResources.grantChain,
      { signedGrant: options.signedGrant, evidence: options.evidence },
    ],
    grantStatement: options.grantStatement,
    review: options.review,
  });
}

import {
  boundedBytes,
  boundedIdentifier,
  bytesEqual,
  copyAgentName,
  copyApprovalPolicy,
  copyExactBytes,
  copyGrantChain,
  copyPolicy,
  copyPrincipal,
  copySignedGrantMaterial,
  copyTrustedAuthority,
  copyTrustedAuthoritySnapshot,
  policiesEqual,
} from "./copying.js";
export {
  boundedBytes,
  boundedIdentifier,
  bytesEqual,
  copyApprovalPolicy,
  copyExactBytes,
  copyPolicy,
  copyPrincipal,
  policiesEqual,
} from "./copying.js";
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
    bindProfileRuntimeCopy(value, copied);
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
    value.provider === null ||
    typeof value.provider !== "object" ||
    typeof value.provider.approve !== "function"
  ) {
    throw new AuthsWorkflowError(
      "invalid-provider",
      "approval configuration does not implement the Auths approval port",
    );
  }
  const policy = copyApprovalPolicy(value.policy);
  if (!policiesEqual(policy.reference, required)) {
    throw new AuthsWorkflowError(
      "approval-policy-mismatch",
      "attach approval policy does not match trusted authority",
    );
  }
  return Object.freeze({
    policy,
    provider: value.provider,
  });
}

import {
  authoritySummary,
  copyDelegationReview,
  copyEffectiveAuthority,
} from "./authority.js";
export { authoritySummary } from "./authority.js";
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

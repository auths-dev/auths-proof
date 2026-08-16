import { authorizePreparedAction } from "../../internal/authorization.js";
import {
  commandsForGateway,
  createProfilePlan,
  type ProfilePlan,
  type VerifiedPlanCommand,
} from "../../plans.js";
import { loadPackagedWorkflowEngine } from "../../verifier/wasm.js";
import {
  AuthsWorkflowError,
  ProviderOperationError,
  type AuthorizationResult,
  type ApprovalConfiguration,
  type AttachedAgent,
  type Profile,
  type ReviewField,
  type WorkflowErrorCode,
  engineForClient,
  registerProfileRuntime,
  resourcesForAttachedAgent,
} from "../../workflow.js";

const PROFILE_TOKEN: unique symbol = Symbol("auths-application-profile");
const ACTION_TOKEN: unique symbol = Symbol("auths-application-action");
const COMMAND_TOKEN: unique symbol = Symbol("auths-application-command");

let mintApplicationCommand: <Command>(
  profile: object,
  command: Command,
  receiptBindings: ApplicationReceiptBindings,
  receiptArtifacts: ApplicationReceiptArtifacts,
) => ApplicationCommand<Command>;
let mintApplicationAction: <Input>(
  profile: object,
  canonical: CanonicalProfileAction,
) => ApplicationAction<Input>;
let mintApplicationProfile: <Input, Command>(
  definition: ProfileDefinition<Input, Command>,
) => ApplicationProfile<Input, Command>;
let mintVerifiedApplicationCommand: <Command>(
  profile: object,
  canonical: CanonicalProfileAction,
  receiptBindings: ApplicationReceiptBindings,
  receiptArtifacts: ApplicationReceiptArtifacts,
) => ApplicationCommand<Command>;

export interface ProfilePermission {
  readonly capability: string;
  readonly resource: string;
}

export interface ProfileBudget {
  readonly algebra: string;
  readonly value: bigint;
}

export interface CanonicalProfileAction {
  readonly mediaType: string;
  readonly body: Uint8Array;
  readonly permission: ProfilePermission;
  readonly resourceNamespace: string;
  readonly budget?: ProfileBudget;
  readonly audience: string;
  readonly display: readonly ReviewField[];
}

export interface ProfileAuthorityRequirement {
  readonly permission: ProfilePermission;
  readonly resourceNamespace: string;
  readonly audience: string;
  readonly budget?: ProfileBudget;
}

export interface ProfileDefinition<Input, Command = CanonicalProfileAction> {
  readonly id: string;
  readonly version: number;
  canonicalize(input: Input): CanonicalProfileAction;
  decodeVerified?(canonical: CanonicalProfileAction): Command;
}

interface ActionResources {
  readonly profile: object;
  readonly canonical: CanonicalProfileAction;
}

interface ApplicationProfileRuntime {
  readonly id: string;
  readonly version: number;
}

const actionResources = new WeakMap<object, ActionResources>();
const commandResources = new WeakMap<object, {
  readonly profile: object;
  readonly command: unknown;
  readonly receiptBindings: ApplicationReceiptBindings;
  readonly receiptArtifacts: ApplicationReceiptArtifacts;
}>();
const profileDecoders = new WeakMap<
  object,
  (canonical: CanonicalProfileAction) => unknown
>();

/** A verified application-profile command that cannot be constructed or serialized. */
export class ApplicationCommand<Command> {
  declare private readonly __commandType: (command: Command) => Command;

  private constructor(
    token: typeof COMMAND_TOKEN,
    profile: object,
    command: Command,
    receiptBindings: ApplicationReceiptBindings,
    receiptArtifacts: ApplicationReceiptArtifacts,
  ) {
    if (token !== COMMAND_TOKEN) throw new TypeError("sealed Auths application command");
    commandResources.set(this, {
      profile,
      command,
      receiptBindings: copyReceiptBindings(receiptBindings),
      receiptArtifacts: copyReceiptArtifacts(receiptArtifacts),
    });
    Object.freeze(this);
  }

  private static create<Command>(
    token: typeof COMMAND_TOKEN,
    profile: object,
    command: Command,
    receiptBindings: ApplicationReceiptBindings,
    receiptArtifacts: ApplicationReceiptArtifacts,
  ): ApplicationCommand<Command> {
    return new ApplicationCommand(token, profile, command, receiptBindings, receiptArtifacts);
  }

  static {
    mintApplicationCommand = (profile, command, receiptBindings, receiptArtifacts) =>
      ApplicationCommand.create(
        COMMAND_TOKEN,
        profile,
        command,
        receiptBindings,
        receiptArtifacts,
      );
  }

  toJSON(): never {
    throw new TypeError("verified Auths commands are not serializable");
  }
}

export type ApplicationExecutionState = "committed" | "released" | "outcome-unknown";
export type ApplicationOutcome = "succeeded" | "failed" | "cancelled" | "outcome-unknown";

export interface ApplicationExecutionContext {
  readonly idempotencyKey: string;
  readonly canonicalCommand: Uint8Array;
  readonly planCommitment?: Uint8Array;
  readonly memberIndex?: number;
  readonly memberCount?: number;
  readonly signal?: AbortSignal;
}

export interface ApplicationReceipt {
  readonly idempotencyKey: string;
  readonly commandCommitment: Uint8Array;
  readonly authorityCommitment: Uint8Array;
  readonly contextCommitment: Uint8Array;
  readonly planCommitment?: Uint8Array;
  readonly stateClaim: ApplicationExecutionState;
  readonly outcome: ApplicationOutcome;
  readonly observedAt: number;
  readonly decisionReceipt: AttestedApplicationReceipt;
  readonly executionReceipt?: AttestedApplicationReceipt;
}

export interface ApplicationReceiptSigner {
  readonly principal: string;
  readonly verificationMethod: string;
  readonly suite: string;
  readonly evidence: Uint8Array;
}

export interface ApplicationReceiptAttestor {
  readonly signer: ApplicationReceiptSigner;
  sign(preimage: Uint8Array): Promise<Uint8Array>;
}

export interface AttestedApplicationReceipt {
  readonly kind: "decision" | "execution";
  readonly receiptId: Uint8Array;
  readonly bytes: Uint8Array;
  readonly signer: ApplicationReceiptSigner;
}

export interface ApplicationExecution<Result> {
  readonly output: Result;
  readonly receipt: ApplicationReceipt;
}

export interface ApplicationPlanExecution<Result> {
  readonly outputs: readonly Result[];
  readonly receipts: readonly ApplicationReceipt[];
}

export interface ApplicationReservation {
  readonly idempotencyKey: string;
  readonly commandCommitment: Uint8Array;
  readonly authorityCommitment: Uint8Array;
  readonly contextCommitment: Uint8Array;
  readonly planCommitment?: Uint8Array;
  readonly memberIndex?: number;
  readonly memberCount?: number;
  readonly observedAt: number;
}

export interface ApplicationExecutionStore {
  reserve(
    reservation: ApplicationReservation,
  ): Promise<"reserved" | "exact-replay" | "conflict" | "expired" | "out-of-order" | "unavailable">;
  authorizeCredential(idempotencyKey: string): Promise<"authorized" | "conflict" | "unavailable">;
  enterProvider(idempotencyKey: string): Promise<"entered" | "conflict" | "unavailable">;
  finish(
    idempotencyKey: string,
    outcome: ApplicationOutcome,
    decisionReceipt: AttestedApplicationReceipt,
    executionReceipt?: AttestedApplicationReceipt,
  ): Promise<"stored" | "conflict" | "unavailable">;
}

export interface ApplicationCredentialProvider<Command, Credential> {
  acquire(command: Command, context: ApplicationExecutionContext): Promise<Credential>;
}

export interface ApplicationGatewayOptions<Command, Credential, Result> {
  readonly state: ApplicationExecutionStore;
  readonly credentials: ApplicationCredentialProvider<Command, Credential>;
  readonly receipts: ApplicationReceiptAttestor;
  canonicalizeResult(result: Result): Uint8Array;
  execute(
    command: Command,
    credential: Credential,
    context: ApplicationExecutionContext,
  ): Promise<Result>;
}

export class ApplicationGatewayError extends AuthsWorkflowError {
  readonly receipt: ApplicationReceipt;
  readonly completedReceipts: readonly ApplicationReceipt[];

  constructor(receipt: ApplicationReceipt, completedReceipts: readonly ApplicationReceipt[] = []) {
    const unknown = receipt.outcome === "outcome-unknown";
    super("gateway-failed", unknown
      ? "application gateway execution outcome is unknown"
      : "application gateway execution failed without an effect", {
      operation: "execute",
      stage: "provider",
      retry: unknown ? "unknown" : "safe",
      effect: unknown ? "possible" : "not-applied",
      remediation: { action: unknown ? "reconcile-idempotency-key" : "inspect-provider-failure" },
    });
    this.receipt = receipt;
    this.completedReceipts = Object.freeze([...completedReceipts]);
  }
}

export class ApplicationGatewayCancelled extends AuthsWorkflowError {
  readonly receipt: ApplicationReceipt;
  readonly completedReceipts: readonly ApplicationReceipt[];

  constructor(receipt: ApplicationReceipt, completedReceipts: readonly ApplicationReceipt[] = []) {
    const enteredProvider = receipt.outcome === "outcome-unknown";
    super("gateway-cancelled", enteredProvider
      ? "application gateway task was cancelled after provider entry"
      : "application gateway task was cancelled before provider entry", {
      operation: "execute",
      stage: enteredProvider ? "provider" : "credential",
      retry: enteredProvider ? "unknown" : "safe",
      effect: enteredProvider ? "possible" : "not-applied",
      remediation: { action: enteredProvider ? "reconcile-idempotency-key" : "retry-with-new-command" },
    });
    this.receipt = receipt;
    this.completedReceipts = Object.freeze([...completedReceipts]);
  }
}

export interface ApplicationGateway<Command, Result> {
  parse(command: ApplicationCommand<Command>): ApplicationCommand<Command>;
  execute(
    command: ApplicationCommand<Command>,
    context: Readonly<{ idempotencyKey: string; signal?: AbortSignal }>,
  ): Promise<ApplicationExecution<Result>>;
  executePlan(
    command: VerifiedPlanCommand<ApplicationCommand<Command>>,
    context: Readonly<{ idempotencyKey: string; signal?: AbortSignal }>,
  ): Promise<ApplicationPlanExecution<Result>>;
}

interface ApplicationReceiptBindings {
  readonly commandCommitment: Uint8Array;
  readonly authorityCommitment: Uint8Array;
  readonly contextCommitment: Uint8Array;
}

interface ApplicationReceiptArtifacts {
  readonly proofCbor: Uint8Array;
  readonly canonicalActionCbor: Uint8Array;
  readonly trustedContextCbor: Uint8Array;
  readonly commandBytes: Uint8Array;
}

/** A profile-owned action that cannot be detached from its canonicalizer. */
export class ApplicationAction<Input> {
  declare private readonly __inputType: (input: Input) => Input;

  private constructor(
    token: typeof ACTION_TOKEN,
    profile: object,
    canonical: CanonicalProfileAction,
  ) {
    if (token !== ACTION_TOKEN) throw new TypeError("sealed Auths profile action");
    actionResources.set(this, {
      profile,
      canonical: copyCanonical(canonical),
    });
    Object.freeze(this);
  }

  private static create<Input>(
    token: typeof ACTION_TOKEN,
    profile: object,
    canonical: CanonicalProfileAction,
  ): ApplicationAction<Input> {
    if (token !== ACTION_TOKEN) throw new TypeError("sealed Auths profile action");
    return new ApplicationAction(token, profile, canonical);
  }

  static {
    mintApplicationAction = (profile, canonical) =>
      ApplicationAction.create(ACTION_TOKEN, profile, canonical);
  }
}

/** Closed application profile backed by the native Auths protocol authoring path. */
export class ApplicationProfile<Input, Command = CanonicalProfileAction>
  implements Profile<ApplicationAction<Input>, ApplicationCommand<Command>>
{
  readonly id: string;
  readonly version: number;
  declare readonly __action?: ApplicationAction<Input>;
  declare readonly __command?: ApplicationCommand<Command>;
  readonly #canonicalize: (input: Input) => CanonicalProfileAction;

  private constructor(token: typeof PROFILE_TOKEN, definition: ProfileDefinition<Input, Command>) {
    if (token !== PROFILE_TOKEN) throw new TypeError("sealed Auths application profile");
    this.id = boundedText(definition.id, 128, "profile id");
    if (!Number.isSafeInteger(definition.version) || definition.version < 1 || definition.version > 65_535) {
      throw new AuthsWorkflowError("invalid-profile", "profile version is outside bounds");
    }
    if (typeof definition.canonicalize !== "function") {
      throw new AuthsWorkflowError("invalid-profile", "profile canonicalizer is missing");
    }
    this.version = definition.version;
    this.#canonicalize = definition.canonicalize;
    profileDecoders.set(
      this,
      definition.decodeVerified ?? ((canonical) => canonical as Command),
    );
    registerProfileRuntime(this, {
      authorize: (agent, action, approvalOverride) => authorizeApplication(
        agent,
        this,
        action,
        approvalOverride,
      ),
    });
    Object.freeze(this);
  }

  private static create<Input, Command>(
    token: typeof PROFILE_TOKEN,
    definition: ProfileDefinition<Input, Command>,
  ): ApplicationProfile<Input, Command> {
    if (token !== PROFILE_TOKEN) throw new TypeError("sealed Auths application profile");
    return new ApplicationProfile(token, definition);
  }

  static {
    mintApplicationProfile = (definition) =>
      ApplicationProfile.create(PROFILE_TOKEN, definition);
    mintVerifiedApplicationCommand = (
      profile,
      canonical,
      receiptBindings,
      receiptArtifacts,
    ) => createVerifiedCommandFor(profile, canonical, receiptBindings, receiptArtifacts);
  }

  action(input: Input): ApplicationAction<Input> {
    let canonical: CanonicalProfileAction;
    try {
      canonical = this.#canonicalize(input);
    } catch (error) {
      if (error instanceof AuthsWorkflowError) throw error;
      throw new AuthsWorkflowError("invalid-profile", "profile rejected the proposed action");
    }
    return mintApplicationAction(this, copyCanonical(canonical));
  }

  /** Returns profile-derived grant inputs for this exact sealed action. */
  authorityFor(action: ApplicationAction<Input>): ProfileAuthorityRequirement {
    const resources = actionResources.get(action);
    if (resources === undefined || resources.profile !== this) {
      throw new AuthsWorkflowError(
        "invalid-profile",
        "action was not created by this application profile",
      );
    }
    return copyAuthorityRequirement(resources.canonical);
  }

  /** Returns a copied semantic projection for conformance tests and tooling. */
  inspectAction(action: ApplicationAction<Input>): CanonicalProfileAction {
    return this.canonicalFor(action);
  }

  async plan(actions: readonly ApplicationAction<Input>[]): Promise<ProfilePlan<ApplicationAction<Input>>> {
    const canonicals = actions.map((action) => this.canonicalFor(action));
    const authority = validateCompatibleAuthority(canonicals);
    const engine = await loadPackagedWorkflowEngine();
    return createProfilePlan(
      this,
      actions,
      (action) => {
        const canonical = this.canonicalFor(action);
        try {
          return engine.canonicalizeProfilePlanMemberV1(
            this.id,
            this.version,
            canonical.mediaType,
            canonical.body.slice(),
            canonical.permission.capability,
            canonical.permission.resource,
            canonical.budget !== undefined,
            canonical.budget?.algebra ?? "",
            canonical.budget?.value ?? 0n,
            canonical.resourceNamespace,
            canonical.audience,
          );
        } catch {
          throw new AuthsWorkflowError(
            "invalid-profile",
            "native application profile rejected a plan member",
          );
        }
      },
      authority,
    );
  }

  gateway<Credential, Result>(
    options: ApplicationGatewayOptions<Command, Credential, Result>,
  ): ApplicationGateway<Command, Result> {
    if (
      options === null ||
      typeof options !== "object" ||
      typeof options.execute !== "function" ||
      typeof options.canonicalizeResult !== "function" ||
      typeof options.receipts?.sign !== "function" ||
      typeof options.credentials?.acquire !== "function" ||
      typeof options.state?.reserve !== "function" ||
      typeof options.state.authorizeCredential !== "function" ||
      typeof options.state.enterProvider !== "function" ||
      typeof options.state.finish !== "function"
    ) {
      throw new AuthsWorkflowError("invalid-profile", "application gateway ports are incomplete");
    }
    const profile = this;
    return Object.freeze({
      parse(sealed: ApplicationCommand<Command>): ApplicationCommand<Command> {
        const resources = commandResources.get(sealed);
        if (resources === undefined || resources.profile !== profile) {
          throw new AuthsWorkflowError("invalid-profile", "application command is forged or belongs to another profile");
        }
        return sealed;
      },
      async execute(
        sealed: ApplicationCommand<Command>,
        context: Readonly<{ idempotencyKey: string; signal?: AbortSignal }>,
      ): Promise<ApplicationExecution<Result>> {
        const resources = consumeCommand(sealed, profile);
        const executionContext = executionContextFor(context);
        return executeOne(options, resources, executionContext);
      },
      async executePlan(
        sealed: VerifiedPlanCommand<ApplicationCommand<Command>>,
        context: Readonly<{ idempotencyKey: string; signal?: AbortSignal }>,
      ): Promise<ApplicationPlanExecution<Result>> {
        const idempotencyKey = boundedIdempotencyKey(context?.idempotencyKey);
        const commands = commandsForGateway(sealed);
        const resources = commands.map((command) => commandResources.get(command));
        if (resources.some((value) => value === undefined || value.profile !== profile)) {
          throw new AuthsWorkflowError("invalid-profile", "application plan command is forged or belongs to another profile");
        }
        for (const command of commands) commandResources.delete(command);
        const outputs: Result[] = [];
        const receipts: ApplicationReceipt[] = [];
        const planCommitment = sealed.planCommitment;
        for (let index = 0; index < resources.length; index += 1) {
          const executionContext = Object.freeze({
            idempotencyKey: `${idempotencyKey}:${index}`,
            canonicalCommand: new Uint8Array(),
            planCommitment: planCommitment.slice(),
            memberIndex: index,
            memberCount: resources.length,
            ...(context.signal === undefined ? {} : { signal: context.signal }),
          });
          try {
            const execution = await executeOne(
              options,
              resources[index] as NonNullable<(typeof resources)[number]>,
              executionContext,
            );
            outputs.push(execution.output);
            receipts.push(execution.receipt);
          } catch (error) {
            if (error instanceof ApplicationGatewayCancelled || error instanceof ApplicationGatewayError) {
              const Failure = error instanceof ApplicationGatewayCancelled
                ? ApplicationGatewayCancelled
                : ApplicationGatewayError;
              throw new Failure(error.receipt, receipts);
            }
            throw error;
          }
        }
        return Object.freeze({
          outputs: Object.freeze(outputs),
          receipts: Object.freeze(receipts),
        });
      },
    });
  }

  private canonicalFor(action: ApplicationAction<Input>): CanonicalProfileAction {
    const resources = actionResources.get(action);
    if (resources === undefined || resources.profile !== this) {
      throw new AuthsWorkflowError("invalid-profile", "action was not created by this application profile");
    }
    return copyCanonical(resources.canonical);
  }

}

function createVerifiedCommandFor<Command>(
  profile: object,
  canonical: CanonicalProfileAction,
  receiptBindings: ApplicationReceiptBindings,
  receiptArtifacts: ApplicationReceiptArtifacts,
): ApplicationCommand<Command> {
  const decoder = profileDecoders.get(profile);
  if (decoder === undefined) {
    throw new AuthsWorkflowError("invalid-profile", "application profile decoder is unavailable");
  }
  let decoded: Command;
  try {
    decoded = decoder(copyCanonical(canonical)) as Command;
  } catch (error) {
    if (error instanceof AuthsWorkflowError) throw error;
    const detail = error instanceof Error ? error.message : "unknown decoder failure";
    throw new AuthsWorkflowError(
      "invalid-profile",
      `application profile rejected verified command decoding: ${detail}`,
    );
  }
  return mintApplicationCommand(profile, decoded, receiptBindings, receiptArtifacts);
}

/** Defines one application-owned profile without registering a generic executor. */
export function defineProfile<Input, Command = CanonicalProfileAction>(
  definition: ProfileDefinition<Input, Command>,
): ApplicationProfile<Input, Command> {
  if (definition === null || typeof definition !== "object") {
    throw new AuthsWorkflowError("invalid-profile", "profile definition is missing");
  }
  return mintApplicationProfile(definition);
}

async function authorizeApplication(
  agent: AttachedAgent<Profile>,
  profile: ApplicationProfileRuntime,
  candidate: unknown,
  approvalOverride?: ApprovalConfiguration,
): Promise<AuthorizationResult<ApplicationCommand<unknown>>> {
  agent.assertActive();
  const action = candidate instanceof ApplicationAction
    ? actionResources.get(candidate)
    : undefined;
  if (action === undefined || action.profile !== profile) {
    throw new AuthsWorkflowError(
      "invalid-profile",
      "action was not created by the attached application profile",
    );
  }
  const resources = resourcesForAttachedAgent(agent);
  const engine = engineForClient(resources.client);
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const evaluationTime = BigInt(Math.floor(Date.now() / 1000));
  const canonical = action.canonical;
  let receiptBindings: ApplicationReceiptBindings | undefined;
  let receiptArtifacts: ApplicationReceiptArtifacts | undefined;
  let preparation;
  try {
    preparation = engine.prepareProfileActionV1(
      profile.id,
      profile.version,
      canonical.mediaType,
      canonical.body.slice(),
      canonical.permission.capability,
      canonical.permission.resource,
      canonical.budget !== undefined,
      canonical.budget?.algebra ?? "",
      canonical.budget?.value ?? 0n,
      canonical.audience,
      agent.identity.principal.principal,
      resources.signedGrant.slice(),
      challenge,
      evaluationTime,
    );
  } catch {
    throw new AuthsWorkflowError(
      "invalid-profile",
      "native protocol authoring rejected the canonical profile action",
    );
  }
  const result = await authorizePreparedAction(
    agent,
    preparation,
    canonical.display,
    approvalOverride,
    (artifacts) => {
      const bindings = engine.profileReceiptBindingsV1(
        artifacts.proofCbor,
        artifacts.canonicalActionCbor,
        artifacts.trustedContextCbor,
      );
      try {
        receiptBindings = copyReceiptBindings({
          commandCommitment: bindings.actionCommitment,
          authorityCommitment: bindings.authorityCommitment,
          contextCommitment: bindings.contextCommitment,
        });
        receiptArtifacts = copyReceiptArtifacts({
          proofCbor: artifacts.proofCbor,
          canonicalActionCbor: artifacts.canonicalActionCbor,
          trustedContextCbor: artifacts.trustedContextCbor,
          commandBytes: canonical.body,
        });
      } finally {
        bindings.free?.();
      }
    },
  );
  if (result.kind !== "authorized") return result;
  if (receiptBindings === undefined || receiptArtifacts === undefined) {
    throw new AuthsWorkflowError("invalid-profile", "native authorization omitted receipt bindings");
  }
  return Object.freeze({
    ...result,
    command: mintVerifiedApplicationCommand(
      profile,
      canonical,
      receiptBindings,
      receiptArtifacts,
    ),
  });
}

async function executeOne<Command, Credential, Result>(
  options: ApplicationGatewayOptions<Command, Credential, Result>,
  resources: Readonly<{
    command: unknown;
    receiptBindings: ApplicationReceiptBindings;
    receiptArtifacts: ApplicationReceiptArtifacts;
  }>,
  context: ApplicationExecutionContext,
): Promise<ApplicationExecution<Result>> {
  const exactContext = Object.freeze({
    ...context,
    canonicalCommand: resources.receiptArtifacts.commandBytes.slice(),
  });
  const decisionReceipt = await prepareDecisionReceipt(options.receipts, resources.receiptArtifacts);
  const reservation = reservationFor(resources.receiptBindings, exactContext);
  const reserved = await callState(() => options.state.reserve(reservation));
  if (reserved !== "reserved") {
    throw gatewayStateError(reserved);
  }
  if (isAborted(exactContext.signal)) {
    await finish(options.state, exactContext, "cancelled", decisionReceipt);
    throw new ApplicationGatewayCancelled(
      receiptFor(resources.receiptBindings, exactContext, "cancelled", decisionReceipt),
    );
  }
  const credentialAuthorization = await callState(
    () => options.state.authorizeCredential(exactContext.idempotencyKey),
  );
  if (credentialAuthorization !== "authorized") {
    await finish(options.state, exactContext, "failed", decisionReceipt);
    throw gatewayStateError(credentialAuthorization);
  }
  let credential: Credential;
  try {
    credential = await options.credentials.acquire(resources.command as Command, exactContext);
  } catch {
    await finish(options.state, exactContext, "failed", decisionReceipt);
    throw new ApplicationGatewayError(
      receiptFor(resources.receiptBindings, exactContext, "failed", decisionReceipt),
    );
  }
  if (isAborted(exactContext.signal)) {
    await finish(options.state, exactContext, "cancelled", decisionReceipt);
    throw new ApplicationGatewayCancelled(
      receiptFor(resources.receiptBindings, exactContext, "cancelled", decisionReceipt),
    );
  }
  const entered = await callState(() => options.state.enterProvider(exactContext.idempotencyKey));
  if (entered !== "entered") {
    await finish(options.state, exactContext, "failed", decisionReceipt);
    throw gatewayStateError(entered);
  }
  let output: Result;
  try {
    output = await options.execute(resources.command as Command, credential, exactContext);
  } catch (error) {
    const definitelyFailed = error instanceof ProviderOperationError && error.effect === "not-applied";
    const outcome: ApplicationOutcome = definitelyFailed ? "failed" : "outcome-unknown";
    let executionReceipt: AttestedApplicationReceipt | undefined;
    if (definitelyFailed) {
      try {
        executionReceipt = await prepareExecutionReceipt(
          options.receipts,
          decisionReceipt,
          resources.receiptArtifacts.commandBytes,
          exactContext,
          "failed",
        );
      } catch {
        executionReceipt = undefined;
      }
    }
    await finish(options.state, exactContext, outcome, decisionReceipt, executionReceipt);
    const receipt = receiptFor(resources.receiptBindings, exactContext, outcome, decisionReceipt, executionReceipt);
    throw new ApplicationGatewayError(receipt);
  }

  let resultBytes: Uint8Array;
  try {
    resultBytes = options.canonicalizeResult(output).slice();
    if (resultBytes.length === 0) throw new TypeError("empty canonical result");
  } catch {
    await finish(options.state, exactContext, "outcome-unknown", decisionReceipt);
    throw new ApplicationGatewayError(
      receiptFor(resources.receiptBindings, exactContext, "outcome-unknown", decisionReceipt),
    );
  }
  const executionReceipt = await prepareExecutionReceipt(
    options.receipts,
    decisionReceipt,
    resources.receiptArtifacts.commandBytes,
    exactContext,
    "succeeded",
    resultBytes,
  ).catch(async () => {
    await finish(options.state, exactContext, "outcome-unknown", decisionReceipt);
    throw new ApplicationGatewayError(
      receiptFor(resources.receiptBindings, exactContext, "outcome-unknown", decisionReceipt),
    );
  });
  const completed = receiptFor(
    resources.receiptBindings,
    exactContext,
    "succeeded",
    decisionReceipt,
    executionReceipt,
  );
  if (await finish(options.state, exactContext, "succeeded", decisionReceipt, executionReceipt) !== "stored") {
    throw new ApplicationGatewayError(
      receiptFor(
        resources.receiptBindings,
        exactContext,
        "outcome-unknown",
        decisionReceipt,
        executionReceipt,
      ),
    );
  }
  return Object.freeze({ output, receipt: completed });
}

function reservationFor(
  binding: ApplicationReceiptBindings,
  context: ApplicationExecutionContext,
): ApplicationReservation {
  return Object.freeze({
    idempotencyKey: context.idempotencyKey,
    commandCommitment: binding.commandCommitment.slice(),
    authorityCommitment: binding.authorityCommitment.slice(),
    contextCommitment: binding.contextCommitment.slice(),
    ...(context.planCommitment === undefined
      ? {}
      : { planCommitment: context.planCommitment.slice() }),
    ...(context.memberIndex === undefined ? {} : { memberIndex: context.memberIndex }),
    ...(context.memberCount === undefined ? {} : { memberCount: context.memberCount }),
    observedAt: Math.floor(Date.now() / 1000),
  });
}

async function callState<Result>(operation: () => Promise<Result>): Promise<Result | "unavailable"> {
  try {
    return await operation();
  } catch {
    return "unavailable";
  }
}

function gatewayStateError(code: string): AuthsWorkflowError {
  const normalized = ["exact-replay", "conflict", "expired", "out-of-order", "unavailable"].includes(code)
    ? code
    : "unavailable";
  return new AuthsWorkflowError("gateway-" + normalized as WorkflowErrorCode, "application gateway state rejected execution", {
    operation: "execute",
    stage: "reservation",
    retry: normalized === "unavailable" ? "safe" : "never",
    effect: "not-applied",
  });
}

function consumeCommand<Command>(
  sealed: ApplicationCommand<Command>,
  profile: object,
): Readonly<{
  command: unknown;
  receiptBindings: ApplicationReceiptBindings;
  receiptArtifacts: ApplicationReceiptArtifacts;
}> {
  const resources = commandResources.get(sealed);
  if (resources === undefined || resources.profile !== profile) {
    throw new AuthsWorkflowError("invalid-profile", "application command is forged, consumed, or belongs to another profile");
  }
  commandResources.delete(sealed);
  return resources;
}

function executionContextFor(
  context: Readonly<{ idempotencyKey: string; signal?: AbortSignal }>,
): ApplicationExecutionContext {
  return Object.freeze({
    idempotencyKey: boundedIdempotencyKey(context?.idempotencyKey),
    canonicalCommand: new Uint8Array(),
    ...(context?.signal === undefined ? {} : { signal: context.signal }),
  });
}

function receiptFor(
  binding: ApplicationReceiptBindings,
  context: ApplicationExecutionContext,
  outcome: ApplicationOutcome,
  decisionReceipt: AttestedApplicationReceipt,
  executionReceipt?: AttestedApplicationReceipt,
): ApplicationReceipt {
  return Object.freeze({
    idempotencyKey: context.idempotencyKey,
    commandCommitment: binding.commandCommitment.slice(),
    authorityCommitment: binding.authorityCommitment.slice(),
    contextCommitment: binding.contextCommitment.slice(),
    ...(context.planCommitment === undefined
      ? {}
      : { planCommitment: context.planCommitment.slice() }),
    stateClaim: outcome === "succeeded"
      ? "committed"
      : outcome === "outcome-unknown"
        ? "outcome-unknown"
        : "released",
    outcome,
    observedAt: Math.floor(Date.now() / 1000),
    decisionReceipt: copyAttestedReceipt(decisionReceipt),
    ...(executionReceipt === undefined
      ? {}
      : { executionReceipt: copyAttestedReceipt(executionReceipt) }),
  });
}

async function prepareDecisionReceipt(
  attestor: ApplicationReceiptAttestor,
  artifacts: ApplicationReceiptArtifacts,
): Promise<AttestedApplicationReceipt> {
  const engine = await loadPackagedWorkflowEngine();
  const signer = copyReceiptSigner(attestor.signer);
  const preparation = engine.prepareAuthorizedDecisionReceiptV1(
    artifacts.proofCbor.slice(),
    artifacts.canonicalActionCbor.slice(),
    artifacts.trustedContextCbor.slice(),
    BigInt(Math.floor(Date.now() / 1000)),
    signer.principal,
    signer.verificationMethod,
    signer.suite,
  );
  try {
    const signature = await attestor.sign(preparation.signingPreimage.slice());
    const bytes = engine.attestDecisionReceiptV1(
      preparation.canonical.slice(),
      signer.principal,
      signer.verificationMethod,
      signer.suite,
      signature.slice(),
    );
    return copyAttestedReceipt({
      kind: "decision",
      receiptId: preparation.receiptId,
      bytes,
      signer,
    });
  } finally {
    preparation.free?.();
  }
}

async function prepareExecutionReceipt(
  attestor: ApplicationReceiptAttestor,
  decisionReceipt: AttestedApplicationReceipt,
  commandBytes: Uint8Array,
  context: ApplicationExecutionContext,
  outcome: "succeeded" | "failed",
  result?: Uint8Array,
): Promise<AttestedApplicationReceipt> {
  const engine = await loadPackagedWorkflowEngine();
  const signer = copyReceiptSigner(attestor.signer);
  const preparation = engine.prepareApplicationExecutionReceiptV1(
    decisionReceipt.receiptId.slice(),
    context.idempotencyKey,
    context.planCommitment !== undefined,
    context.planCommitment?.slice() ?? new Uint8Array(),
    context.memberIndex ?? 0,
    context.memberCount ?? 0,
    commandBytes.slice(),
    outcome,
    result !== undefined,
    result?.slice() ?? new Uint8Array(),
    BigInt(Math.floor(Date.now() / 1000)),
    signer.principal,
    signer.verificationMethod,
    signer.suite,
  );
  try {
    const signature = await attestor.sign(preparation.signingPreimage.slice());
    const bytes = engine.attestExecutionReceiptV1(
      preparation.canonical.slice(),
      signer.principal,
      signer.verificationMethod,
      signer.suite,
      signature.slice(),
    );
    return copyAttestedReceipt({
      kind: "execution",
      receiptId: preparation.receiptId,
      bytes,
      signer,
    });
  } finally {
    preparation.free?.();
  }
}

async function finish(
  state: ApplicationExecutionStore,
  context: ApplicationExecutionContext,
  outcome: ApplicationOutcome,
  decisionReceipt: AttestedApplicationReceipt,
  executionReceipt?: AttestedApplicationReceipt,
): Promise<"stored" | "conflict" | "unavailable"> {
  return callState(() => state.finish(
    context.idempotencyKey,
    outcome,
    copyAttestedReceipt(decisionReceipt),
    executionReceipt === undefined ? undefined : copyAttestedReceipt(executionReceipt),
  ));
}

/** Verifies a native Auths receipt against its embedded raw-key signer descriptor. */
export async function verifyApplicationReceipt(receipt: AttestedApplicationReceipt): Promise<void> {
  const value = copyAttestedReceipt(receipt);
  const engine = await loadPackagedWorkflowEngine();
  engine.verifyRawKeyReceiptV1(
    value.kind,
    value.bytes,
    value.receiptId,
    value.signer.principal,
    value.signer.verificationMethod,
    value.signer.suite,
    value.signer.evidence,
  );
}

function copyReceiptBindings(value: ApplicationReceiptBindings): ApplicationReceiptBindings {
  for (const item of [value.commandCommitment, value.authorityCommitment, value.contextCommitment]) {
    if (!(item instanceof Uint8Array) || item.length !== 32) {
      throw new AuthsWorkflowError("invalid-profile", "native receipt commitment is invalid");
    }
  }
  return Object.freeze({
    commandCommitment: value.commandCommitment.slice(),
    authorityCommitment: value.authorityCommitment.slice(),
    contextCommitment: value.contextCommitment.slice(),
  });
}

function copyReceiptArtifacts(value: ApplicationReceiptArtifacts): ApplicationReceiptArtifacts {
  const proofCbor = boundedBytes(value.proofCbor, "receipt proof");
  const canonicalActionCbor = boundedBytes(value.canonicalActionCbor, "receipt action");
  const trustedContextCbor = boundedBytes(value.trustedContextCbor, "receipt context");
  const commandBytes = boundedBytes(value.commandBytes, "receipt command");
  return Object.freeze({ proofCbor, canonicalActionCbor, trustedContextCbor, commandBytes });
}

function copyReceiptSigner(value: ApplicationReceiptSigner): ApplicationReceiptSigner {
  if (value === null || typeof value !== "object") {
    throw new AuthsWorkflowError("invalid-profile", "receipt signer is missing");
  }
  return Object.freeze({
    principal: boundedText(value.principal, 512, "receipt signer principal"),
    verificationMethod: boundedText(value.verificationMethod, 512, "receipt verification method"),
    suite: boundedText(value.suite, 128, "receipt signature suite"),
    evidence: boundedBytes(value.evidence, "receipt signer evidence"),
  });
}

function copyAttestedReceipt(value: AttestedApplicationReceipt): AttestedApplicationReceipt {
  if (value === null || typeof value !== "object" || !["decision", "execution"].includes(value.kind)) {
    throw new AuthsWorkflowError("invalid-profile", "attested receipt is invalid");
  }
  if (!(value.receiptId instanceof Uint8Array) || value.receiptId.length !== 32) {
    throw new AuthsWorkflowError("invalid-profile", "receipt id is invalid");
  }
  return Object.freeze({
    kind: value.kind,
    receiptId: value.receiptId.slice(),
    bytes: boundedBytes(value.bytes, "attested receipt"),
    signer: copyReceiptSigner(value.signer),
  });
}

function boundedBytes(value: unknown, label: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length === 0 || value.length > 1024 * 1024) {
    throw new AuthsWorkflowError("invalid-profile", `${label} is outside bounds`);
  }
  return value.slice();
}

function boundedIdempotencyKey(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || new TextEncoder().encode(value).length > 256) {
    throw new AuthsWorkflowError("invalid-profile", "idempotency key is outside bounds");
  }
  return value;
}

function isAborted(signal: AbortSignal | undefined): boolean {
  return signal?.aborted === true;
}

function validateCompatibleAuthority(
  actions: readonly CanonicalProfileAction[],
): {
  readonly permissions: readonly ProfilePermission[];
  readonly resourceNamespaces: readonly string[];
  readonly audiences: readonly string[];
  readonly budget?: ProfileBudget;
} {
  const first = actions[0];
  if (first === undefined) throw new AuthsWorkflowError("invalid-profile", "profile plan is empty");
  let aggregateBudget = 0n;
  for (const action of actions) {
    if (action.resourceNamespace !== first.resourceNamespace || action.audience !== first.audience) {
      throw new AuthsWorkflowError("invalid-profile", "profile plan has incompatible namespace or audience");
    }
    if (action.budget?.algebra !== first.budget?.algebra) {
      throw new AuthsWorkflowError("invalid-profile", "profile plan has incompatible budget algebra");
    }
    aggregateBudget += action.budget?.value ?? 0n;
    if (aggregateBudget > 18_446_744_073_709_551_615n) {
      throw new AuthsWorkflowError("invalid-profile", "profile plan aggregate budget exceeds bounds");
    }
  }
  const permissions = [...new Map(
    actions.map((action) => [
      `${action.permission.capability}\0${action.permission.resource}`,
      action.permission,
    ]),
  ).values()];
  return Object.freeze({
    permissions: Object.freeze(permissions.map((permission) => Object.freeze({ ...permission }))),
    resourceNamespaces: Object.freeze([first.resourceNamespace]),
    audiences: Object.freeze([first.audience]),
    ...(first.budget === undefined
      ? {}
      : { budget: Object.freeze({ algebra: first.budget.algebra, value: aggregateBudget }) }),
  });
}

function copyCanonical(value: CanonicalProfileAction): CanonicalProfileAction {
  if (value === null || typeof value !== "object") {
    throw new AuthsWorkflowError("invalid-profile", "canonical profile action is missing");
  }
  const body = value.body instanceof Uint8Array ? value.body.slice() : undefined;
  if (body === undefined || body.length === 0 || body.length > 1024 * 1024) {
    throw new AuthsWorkflowError("invalid-profile", "canonical action body is outside bounds");
  }
  const capability = boundedText(value.permission?.capability, 256, "capability");
  const resource = boundedText(value.permission?.resource, 2048, "resource");
  const resourceNamespace = boundedText(
    value.resourceNamespace,
    2048,
    "resource namespace",
  );
  const audience = boundedText(value.audience, 512, "audience");
  const mediaType = boundedText(value.mediaType, 256, "media type");
  const display = Object.freeze(value.display.map((field) => Object.freeze({
    label: boundedText(field.label, 128, "display label"),
    value: boundedText(field.value, 4096, "display value"),
  })));
  if (display.length === 0 || display.length > 32) {
    throw new AuthsWorkflowError("invalid-profile", "approval display is outside bounds");
  }
  let budget: ProfileBudget | undefined;
  if (value.budget !== undefined) {
    if (typeof value.budget.value !== "bigint" || value.budget.value < 1n || value.budget.value > 18_446_744_073_709_551_615n) {
      throw new AuthsWorkflowError("invalid-profile", "profile budget is outside bounds");
    }
    budget = Object.freeze({
      algebra: boundedText(value.budget.algebra, 128, "budget algebra"),
      value: value.budget.value,
    });
  }
  return Object.freeze({
    mediaType,
    body,
    permission: Object.freeze({ capability, resource }),
    resourceNamespace,
    ...(budget === undefined ? {} : { budget }),
    audience,
    display,
  });
}

function copyAuthorityRequirement(
  canonical: CanonicalProfileAction,
): ProfileAuthorityRequirement {
  return Object.freeze({
    permission: Object.freeze({ ...canonical.permission }),
    resourceNamespace: canonical.resourceNamespace,
    audience: canonical.audience,
    ...(canonical.budget === undefined
      ? {}
      : { budget: Object.freeze({ ...canonical.budget }) }),
  });
}

function boundedText(value: unknown, maxBytes: number, label: string): string {
  if (typeof value !== "string" || value.length === 0 || new TextEncoder().encode(value).length > maxBytes) {
    throw new AuthsWorkflowError("invalid-profile", `${label} is outside bounds`);
  }
  return value;
}

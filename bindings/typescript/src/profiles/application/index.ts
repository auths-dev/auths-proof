import { authorizePreparedAction } from "../../internal/authorization.js";
import { createProfilePlan, type ProfilePlan } from "../../plans.js";
import { loadPackagedWorkflowEngine } from "../../verifier/wasm.js";
import {
  AuthsWorkflowError,
  type AuthorizationResult,
  type ApprovalConfiguration,
  type AttachedAgent,
  type Profile,
  type ReviewField,
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
  ) {
    if (token !== COMMAND_TOKEN) throw new TypeError("sealed Auths application command");
    commandResources.set(this, { profile, command });
    Object.freeze(this);
  }

  private static create<Command>(
    token: typeof COMMAND_TOKEN,
    profile: object,
    command: Command,
  ): ApplicationCommand<Command> {
    return new ApplicationCommand(token, profile, command);
  }

  static {
    mintApplicationCommand = (profile, command) =>
      ApplicationCommand.create(COMMAND_TOKEN, profile, command);
  }

  toJSON(): never {
    throw new TypeError("verified Auths commands are not serializable");
  }
}

export interface ApplicationGateway<Command, Result> {
  parse(command: ApplicationCommand<Command>): ApplicationCommand<Command>;
  execute(command: ApplicationCommand<Command>): Promise<Result>;
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
    mintVerifiedApplicationCommand = (profile, canonical) =>
      createVerifiedCommandFor(profile, canonical);
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

  gateway<Result>(
    execute: (command: Command) => Promise<Result>,
  ): ApplicationGateway<Command, Result> {
    if (typeof execute !== "function") {
      throw new AuthsWorkflowError("invalid-profile", "application gateway executor is missing");
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
      async execute(sealed: ApplicationCommand<Command>): Promise<Result> {
        const resources = commandResources.get(sealed);
        if (resources === undefined || resources.profile !== profile) {
          throw new AuthsWorkflowError("invalid-profile", "application command is forged or belongs to another profile");
        }
        return execute(resources.command as Command);
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
  return mintApplicationCommand(profile, decoded);
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
  );
  if (result.kind !== "authorized") return result;
  return Object.freeze({
    ...result,
    command: mintVerifiedApplicationCommand(profile, canonical),
  });
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

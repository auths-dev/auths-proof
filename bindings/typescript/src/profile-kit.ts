import { type VerificationResult } from "./index.js";
import { authorizePreparedAction } from "./internal/authorization.js";
import {
  AuthsWorkflowError,
  type AttachedAgent,
  type Profile,
  type ReviewField,
  engineForClient,
  registerProfileRuntime,
  resourcesForAttachedAgent,
} from "./workflow.js";

const PROFILE_TOKEN: unique symbol = Symbol("auths-application-profile");
const ACTION_TOKEN: unique symbol = Symbol("auths-application-action");

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

export interface ProfileDefinition<Input> {
  readonly id: string;
  readonly version: number;
  canonicalize(input: Input): CanonicalProfileAction;
}

interface ActionResources<Input> {
  readonly profile: ApplicationProfile<Input>;
  readonly canonical: CanonicalProfileAction;
}

const actionResources = new WeakMap<ApplicationAction<unknown>, ActionResources<unknown>>();

/** A profile-owned action that cannot be detached from its canonicalizer. */
export class ApplicationAction<Input> {
  private constructor(
    token: typeof ACTION_TOKEN,
    profile: ApplicationProfile<Input>,
    canonical: CanonicalProfileAction,
  ) {
    if (token !== ACTION_TOKEN) throw new TypeError("sealed Auths profile action");
    actionResources.set(this, {
      profile: profile as ApplicationProfile<unknown>,
      canonical: copyCanonical(canonical),
    });
    Object.freeze(this);
  }

  static create<Input>(
    token: typeof ACTION_TOKEN,
    profile: ApplicationProfile<Input>,
    canonical: CanonicalProfileAction,
  ): ApplicationAction<Input> {
    if (token !== ACTION_TOKEN) throw new TypeError("sealed Auths profile action");
    return new ApplicationAction(token, profile, canonical);
  }
}

/** Closed application profile backed by the native Auths protocol authoring path. */
export class ApplicationProfile<Input>
  implements Profile<ApplicationAction<Input>, never>
{
  readonly id: string;
  readonly version: number;
  declare readonly __action?: ApplicationAction<Input>;
  declare readonly __command?: never;
  readonly #canonicalize: (input: Input) => CanonicalProfileAction;

  private constructor(token: typeof PROFILE_TOKEN, definition: ProfileDefinition<Input>) {
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
    registerProfileRuntime(this, {
      authorize: (agent, action) => authorizeApplication(
        agent,
        this as ApplicationProfile<unknown>,
        action,
      ),
    });
    Object.freeze(this);
  }

  static create<Input>(
    token: typeof PROFILE_TOKEN,
    definition: ProfileDefinition<Input>,
  ): ApplicationProfile<Input> {
    if (token !== PROFILE_TOKEN) throw new TypeError("sealed Auths application profile");
    return new ApplicationProfile(token, definition);
  }

  action(input: Input): ApplicationAction<Input> {
    let canonical: CanonicalProfileAction;
    try {
      canonical = this.#canonicalize(input);
    } catch (error) {
      if (error instanceof AuthsWorkflowError) throw error;
      throw new AuthsWorkflowError("invalid-profile", "profile rejected the proposed action");
    }
    return ApplicationAction.create(ACTION_TOKEN, this, copyCanonical(canonical));
  }

  /** Returns profile-derived grant inputs for this exact sealed action. */
  authorityFor(action: ApplicationAction<Input>): ProfileAuthorityRequirement {
    const resources = actionResources.get(action as ApplicationAction<unknown>);
    if (resources === undefined || resources.profile !== this) {
      throw new AuthsWorkflowError(
        "invalid-profile",
        "action was not created by this application profile",
      );
    }
    return copyAuthorityRequirement(resources.canonical);
  }
}

/** Defines one application-owned profile without registering a generic executor. */
export function defineProfile<Input>(
  definition: ProfileDefinition<Input>,
): ApplicationProfile<Input> {
  if (definition === null || typeof definition !== "object") {
    throw new AuthsWorkflowError("invalid-profile", "profile definition is missing");
  }
  return ApplicationProfile.create(PROFILE_TOKEN, definition);
}

async function authorizeApplication(
  agent: AttachedAgent<Profile>,
  profile: ApplicationProfile<unknown>,
  candidate: unknown,
): Promise<VerificationResult> {
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
  return authorizePreparedAction(agent, preparation, canonical.display);
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

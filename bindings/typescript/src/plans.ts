import { type Profile } from "./workflow.js";
import { AuthsWorkflowError } from "./workflow/errors.js";
import { loadPackagedWorkflowEngine } from "./verifier/wasm.js";

const PLAN_TOKEN: unique symbol = Symbol("auths-profile-plan");
const COMMAND_TOKEN: unique symbol = Symbol("auths-verified-plan-command");
let mintProfilePlan: <Action>(
  profile: Profile,
  actions: readonly Action[],
  commitment: Uint8Array,
  authority: PlanAuthoritySummary,
  memberCommitments: readonly Uint8Array[],
) => ProfilePlan<Action>;
let mintVerifiedPlan: <Command>(
  commands: readonly Command[],
  commitment: Uint8Array,
) => VerifiedPlanCommand<Command>;
const planResources = new WeakMap<ProfilePlan<unknown>, {
  profile: Profile;
  actions: readonly unknown[];
  memberCommitments: readonly Uint8Array[];
}>();
const commandResources = new WeakMap<VerifiedPlanCommand<unknown>, {
  readonly commands: readonly unknown[];
  readonly commitment: Uint8Array;
}>();

export interface PlanAuthoritySummary {
  readonly profile: Readonly<{ id: string; version: number }>;
  readonly permissions: readonly Readonly<{ capability: string; resource: string }>[];
  readonly resourceNamespaces: readonly string[];
  readonly audiences: readonly string[];
  readonly budget?: Readonly<{ algebra: string; value: bigint }>;
}

/** An immutable ordered set of actions owned by one exact profile instance. */
export class ProfilePlan<Action> {
  readonly length: number;
  readonly #commitment: Uint8Array;
  readonly #authority: PlanAuthoritySummary;

  private constructor(
    token: typeof PLAN_TOKEN,
    profile: Profile,
    actions: readonly Action[],
    commitment: Uint8Array,
    authority: PlanAuthoritySummary,
    memberCommitments: readonly Uint8Array[],
  ) {
    if (token !== PLAN_TOKEN) throw new TypeError("sealed Auths profile plan");
    this.#commitment = commitment.slice();
    this.length = actions.length;
    this.#authority = copyAuthority(authority);
    planResources.set(this as ProfilePlan<unknown>, {
      profile,
      actions: Object.freeze([...actions]),
      memberCommitments: Object.freeze(memberCommitments.map((item) => item.slice())),
    });
    Object.freeze(this);
  }

  /** Commitment over this exact ordered membership, stated by auths-author. */
  get commitment(): Uint8Array {
    return this.#commitment.slice();
  }

  get authority(): PlanAuthoritySummary {
    return copyAuthority(this.#authority);
  }

  private static create<Action>(
    token: typeof PLAN_TOKEN,
    profile: Profile,
    actions: readonly Action[],
    commitment: Uint8Array,
    authority: PlanAuthoritySummary,
    memberCommitments: readonly Uint8Array[],
  ): ProfilePlan<Action> {
    return new ProfilePlan(token, profile, actions, commitment, authority, memberCommitments);
  }

  static {
    mintProfilePlan = (profile, actions, commitment, authority, members) =>
      ProfilePlan.create(PLAN_TOKEN, profile, actions, commitment, authority, members);
  }
}

/** A non-serializable plan capability containing only individually verified commands. */
export class VerifiedPlanCommand<Command> {
  readonly count: number;
  readonly #commitment: Uint8Array;

  private constructor(
    token: typeof COMMAND_TOKEN,
    commands: readonly Command[],
    commitment: Uint8Array,
  ) {
    if (token !== COMMAND_TOKEN) throw new TypeError("sealed Auths verified plan command");
    if (!(commitment instanceof Uint8Array) || commitment.length !== 32) {
      throw new TypeError("verified Auths plan commitment is invalid");
    }
    this.count = commands.length;
    this.#commitment = commitment.slice();
    commandResources.set(this as VerifiedPlanCommand<unknown>, {
      commands: Object.freeze([...commands]),
      commitment: commitment.slice(),
    });
    Object.freeze(this);
  }

  get planCommitment(): Uint8Array {
    return this.#commitment.slice();
  }

  private static create<Command>(
    token: typeof COMMAND_TOKEN,
    commands: readonly Command[],
    commitment: Uint8Array,
  ): VerifiedPlanCommand<Command> {
    return new VerifiedPlanCommand(token, commands, commitment);
  }

  static {
    mintVerifiedPlan = (commands, commitment) =>
      VerifiedPlanCommand.create(COMMAND_TOKEN, commands, commitment);
  }
}

export async function createProfilePlan<Action>(
  profile: Profile,
  actions: readonly Action[],
  canonicalize: (action: Action) => Uint8Array,
  authority?: Omit<PlanAuthoritySummary, "profile">,
): Promise<ProfilePlan<Action>> {
  if (!Array.isArray(actions) || actions.length === 0 || actions.length > 256) {
    throw new AuthsWorkflowError("invalid-profile", "profile plan action count is outside bounds");
  }
  const parts = actions.map((action) => canonicalize(action));
  if (parts.some((part) => !(part instanceof Uint8Array) || part.length === 0)) {
    throw new AuthsWorkflowError("invalid-profile", "profile plan contains an invalid action");
  }
  // Plan membership and order decide what one approval covers, so the
  // commitment is stated by auths-author rather than framed here.
  const members = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  const memberLengths = new Uint32Array(parts.length);
  let offset = 0;
  parts.forEach((part, index) => {
    members.set(part, offset);
    memberLengths[index] = part.length;
    offset += part.length;
  });
  const engine = await loadPackagedWorkflowEngine();
  let planCommitment;
  try {
    planCommitment = engine.commitProfilePlanV1(
      profile.id,
      profile.version,
      members,
      memberLengths,
    );
  } catch {
    throw new AuthsWorkflowError("invalid-profile", "profile plan is outside the supported commitment");
  }
  const commitment = planCommitment.plan.slice();
  const memberCommitments = Array.from(
    { length: planCommitment.memberCount },
    (_unused, index) => planCommitment.members.slice(index * 32, index * 32 + 32),
  );
  members.fill(0);
  return mintProfilePlan(
    profile,
    actions,
    commitment,
    {
      profile: { id: profile.id, version: profile.version },
      permissions: authority?.permissions ?? [],
      resourceNamespaces: authority?.resourceNamespaces ?? [],
      audiences: authority?.audiences ?? [],
      ...(authority?.budget === undefined ? {} : { budget: authority.budget }),
    },
    memberCommitments,
  );
}

export function actionsForPlan<Action>(plan: ProfilePlan<Action>, profile: Profile): readonly Action[] {
  const resources = planResources.get(plan as ProfilePlan<unknown>);
  if (
    resources === undefined ||
    resources.profile.id !== profile.id ||
    resources.profile.version !== profile.version
  ) {
    throw new AuthsWorkflowError("invalid-profile", "plan was not created by the attached profile");
  }
  return resources.actions as readonly Action[];
}

export function memberCommitmentsForPlan<Action>(
  plan: ProfilePlan<Action>,
  profile: Profile,
): readonly Uint8Array[] {
  const resources = planResources.get(plan as ProfilePlan<unknown>);
  if (
    resources === undefined ||
    resources.profile.id !== profile.id ||
    resources.profile.version !== profile.version
  ) {
    throw new AuthsWorkflowError("invalid-profile", "plan was not created by the attached profile");
  }
  return Object.freeze(resources.memberCommitments.map((item) => item.slice()));
}

export function createVerifiedPlanCommand<Command>(
  commands: readonly Command[],
  commitment: Uint8Array,
): VerifiedPlanCommand<Command> {
  if (commands.length === 0) throw new AuthsWorkflowError("invalid-profile", "verified plan is empty");
  return mintVerifiedPlan(commands, commitment);
}

/** Gateway-only extraction; the individual command capabilities remain sealed. */
export function commandsForGateway<Command>(command: VerifiedPlanCommand<Command>): readonly Command[] {
  const commands = commandResources.get(command as VerifiedPlanCommand<unknown>);
  if (commands === undefined) throw new AuthsWorkflowError("invalid-profile", "verified plan command is forged");
  return commands.commands as readonly Command[];
}

function copyAuthority(value: PlanAuthoritySummary): PlanAuthoritySummary {
  return Object.freeze({
    profile: Object.freeze({ ...value.profile }),
    permissions: Object.freeze(value.permissions.map((permission) => Object.freeze({ ...permission }))),
    resourceNamespaces: Object.freeze([...value.resourceNamespaces]),
    audiences: Object.freeze([...value.audiences]),
    ...(value.budget === undefined ? {} : { budget: Object.freeze({ ...value.budget }) }),
  });
}

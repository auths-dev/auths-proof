import { type Profile } from "./workflow.js";
import { AuthsWorkflowError } from "./workflow/errors.js";
import { commitCanonical, type CanonicalCommitment } from "./commitments.js";

const PLAN_TOKEN: unique symbol = Symbol("auths-profile-plan");
const COMMAND_TOKEN: unique symbol = Symbol("auths-verified-plan-command");
let mintProfilePlan: <Action>(
  profile: Profile,
  actions: readonly Action[],
  commitment: CanonicalCommitment,
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
  readonly #commitment: CanonicalCommitment;
  readonly #authority: PlanAuthoritySummary;

  private constructor(
    token: typeof PLAN_TOKEN,
    profile: Profile,
    actions: readonly Action[],
    commitment: CanonicalCommitment,
    authority: PlanAuthoritySummary,
    memberCommitments: readonly Uint8Array[],
  ) {
    if (token !== PLAN_TOKEN) throw new TypeError("sealed Auths profile plan");
    this.#commitment = Object.freeze({ ...commitment, digest: commitment.digest.slice() });
    this.length = actions.length;
    this.#authority = copyAuthority(authority);
    planResources.set(this as ProfilePlan<unknown>, {
      profile,
      actions: Object.freeze([...actions]),
      memberCommitments: Object.freeze(memberCommitments.map((item) => item.slice())),
    });
    Object.freeze(this);
  }

  get commitment(): CanonicalCommitment {
    return Object.freeze({ ...this.#commitment, digest: this.#commitment.digest.slice() });
  }

  get authority(): PlanAuthoritySummary {
    return copyAuthority(this.#authority);
  }

  private static create<Action>(
    token: typeof PLAN_TOKEN,
    profile: Profile,
    actions: readonly Action[],
    commitment: CanonicalCommitment,
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
  const size = parts.reduce((sum, part) => sum + 8 + part.length, 0);
  const canonical = new Uint8Array(size);
  const view = new DataView(canonical.buffer);
  let offset = 0;
  for (const part of parts) {
    view.setBigUint64(offset, BigInt(part.length), false);
    offset += 8;
    canonical.set(part, offset);
    offset += part.length;
  }
  const commitment = await commitCanonical(
    `auths.profile-plan.${profile.id}.${profile.version}`,
    canonical,
  );
  const memberCommitments = await Promise.all(parts.map(async (part, index) => (
    await commitCanonical(
      `auths.profile-plan-member.${profile.id}.${profile.version}.${index}`,
      part,
    )
  ).digest));
  canonical.fill(0);
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

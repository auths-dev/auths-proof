import {
  AuthsWorkflowError,
  type AgentIdentity,
  type AttachedAgent,
  type AuthorityDiffSummary,
  type DelegatedActionConstraint,
  type DelegatedAuthorityRequest,
  type DelegatedBudget,
  type DelegatedStatus,
  type DelegationOptions,
  type DelegationReview,
  type OverGrantingWarning,
  type Profile,
  type Signer,
  type WorkflowGrantPlan,
  authoritySummary,
  boundedIdentifier,
  copyPrincipal,
  createDelegatedAttachedAgent,
  engineForClient,
  resourcesForAttachedAgent,
} from "../workflow.js";
import { SigningCoordinator, WasmSigningAdapter } from "./signing.js";

const DIGEST_BYTES = 32;
const MAX_U64 = (1n << 64n) - 1n;
const MAX_COLLECTION = 256;
const WARNING_FLAGS: readonly [number, OverGrantingWarning][] = [
  [1, "any-body"],
  [2, "multiple-permissions"],
  [4, "multiple-audiences"],
  [8, "delegation-allowed"],
  [16, "no-budget-ceiling"],
  [32, "long-validity"],
];

export async function delegateAttachedAgent<P extends Profile>(
  parent: AttachedAgent<P>,
  options: DelegationOptions<P>,
): Promise<AttachedAgent<P>> {
  parent.assertActive();
  let prepared: PreparedDelegation<P> | undefined;
  try {
    prepared = await prepareDelegation(parent, options);
    const { resources, name, profile, childIdentity, plan, review, engine } = prepared;
    const now = BigInt(Math.floor(Date.now() / 1000));
    const signed = await new SigningCoordinator(
      new WasmSigningAdapter(engine),
    ).execute({
      objectKind: "grant",
      unsignedObject: plan.statementCbor,
      principal: parent.identity.principal,
      signer: resources.signer,
      approval: resources.approval,
      requiredApproval: resources.client.trustedAuthority.requiredApproval,
      expiresAt: now + 300n,
      display: delegationDisplay(name, childIdentity, review),
    });
    let projected;
    try {
      projected = engine.inspectSignedGrantV1(signed.signedObject);
      const summary = authoritySummary(projected, "delegated");
      if (
        summary.issuer !== parent.identity.principal.principal ||
        summary.subject !== childIdentity.principal.principal ||
        summary.profile.id !== profile.id ||
        summary.profile.version !== profile.version ||
        projected.hasParent !== true
      ) {
        throw new AuthsWorkflowError(
          "authority-mismatch",
          "signed child grant does not match its native delegation plan",
        );
      }
      return createDelegatedAttachedAgent({
        parent,
        name,
        identity: childIdentity,
        profile,
        authority: summary,
        signer: options.signer,
        signedGrant: signed.signedObject,
        evidence: signed.evidence,
        grantStatement: plan.statementCbor,
        review,
      });
    } finally {
      projected?.free?.();
      signed.signedObject.fill(0);
    }
  } catch (error) {
    await cleanupChildSigner(options.signer);
    if (error instanceof AuthsWorkflowError) throw error;
    throw new AuthsWorkflowError(
      "invalid-delegation",
      "delegation failed before an attached child was created",
    );
  } finally {
    prepared?.plan.free?.();
  }
}

interface PreparedDelegation<P extends Profile> {
  readonly resources: ReturnType<typeof resourcesForAttachedAgent>;
  readonly name: string;
  readonly profile: P;
  readonly childIdentity: AgentIdentity;
  readonly plan: WorkflowGrantPlan;
  readonly review: DelegationReview;
  readonly engine: ReturnType<typeof engineForClient>;
}

/** Produces the native semantic diff before approval or signing. */
export async function reviewDelegation<P extends Profile>(
  parent: AttachedAgent<P>,
  options: DelegationOptions<P>,
): Promise<DelegationReview> {
  parent.assertActive();
  const prepared = await prepareDelegation(parent, options);
  try {
    return prepared.review;
  } finally {
    prepared.plan.free?.();
  }
}

async function prepareDelegation<P extends Profile>(
  parent: AttachedAgent<P>,
  options: DelegationOptions<P>,
): Promise<PreparedDelegation<P>> {
  validateDelegationShape(options);
  const resources = resourcesForAttachedAgent(parent);
  const name = agentName(options.name);
  const profile = selectedProfile(parent.profile, options.profile);
  const request = copyAuthorityRequest(options.authority);
  validateSigner(options.signer);
  const engine = engineForClient(resources.client);
  let childIdentity: AgentIdentity;
  try {
    const principal = copyPrincipal(await options.signer.publicIdentity());
    childIdentity = Object.freeze({
      principal: Object.freeze({
        ...principal,
        principal: engine.canonicalPrincipalV1(principal.principal),
      }),
      signerKind: boundedIdentifier(options.signer.kind, "signer kind"),
      signerLifecycle: options.signer.lifecycle,
    });
  } catch (error) {
    if (error instanceof AuthsWorkflowError) throw error;
    throw new AuthsWorkflowError("invalid-principal", "child signer returned an invalid principal descriptor");
  }
  const action = actionFields(request.actionConstraint);
  const budget = budgetFields(request.budget);
  const status = statusFields(request.status);
  let plan: WorkflowGrantPlan;
  try {
    plan = engine.planChildGrantFieldsV1(
      resources.grantStatement.slice(),
      childIdentity.principal.principal,
      request.permissions.map((permission) => permission.capability),
      request.permissions.map((permission) => permission.resource),
      request.validity.notBefore,
      request.validity.expiresAt,
      request.audiences,
      action.mode,
      action.digests,
      budget.mode,
      budget.algebra,
      budget.value,
      request.remainingDepth,
      status.mode,
      status.method,
      status.maxAge,
      request.assuranceFloor,
    );
  } catch {
    throw new AuthsWorkflowError(
      "delegation-expanded",
      "native authoring rejected widened or invalid child authority",
    );
  }
  return { resources, name, profile, childIdentity, plan, review: reviewFromPlan(plan, engine), engine };
}

function validateDelegationShape<P extends Profile>(
  options: DelegationOptions<P>,
): void {
  if (options === null || typeof options !== "object") {
    throw new AuthsWorkflowError(
      "invalid-delegation",
      "delegation options are missing",
    );
  }
  rejectUnknownKeys(options, ["name", "authority", "signer", "profile"]);
}

function copyAuthorityRequest(
  value: DelegatedAuthorityRequest,
): DelegatedAuthorityRequest & {
  readonly actionConstraint: DelegatedActionConstraint;
  readonly budget: DelegatedBudget;
  readonly status: DelegatedStatus;
  readonly assuranceFloor: string;
} {
  if (value === null || typeof value !== "object") {
    throw invalidAuthority();
  }
  rejectUnknownKeys(value, [
    "permissions",
    "validity",
    "audiences",
    "actionConstraint",
    "budget",
    "remainingDepth",
    "status",
    "assuranceFloor",
  ]);
  if (
    !Array.isArray(value.permissions) ||
    value.permissions.length === 0 ||
    value.permissions.length > MAX_COLLECTION ||
    !Array.isArray(value.audiences) ||
    value.audiences.length === 0 ||
    value.audiences.length > MAX_COLLECTION ||
    value.validity === null ||
    typeof value.validity !== "object" ||
    !Number.isInteger(value.remainingDepth) ||
    value.remainingDepth < 0 ||
    value.remainingDepth > 0xffff
  ) {
    throw invalidAuthority();
  }
  const validity = Object.freeze({
    notBefore: boundedU64(value.validity.notBefore),
    expiresAt: boundedU64(value.validity.expiresAt),
  });
  if (validity.notBefore > validity.expiresAt) throw invalidAuthority();
  return Object.freeze({
    permissions: Object.freeze(
      value.permissions.map((permission) => {
        if (permission === null || typeof permission !== "object") {
          throw invalidAuthority();
        }
        rejectUnknownKeys(permission, ["capability", "resource"]);
        return Object.freeze({
          capability: authorityIdentifier(permission.capability),
          resource: authorityIdentifier(permission.resource),
        });
      }),
    ),
    validity,
    audiences: Object.freeze(
      value.audiences.map((audience) => authorityIdentifier(audience)),
    ),
    actionConstraint: copyAction(value.actionConstraint ?? { kind: "inherit" }),
    budget: copyBudget(value.budget ?? { kind: "inherit" }),
    remainingDepth: value.remainingDepth,
    status: copyStatus(value.status ?? { kind: "inherit" }),
    assuranceFloor:
      value.assuranceFloor === undefined
        ? ""
        : authorityIdentifier(value.assuranceFloor),
  });
}

function copyAction(value: DelegatedActionConstraint): DelegatedActionConstraint {
  if (value === null || typeof value !== "object") throw invalidAuthority();
  switch (value.kind) {
    case "inherit":
    case "any-body":
      rejectUnknownKeys(value, ["kind"]);
      return Object.freeze({ kind: value.kind });
    case "exact-body":
      rejectUnknownKeys(value, ["kind", "digest"]);
      return Object.freeze({ kind: value.kind, digest: exactDigest(value.digest) });
    case "allowed-bodies":
      rejectUnknownKeys(value, ["kind", "digests"]);
      if (
        !Array.isArray(value.digests) ||
        value.digests.length === 0 ||
        value.digests.length > MAX_COLLECTION
      ) throw invalidAuthority();
      return Object.freeze({
        kind: value.kind,
        digests: Object.freeze(value.digests.map(exactDigest)),
      });
    default:
      throw invalidAuthority();
  }
}

function copyBudget(value: DelegatedBudget): DelegatedBudget {
  if (value === null || typeof value !== "object") throw invalidAuthority();
  switch (value.kind) {
    case "inherit":
    case "none":
      rejectUnknownKeys(value, ["kind"]);
      return Object.freeze({ kind: value.kind });
    case "ceiling":
      rejectUnknownKeys(value, ["kind", "algebra", "value"]);
      return Object.freeze({
        kind: value.kind,
        algebra: authorityIdentifier(value.algebra),
        value: boundedU64(value.value),
      });
    default:
      throw invalidAuthority();
  }
}

function copyStatus(value: DelegatedStatus): DelegatedStatus {
  if (value === null || typeof value !== "object") throw invalidAuthority();
  switch (value.kind) {
    case "inherit":
    case "expiry-only":
      rejectUnknownKeys(value, ["kind"]);
      return Object.freeze({ kind: value.kind });
    case "snapshot-required":
      rejectUnknownKeys(value, ["kind", "method", "maxAge"]);
      return Object.freeze({
        kind: value.kind,
        method: authorityIdentifier(value.method),
        maxAge: boundedU64(value.maxAge, true),
      });
    default:
      throw invalidAuthority();
  }
}

function actionFields(value: DelegatedActionConstraint) {
  if (value.kind === "exact-body") {
    return { mode: value.kind, digests: value.digest.slice() };
  }
  if (value.kind === "allowed-bodies") {
    const digests = new Uint8Array(value.digests.length * DIGEST_BYTES);
    value.digests.forEach((digest, index) => {
      digests.set(digest, index * DIGEST_BYTES);
    });
    return { mode: value.kind, digests };
  }
  return { mode: value.kind, digests: new Uint8Array() };
}

function budgetFields(value: DelegatedBudget) {
  return value.kind === "ceiling"
    ? { mode: value.kind, algebra: value.algebra, value: value.value }
    : { mode: value.kind, algebra: "", value: 0n };
}

function statusFields(value: DelegatedStatus) {
  return value.kind === "snapshot-required"
    ? {
        mode: value.kind,
        method: value.method,
        maxAge: value.maxAge,
      }
    : { mode: value.kind, method: "", maxAge: 0n };
}

function reviewFromPlan(
  plan: WorkflowGrantPlan,
  engine: ReturnType<typeof engineForClient>,
): DelegationReview {
  const knownMask = WARNING_FLAGS.reduce((mask, [flag]) => mask | flag, 0);
  if ((plan.warningMask & ~knownMask) !== 0) {
    throw new AuthsWorkflowError(
      "invalid-provider",
      "native grant plan returned an unknown warning",
    );
  }
  const diff: AuthorityDiffSummary = Object.freeze({
    removedPermissions: plan.removedPermissions,
    removedAudiences: plan.removedAudiences,
    validityShortened: plan.validityShortened,
    actionNarrowed: plan.actionNarrowed,
    budgetNarrowed: plan.budgetNarrowed,
    statusNarrowed: plan.statusNarrowed,
    parentDepth: plan.parentDepth,
    childDepth: plan.childDepth,
  });
  return Object.freeze({
    proposalCommitment: engine.commitCanonicalV1(
      "auths.delegation-proposal.v1",
      plan.statementCbor,
    ).slice(),
    diff,
    warnings: Object.freeze(
      WARNING_FLAGS.filter(([flag]) => (plan.warningMask & flag) !== 0).map(
        ([, warning]) => warning,
      ),
    ),
  });
}

function delegationDisplay(
  name: string,
  identity: AgentIdentity,
  review: DelegationReview,
) {
  return Object.freeze([
    Object.freeze({ label: "Child agent", value: name }),
    Object.freeze({ label: "Child principal", value: identity.principal.principal }),
    Object.freeze({
      label: "Permissions removed",
      value: String(review.diff.removedPermissions),
    }),
    Object.freeze({
      label: "Delegation depth",
      value: `${review.diff.parentDepth} -> ${review.diff.childDepth}`,
    }),
    Object.freeze({
      label: "Warnings",
      value: review.warnings.length === 0 ? "none" : review.warnings.join(", "),
    }),
  ]);
}

function selectedProfile<P extends Profile>(parent: P, proposed: P | undefined): P {
  if (proposed === undefined) return parent;
  if (
    proposed === null ||
    typeof proposed !== "object" ||
    proposed.id !== parent.id ||
    proposed.version !== parent.version
  ) {
    throw new AuthsWorkflowError(
      "delegation-expanded",
      "child profile must exactly match its parent profile",
    );
  }
  return parent;
}

function validateSigner(signer: Signer): void {
  if (
    signer === null ||
    typeof signer !== "object" ||
    typeof signer.publicIdentity !== "function" ||
    typeof signer.sign !== "function" ||
    !["durable", "ephemeral"].includes(signer.lifecycle)
  ) {
    throw new AuthsWorkflowError(
      "invalid-provider",
      "child signer does not implement the Auths signer port",
    );
  }
}

function exactDigest(value: Uint8Array): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== DIGEST_BYTES) {
    throw invalidAuthority();
  }
  return value.slice();
}

function boundedU64(value: bigint, nonzero = false): bigint {
  if (
    typeof value !== "bigint" ||
    value < (nonzero ? 1n : 0n) ||
    value > MAX_U64
  ) throw invalidAuthority();
  return value;
}

function authorityIdentifier(value: string): string {
  try {
    return boundedIdentifier(value, "delegated authority identifier");
  } catch {
    throw invalidAuthority();
  }
}

function agentName(value: string): string {
  try {
    return boundedIdentifier(value, "agent name");
  } catch {
    throw new AuthsWorkflowError(
      "invalid-agent-name",
      "child agent name is outside the supported identifier bound",
    );
  }
}

function rejectUnknownKeys(value: object, allowed: readonly string[]): void {
  if (Object.keys(value).some((key) => !allowed.includes(key))) {
    throw invalidAuthority();
  }
}

function invalidAuthority(): AuthsWorkflowError {
  return new AuthsWorkflowError(
    "invalid-delegation",
    "child authority request is malformed or outside workflow bounds",
  );
}

async function cleanupChildSigner(signer: Signer): Promise<void> {
  if (signer.dispose === undefined) return;
  try {
    await signer.dispose();
  } catch {
    // Preserve the original fail-closed delegation error.
  }
}

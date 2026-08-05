import { AuthsWorkflowError } from "../errors.js";
import type {
  DelegationReview,
  EffectiveAuthoritySummary,
  WorkflowSignedGrantAuthority,
} from "../contracts.js";

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
export function copyDelegationReview(value: DelegationReview): DelegationReview {
  return Object.freeze({
    diff: Object.freeze({ ...value.diff }),
    warnings: Object.freeze(Array.from(value.warnings)),
  });
}
export function copyEffectiveAuthority(
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

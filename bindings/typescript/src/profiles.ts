/** Qualified, profile-owned effect verticals. */
export * from "./profiles/mcp/index.js";

export type ProductionProfileId =
  | "auths.opentofu.saved-plan-apply/1"
  | "auths.postgresql.bounded-update/1"
  | "auths.github.issue-address/1";

export interface ProductionProfile {
  readonly id: ProductionProfileId;
}

export function opentofuSavedPlanApply(): ProductionProfile {
  return Object.freeze({ id: "auths.opentofu.saved-plan-apply/1" });
}

export function postgresqlBoundedUpdate(): ProductionProfile {
  return Object.freeze({ id: "auths.postgresql.bounded-update/1" });
}

export function githubIssueAddress(): ProductionProfile {
  return Object.freeze({ id: "auths.github.issue-address/1" });
}

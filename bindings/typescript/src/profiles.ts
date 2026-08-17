/** Qualified, profile-owned effect verticals. */
export * from "./profiles/mcp/index.js";

// The remaining three qualified profiles are declared alongside the service
// client because it routes on them, but a profile is a VERTICAL, not a
// transport concept: bindings/public-topology-v1.json maps the vertical layer
// to this entry point, and all four qualifiedProfiles belong here. These are
// re-exports of the same declarations, not copies, so `mcp` and its three peers
// are reachable from one place without giving either name two meanings.
export {
  githubIssueAddress,
  opentofuSavedPlanApply,
  postgresqlBoundedUpdate,
  type ServiceProfile,
  type ServiceProfileId,
} from "./service.js";

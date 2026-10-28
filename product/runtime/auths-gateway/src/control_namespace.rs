//! Exact native control namespaces, excluded from provider effect compilation.
//!
//! A tool-scoped control grant must not acquire provider meaning because a
//! recipe reuses its MCP service/tool. Keep classification shared by both
//! recipe compilers and enrollment resource-pin validation.

/// Provider-neutral task activation and exact-approval control namespace.
pub(crate) const TASK_SERVICE: &str = "auths-agent-task";
/// Native participant activation, enrollment and acceptance control namespace.
pub const PARTICIPANT_SERVICE: &str = "auths-participant";

pub(crate) fn is_control_service(service: &str) -> bool {
    matches!(service, TASK_SERVICE | PARTICIPANT_SERVICE)
}

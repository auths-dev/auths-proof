//! `mcp-arguments-v1`: the profile policy for observation requirements over
//! exact MCP tool calls.
//!
//! The kernel treats action bodies as opaque, so an observation requirement
//! that compares an observed fact with the action, or names its subject from
//! the action, needs the profile to supply that value. This policy exposes the
//! **top-level verified arguments** of an `auths.mcp/2` call by name and
//! nothing else: no service, tool, nested member, array element, or derived
//! value. A JSON string of at most 256 UTF-8 bytes is a text fact and a JSON
//! integer in `0..=u64::MAX` is an unsigned fact; every other argument, an
//! over-bound string, and an absent name are undefined, which makes a
//! requirement that needs them indeterminate.
//!
//! The policy is pure and bounded by the canonical body length. It accepts
//! only canonical `auths.mcp/2` actions, so a context that selects it cannot
//! authorize a body this decoder would read differently. Its identifier and
//! these rules are committed in the verifier configuration the trusted
//! context pins.

use auths_model::{
    AdapterConfigurationId, CanonicalAction, FactName, FactText, FactValue,
    MAX_FACT_VALUE_TEXT_BYTES, ProfileId, ProfilePolicyId, ProfileRef,
};
use auths_ports::{
    PrincipalMethod, ProfileDecision, ProfilePolicy, RegistryOperationError, SignatureSuite,
};
use auths_registries::{ImmutableRegistries, PureRegistrySet, RegistryError};
use serde_json::Value;
use std::fmt;

use crate::{MEDIA_TYPE, McpToolCall, PROFILE_ID, PROFILE_VERSION};

/// Profile-policy identifier selected by a trusted context whose observation
/// requirements read MCP arguments.
pub const MCP_ARGUMENTS_V1: &str = "mcp-arguments-v1";

/// Configuration components committed with the policy identifier. Changing
/// what the policy exposes changes the verifier configuration.
const CONFIGURATION: [&[u8]; 4] = [
    b"auths.mcp/2",
    b"top-level-arguments",
    b"text<=256:uint64",
    b"accept-canonical-mcp-only",
];

/// Pure profile policy exposing top-level verified MCP arguments as facts.
pub struct McpArgumentsPolicy {
    id: ProfilePolicyId,
}

impl McpArgumentsPolicy {
    /// Constructs the policy.
    ///
    /// # Errors
    /// Returns [`RegistryOperationError::InvalidInput`] only if the compiled
    /// identifier is invalid.
    pub fn new() -> Result<Self, RegistryOperationError> {
        Ok(Self {
            id: ProfilePolicyId::parse(MCP_ARGUMENTS_V1)
                .map_err(|_| RegistryOperationError::InvalidInput)?,
        })
    }
}

/// Decodes a canonical `auths.mcp/2` call, or `None` for any other action.
fn mcp_call(action: &CanonicalAction) -> Option<McpToolCall> {
    let profile = ProfileRef::new(ProfileId::parse(PROFILE_ID).ok()?, PROFILE_VERSION).ok()?;
    if action.profile() != &profile
        || action.media_type().as_str() != MEDIA_TYPE
        || action.requested_budget().is_some()
    {
        return None;
    }
    let call = McpToolCall::from_canonical_bytes(action.body()).ok()?;
    (call.permission().ok()? == *action.permission()).then_some(call)
}

/// Maps one JSON argument to a fact value, or `None` when it has no fact form.
fn argument_fact(value: &Value) -> Option<FactValue> {
    match value {
        Value::String(text) if text.len() <= MAX_FACT_VALUE_TEXT_BYTES => {
            FactText::new(text).ok().map(FactValue::Text)
        }
        Value::Number(number) => number.as_u64().map(FactValue::Uint),
        _ => None,
    }
}

impl ProfilePolicy for McpArgumentsPolicy {
    fn id(&self) -> &ProfilePolicyId {
        &self.id
    }

    fn configuration_id(&self) -> AdapterConfigurationId {
        auths_ports::configuration_id(self.id.as_str().as_bytes(), CONFIGURATION)
    }

    fn maximum_work_units(&self, action: &CanonicalAction) -> u64 {
        u64::try_from(action.body().len().saturating_add(1)).unwrap_or(u64::MAX)
    }

    fn evaluate(
        &self,
        action: &CanonicalAction,
    ) -> Result<ProfileDecision, RegistryOperationError> {
        Ok(if mcp_call(action).is_some() {
            ProfileDecision::Accept
        } else {
            ProfileDecision::Deny
        })
    }

    fn action_fact(
        &self,
        action: &CanonicalAction,
        name: &FactName,
    ) -> Result<Option<FactValue>, RegistryOperationError> {
        let call = mcp_call(action).ok_or(RegistryOperationError::InvalidInput)?;
        Ok(call.arguments().get(name.as_str()).and_then(argument_fact))
    }
}

/// Failure to construct the `mcp-arguments-v1` verifier registries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpArgumentsRegistryError {
    /// The compiled policy identifier was invalid.
    Policy(RegistryOperationError),
    /// The registry set rejected a duplicate or invalid identifier.
    Registry(RegistryError),
}

impl fmt::Display for McpArgumentsRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Policy(_) => formatter.write_str("invalid mcp-arguments-v1 policy identifier"),
            Self::Registry(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for McpArgumentsRegistryError {}

/// Runs `check` against the immutable registries of the `mcp-arguments-v1`
/// verifier configuration: exactly `methods` and `suites` plus this policy.
///
/// Every verifier that must accept a context pinning this configuration
/// builds its registries here, so the gateway and the SDK verifiers commit
/// to one configuration identifier for the same methods and suites.
///
/// # Errors
///
/// Returns [`McpArgumentsRegistryError`] for a duplicate method or suite
/// identifier or an invalid compiled identifier.
pub fn with_mcp_arguments_registries<T>(
    methods: &[&dyn PrincipalMethod],
    suites: &[&dyn SignatureSuite],
    check: impl FnOnce(&ImmutableRegistries<'_>) -> T,
) -> Result<T, McpArgumentsRegistryError> {
    let policy = McpArgumentsPolicy::new().map_err(McpArgumentsRegistryError::Policy)?;
    let policies: [&dyn ProfilePolicy; 1] = [&policy];
    let registries = ImmutableRegistries::with_pure(
        methods,
        suites,
        PureRegistrySet {
            resource_matchers: &[],
            profile_policies: &policies,
            budget_algebras: &[],
            extension_handlers: &[],
            status_methods: &[],
            assurance_claims: &[],
            assurance_implications: &[],
        },
    )
    .map_err(McpArgumentsRegistryError::Registry)?;
    Ok(check(&registries))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::McpProfile;
    use auths_profile_api::ActionProfile as _;
    use serde_json::json;

    fn action(arguments: &Value) -> CanonicalAction {
        let call = McpToolCall::new(
            "airtable-gateway-demo",
            "set_demo_status_v1",
            arguments.as_object().expect("object").clone(),
        )
        .expect("call");
        McpProfile
            .canonicalize(&call.canonical_bytes().expect("canonical"))
            .expect("canonical action")
    }

    fn fact(action: &CanonicalAction, name: &str) -> Option<FactValue> {
        McpArgumentsPolicy::new()
            .expect("policy")
            .action_fact(action, &FactName::parse(name).expect("name"))
            .expect("pure lookup")
    }

    #[test]
    fn exposes_only_top_level_text_and_unsigned_arguments() {
        let long = "x".repeat(MAX_FACT_VALUE_TEXT_BYTES + 1);
        let exact = "y".repeat(MAX_FACT_VALUE_TEXT_BYTES);
        let action = action(&json!({
            "expected": "Pending",
            "count": 7,
            "negative": -1,
            "fraction": 1.5,
            "flag": true,
            "nested": {"expected": "Approved"},
            "list": ["Approved"],
            "long": long,
            "exact": exact,
        }));
        assert_eq!(
            fact(&action, "expected"),
            Some(FactValue::Text(FactText::new("Pending").expect("text")))
        );
        assert_eq!(fact(&action, "count"), Some(FactValue::Uint(7)));
        assert_eq!(
            fact(&action, "exact"),
            Some(FactValue::Text(FactText::new(&exact).expect("text")))
        );
        for undefined in [
            "negative", "fraction", "flag", "nested", "list", "long", "absent", "service",
        ] {
            assert_eq!(fact(&action, undefined), None, "{undefined}");
        }
    }

    #[test]
    fn accepts_only_canonical_mcp_actions() {
        let policy = McpArgumentsPolicy::new().expect("policy");
        let mcp = action(&json!({"expected": "Pending"}));
        assert_eq!(policy.evaluate(&mcp), Ok(ProfileDecision::Accept));
        let foreign = CanonicalAction::new(
            mcp.profile().clone(),
            auths_model::MediaType::parse("application/octet-stream").expect("media"),
            mcp.body().to_vec(),
            mcp.permission().clone(),
            None,
        )
        .expect("foreign action");
        assert_eq!(policy.evaluate(&foreign), Ok(ProfileDecision::Deny));
        assert_eq!(
            policy.action_fact(&foreign, &FactName::parse("expected").expect("name")),
            Err(RegistryOperationError::InvalidInput)
        );
    }

    #[test]
    fn configuration_commitment_names_the_policy_and_its_rules() {
        let policy = McpArgumentsPolicy::new().expect("policy");
        assert_eq!(policy.id().as_str(), MCP_ARGUMENTS_V1);
        assert_ne!(
            policy.configuration_id(),
            auths_ports::configuration_id(MCP_ARGUMENTS_V1.as_bytes(), core::iter::empty())
        );
        assert_eq!(
            policy.configuration_id(),
            McpArgumentsPolicy::new()
                .expect("policy")
                .configuration_id()
        );
    }

    #[test]
    #[allow(
        clippy::redundant_closure_for_method_calls,
        reason = "the method path is not general over the registries' borrow lifetime"
    )]
    fn registries_commit_the_policy_into_a_distinct_configuration() {
        let with_policy =
            with_mcp_arguments_registries(&[], &[], |registries| registries.configuration_id())
                .expect("registries");
        let without = ImmutableRegistries::new(&[], &[])
            .expect("registries")
            .configuration_id();
        assert_ne!(with_policy, without);
        assert_eq!(
            with_policy,
            with_mcp_arguments_registries(&[], &[], |registries| registries.configuration_id())
                .expect("registries")
        );
    }
}

//! Entry points for the gateway fuzz targets, compiled only with the
//! `fuzzing` feature.
//!
//! Each function wraps a crate-private parser or rule without changing it,
//! so a fuzz target exercises exactly the shipping code. Nothing here is a
//! production API.

use crate::{
    ClosedProviderRequest, CompiledRecipe, GatewayAttemptStage, GatewayRecipeError, OUTCOME_SCHEMA,
};
use auths_model::PrincipalId;
use serde_json::{Map, Value};

/// The stage of one stored attempt record, when the bytes decode to a
/// record whose fields agree with it.
#[must_use]
pub fn attempt_stage(bytes: &[u8]) -> Option<GatewayAttemptStage> {
    crate::store::fuzz_snapshot(bytes).map(|snapshot| snapshot.stage())
}

/// Whether the store would let `new` replace `old`, when both decode.
#[must_use]
pub fn attempt_transition(old: &[u8], new: &[u8]) -> Option<bool> {
    crate::store::fuzz_transition(old, new)
}

/// The closed provider request a recipe builds from verified arguments and
/// an action commitment.
///
/// # Errors
/// Returns the construction refusal.
pub fn closed_request(
    recipe: &CompiledRecipe,
    arguments: &Map<String, Value>,
    action_commitment: [u8; 32],
) -> Result<ClosedProviderRequest, GatewayRecipeError> {
    recipe.closed_request_from_arguments(arguments, action_commitment)
}

/// The profile field whose value an account-scope header carries, when the
/// recipe declares one.
#[must_use]
pub fn account_scope_field(recipe: &CompiledRecipe) -> Option<String> {
    recipe.account_scope_field().map(str::to_owned)
}

/// What a verified outcome states.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedOutcomeSummary {
    /// The signed stage, kebab-case.
    pub stage: &'static str,
    /// The signed subject.
    pub subject: String,
    /// The signing time.
    pub observed_at: u64,
    /// Whether the fact set satisfies the presence rule; always true for a
    /// verified outcome.
    pub well_formed: bool,
}

/// Verifies one outcome under the pinned `observer`.
#[must_use]
pub fn verify_outcome(bytes: &[u8], observer: &PrincipalId) -> Option<VerifiedOutcomeSummary> {
    crate::observer::verify_outcome(bytes, observer)
        .ok()
        .map(|verified| VerifiedOutcomeSummary {
            stage: verified.stage(),
            subject: verified.subject.clone(),
            observed_at: verified.observed_at,
            well_formed: verified.record.well_formed(),
        })
}

/// The schema a verified outcome must carry.
#[must_use]
pub const fn outcome_schema() -> &'static str {
    OUTCOME_SCHEMA
}

/// The principal of the fixed test observer of seed byte `seed`, the
/// observer of the committed outcome vectors.
#[must_use]
pub fn test_observer(seed: u8) -> PrincipalId {
    crate::GatewayObserver::test_principal(seed)
}

/// Which closed application frame `bytes` parse as: `submit`, `observe`, or
/// `None`.
#[cfg(unix)]
#[must_use]
pub fn app_frame_kind(bytes: &[u8]) -> Option<&'static str> {
    crate::app::frame_kind(bytes)
}

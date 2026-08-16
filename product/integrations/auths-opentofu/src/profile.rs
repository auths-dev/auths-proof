//! Auths profile for applying one exact OpenTofu saved plan.

use auths_model::{
    BudgetAlgebraId, BudgetCeiling, CanonicalAction, CapabilityId, MediaType, Permission,
    ProfileId, ProfileRef, ResourceId,
};
use auths_profile_api::{
    ActionProfile, ProfileBudgetExpression, ProfileContractError, ReviewDisplay,
};
use auths_sdk::VerifiedAction;
use sha2::{Digest as _, Sha256};

use crate::{
    action::OpenTofuSavedPlanApplyV1,
    canonical::sha256,
    errors::ValidationError,
    types::{APPLY_CAPABILITY, MAX_ACTION_BYTES, MEDIA_TYPE, PROFILE_ID, PROFILE_VERSION},
};

const EFFECT_BUDGET_ALGEBRA: &str = "numeric-ceiling-v1";

/// Verified command decoded only from sealed Auths output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenTofuApplyCommand {
    action: OpenTofuSavedPlanApplyV1,
}

impl OpenTofuApplyCommand {
    #[must_use]
    pub const fn action(&self) -> &OpenTofuSavedPlanApplyV1 {
        &self.action
    }
}

/// `auths.opentofu.saved-plan-apply/1`.
#[derive(Clone, Copy, Debug, Default)]
pub struct OpenTofuSavedPlanProfile;

impl ActionProfile for OpenTofuSavedPlanProfile {
    type Command = OpenTofuApplyCommand;

    /// `canonical_action` always declares one `numeric-ceiling-v1` unit.
    const BUDGET_EXPRESSION: ProfileBudgetExpression = ProfileBudgetExpression::Expressible;

    fn canonicalize(&self, untrusted: &[u8]) -> Result<CanonicalAction, ProfileContractError> {
        if untrusted.is_empty() || untrusted.len() > MAX_ACTION_BYTES {
            return Err(ProfileContractError::LimitExceeded);
        }
        let action = OpenTofuSavedPlanApplyV1::from_canonical_bytes(untrusted)
            .map_err(ProfileContractError::from)?;
        canonical_action(
            &action,
            action
                .canonical_bytes()
                .map_err(ProfileContractError::from)?,
        )
    }

    fn review_display(
        &self,
        canonical: &CanonicalAction,
    ) -> Result<ReviewDisplay, ProfileContractError> {
        let action = validate_canonical_action(canonical)?;
        Ok(ReviewDisplay::new(
            "Auths V1 · Apply one exact OpenTofu saved plan",
            vec![
                ("Backend".into(), action.backend_identity().into()),
                ("Workspace".into(), action.workspace().into()),
                ("State lineage".into(), action.state_lineage().into()),
                ("State serial".into(), action.state_serial().to_string()),
                ("Saved plan".into(), action.opaque_plan_digest().to_string()),
                (
                    "Resource changes".into(),
                    action.permitted_change_summary().total().to_string(),
                ),
                ("Executor".into(), action.executor_audience().into()),
            ],
            hex::encode(Sha256::digest(canonical.body())),
        ))
    }

    fn decode_verified(
        &self,
        verified: &VerifiedAction,
    ) -> Result<Self::Command, ProfileContractError> {
        Ok(OpenTofuApplyCommand {
            action: validate_canonical_action(verified.canonical_action())?,
        })
    }
}

fn canonical_action(
    action: &OpenTofuSavedPlanApplyV1,
    body: Vec<u8>,
) -> Result<CanonicalAction, ProfileContractError> {
    CanonicalAction::new(
        expected_profile()?,
        MediaType::parse(MEDIA_TYPE).map_err(|_| ProfileContractError::UnsupportedProfile)?,
        body,
        permission(action)?,
        Some(BudgetCeiling::new(
            BudgetAlgebraId::parse(EFFECT_BUDGET_ALGEBRA)
                .map_err(|_| ProfileContractError::MeaningMismatch)?,
            1,
        )),
    )
    .map_err(|_| ProfileContractError::LimitExceeded)
}

fn validate_canonical_action(
    canonical: &CanonicalAction,
) -> Result<OpenTofuSavedPlanApplyV1, ProfileContractError> {
    if canonical.profile() != &expected_profile()? || canonical.media_type().as_str() != MEDIA_TYPE
    {
        return Err(ProfileContractError::UnsupportedProfile);
    }
    let action = OpenTofuSavedPlanApplyV1::from_canonical_bytes(canonical.body())
        .map_err(ProfileContractError::from)?;
    let expected = canonical_action(&action, canonical.body().to_vec())?;
    if canonical.permission() != expected.permission()
        || canonical.requested_budget() != expected.requested_budget()
        || !canonical.detached_attachments().is_empty()
    {
        return Err(ProfileContractError::MeaningMismatch);
    }
    Ok(action)
}

fn expected_profile() -> Result<ProfileRef, ProfileContractError> {
    ProfileRef::new(
        ProfileId::parse(PROFILE_ID).map_err(|_| ProfileContractError::UnsupportedProfile)?,
        PROFILE_VERSION,
    )
    .map_err(|_| ProfileContractError::UnsupportedProfile)
}

fn permission(action: &OpenTofuSavedPlanApplyV1) -> Result<Permission, ProfileContractError> {
    let backend = sha256(action.backend_identity().as_bytes());
    let workspace = sha256(action.workspace().as_bytes());
    let lineage = sha256(action.state_lineage().as_bytes());
    let resource = format!(
        "opentofu://{backend}/{workspace}/{lineage}/{}",
        action.opaque_plan_digest()
    );
    Ok(Permission::new(
        CapabilityId::parse(APPLY_CAPABILITY).map_err(|_| ProfileContractError::MeaningMismatch)?,
        ResourceId::parse(&resource).map_err(|_| ProfileContractError::MeaningMismatch)?,
    ))
}

impl From<ValidationError> for ProfileContractError {
    fn from(error: ValidationError) -> Self {
        match error {
            ValidationError::LimitExceeded => Self::LimitExceeded,
            ValidationError::Malformed => Self::Malformed,
            ValidationError::NonCanonical => Self::NonCanonical,
            ValidationError::UnsupportedProfile => Self::UnsupportedProfile,
            ValidationError::InvalidConfiguration
            | ValidationError::InvalidEvidence
            | ValidationError::ForbiddenFeature
            | ValidationError::DependencyNotPinned
            | ValidationError::ChangeOutsideProfile
            | ValidationError::DestroyDenied
            | ValidationError::ReplacementDenied => Self::MeaningMismatch,
        }
    }
}

#[cfg(test)]
mod tests {
    use auths_profile_api::ActionProfile as _;

    use super::*;
    use crate::test_support::fixture;

    #[test]
    fn profile_binds_exact_plan_and_one_effect_budget() {
        let fixture = fixture();
        let canonical = OpenTofuSavedPlanProfile
            .canonicalize(&fixture.action.canonical_bytes().unwrap())
            .unwrap();
        assert_eq!(
            canonical.permission().capability().as_str(),
            APPLY_CAPABILITY
        );
        assert!(
            canonical
                .permission()
                .resource()
                .as_str()
                .ends_with(fixture.action.opaque_plan_digest().as_str())
        );
        assert_eq!(canonical.requested_budget().unwrap().value(), 1);
    }
}

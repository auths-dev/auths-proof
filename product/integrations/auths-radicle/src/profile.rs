//! Auths application profile for one exact Radicle patch publication.

use auths_model::{
    BudgetAlgebraId, BudgetCeiling, CanonicalAction, CapabilityId, MediaType, Permission,
    ProfileId, ProfileRef, ResourceId,
};
use auths_profile_api::{
    ActionProfile, ProfileBudgetExpression, ProfileContractError, ReviewDisplay,
};
use auths_sdk::VerifiedAction;
use sha2::{Digest as _, Sha256};

use crate::types::{
    MAX_ACTION_BYTES, MEDIA_TYPE, OpenPatchActionV1, PATCH_OPEN_CAPABILITY, PROFILE_ID,
    PROFILE_VERSION, ValidationError,
};

const PUBLICATION_BUDGET_ALGEBRA: &str = "numeric-ceiling-v1";

/// Profile-decoded command obtainable only from an Auths-verified action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RadiclePatchCommand {
    action: OpenPatchActionV1,
}

impl RadiclePatchCommand {
    /// Returns the exact action authorized by Auths.
    #[must_use]
    pub const fn action(&self) -> &OpenPatchActionV1 {
        &self.action
    }
}

/// `auths.radicle.issue-address/1` profile implementation.
#[derive(Clone, Copy, Debug, Default)]
pub struct RadiclePatchProfile;

impl ActionProfile for RadiclePatchProfile {
    type Command = RadiclePatchCommand;

    /// `canonical_action` derives a `numeric-ceiling-v1` request from the
    /// publication budget ordinal.
    const BUDGET_EXPRESSION: ProfileBudgetExpression = ProfileBudgetExpression::Expressible;

    fn canonicalize(&self, untrusted: &[u8]) -> Result<CanonicalAction, ProfileContractError> {
        if untrusted.is_empty() || untrusted.len() > MAX_ACTION_BYTES {
            return Err(ProfileContractError::LimitExceeded);
        }
        let action: OpenPatchActionV1 =
            serde_json::from_slice(untrusted).map_err(|_| ProfileContractError::Malformed)?;
        action.validate().map_err(ProfileContractError::from)?;
        let bytes = action
            .canonical_bytes()
            .map_err(|_| ProfileContractError::Malformed)?;
        canonical_action(&action, bytes)
    }

    fn review_display(
        &self,
        canonical: &CanonicalAction,
    ) -> Result<ReviewDisplay, ProfileContractError> {
        let action = validate_canonical_action(canonical)?;
        let digest = Sha256::digest(canonical.body());
        Ok(ReviewDisplay::new(
            "Auths V1 · Open one Radicle patch",
            vec![
                ("Repository".into(), action.rid().to_string()),
                ("Issue".into(), action.issue_id().to_string()),
                ("Base".into(), action.canonical_base_oid().to_string()),
                ("Candidate".into(), action.candidate_oid().to_string()),
                ("Signer".into(), action.signer_did().to_string()),
                ("Executor".into(), action.executor_audience().to_string()),
                (
                    "Workflow grant".into(),
                    action.workflow_grant_digest().to_string(),
                ),
                ("Canonical update".into(), "not permitted".into()),
            ],
            hex::encode(digest),
        ))
    }

    fn decode_verified(
        &self,
        verified: &VerifiedAction,
    ) -> Result<Self::Command, ProfileContractError> {
        Ok(RadiclePatchCommand {
            action: validate_canonical_action(verified.canonical_action())?,
        })
    }
}

fn canonical_action(
    action: &OpenPatchActionV1,
    body: Vec<u8>,
) -> Result<CanonicalAction, ProfileContractError> {
    CanonicalAction::new(
        expected_profile()?,
        MediaType::parse(MEDIA_TYPE).map_err(|_| ProfileContractError::UnsupportedProfile)?,
        body,
        permission(action)?,
        Some(BudgetCeiling::new(
            BudgetAlgebraId::parse(PUBLICATION_BUDGET_ALGEBRA)
                .map_err(|_| ProfileContractError::MeaningMismatch)?,
            u64::from(action.publication_budget_ordinal()),
        )),
    )
    .map_err(|_| ProfileContractError::LimitExceeded)
}

fn validate_canonical_action(
    canonical: &CanonicalAction,
) -> Result<OpenPatchActionV1, ProfileContractError> {
    if canonical.profile() != &expected_profile()? || canonical.media_type().as_str() != MEDIA_TYPE
    {
        return Err(ProfileContractError::UnsupportedProfile);
    }
    let action = OpenPatchActionV1::from_canonical_bytes(canonical.body())
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

fn permission(action: &OpenPatchActionV1) -> Result<Permission, ProfileContractError> {
    let resource = format!(
        "radicle://{}/issues/{}/grants/{}",
        action.rid(),
        action.issue_id(),
        action.workflow_grant_digest()
    );
    Ok(Permission::new(
        CapabilityId::parse(PATCH_OPEN_CAPABILITY)
            .map_err(|_| ProfileContractError::MeaningMismatch)?,
        ResourceId::parse(&resource).map_err(|_| ProfileContractError::MeaningMismatch)?,
    ))
}

impl From<ValidationError> for ProfileContractError {
    fn from(error: ValidationError) -> Self {
        match error {
            ValidationError::LimitExceeded => Self::LimitExceeded,
            ValidationError::Malformed | ValidationError::Canonicalization => Self::Malformed,
            ValidationError::NonCanonical => Self::NonCanonical,
            ValidationError::InvalidAction => Self::UnsupportedProfile,
            ValidationError::InvalidConfiguration
            | ValidationError::InvalidGrant
            | ValidationError::InvalidCandidate
            | ValidationError::InvalidEvidence
            | ValidationError::InvalidPath
            | ValidationError::ForbiddenFileMode => Self::MeaningMismatch,
        }
    }
}

#[cfg(test)]
mod tests {
    use auths_profile_api::ActionProfile as _;

    use super::*;
    use crate::test_support::{NOW, action, candidate, configuration, evidence, grant, submission};

    #[test]
    fn profile_derives_exact_resource_and_one_write_budget() {
        let configuration = configuration(30);
        let grant = grant(configuration.clone());
        let submission = submission();
        let candidate = candidate(&submission);
        let evidence = evidence(&grant, NOW);
        let action = action(&grant, &configuration, &submission, &candidate, &evidence);

        let canonical = RadiclePatchProfile
            .canonicalize(&action.canonical_bytes().unwrap())
            .unwrap();

        assert_eq!(
            canonical.permission().capability().as_str(),
            PATCH_OPEN_CAPABILITY
        );
        assert_eq!(
            canonical.permission().resource().as_str(),
            format!(
                "radicle://{}/issues/{}/grants/{}",
                grant.rid(),
                grant.issue_id(),
                grant.digest().unwrap()
            )
        );
        let budget = canonical.requested_budget().unwrap();
        assert_eq!(budget.algebra().as_str(), "numeric-ceiling-v1");
        assert_eq!(budget.value(), 1);
    }
}

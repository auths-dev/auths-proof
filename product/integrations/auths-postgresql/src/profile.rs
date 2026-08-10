//! Auths action profile for one exact bounded PostgreSQL transition.

use auths_model::{
    BudgetAlgebraId, BudgetCeiling, CanonicalAction, CapabilityId, MediaType, Permission,
    ProfileId, ProfileRef, ResourceId,
};
use auths_profile_api::{ActionProfile, ProfileContractError, ReviewDisplay};
use auths_sdk::VerifiedAction;
use sha2::{Digest as _, Sha256};

use crate::{
    action::PostgresBoundedUpdateV1,
    canonical::sha256,
    schema::{
        MAX_ACTION_BYTES, MEDIA_TYPE, PROFILE_ID, PROFILE_VERSION, UPDATE_CAPABILITY,
        ValidationError,
    },
};

const EFFECT_BUDGET_ALGEBRA: &str = "numeric-ceiling-v1";

/// Verified command decoded only from sealed Auths output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostgresUpdateCommand {
    action: PostgresBoundedUpdateV1,
}

impl PostgresUpdateCommand {
    #[must_use]
    pub const fn action(&self) -> &PostgresBoundedUpdateV1 {
        &self.action
    }
}

/// `auths.postgresql.bounded-update/1`.
#[derive(Clone, Copy, Debug, Default)]
pub struct PostgresBoundedUpdateProfile;

impl ActionProfile for PostgresBoundedUpdateProfile {
    type Command = PostgresUpdateCommand;

    fn canonicalize(&self, untrusted: &[u8]) -> Result<CanonicalAction, ProfileContractError> {
        if untrusted.is_empty() || untrusted.len() > MAX_ACTION_BYTES {
            return Err(ProfileContractError::LimitExceeded);
        }
        let action = PostgresBoundedUpdateV1::from_canonical_bytes(untrusted)
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
            "Auths V1 · Execute one bounded PostgreSQL update",
            vec![
                ("Database".into(), action.intent.database_name.to_string()),
                (
                    "Relation".into(),
                    format!("{}.{}", action.intent.schema_name, action.intent.table_name),
                ),
                ("Rows".into(), action.intent.expected_row_count.to_string()),
                ("Row set".into(), action.row_set_digest.to_string()),
                (
                    "Before state".into(),
                    action.before_state_digest.to_string(),
                ),
                ("After state".into(), action.after_state_digest.to_string()),
            ],
            hex::encode(Sha256::digest(canonical.body())),
        ))
    }

    fn decode_verified(
        &self,
        verified: &VerifiedAction,
    ) -> Result<Self::Command, ProfileContractError> {
        Ok(PostgresUpdateCommand {
            action: validate_canonical_action(verified.canonical_action())?,
        })
    }
}

fn canonical_action(
    action: &PostgresBoundedUpdateV1,
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
) -> Result<PostgresBoundedUpdateV1, ProfileContractError> {
    if canonical.profile() != &expected_profile()? || canonical.media_type().as_str() != MEDIA_TYPE
    {
        return Err(ProfileContractError::UnsupportedProfile);
    }
    let action = PostgresBoundedUpdateV1::from_canonical_bytes(canonical.body())
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

fn permission(action: &PostgresBoundedUpdateV1) -> Result<Permission, ProfileContractError> {
    let server = sha256(action.database_server_identity.as_bytes());
    let database = sha256(action.intent.database_name.as_str().as_bytes());
    let resource = format!(
        "postgresql://{server}/{database}/{}/{}/{}/{}/{}",
        action.relation_oid,
        action.tenant_commitment,
        action.row_set_digest,
        action.before_state_digest,
        action.after_state_digest
    );
    Ok(Permission::new(
        CapabilityId::parse(UPDATE_CAPABILITY)
            .map_err(|_| ProfileContractError::MeaningMismatch)?,
        ResourceId::parse(&resource).map_err(|_| ProfileContractError::MeaningMismatch)?,
    ))
}

impl From<ValidationError> for ProfileContractError {
    fn from(error: ValidationError) -> Self {
        match error {
            ValidationError::LimitExceeded => Self::LimitExceeded,
            ValidationError::MalformedMutation => Self::Malformed,
            ValidationError::NonCanonical => Self::NonCanonical,
            ValidationError::UnsupportedProfile => Self::UnsupportedProfile,
            ValidationError::UnsupportedValue
            | ValidationError::InvalidConfiguration
            | ValidationError::InvalidEvidence
            | ValidationError::Canonicalization => Self::MeaningMismatch,
        }
    }
}

#[cfg(test)]
mod tests {
    use auths_profile_api::ActionProfile as _;

    use super::*;
    use crate::test_support::fixture;

    #[test]
    fn profile_binds_transition_and_one_effect() {
        let fixture = fixture();
        let canonical = PostgresBoundedUpdateProfile
            .canonicalize(&fixture.action.canonical_bytes().unwrap())
            .unwrap();
        assert_eq!(
            canonical.permission().capability().as_str(),
            UPDATE_CAPABILITY
        );
        assert!(
            canonical
                .permission()
                .resource()
                .as_str()
                .contains(fixture.action.after_state_digest.as_str())
        );
        assert_eq!(canonical.requested_budget().unwrap().value(), 1);
    }
}

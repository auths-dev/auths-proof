//! Auths profiles and verified commands for the two records operations.

use auths_model::{
    BudgetAlgebraId, BudgetCeiling, CanonicalAction, CapabilityId, MediaType, Permission,
    ProfileId, ProfileRef, ResourceId,
};
use auths_profile_api::{
    ActionProfile, ProfileBudgetExpression, ProfileContractError, ReviewDisplay,
};
use auths_sdk::VerifiedAction;

use crate::{
    CREATE_PROFILE_ID, CreateRecordV1, MEDIA_TYPE, PROFILE_VERSION, READ_PROFILE_ID, ReadRecordV1,
    RecordsError, canonical::sha256,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedCreateRecordCommand {
    action: CreateRecordV1,
}

impl VerifiedCreateRecordCommand {
    #[must_use]
    pub const fn action(&self) -> &CreateRecordV1 {
        &self.action
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedReadRecordCommand {
    action: ReadRecordV1,
}

impl VerifiedReadRecordCommand {
    #[must_use]
    pub const fn action(&self) -> &ReadRecordV1 {
        &self.action
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CreateRecordProfile;

impl ActionProfile for CreateRecordProfile {
    type Command = VerifiedCreateRecordCommand;

    /// `canonical_create` always declares one `numeric-ceiling-v1` unit.
    const BUDGET_EXPRESSION: ProfileBudgetExpression = ProfileBudgetExpression::Expressible;

    fn canonicalize(&self, untrusted: &[u8]) -> Result<CanonicalAction, ProfileContractError> {
        let action =
            CreateRecordV1::from_canonical_bytes(untrusted).map_err(ProfileContractError::from)?;
        canonical_create(
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
        let action = validate_create(canonical)?;
        Ok(ReviewDisplay::new(
            "Auths V1 · Create one record",
            vec![
                ("Namespace".into(), action.namespace_id.as_str().into()),
                ("Record".into(), action.record_id.as_str().into()),
                ("Customer".into(), action.customer.name.clone()),
                ("Executor".into(), action.executor_audience.clone()),
            ],
            sha256(canonical.body()),
        ))
    }

    fn decode_verified(
        &self,
        verified: &VerifiedAction,
    ) -> Result<Self::Command, ProfileContractError> {
        Ok(VerifiedCreateRecordCommand {
            action: validate_create(verified.canonical_action())?,
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ReadRecordProfile;

impl ActionProfile for ReadRecordProfile {
    type Command = VerifiedReadRecordCommand;

    /// `canonical_read` always declares one `numeric-ceiling-v1` unit.
    const BUDGET_EXPRESSION: ProfileBudgetExpression = ProfileBudgetExpression::Expressible;

    fn canonicalize(&self, untrusted: &[u8]) -> Result<CanonicalAction, ProfileContractError> {
        let action =
            ReadRecordV1::from_canonical_bytes(untrusted).map_err(ProfileContractError::from)?;
        canonical_read(
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
        let action = validate_read(canonical)?;
        Ok(ReviewDisplay::new(
            "Auths V1 · Read one record projection",
            vec![
                ("Namespace".into(), action.namespace_id.as_str().into()),
                ("Record".into(), action.record_id.as_str().into()),
                ("Fields".into(), format!("{:?}", action.allowed_fields)),
                (
                    "Response ceiling".into(),
                    action.maximum_response_bytes.to_string(),
                ),
                ("Executor".into(), action.executor_audience.clone()),
            ],
            sha256(canonical.body()),
        ))
    }

    fn decode_verified(
        &self,
        verified: &VerifiedAction,
    ) -> Result<Self::Command, ProfileContractError> {
        Ok(VerifiedReadRecordCommand {
            action: validate_read(verified.canonical_action())?,
        })
    }
}

fn canonical_create(
    action: &CreateRecordV1,
    body: Vec<u8>,
) -> Result<CanonicalAction, ProfileContractError> {
    CanonicalAction::new(
        profile(CREATE_PROFILE_ID)?,
        media_type()?,
        body,
        Permission::new(
            CapabilityId::parse("records.create")
                .map_err(|_| ProfileContractError::MeaningMismatch)?,
            ResourceId::parse(&format!(
                "records://{}/{}",
                action.namespace_id.as_str(),
                action.record_id.as_str()
            ))
            .map_err(|_| ProfileContractError::MeaningMismatch)?,
        ),
        Some(BudgetCeiling::new(
            BudgetAlgebraId::parse("numeric-ceiling-v1")
                .map_err(|_| ProfileContractError::MeaningMismatch)?,
            1,
        )),
    )
    .map_err(|_| ProfileContractError::LimitExceeded)
}

fn canonical_read(
    action: &ReadRecordV1,
    body: Vec<u8>,
) -> Result<CanonicalAction, ProfileContractError> {
    CanonicalAction::new(
        profile(READ_PROFILE_ID)?,
        media_type()?,
        body,
        Permission::new(
            CapabilityId::parse("records.read")
                .map_err(|_| ProfileContractError::MeaningMismatch)?,
            ResourceId::parse(&format!(
                "records://{}/{}",
                action.namespace_id.as_str(),
                action.record_id.as_str()
            ))
            .map_err(|_| ProfileContractError::MeaningMismatch)?,
        ),
        Some(BudgetCeiling::new(
            BudgetAlgebraId::parse("numeric-ceiling-v1")
                .map_err(|_| ProfileContractError::MeaningMismatch)?,
            1,
        )),
    )
    .map_err(|_| ProfileContractError::LimitExceeded)
}

fn validate_create(canonical: &CanonicalAction) -> Result<CreateRecordV1, ProfileContractError> {
    if canonical.profile() != &profile(CREATE_PROFILE_ID)?
        || canonical.media_type().as_str() != MEDIA_TYPE
    {
        return Err(ProfileContractError::UnsupportedProfile);
    }
    let action = CreateRecordV1::from_canonical_bytes(canonical.body())
        .map_err(ProfileContractError::from)?;
    let expected = canonical_create(&action, canonical.body().to_vec())?;
    validate_semantics(canonical, &expected)?;
    Ok(action)
}

fn validate_read(canonical: &CanonicalAction) -> Result<ReadRecordV1, ProfileContractError> {
    if canonical.profile() != &profile(READ_PROFILE_ID)?
        || canonical.media_type().as_str() != MEDIA_TYPE
    {
        return Err(ProfileContractError::UnsupportedProfile);
    }
    let action =
        ReadRecordV1::from_canonical_bytes(canonical.body()).map_err(ProfileContractError::from)?;
    let expected = canonical_read(&action, canonical.body().to_vec())?;
    validate_semantics(canonical, &expected)?;
    Ok(action)
}

fn validate_semantics(
    canonical: &CanonicalAction,
    expected: &CanonicalAction,
) -> Result<(), ProfileContractError> {
    if canonical.permission() != expected.permission()
        || canonical.requested_budget() != expected.requested_budget()
        || !canonical.detached_attachments().is_empty()
    {
        return Err(ProfileContractError::MeaningMismatch);
    }
    Ok(())
}

fn profile(id: &str) -> Result<ProfileRef, ProfileContractError> {
    ProfileRef::new(
        ProfileId::parse(id).map_err(|_| ProfileContractError::UnsupportedProfile)?,
        PROFILE_VERSION,
    )
    .map_err(|_| ProfileContractError::UnsupportedProfile)
}

fn media_type() -> Result<MediaType, ProfileContractError> {
    MediaType::parse(MEDIA_TYPE).map_err(|_| ProfileContractError::UnsupportedProfile)
}

impl From<RecordsError> for ProfileContractError {
    fn from(error: RecordsError) -> Self {
        match error {
            RecordsError::LimitExceeded => Self::LimitExceeded,
            RecordsError::Malformed | RecordsError::Canonicalization => Self::Malformed,
            RecordsError::NonCanonical => Self::NonCanonical,
            RecordsError::MeaningMismatch | RecordsError::StateUnavailable => Self::MeaningMismatch,
        }
    }
}

#[cfg(test)]
mod tests {
    use auths_profile_api::ActionProfile as _;

    use super::*;
    use crate::{
        BoundedRecordApiPolicyV1, CREATE_OPERATION, CustomerRecordV1, READ_OPERATION, ReadField,
        RecordIdentifier, demo_configuration,
    };

    #[test]
    fn verified_commands_are_decoded_only_from_sealed_auths_output() {
        let configuration = demo_configuration("https://records-executor.auths.dev");
        let policy = BoundedRecordApiPolicyV1 {
            policy_type: "auths.demo.bounded-record-api-policy".into(),
            policy_version: 1,
            policy_id: "fixture".into(),
            namespace_id: RecordIdentifier::parse("visitor-fixture").unwrap(),
            presenter_principal: "key:fixture".into(),
            allowed_operations: vec![CREATE_OPERATION.into(), READ_OPERATION.into()],
            allowed_record_ids: Vec::new(),
            allowed_record_id_prefixes: vec!["demo-".into()],
            maximum_value_bytes: 1024,
            maximum_response_bytes: 4096,
            allowed_read_fields: vec![ReadField::Customer, ReadField::RecordId],
            maximum_creates: 1,
            maximum_reads: 1,
            maximum_created_bytes: 1024,
            maximum_disclosed_bytes: 4096,
            fixed_and_rolling_budgets: Vec::new(),
            valid_from: 100,
            expires_at: 1_000,
            maximum_action_lifetime_seconds: 300,
            maximum_presentation_lifetime_seconds: 120,
            maximum_evidence_age_seconds: 60,
            executor_audience: configuration.configured_executor_audience.clone(),
        };
        let action = CreateRecordV1 {
            profile: "auths.demo.records.create/1".into(),
            namespace_id: policy.namespace_id.clone(),
            record_id: RecordIdentifier::parse("demo-one").unwrap(),
            customer: CustomerRecordV1 {
                age: 25,
                name: "Bob".into(),
                notes: "Demo customer".into(),
                occupation: "Sales".into(),
            },
            value_encoding: "auths.demo.customer-record/1".into(),
            expected_absent: true,
            policy_digest: policy.digest().unwrap(),
            required_evaluator: "auths.records.create-evaluator/1".into(),
            required_configuration_digest: configuration.digest().unwrap(),
            executor_audience: policy.executor_audience,
            expires_at: 500,
            nonce: "fixture-nonce-0001".into(),
        };
        let canonical = CreateRecordProfile
            .canonicalize(&action.canonical_bytes().unwrap())
            .unwrap();
        assert_eq!(canonical.profile().id().as_str(), CREATE_PROFILE_ID);
        assert_eq!(
            canonical.permission().capability().as_str(),
            "records.create"
        );
    }
}

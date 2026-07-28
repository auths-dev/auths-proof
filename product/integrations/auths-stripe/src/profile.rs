//! Auths application profile for one exact Stripe refund.

use auths_model::{
    BudgetAlgebraId, BudgetCeiling, CanonicalAction, CapabilityId, MediaType, Permission,
    ProfileId, ProfileRef, ResourceId,
};
use auths_profile_api::{ActionProfile, ApprovalDisplay, ProfileContractError};
use auths_sdk::VerifiedAction;
use sha2::{Digest as _, Sha256};

use crate::types::{
    ExactRefundActionV1, MAX_ACTION_BYTES, MEDIA_TYPE, PROFILE_ID, PROFILE_VERSION,
    REFUND_CAPABILITY, ValidationError,
};

const REFUND_BUDGET_ALGEBRA: &str = "numeric-ceiling-v1";

/// Profile-decoded command obtainable only from an Auths-verified action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StripeRefundCommand {
    action: ExactRefundActionV1,
}

impl StripeRefundCommand {
    /// Returns the exact action authorized by Auths.
    #[must_use]
    pub const fn action(&self) -> &ExactRefundActionV1 {
        &self.action
    }
}

/// `auths.stripe.exact-refund/1` profile implementation.
#[derive(Clone, Copy, Debug, Default)]
pub struct StripeRefundProfile;

impl ActionProfile for StripeRefundProfile {
    type Command = StripeRefundCommand;

    fn canonicalize(&self, untrusted: &[u8]) -> Result<CanonicalAction, ProfileContractError> {
        if untrusted.is_empty() || untrusted.len() > MAX_ACTION_BYTES {
            return Err(ProfileContractError::LimitExceeded);
        }
        let action: ExactRefundActionV1 =
            serde_json::from_slice(untrusted).map_err(|_| ProfileContractError::Malformed)?;
        action.validate().map_err(ProfileContractError::from)?;
        let body = action
            .canonical_bytes()
            .map_err(|_| ProfileContractError::Malformed)?;
        canonical_action(&action, body)
    }

    fn approval_display(
        &self,
        canonical: &CanonicalAction,
    ) -> Result<ApprovalDisplay, ProfileContractError> {
        let action = validate_canonical_action(canonical)?;
        Ok(ApprovalDisplay::new(
            "Auths V1 · Refund one Stripe test payment",
            vec![
                ("Account".into(), action.stripe_account_id().to_string()),
                ("Charge".into(), action.charge_id().to_string()),
                (
                    "Amount".into(),
                    format!(
                        "{} {} minor units",
                        action.amount().amount_minor(),
                        action.amount().currency()
                    ),
                ),
                (
                    "Reason".into(),
                    action.reason().unwrap_or("unspecified").to_owned(),
                ),
                ("Mode".into(), "test".into()),
                ("Executor".into(), action.executor_audience().to_owned()),
                (
                    "Idempotency key".into(),
                    action.idempotency_key().to_owned(),
                ),
            ],
            hex::encode(Sha256::digest(canonical.body())),
        ))
    }

    fn decode_verified(
        &self,
        verified: &VerifiedAction,
    ) -> Result<Self::Command, ProfileContractError> {
        Ok(StripeRefundCommand {
            action: validate_canonical_action(verified.canonical_action())?,
        })
    }
}

fn canonical_action(
    action: &ExactRefundActionV1,
    body: Vec<u8>,
) -> Result<CanonicalAction, ProfileContractError> {
    CanonicalAction::new(
        expected_profile()?,
        MediaType::parse(MEDIA_TYPE).map_err(|_| ProfileContractError::UnsupportedProfile)?,
        body,
        permission(action)?,
        Some(BudgetCeiling::new(
            BudgetAlgebraId::parse(REFUND_BUDGET_ALGEBRA)
                .map_err(|_| ProfileContractError::MeaningMismatch)?,
            1,
        )),
    )
    .map_err(|_| ProfileContractError::LimitExceeded)
}

fn validate_canonical_action(
    canonical: &CanonicalAction,
) -> Result<ExactRefundActionV1, ProfileContractError> {
    if canonical.profile() != &expected_profile()? || canonical.media_type().as_str() != MEDIA_TYPE
    {
        return Err(ProfileContractError::UnsupportedProfile);
    }
    let action = ExactRefundActionV1::from_canonical_bytes(canonical.body())
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

fn permission(action: &ExactRefundActionV1) -> Result<Permission, ProfileContractError> {
    let resource = format!(
        "stripe-test://{}/charges/{}/refunds/{}",
        action.stripe_account_id(),
        action.charge_id(),
        action.workflow_id()
    );
    Ok(Permission::new(
        CapabilityId::parse(REFUND_CAPABILITY)
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
            ValidationError::InvalidMoney
            | ValidationError::InvalidConfiguration
            | ValidationError::InvalidEvidence
            | ValidationError::InvalidProviderResult => Self::MeaningMismatch,
        }
    }
}

#[cfg(test)]
mod tests {
    use auths_profile_api::ActionProfile as _;

    use super::*;
    use crate::{
        test_support::{action, configuration, evidence},
        types::REFUND_CAPABILITY,
    };

    #[test]
    fn profile_binds_exact_refund_and_one_write_budget() {
        let configuration = configuration(1_500);
        let evidence = evidence(2_000, 0);
        let action = action(&configuration, &evidence, 1_000);
        let canonical = StripeRefundProfile
            .canonicalize(&action.canonical_bytes().unwrap())
            .unwrap();

        assert_eq!(
            canonical.permission().capability().as_str(),
            REFUND_CAPABILITY
        );
        assert!(canonical.permission().resource().as_str().contains("ch_"));
        let budget = canonical.requested_budget().unwrap();
        assert_eq!(budget.algebra().as_str(), "numeric-ceiling-v1");
        assert_eq!(budget.value(), 1);
    }
}

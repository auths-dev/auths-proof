//! Auths profile for one exact Connect Transfer.

#![allow(
    clippy::must_use_candidate,
    reason = "the verified command exposes one immutable action"
)]

use auths_model::{
    CanonicalAction, CapabilityId, MediaType, Permission, ProfileId, ProfileRef, ResourceId,
};
use auths_profile_api::{
    ActionProfile, ProfileBudgetExpression, ProfileContractError, ReviewDisplay,
};
use auths_sdk::VerifiedAction;
use sha2::{Digest as _, Sha256};

use super::StripeExactConnectTransferV1;

const CAPABILITY: &str = "stripe.connect-transfer/create";
const MEDIA_TYPE: &str = "application/vnd.auths.stripe.connect-transfer+json;version=1";
const MAX_ACTION_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StripeConnectTransferCommand {
    action: StripeExactConnectTransferV1,
}

impl StripeConnectTransferCommand {
    pub const fn action(&self) -> &StripeExactConnectTransferV1 {
        &self.action
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct StripeConnectTransferProfile;

impl ActionProfile for StripeConnectTransferProfile {
    type Command = StripeConnectTransferCommand;

    /// `canonical_action` passes `None` and `validate_canonical` rejects any
    /// requested budget.
    const BUDGET_EXPRESSION: ProfileBudgetExpression = ProfileBudgetExpression::Inexpressible;

    fn canonicalize(&self, untrusted: &[u8]) -> Result<CanonicalAction, ProfileContractError> {
        if untrusted.is_empty() || untrusted.len() > MAX_ACTION_BYTES {
            return Err(ProfileContractError::LimitExceeded);
        }
        let action: StripeExactConnectTransferV1 =
            serde_json::from_slice(untrusted).map_err(|_| ProfileContractError::Malformed)?;
        action
            .validate()
            .map_err(|_| ProfileContractError::Malformed)?;
        canonical_action(
            &action,
            action
                .canonical_bytes()
                .map_err(|_| ProfileContractError::Malformed)?,
        )
    }

    fn review_display(
        &self,
        canonical: &CanonicalAction,
    ) -> Result<ReviewDisplay, ProfileContractError> {
        let action = validate_canonical(canonical)?;
        Ok(ReviewDisplay::new(
            "Auths V1 · Transfer exact platform funds",
            vec![
                (
                    "Destination".into(),
                    action.destination_account_id().to_string(),
                ),
                (
                    "Source Charge".into(),
                    action.source_charge_id().to_string(),
                ),
                (
                    "Amount".into(),
                    format!(
                        "{} {} minor units",
                        action.amount_minor(),
                        action.currency()
                    ),
                ),
                ("Transfer group".into(), action.transfer_group().into()),
                ("Business scope".into(), action.business_scope().into()),
            ],
            hex::encode(Sha256::digest(canonical.body())),
        ))
    }

    fn decode_verified(
        &self,
        verified: &VerifiedAction,
    ) -> Result<Self::Command, ProfileContractError> {
        Ok(StripeConnectTransferCommand {
            action: validate_canonical(verified.canonical_action())?,
        })
    }
}

fn canonical_action(
    action: &StripeExactConnectTransferV1,
    body: Vec<u8>,
) -> Result<CanonicalAction, ProfileContractError> {
    CanonicalAction::new(
        expected_profile()?,
        MediaType::parse(MEDIA_TYPE).map_err(|_| ProfileContractError::UnsupportedProfile)?,
        body,
        permission(action)?,
        None,
    )
    .map_err(|_| ProfileContractError::LimitExceeded)
}

fn validate_canonical(
    canonical: &CanonicalAction,
) -> Result<StripeExactConnectTransferV1, ProfileContractError> {
    if canonical.profile() != &expected_profile()? || canonical.media_type().as_str() != MEDIA_TYPE
    {
        return Err(ProfileContractError::UnsupportedProfile);
    }
    let action: StripeExactConnectTransferV1 =
        serde_json::from_slice(canonical.body()).map_err(|_| ProfileContractError::Malformed)?;
    action
        .validate()
        .map_err(|_| ProfileContractError::Malformed)?;
    let expected = canonical_action(
        &action,
        action
            .canonical_bytes()
            .map_err(|_| ProfileContractError::Malformed)?,
    )?;
    if canonical.body() != expected.body()
        || canonical.permission() != expected.permission()
        || canonical.requested_budget().is_some()
        || !canonical.detached_attachments().is_empty()
    {
        return Err(ProfileContractError::MeaningMismatch);
    }
    Ok(action)
}

fn expected_profile() -> Result<ProfileRef, ProfileContractError> {
    ProfileRef::new(
        ProfileId::parse("auths.stripe.exact-connect-transfer")
            .map_err(|_| ProfileContractError::UnsupportedProfile)?,
        1,
    )
    .map_err(|_| ProfileContractError::UnsupportedProfile)
}

fn permission(action: &StripeExactConnectTransferV1) -> Result<Permission, ProfileContractError> {
    Ok(Permission::new(
        CapabilityId::parse(CAPABILITY).map_err(|_| ProfileContractError::MeaningMismatch)?,
        ResourceId::parse(&format!(
            "stripe-connect://{}/destinations/{}/sources/{}",
            action.platform_account_id(),
            action.destination_account_id(),
            action.source_charge_id()
        ))
        .map_err(|_| ProfileContractError::MeaningMismatch)?,
    ))
}

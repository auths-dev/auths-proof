//! Auths profile for exact Subscription cancellation.

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

use super::StripeExactSubscriptionCancelV1;
use crate::subscription::SubscriptionCancelMode;

const CAPABILITY: &str = "stripe.subscription-cancel/execute";
const MEDIA_TYPE: &str = "application/vnd.auths.stripe.subscription-cancel+json;version=1";
const MAX_ACTION_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StripeSubscriptionCancelCommand {
    action: StripeExactSubscriptionCancelV1,
}

impl StripeSubscriptionCancelCommand {
    pub const fn action(&self) -> &StripeExactSubscriptionCancelV1 {
        &self.action
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct StripeSubscriptionCancelProfile;

impl ActionProfile for StripeSubscriptionCancelProfile {
    type Command = StripeSubscriptionCancelCommand;

    /// `canonical_action` passes `None` and `validate_canonical` requires exact
    /// equality with it.
    const BUDGET_EXPRESSION: ProfileBudgetExpression = ProfileBudgetExpression::Inexpressible;

    fn canonicalize(&self, untrusted: &[u8]) -> Result<CanonicalAction, ProfileContractError> {
        if untrusted.is_empty() || untrusted.len() > MAX_ACTION_BYTES {
            return Err(ProfileContractError::LimitExceeded);
        }
        let action: StripeExactSubscriptionCancelV1 =
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
            "Auths V1 · Cancel exact Subscription",
            vec![
                ("Subscription".into(), action.subscription_id().to_string()),
                ("Customer".into(), action.customer_id().to_string()),
                (
                    "Mode".into(),
                    match action.mode() {
                        SubscriptionCancelMode::AtPeriodEnd => "at current period end",
                        SubscriptionCancelMode::Immediate => "immediately",
                    }
                    .into(),
                ),
                (
                    "Invoice behavior".into(),
                    "invoice_now=false · prorate=false".into(),
                ),
            ],
            hex::encode(Sha256::digest(canonical.body())),
        ))
    }

    fn decode_verified(
        &self,
        verified: &VerifiedAction,
    ) -> Result<Self::Command, ProfileContractError> {
        Ok(StripeSubscriptionCancelCommand {
            action: validate_canonical(verified.canonical_action())?,
        })
    }
}

fn canonical_action(
    action: &StripeExactSubscriptionCancelV1,
    body: Vec<u8>,
) -> Result<CanonicalAction, ProfileContractError> {
    CanonicalAction::new(
        ProfileRef::new(
            ProfileId::parse("auths.stripe.exact-subscription-cancel")
                .map_err(|_| ProfileContractError::UnsupportedProfile)?,
            1,
        )
        .map_err(|_| ProfileContractError::UnsupportedProfile)?,
        MediaType::parse(MEDIA_TYPE).map_err(|_| ProfileContractError::UnsupportedProfile)?,
        body,
        Permission::new(
            CapabilityId::parse(CAPABILITY).map_err(|_| ProfileContractError::MeaningMismatch)?,
            ResourceId::parse(&format!(
                "stripe-subscription://{}/subscriptions/{}",
                action.stripe_account_id(),
                action.subscription_id()
            ))
            .map_err(|_| ProfileContractError::MeaningMismatch)?,
        ),
        None,
    )
    .map_err(|_| ProfileContractError::LimitExceeded)
}

fn validate_canonical(
    canonical: &CanonicalAction,
) -> Result<StripeExactSubscriptionCancelV1, ProfileContractError> {
    let action: StripeExactSubscriptionCancelV1 =
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
    if canonical != &expected {
        return Err(ProfileContractError::MeaningMismatch);
    }
    Ok(action)
}

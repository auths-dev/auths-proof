//! Auths application profile for one exact `PaymentIntent` cancellation.

use auths_model::{
    CanonicalAction, CapabilityId, MediaType, Permission, ProfileId, ProfileRef, ResourceId,
};
use auths_profile_api::{ActionProfile, ApprovalDisplay, ProfileContractError};
use auths_sdk::VerifiedAction;
use sha2::{Digest as _, Sha256};

use super::action::StripeExactPaymentCancelV1;

const CANCEL_CAPABILITY: &str = "stripe.payment-intent/cancel";
const MEDIA_TYPE: &str = "application/vnd.auths.stripe.payment-cancel+json;version=1";
const MAX_ACTION_BYTES: usize = 64 * 1024;

/// Profile-decoded cancellation obtainable only from an Auths-verified action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StripePaymentCancelCommand {
    action: StripeExactPaymentCancelV1,
}

impl StripePaymentCancelCommand {
    #[must_use]
    pub const fn action(&self) -> &StripeExactPaymentCancelV1 {
        &self.action
    }
}

/// `auths.stripe.exact-payment-cancel/1` profile.
#[derive(Clone, Copy, Debug, Default)]
pub struct StripePaymentCancelProfile;

impl ActionProfile for StripePaymentCancelProfile {
    type Command = StripePaymentCancelCommand;

    fn canonicalize(&self, untrusted: &[u8]) -> Result<CanonicalAction, ProfileContractError> {
        if untrusted.is_empty() || untrusted.len() > MAX_ACTION_BYTES {
            return Err(ProfileContractError::LimitExceeded);
        }
        let action: StripeExactPaymentCancelV1 =
            serde_json::from_slice(untrusted).map_err(|_| ProfileContractError::Malformed)?;
        action.validate().map_err(ProfileContractError::from)?;
        canonical_action(
            &action,
            action
                .canonical_bytes()
                .map_err(|_| ProfileContractError::Malformed)?,
        )
    }

    fn approval_display(
        &self,
        canonical: &CanonicalAction,
    ) -> Result<ApprovalDisplay, ProfileContractError> {
        let action = validate_canonical_action(canonical)?;
        Ok(ApprovalDisplay::new(
            "Auths V1 · Cancel one Stripe PaymentIntent",
            vec![
                ("Account".into(), action.stripe_account_id().to_string()),
                (
                    "PaymentIntent".into(),
                    action.payment_intent_id().to_string(),
                ),
                ("Customer".into(), action.customer_id().to_string()),
                ("Order".into(), action.order_scope().into()),
                ("Current state".into(), action.current_status().into()),
                (
                    "Reason".into(),
                    action.cancellation_reason().as_str().into(),
                ),
                (
                    "Hold release".into(),
                    format!(
                        "{} minor units after observation",
                        action.amount_capturable_minor()
                    ),
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
        Ok(StripePaymentCancelCommand {
            action: validate_canonical_action(verified.canonical_action())?,
        })
    }
}

fn canonical_action(
    action: &StripeExactPaymentCancelV1,
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

fn validate_canonical_action(
    canonical: &CanonicalAction,
) -> Result<StripeExactPaymentCancelV1, ProfileContractError> {
    if canonical.profile() != &expected_profile()? || canonical.media_type().as_str() != MEDIA_TYPE
    {
        return Err(ProfileContractError::UnsupportedProfile);
    }
    let action: StripeExactPaymentCancelV1 =
        serde_json::from_slice(canonical.body()).map_err(|_| ProfileContractError::Malformed)?;
    action.validate().map_err(ProfileContractError::from)?;
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
        ProfileId::parse("auths.stripe.exact-payment-cancel")
            .map_err(|_| ProfileContractError::UnsupportedProfile)?,
        1,
    )
    .map_err(|_| ProfileContractError::UnsupportedProfile)
}

fn permission(action: &StripeExactPaymentCancelV1) -> Result<Permission, ProfileContractError> {
    let resource = format!(
        "stripe-test://{}/payment-intents/{}/cancel/{}",
        action.stripe_account_id(),
        action.payment_intent_id(),
        action.cancellation_reason().as_str(),
    );
    Ok(Permission::new(
        CapabilityId::parse(CANCEL_CAPABILITY)
            .map_err(|_| ProfileContractError::MeaningMismatch)?,
        ResourceId::parse(&resource).map_err(|_| ProfileContractError::MeaningMismatch)?,
    ))
}

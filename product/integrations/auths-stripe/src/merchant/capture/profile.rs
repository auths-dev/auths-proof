//! Auths application profile for one exact final capture.

use auths_model::{
    BudgetAlgebraId, BudgetCeiling, CanonicalAction, CapabilityId, MediaType, Permission,
    ProfileId, ProfileRef, ResourceId,
};
use auths_profile_api::{
    ActionProfile, ProfileBudgetExpression, ProfileContractError, ReviewDisplay,
};
use auths_sdk::VerifiedAction;
use sha2::{Digest as _, Sha256};

use super::action::StripeExactPaymentCaptureV1;

const CAPTURE_CAPABILITY: &str = "stripe.payment-intent/capture";
const BUDGET_ALGEBRA: &str = "numeric-ceiling-v1";
const MEDIA_TYPE: &str = "application/vnd.auths.stripe.payment-capture+json;version=1";
const MAX_ACTION_BYTES: usize = 64 * 1024;

/// Profile-decoded capture obtainable only from an Auths-verified action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StripePaymentCaptureCommand {
    action: StripeExactPaymentCaptureV1,
}

impl StripePaymentCaptureCommand {
    /// Exact action opened by the verified proof.
    #[must_use]
    pub const fn action(&self) -> &StripeExactPaymentCaptureV1 {
        &self.action
    }
}

/// `auths.stripe.exact-payment-capture/1` profile.
#[derive(Clone, Copy, Debug, Default)]
pub struct StripePaymentCaptureProfile;

impl ActionProfile for StripePaymentCaptureProfile {
    type Command = StripePaymentCaptureCommand;

    /// `canonical_action` declares the exact minor-unit capture amount as a
    /// `numeric-ceiling-v1` request.
    const BUDGET_EXPRESSION: ProfileBudgetExpression = ProfileBudgetExpression::Expressible;

    fn canonicalize(&self, untrusted: &[u8]) -> Result<CanonicalAction, ProfileContractError> {
        if untrusted.is_empty() || untrusted.len() > MAX_ACTION_BYTES {
            return Err(ProfileContractError::LimitExceeded);
        }
        let action: StripeExactPaymentCaptureV1 =
            serde_json::from_slice(untrusted).map_err(|_| ProfileContractError::Malformed)?;
        action.validate().map_err(ProfileContractError::from)?;
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
        let action = validate_canonical_action(canonical)?;
        Ok(ReviewDisplay::new(
            "Auths V1 · Capture one Stripe authorization",
            vec![
                ("Account".into(), action.stripe_account_id().to_string()),
                (
                    "PaymentIntent".into(),
                    action.payment_intent_id().to_string(),
                ),
                ("Charge".into(), action.latest_charge_id().to_string()),
                ("Customer".into(), action.customer_id().to_string()),
                ("Order".into(), action.order_scope().into()),
                (
                    "Capture".into(),
                    format!(
                        "{} {} minor units",
                        action.amount_to_capture_minor(),
                        action.currency()
                    ),
                ),
                (
                    "Hold before".into(),
                    format!("{} minor units", action.amount_capturable_before_minor()),
                ),
                ("Mode".into(), "final capture; test".into()),
                ("Executor".into(), action.executor_audience().into()),
            ],
            hex::encode(Sha256::digest(canonical.body())),
        ))
    }

    fn decode_verified(
        &self,
        verified: &VerifiedAction,
    ) -> Result<Self::Command, ProfileContractError> {
        Ok(StripePaymentCaptureCommand {
            action: validate_canonical_action(verified.canonical_action())?,
        })
    }
}

fn canonical_action(
    action: &StripeExactPaymentCaptureV1,
    body: Vec<u8>,
) -> Result<CanonicalAction, ProfileContractError> {
    CanonicalAction::new(
        expected_profile()?,
        MediaType::parse(MEDIA_TYPE).map_err(|_| ProfileContractError::UnsupportedProfile)?,
        body,
        permission(action)?,
        Some(BudgetCeiling::new(
            BudgetAlgebraId::parse(BUDGET_ALGEBRA)
                .map_err(|_| ProfileContractError::MeaningMismatch)?,
            action.amount_to_capture_minor(),
        )),
    )
    .map_err(|_| ProfileContractError::LimitExceeded)
}

fn validate_canonical_action(
    canonical: &CanonicalAction,
) -> Result<StripeExactPaymentCaptureV1, ProfileContractError> {
    if canonical.profile() != &expected_profile()? || canonical.media_type().as_str() != MEDIA_TYPE
    {
        return Err(ProfileContractError::UnsupportedProfile);
    }
    let action: StripeExactPaymentCaptureV1 =
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
        || canonical.requested_budget() != expected.requested_budget()
        || !canonical.detached_attachments().is_empty()
    {
        return Err(ProfileContractError::MeaningMismatch);
    }
    Ok(action)
}

fn expected_profile() -> Result<ProfileRef, ProfileContractError> {
    ProfileRef::new(
        ProfileId::parse("auths.stripe.exact-payment-capture")
            .map_err(|_| ProfileContractError::UnsupportedProfile)?,
        1,
    )
    .map_err(|_| ProfileContractError::UnsupportedProfile)
}

fn permission(action: &StripeExactPaymentCaptureV1) -> Result<Permission, ProfileContractError> {
    let resource = format!(
        "stripe-test://{}/payment-intents/{}/authorizations/{}",
        action.stripe_account_id(),
        action.payment_intent_id(),
        action.authorization_reservation_id()
    );
    Ok(Permission::new(
        CapabilityId::parse(CAPTURE_CAPABILITY)
            .map_err(|_| ProfileContractError::MeaningMismatch)?,
        ResourceId::parse(&resource).map_err(|_| ProfileContractError::MeaningMismatch)?,
    ))
}

#[cfg(test)]
mod tests {
    use auths_profile_api::ActionProfile as _;

    use super::*;
    use crate::{
        merchant::{MerchantOperation, StripePaymentAuthorizeProfile},
        test_support::{
            merchant_authorize_action, merchant_authorize_configuration, merchant_capture_action,
            merchant_capture_configuration, merchant_policy,
        },
    };

    #[test]
    fn capture_profile_cannot_open_an_authorization_action() {
        let capture_policy = merchant_policy(MerchantOperation::Capture, 1_000, 2_000);
        let capture_configuration = merchant_capture_configuration(&capture_policy);
        let capture = merchant_capture_action(
            "merchant-capture-profile-0001",
            &capture_policy,
            &capture_configuration,
            500,
        );
        let authorize_policy = merchant_policy(MerchantOperation::Authorize, 1_000, 2_000);
        let authorize_configuration = merchant_authorize_configuration(&authorize_policy);
        let authorize = merchant_authorize_action(
            "merchant-authorize-profile-0001",
            &authorize_policy,
            &authorize_configuration,
            1_000,
        );

        assert!(
            StripePaymentCaptureProfile
                .canonicalize(&authorize.canonical_bytes().unwrap())
                .is_err()
        );
        assert!(
            StripePaymentAuthorizeProfile
                .canonicalize(&capture.canonical_bytes().unwrap())
                .is_err()
        );
        let canonical = StripePaymentCaptureProfile
            .canonicalize(&capture.canonical_bytes().unwrap())
            .unwrap();
        assert_eq!(
            canonical.permission().capability().as_str(),
            CAPTURE_CAPABILITY
        );
        assert_eq!(
            canonical.requested_budget(),
            Some(&BudgetCeiling::new(
                BudgetAlgebraId::parse(BUDGET_ALGEBRA).unwrap(),
                capture.amount_to_capture_minor(),
            ))
        );
    }
}

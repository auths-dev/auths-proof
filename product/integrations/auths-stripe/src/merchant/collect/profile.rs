//! Auths application profile for one exact Stripe merchant collection.

use auths_model::{
    BudgetAlgebraId, BudgetCeiling, CanonicalAction, CapabilityId, MediaType, Permission,
    ProfileId, ProfileRef, ResourceId,
};
use auths_profile_api::{ActionProfile, ApprovalDisplay, ProfileContractError};
use auths_sdk::VerifiedAction;
use sha2::{Digest as _, Sha256};

use crate::merchant::{MerchantValidationError, StripeExactPaymentCollectV1};

const PAYMENT_COLLECT_CAPABILITY: &str = "stripe.payment-intent/collect";
const PAYMENT_BUDGET_ALGEBRA: &str = "numeric-ceiling-v1";
const PAYMENT_MEDIA_TYPE: &str = "application/vnd.auths.stripe.payment-collect+json;version=1";
const MAX_ACTION_BYTES: usize = 64 * 1024;

/// Profile-decoded collection obtainable only from an Auths-verified action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StripePaymentCollectCommand {
    action: StripeExactPaymentCollectV1,
}

impl StripePaymentCollectCommand {
    /// Exact action opened by the verified proof.
    #[must_use]
    pub const fn action(&self) -> &StripeExactPaymentCollectV1 {
        &self.action
    }
}

/// `auths.stripe.exact-payment-collect/1` profile.
#[derive(Clone, Copy, Debug, Default)]
pub struct StripePaymentCollectProfile;

impl ActionProfile for StripePaymentCollectProfile {
    type Command = StripePaymentCollectCommand;

    fn canonicalize(&self, untrusted: &[u8]) -> Result<CanonicalAction, ProfileContractError> {
        if untrusted.is_empty() || untrusted.len() > MAX_ACTION_BYTES {
            return Err(ProfileContractError::LimitExceeded);
        }
        let action: StripeExactPaymentCollectV1 =
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
            "Auths V1 · Collect one Stripe test payment",
            vec![
                ("Account".into(), action.stripe_account_id().to_string()),
                ("Customer".into(), action.customer_id().to_string()),
                ("Order".into(), action.order_scope().into()),
                (
                    "Amount".into(),
                    format!(
                        "{} {} minor units",
                        action.amount_minor(),
                        action.currency()
                    ),
                ),
                (
                    "Payment method".into(),
                    action.payment_method_id().to_string(),
                ),
                ("Capture".into(), "automatic".into()),
                ("Mode".into(), "test".into()),
                ("Executor".into(), action.executor_audience().into()),
            ],
            hex::encode(Sha256::digest(canonical.body())),
        ))
    }

    fn decode_verified(
        &self,
        verified: &VerifiedAction,
    ) -> Result<Self::Command, ProfileContractError> {
        Ok(StripePaymentCollectCommand {
            action: validate_canonical_action(verified.canonical_action())?,
        })
    }
}

fn canonical_action(
    action: &StripeExactPaymentCollectV1,
    body: Vec<u8>,
) -> Result<CanonicalAction, ProfileContractError> {
    CanonicalAction::new(
        expected_profile()?,
        MediaType::parse(PAYMENT_MEDIA_TYPE)
            .map_err(|_| ProfileContractError::UnsupportedProfile)?,
        body,
        permission(action)?,
        Some(BudgetCeiling::new(
            BudgetAlgebraId::parse(PAYMENT_BUDGET_ALGEBRA)
                .map_err(|_| ProfileContractError::MeaningMismatch)?,
            action.amount_minor(),
        )),
    )
    .map_err(|_| ProfileContractError::LimitExceeded)
}

fn validate_canonical_action(
    canonical: &CanonicalAction,
) -> Result<StripeExactPaymentCollectV1, ProfileContractError> {
    if canonical.profile() != &expected_profile()?
        || canonical.media_type().as_str() != PAYMENT_MEDIA_TYPE
    {
        return Err(ProfileContractError::UnsupportedProfile);
    }
    let action: StripeExactPaymentCollectV1 =
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
        ProfileId::parse("auths.stripe.exact-payment-collect")
            .map_err(|_| ProfileContractError::UnsupportedProfile)?,
        1,
    )
    .map_err(|_| ProfileContractError::UnsupportedProfile)
}

fn permission(action: &StripeExactPaymentCollectV1) -> Result<Permission, ProfileContractError> {
    let resource = format!(
        "stripe-test://{}/customers/{}/orders/{}/collections/{}",
        action.stripe_account_id(),
        action.customer_id(),
        action.order_scope(),
        action.nonce()
    );
    Ok(Permission::new(
        CapabilityId::parse(PAYMENT_COLLECT_CAPABILITY)
            .map_err(|_| ProfileContractError::MeaningMismatch)?,
        ResourceId::parse(&resource).map_err(|_| ProfileContractError::MeaningMismatch)?,
    ))
}

impl From<MerchantValidationError> for ProfileContractError {
    fn from(error: MerchantValidationError) -> Self {
        match error {
            MerchantValidationError::InvalidAction => Self::UnsupportedProfile,
            MerchantValidationError::Canonicalization => Self::Malformed,
            MerchantValidationError::InvalidPolicy
            | MerchantValidationError::InvalidConfiguration
            | MerchantValidationError::InvalidEvidence => Self::MeaningMismatch,
        }
    }
}

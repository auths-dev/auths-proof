//! Auths application profile for one exact manual-capture authorization.

use auths_model::{
    BudgetAlgebraId, BudgetCeiling, CanonicalAction, CapabilityId, MediaType, Permission,
    ProfileId, ProfileRef, ResourceId,
};
use auths_profile_api::{ActionProfile, ProfileContractError, ReviewDisplay};
use auths_sdk::VerifiedAction;
use sha2::{Digest as _, Sha256};

use crate::merchant::StripeExactPaymentAuthorizeV1;

const AUTHORIZE_CAPABILITY: &str = "stripe.payment-intent/authorize";
const BUDGET_ALGEBRA: &str = "numeric-ceiling-v1";
const MEDIA_TYPE: &str = "application/vnd.auths.stripe.payment-authorize+json;version=1";
const MAX_ACTION_BYTES: usize = 64 * 1024;

/// Profile-decoded authorization obtainable only from an Auths-verified action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StripePaymentAuthorizeCommand {
    action: StripeExactPaymentAuthorizeV1,
}

impl StripePaymentAuthorizeCommand {
    /// Exact action opened by the verified proof.
    #[must_use]
    pub const fn action(&self) -> &StripeExactPaymentAuthorizeV1 {
        &self.action
    }
}

/// `auths.stripe.exact-payment-authorize/1` profile.
#[derive(Clone, Copy, Debug, Default)]
pub struct StripePaymentAuthorizeProfile;

impl ActionProfile for StripePaymentAuthorizeProfile {
    type Command = StripePaymentAuthorizeCommand;

    fn canonicalize(&self, untrusted: &[u8]) -> Result<CanonicalAction, ProfileContractError> {
        if untrusted.is_empty() || untrusted.len() > MAX_ACTION_BYTES {
            return Err(ProfileContractError::LimitExceeded);
        }
        let action: StripeExactPaymentAuthorizeV1 =
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
            "Auths V1 · Place one Stripe test authorization hold",
            vec![
                ("Account".into(), action.stripe_account_id().to_string()),
                ("Customer".into(), action.customer_id().to_string()),
                ("Order".into(), action.order_scope().into()),
                (
                    "Hold".into(),
                    format!(
                        "{} {} minor units",
                        action.authorized_amount_minor(),
                        action.currency()
                    ),
                ),
                (
                    "Payment method".into(),
                    action.payment_method_id().to_string(),
                ),
                ("Capture".into(), "manual; no settlement".into()),
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
        Ok(StripePaymentAuthorizeCommand {
            action: validate_canonical_action(verified.canonical_action())?,
        })
    }
}

fn canonical_action(
    action: &StripeExactPaymentAuthorizeV1,
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
            action.authorized_amount_minor(),
        )),
    )
    .map_err(|_| ProfileContractError::LimitExceeded)
}

fn validate_canonical_action(
    canonical: &CanonicalAction,
) -> Result<StripeExactPaymentAuthorizeV1, ProfileContractError> {
    if canonical.profile() != &expected_profile()? || canonical.media_type().as_str() != MEDIA_TYPE
    {
        return Err(ProfileContractError::UnsupportedProfile);
    }
    let action: StripeExactPaymentAuthorizeV1 =
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
        ProfileId::parse("auths.stripe.exact-payment-authorize")
            .map_err(|_| ProfileContractError::UnsupportedProfile)?,
        1,
    )
    .map_err(|_| ProfileContractError::UnsupportedProfile)
}

fn permission(action: &StripeExactPaymentAuthorizeV1) -> Result<Permission, ProfileContractError> {
    let resource = format!(
        "stripe-test://{}/customers/{}/orders/{}/authorizations/{}",
        action.stripe_account_id(),
        action.customer_id(),
        action.order_scope(),
        action.nonce()
    );
    Ok(Permission::new(
        CapabilityId::parse(AUTHORIZE_CAPABILITY)
            .map_err(|_| ProfileContractError::MeaningMismatch)?,
        ResourceId::parse(&resource).map_err(|_| ProfileContractError::MeaningMismatch)?,
    ))
}

#[cfg(test)]
mod tests {
    use auths_profile_api::ActionProfile as _;

    use super::*;
    use crate::{
        merchant::{MerchantOperation, StripePaymentCollectProfile},
        test_support::{
            merchant_authorize_action, merchant_authorize_configuration, merchant_collect_action,
            merchant_configuration, merchant_policy,
        },
    };

    #[test]
    fn collect_and_authorize_profiles_cannot_open_each_others_actions() {
        let collect_policy = merchant_policy(MerchantOperation::Collect, 1_000, 2_000);
        let collect_configuration = merchant_configuration(&collect_policy);
        let collect = merchant_collect_action(
            "merchant-cross-profile-collect",
            &collect_policy,
            &collect_configuration,
            1_000,
        );
        let authorize_policy = merchant_policy(MerchantOperation::Authorize, 1_000, 2_000);
        let authorize_configuration = merchant_authorize_configuration(&authorize_policy);
        let authorize = merchant_authorize_action(
            "merchant-cross-profile-authorize",
            &authorize_policy,
            &authorize_configuration,
            1_000,
        );

        assert!(
            StripePaymentAuthorizeProfile
                .canonicalize(&collect.canonical_bytes().unwrap())
                .is_err()
        );
        assert!(
            StripePaymentCollectProfile
                .canonicalize(&authorize.canonical_bytes().unwrap())
                .is_err()
        );
        let collect_canonical = StripePaymentCollectProfile
            .canonicalize(&collect.canonical_bytes().unwrap())
            .unwrap();
        let authorize_canonical = StripePaymentAuthorizeProfile
            .canonicalize(&authorize.canonical_bytes().unwrap())
            .unwrap();
        assert_ne!(collect_canonical.profile(), authorize_canonical.profile());
        assert_ne!(collect.digest().unwrap(), authorize.digest().unwrap());
        assert_ne!(collect_canonical.body(), authorize_canonical.body());
    }
}

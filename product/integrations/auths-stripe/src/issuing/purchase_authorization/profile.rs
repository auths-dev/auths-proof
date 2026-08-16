//! Auths action profile for one exact Issuing authorization.

#![allow(
    clippy::must_use_candidate,
    reason = "the verified command exposes one immutable action accessor"
)]

use auths_model::{
    CanonicalAction, CapabilityId, MediaType, Permission, ProfileId, ProfileRef, ResourceId,
};
use auths_profile_api::{
    ActionProfile, ProfileBudgetExpression, ProfileContractError, ReviewDisplay,
};
use auths_sdk::VerifiedAction;
use sha2::{Digest as _, Sha256};

use super::StripeExactPurchaseAuthorizationV1;

const CAPABILITY: &str = "stripe.issuing-authorization/decide";
const MEDIA_TYPE: &str = "application/vnd.auths.stripe.purchase-authorization+json;version=1";
const MAX_ACTION_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StripePurchaseAuthorizationCommand {
    action: StripeExactPurchaseAuthorizationV1,
}

impl StripePurchaseAuthorizationCommand {
    pub const fn action(&self) -> &StripeExactPurchaseAuthorizationV1 {
        &self.action
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct StripePurchaseAuthorizationProfile;

impl ActionProfile for StripePurchaseAuthorizationProfile {
    type Command = StripePurchaseAuthorizationCommand;

    /// `canonical_action` passes `None` and `validate_canonical` rejects any
    /// requested budget.
    const BUDGET_EXPRESSION: ProfileBudgetExpression = ProfileBudgetExpression::Inexpressible;

    fn canonicalize(&self, untrusted: &[u8]) -> Result<CanonicalAction, ProfileContractError> {
        if untrusted.is_empty() || untrusted.len() > MAX_ACTION_BYTES {
            return Err(ProfileContractError::LimitExceeded);
        }
        let action: StripeExactPurchaseAuthorizationV1 =
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
            "Auths V1 · Decide one bounded Stripe Issuing purchase",
            vec![
                ("Merchant".into(), action.merchant_id().into()),
                ("Category".into(), action.merchant_category().into()),
                ("Country".into(), action.merchant_country().into()),
                (
                    "Full amount".into(),
                    format!(
                        "{} {} minor units",
                        action.amount_minor(),
                        action.currency()
                    ),
                ),
                (
                    "Procurement scope".into(),
                    action.procurement_scope().into(),
                ),
            ],
            hex::encode(Sha256::digest(canonical.body())),
        ))
    }

    fn decode_verified(
        &self,
        verified: &VerifiedAction,
    ) -> Result<Self::Command, ProfileContractError> {
        Ok(StripePurchaseAuthorizationCommand {
            action: validate_canonical(verified.canonical_action())?,
        })
    }
}

fn canonical_action(
    action: &StripeExactPurchaseAuthorizationV1,
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
) -> Result<StripeExactPurchaseAuthorizationV1, ProfileContractError> {
    if canonical.profile() != &expected_profile()? || canonical.media_type().as_str() != MEDIA_TYPE
    {
        return Err(ProfileContractError::UnsupportedProfile);
    }
    let action: StripeExactPurchaseAuthorizationV1 =
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
        ProfileId::parse("auths.stripe.exact-purchase-authorization")
            .map_err(|_| ProfileContractError::UnsupportedProfile)?,
        1,
    )
    .map_err(|_| ProfileContractError::UnsupportedProfile)
}

fn permission(
    action: &StripeExactPurchaseAuthorizationV1,
) -> Result<Permission, ProfileContractError> {
    Ok(Permission::new(
        CapabilityId::parse(CAPABILITY).map_err(|_| ProfileContractError::MeaningMismatch)?,
        ResourceId::parse(&format!(
            "stripe-issuing://{}/authorizations/{}",
            action.stripe_account_id(),
            action.authorization_id()
        ))
        .map_err(|_| ProfileContractError::MeaningMismatch)?,
    ))
}

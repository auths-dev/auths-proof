//! Auths action profile for one exact Subscription modification.

use auths_model::{
    CanonicalAction, CapabilityId, MediaType, Permission, ProfileId, ProfileRef, ResourceId,
};
use auths_profile_api::{ActionProfile, ProfileContractError, ReviewDisplay};
use auths_sdk::VerifiedAction;
use sha2::{Digest as _, Sha256};

use super::StripeExactSubscriptionModifyV1;

const CAPABILITY: &str = "stripe.subscription/modify";
const MEDIA_TYPE: &str = "application/vnd.auths.stripe.subscription-modify+json;version=1";
const MAX_ACTION_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StripeSubscriptionModifyCommand {
    action: StripeExactSubscriptionModifyV1,
}

impl StripeSubscriptionModifyCommand {
    pub const fn action(&self) -> &StripeExactSubscriptionModifyV1 {
        &self.action
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct StripeSubscriptionModifyProfile;

impl ActionProfile for StripeSubscriptionModifyProfile {
    type Command = StripeSubscriptionModifyCommand;

    fn canonicalize(&self, untrusted: &[u8]) -> Result<CanonicalAction, ProfileContractError> {
        if untrusted.is_empty() || untrusted.len() > MAX_ACTION_BYTES {
            return Err(ProfileContractError::LimitExceeded);
        }
        let action: StripeExactSubscriptionModifyV1 =
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
            "Auths V1 · Modify one bounded Stripe subscription",
            vec![
                ("Subscription".into(), action.subscription_id().to_string()),
                (
                    "Recurring before → after".into(),
                    format!(
                        "{} → {} {} minor units",
                        action.before_recurring_minor(),
                        action.after_recurring_minor(),
                        action.currency()
                    ),
                ),
                (
                    "Independent proration debit".into(),
                    format!("{} minor units", action.proration_debit_minor()),
                ),
                (
                    "Observed credit".into(),
                    format!("{} minor units", action.proration_credit_minor()),
                ),
                (
                    "Incremental term liability".into(),
                    format!("{} minor units", action.incremental_term_liability_minor()),
                ),
                ("Payment behavior".into(), "pending_if_incomplete".into()),
            ],
            hex::encode(Sha256::digest(canonical.body())),
        ))
    }

    fn decode_verified(
        &self,
        verified: &VerifiedAction,
    ) -> Result<Self::Command, ProfileContractError> {
        Ok(StripeSubscriptionModifyCommand {
            action: validate_canonical(verified.canonical_action())?,
        })
    }
}

fn canonical_action(
    action: &StripeExactSubscriptionModifyV1,
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
) -> Result<StripeExactSubscriptionModifyV1, ProfileContractError> {
    if canonical.profile() != &expected_profile()? || canonical.media_type().as_str() != MEDIA_TYPE
    {
        return Err(ProfileContractError::UnsupportedProfile);
    }
    let action: StripeExactSubscriptionModifyV1 =
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
        ProfileId::parse("auths.stripe.exact-subscription-modify")
            .map_err(|_| ProfileContractError::UnsupportedProfile)?,
        1,
    )
    .map_err(|_| ProfileContractError::UnsupportedProfile)
}

fn permission(
    action: &StripeExactSubscriptionModifyV1,
) -> Result<Permission, ProfileContractError> {
    let resource = format!(
        "stripe-test://{}/subscriptions/{}",
        action.stripe_account_id(),
        action.subscription_id()
    );
    Ok(Permission::new(
        CapabilityId::parse(CAPABILITY).map_err(|_| ProfileContractError::MeaningMismatch)?,
        ResourceId::parse(&resource).map_err(|_| ProfileContractError::MeaningMismatch)?,
    ))
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use super::*;

    #[test]
    fn decoded_action_denies_unknown_fields() {
        let root =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/subscription-modify/v1");
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(root.join("action.json")).unwrap()).unwrap();
        value["change_billing_anchor"] = serde_json::json!(true);
        assert_eq!(
            StripeSubscriptionModifyProfile.canonicalize(&serde_json::to_vec(&value).unwrap()),
            Err(ProfileContractError::Malformed)
        );
    }
}

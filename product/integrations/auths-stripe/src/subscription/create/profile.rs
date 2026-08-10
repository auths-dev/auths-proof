//! Auths profile for one exact fixed-term subscription creation.

use auths_model::{
    CanonicalAction, CapabilityId, MediaType, Permission, ProfileId, ProfileRef, ResourceId,
};
use auths_profile_api::{ActionProfile, ProfileContractError, ReviewDisplay};
use auths_sdk::VerifiedAction;
use sha2::{Digest as _, Sha256};

use super::StripeExactSubscriptionCreateV1;

const CAPABILITY: &str = "stripe.subscription/create";
const MEDIA_TYPE: &str = "application/vnd.auths.stripe.subscription-create+json;version=1";
const MAX_ACTION_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StripeSubscriptionCreateCommand {
    action: StripeExactSubscriptionCreateV1,
}

impl StripeSubscriptionCreateCommand {
    pub const fn action(&self) -> &StripeExactSubscriptionCreateV1 {
        &self.action
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct StripeSubscriptionCreateProfile;

impl ActionProfile for StripeSubscriptionCreateProfile {
    type Command = StripeSubscriptionCreateCommand;

    fn canonicalize(&self, untrusted: &[u8]) -> Result<CanonicalAction, ProfileContractError> {
        if untrusted.is_empty() || untrusted.len() > MAX_ACTION_BYTES {
            return Err(ProfileContractError::LimitExceeded);
        }
        let action: StripeExactSubscriptionCreateV1 =
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
            "Auths V1 · Create one bounded Stripe subscription",
            vec![
                ("Customer".into(), action.customer_id().to_string()),
                (
                    "Recurring".into(),
                    format!(
                        "{} {} minor units",
                        action.projected_recurring_minor(),
                        action.currency()
                    ),
                ),
                ("Cycles".into(), action.projected_cycle_count().to_string()),
                (
                    "Term liability".into(),
                    format!("{} minor units", action.projected_term_liability_minor()),
                ),
                (
                    "First invoice".into(),
                    format!("{} minor units", action.projected_first_invoice_minor()),
                ),
                ("Cancel at".into(), action.cancel_at().to_string()),
                ("Mode".into(), "Stripe test clock".into()),
            ],
            hex::encode(Sha256::digest(canonical.body())),
        ))
    }

    fn decode_verified(
        &self,
        verified: &VerifiedAction,
    ) -> Result<Self::Command, ProfileContractError> {
        Ok(StripeSubscriptionCreateCommand {
            action: validate_canonical(verified.canonical_action())?,
        })
    }
}

fn canonical_action(
    action: &StripeExactSubscriptionCreateV1,
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
) -> Result<StripeExactSubscriptionCreateV1, ProfileContractError> {
    if canonical.profile() != &expected_profile()? || canonical.media_type().as_str() != MEDIA_TYPE
    {
        return Err(ProfileContractError::UnsupportedProfile);
    }
    let action: StripeExactSubscriptionCreateV1 =
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
        ProfileId::parse("auths.stripe.exact-subscription-create")
            .map_err(|_| ProfileContractError::UnsupportedProfile)?,
        1,
    )
    .map_err(|_| ProfileContractError::UnsupportedProfile)
}

fn permission(
    action: &StripeExactSubscriptionCreateV1,
) -> Result<Permission, ProfileContractError> {
    let resource = format!(
        "stripe-test://{}/customers/{}/subscriptions/{}",
        action.stripe_account_id(),
        action.customer_id(),
        action.nonce()
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
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/subscription-create/v1");
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(root.join("action.json")).unwrap()).unwrap();
        value["unbounded_schedule"] = serde_json::json!(true);
        assert_eq!(
            StripeSubscriptionCreateProfile.canonicalize(&serde_json::to_vec(&value).unwrap()),
            Err(ProfileContractError::Malformed)
        );
    }
}

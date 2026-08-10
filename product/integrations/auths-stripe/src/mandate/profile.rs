//! Auths application profile for one exact payment mandate.

use auths_model::{
    CanonicalAction, CapabilityId, MediaType, Permission, ProfileId, ProfileRef, ResourceId,
};
use auths_profile_api::{ActionProfile, ProfileContractError, ReviewDisplay};
use auths_sdk::VerifiedAction;
use sha2::{Digest as _, Sha256};

use super::StripeExactPaymentMandateV1;

const CAPABILITY: &str = "stripe.setup-intent/create-confirm";
const MEDIA_TYPE: &str = "application/vnd.auths.stripe.payment-mandate+json;version=1";
const MAX_ACTION_BYTES: usize = 64 * 1024;

/// Profile-decoded command obtainable only from an Auths-verified action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StripePaymentMandateCommand {
    action: StripeExactPaymentMandateV1,
}

impl StripePaymentMandateCommand {
    #[must_use]
    pub const fn action(&self) -> &StripeExactPaymentMandateV1 {
        &self.action
    }
}

/// `auths.stripe.exact-payment-mandate/1`.
#[derive(Clone, Copy, Debug, Default)]
pub struct StripePaymentMandateProfile;

impl ActionProfile for StripePaymentMandateProfile {
    type Command = StripePaymentMandateCommand;

    fn canonicalize(&self, untrusted: &[u8]) -> Result<CanonicalAction, ProfileContractError> {
        if untrusted.is_empty() || untrusted.len() > MAX_ACTION_BYTES {
            return Err(ProfileContractError::LimitExceeded);
        }
        let action: StripeExactPaymentMandateV1 =
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
            "Auths V1 · Establish one Stripe future-payment capability",
            vec![
                ("Customer".into(), action.customer_id().to_string()),
                (
                    "Future-use scope".into(),
                    format!(
                        "{:?} {} {} minor units / {:?}",
                        action.mandate_amount_type(),
                        action.mandate_amount_minor(),
                        action.currency(),
                        action.interval()
                    ),
                ),
                ("Usage".into(), format!("{:?}", action.usage())),
                ("Reference".into(), action.reference().into()),
                ("Immediate charge".into(), "none".into()),
                ("Mode".into(), "synthetic Stripe test mode".into()),
            ],
            hex::encode(Sha256::digest(canonical.body())),
        ))
    }

    fn decode_verified(
        &self,
        verified: &VerifiedAction,
    ) -> Result<Self::Command, ProfileContractError> {
        Ok(StripePaymentMandateCommand {
            action: validate_canonical(verified.canonical_action())?,
        })
    }
}

fn canonical_action(
    action: &StripeExactPaymentMandateV1,
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
) -> Result<StripeExactPaymentMandateV1, ProfileContractError> {
    if canonical.profile() != &expected_profile()? || canonical.media_type().as_str() != MEDIA_TYPE
    {
        return Err(ProfileContractError::UnsupportedProfile);
    }
    let action: StripeExactPaymentMandateV1 =
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
        ProfileId::parse("auths.stripe.exact-payment-mandate")
            .map_err(|_| ProfileContractError::UnsupportedProfile)?,
        1,
    )
    .map_err(|_| ProfileContractError::UnsupportedProfile)
}

fn permission(action: &StripeExactPaymentMandateV1) -> Result<Permission, ProfileContractError> {
    let resource = format!(
        "stripe-test://{}/customers/{}/payment-mandates/{}",
        action.stripe_account_id(),
        action.customer_id(),
        action.nonce()
    );
    Ok(Permission::new(
        CapabilityId::parse(CAPABILITY).map_err(|_| ProfileContractError::MeaningMismatch)?,
        ResourceId::parse(&resource).map_err(|_| ProfileContractError::MeaningMismatch)?,
    ))
}

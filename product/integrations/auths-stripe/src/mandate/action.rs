//! Exact future-use scope authorized for one Stripe `SetupIntent`.

use auths_model::Audience;
use serde::{Deserialize, Serialize};

use super::{
    MandateConnectAccount, PAYMENT_MANDATE_EVALUATOR_ID, PAYMENT_MANDATE_PROFILE,
    PaymentMandateValidationError, valid_api_version, valid_local,
};
use crate::{
    canonical::{CanonicalError, canonical_digest, canonical_json},
    types::{Currency, CustomerId, DigestHex, PaymentMethodId, StripeAccountId},
};

const MAX_FUTURE_AMOUNT_MINOR: u64 = 99_999_999;

/// Intended Stripe future-use mode.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MandateUsage {
    /// Customer is expected to participate.
    OnSession,
    /// Merchant may initiate later while the customer is absent.
    OffSession,
}

/// Closed future amount semantics.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MandateAmountType {
    /// Every linked future action must equal the amount.
    Fixed,
    /// Every linked future action must be at or below the amount.
    Maximum,
}

/// Closed charging-frequency semantics.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MandateInterval {
    /// One future use.
    OneTime,
    /// At most once per week.
    Weekly,
    /// At most once per month.
    Monthly,
    /// At most once per year.
    Yearly,
}

/// Exact action authorized by Auths.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StripeExactPaymentMandateV1 {
    profile: String,
    stripe_account_id: StripeAccountId,
    connect_account: MandateConnectAccount,
    customer_id: CustomerId,
    payment_method_id: PaymentMethodId,
    payment_method_type: String,
    usage: MandateUsage,
    mandate_amount_type: MandateAmountType,
    mandate_amount_minor: u64,
    currency: Currency,
    interval: MandateInterval,
    reference: String,
    consent_evidence_digest: DigestHex,
    displayed_terms_digest: DigestHex,
    on_behalf_of: Option<StripeAccountId>,
    return_url_commitment: Option<DigestHex>,
    stripe_api_version: String,
    required_policy_digest: DigestHex,
    required_evaluator: String,
    required_configuration_digest: DigestHex,
    executor_audience: String,
    expires_at: u64,
    nonce: DigestHex,
}

/// Constructor inputs for an exact mandate.
pub struct StripeExactPaymentMandateInput {
    pub stripe_account_id: StripeAccountId,
    pub connect_account: MandateConnectAccount,
    pub customer_id: CustomerId,
    pub payment_method_id: PaymentMethodId,
    pub payment_method_type: String,
    pub usage: MandateUsage,
    pub mandate_amount_type: MandateAmountType,
    pub mandate_amount_minor: u64,
    pub currency: Currency,
    pub interval: MandateInterval,
    pub reference: String,
    pub consent_evidence_digest: DigestHex,
    pub displayed_terms_digest: DigestHex,
    pub on_behalf_of: Option<StripeAccountId>,
    pub return_url_commitment: Option<DigestHex>,
    pub stripe_api_version: String,
    pub required_policy_digest: DigestHex,
    pub required_configuration_digest: DigestHex,
    pub executor_audience: String,
    pub expires_at: u64,
    pub nonce: DigestHex,
}

impl StripeExactPaymentMandateV1 {
    /// Builds and validates the closed V1 action.
    pub fn new(
        input: StripeExactPaymentMandateInput,
    ) -> Result<Self, PaymentMandateValidationError> {
        let action = Self {
            profile: PAYMENT_MANDATE_PROFILE.into(),
            stripe_account_id: input.stripe_account_id,
            connect_account: input.connect_account,
            customer_id: input.customer_id,
            payment_method_id: input.payment_method_id,
            payment_method_type: input.payment_method_type,
            usage: input.usage,
            mandate_amount_type: input.mandate_amount_type,
            mandate_amount_minor: input.mandate_amount_minor,
            currency: input.currency,
            interval: input.interval,
            reference: input.reference,
            consent_evidence_digest: input.consent_evidence_digest,
            displayed_terms_digest: input.displayed_terms_digest,
            on_behalf_of: input.on_behalf_of,
            return_url_commitment: input.return_url_commitment,
            stripe_api_version: input.stripe_api_version,
            required_policy_digest: input.required_policy_digest,
            required_evaluator: PAYMENT_MANDATE_EVALUATOR_ID.into(),
            required_configuration_digest: input.required_configuration_digest,
            executor_audience: input.executor_audience,
            expires_at: input.expires_at,
            nonce: input.nonce,
        };
        action.validate()?;
        Ok(action)
    }

    /// Revalidates decoded input.
    pub fn validate(&self) -> Result<(), PaymentMandateValidationError> {
        if self.profile != PAYMENT_MANDATE_PROFILE
            || self.required_evaluator != PAYMENT_MANDATE_EVALUATOR_ID
            || self.payment_method_type != "card"
            || self.mandate_amount_minor == 0
            || self.mandate_amount_minor > MAX_FUTURE_AMOUNT_MINOR
            || !valid_local(&self.reference)
            || !valid_api_version(&self.stripe_api_version)
            || Audience::parse(&self.executor_audience).is_err()
        {
            return Err(PaymentMandateValidationError::Action);
        }
        if let MandateConnectAccount::Connected(account) = &self.connect_account {
            if self.on_behalf_of.as_ref() != Some(account) {
                return Err(PaymentMandateValidationError::Action);
            }
        } else if self.on_behalf_of.is_some() {
            return Err(PaymentMandateValidationError::Action);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        canonical_json(self)
    }

    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }

    pub fn profile(&self) -> &str {
        &self.profile
    }
    pub const fn stripe_account_id(&self) -> &StripeAccountId {
        &self.stripe_account_id
    }
    pub const fn connect_account(&self) -> &MandateConnectAccount {
        &self.connect_account
    }
    pub const fn customer_id(&self) -> &CustomerId {
        &self.customer_id
    }
    pub const fn payment_method_id(&self) -> &PaymentMethodId {
        &self.payment_method_id
    }
    pub fn payment_method_type(&self) -> &str {
        &self.payment_method_type
    }
    pub const fn usage(&self) -> MandateUsage {
        self.usage
    }
    pub const fn mandate_amount_type(&self) -> MandateAmountType {
        self.mandate_amount_type
    }
    pub const fn mandate_amount_minor(&self) -> u64 {
        self.mandate_amount_minor
    }
    pub const fn currency(&self) -> &Currency {
        &self.currency
    }
    pub const fn interval(&self) -> MandateInterval {
        self.interval
    }
    pub fn reference(&self) -> &str {
        &self.reference
    }
    pub const fn consent_evidence_digest(&self) -> &DigestHex {
        &self.consent_evidence_digest
    }
    pub const fn displayed_terms_digest(&self) -> &DigestHex {
        &self.displayed_terms_digest
    }
    pub const fn on_behalf_of(&self) -> Option<&StripeAccountId> {
        self.on_behalf_of.as_ref()
    }
    pub const fn return_url_commitment(&self) -> Option<&DigestHex> {
        self.return_url_commitment.as_ref()
    }
    pub fn stripe_api_version(&self) -> &str {
        &self.stripe_api_version
    }
    pub const fn required_policy_digest(&self) -> &DigestHex {
        &self.required_policy_digest
    }
    pub fn required_evaluator(&self) -> &str {
        &self.required_evaluator
    }
    pub const fn required_configuration_digest(&self) -> &DigestHex {
        &self.required_configuration_digest
    }
    pub fn executor_audience(&self) -> &str {
        &self.executor_audience
    }
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
    pub const fn nonce(&self) -> &DigestHex {
        &self.nonce
    }
}

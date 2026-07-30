//! Exact final-capture action for one existing Stripe authorization.

use auths_model::Audience;
use serde::{Deserialize, Serialize};

use crate::{
    canonical::{CanonicalError, canonical_digest, canonical_json},
    types::{ChargeId, Currency, CustomerId, DigestHex, PaymentIntentId, StripeAccountId},
};

use super::super::{
    MerchantConnectAccount, MerchantEvaluatorCommitment, MerchantValidationError,
    PAYMENT_CAPTURE_PROFILE, valid_api_version, valid_local_id,
};

const MAX_MONEY_MINOR: u64 = 99_999_999;

/// Exact final capture of an already-authorized `PaymentIntent`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StripeExactPaymentCaptureV1 {
    profile: String,
    stripe_account_id: StripeAccountId,
    connect_account: MerchantConnectAccount,
    payment_intent_id: PaymentIntentId,
    latest_charge_id: ChargeId,
    customer_id: CustomerId,
    order_scope: String,
    authorized_amount_minor: u64,
    amount_capturable_before_minor: u64,
    amount_to_capture_minor: u64,
    currency: Currency,
    final_capture: bool,
    application_fee_amount: Option<u64>,
    transfer_data: Option<String>,
    statement_descriptor_commitment: DigestHex,
    fixed_metadata_commitment: DigestHex,
    authorization_action_digest: DigestHex,
    authorization_reservation_id: DigestHex,
    stripe_api_version: String,
    required_policy_digest: DigestHex,
    required_evaluator: MerchantEvaluatorCommitment,
    required_configuration_digest: DigestHex,
    executor_audience: String,
    expires_at: u64,
    nonce: DigestHex,
}

/// Inputs for the exact final-capture action.
pub struct StripeExactPaymentCaptureInput {
    /// Stripe account.
    pub stripe_account_id: StripeAccountId,
    /// Platform or Connect context.
    pub connect_account: MerchantConnectAccount,
    /// Existing manual-capture `PaymentIntent`.
    pub payment_intent_id: PaymentIntentId,
    /// Latest Charge linked by the authorization.
    pub latest_charge_id: ChargeId,
    /// Exact Customer from the authorization.
    pub customer_id: CustomerId,
    /// Protected order scope.
    pub order_scope: String,
    /// Original authorized amount.
    pub authorized_amount_minor: u64,
    /// Capturable amount immediately before capture.
    pub amount_capturable_before_minor: u64,
    /// Positive final amount to capture.
    pub amount_to_capture_minor: u64,
    /// Currency.
    pub currency: Currency,
    /// Protected statement descriptor commitment.
    pub statement_descriptor_commitment: DigestHex,
    /// Protected fixed metadata commitment.
    pub fixed_metadata_commitment: DigestHex,
    /// Exact linked authorization action.
    pub authorization_action_digest: DigestHex,
    /// Exact linked authorization reservation.
    pub authorization_reservation_id: DigestHex,
    /// Pinned Stripe API version.
    pub stripe_api_version: String,
    /// Required immutable policy.
    pub required_policy_digest: DigestHex,
    /// Required runtime configuration.
    pub required_configuration_digest: DigestHex,
    /// Exact executor audience.
    pub executor_audience: String,
    /// Action expiry.
    pub expires_at: u64,
    /// Fresh replay nonce.
    pub nonce: DigestHex,
}

impl StripeExactPaymentCaptureV1 {
    /// Builds a final-capture-only action with no fee or transfer behavior.
    ///
    /// # Errors
    ///
    /// Rejects malformed identifiers, amounts, or forbidden capture modes.
    pub fn new(input: StripeExactPaymentCaptureInput) -> Result<Self, MerchantValidationError> {
        let value = Self {
            profile: PAYMENT_CAPTURE_PROFILE.into(),
            stripe_account_id: input.stripe_account_id,
            connect_account: input.connect_account,
            payment_intent_id: input.payment_intent_id,
            latest_charge_id: input.latest_charge_id,
            customer_id: input.customer_id,
            order_scope: input.order_scope,
            authorized_amount_minor: input.authorized_amount_minor,
            amount_capturable_before_minor: input.amount_capturable_before_minor,
            amount_to_capture_minor: input.amount_to_capture_minor,
            currency: input.currency,
            final_capture: true,
            application_fee_amount: None,
            transfer_data: None,
            statement_descriptor_commitment: input.statement_descriptor_commitment,
            fixed_metadata_commitment: input.fixed_metadata_commitment,
            authorization_action_digest: input.authorization_action_digest,
            authorization_reservation_id: input.authorization_reservation_id,
            stripe_api_version: input.stripe_api_version,
            required_policy_digest: input.required_policy_digest,
            required_evaluator: MerchantEvaluatorCommitment::v1(),
            required_configuration_digest: input.required_configuration_digest,
            executor_audience: input.executor_audience,
            expires_at: input.expires_at,
            nonce: input.nonce,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validates decoded final-capture semantics.
    ///
    /// # Errors
    ///
    /// Rejects values outside the exact V1 capture profile.
    pub fn validate(&self) -> Result<(), MerchantValidationError> {
        if self.profile != PAYMENT_CAPTURE_PROFILE
            || !valid_local_id(&self.order_scope)
            || self.authorized_amount_minor == 0
            || self.authorized_amount_minor > MAX_MONEY_MINOR
            || self.amount_capturable_before_minor == 0
            || self.amount_capturable_before_minor > self.authorized_amount_minor
            || self.amount_to_capture_minor == 0
            || self.amount_to_capture_minor > self.amount_capturable_before_minor
            || !self.final_capture
            || self.application_fee_amount.is_some()
            || self.transfer_data.is_some()
            || !valid_api_version(&self.stripe_api_version)
            || self.required_evaluator != MerchantEvaluatorCommitment::v1()
            || Audience::parse(&self.executor_audience).is_err()
        {
            return Err(MerchantValidationError::InvalidAction);
        }
        Ok(())
    }

    /// Canonical exact-action bytes.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization failure.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        canonical_json(self)
    }

    /// Exact action digest.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization failure.
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }

    /// Profile identifier.
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// Stripe account.
    #[must_use]
    pub const fn stripe_account_id(&self) -> &StripeAccountId {
        &self.stripe_account_id
    }

    /// Connect context.
    #[must_use]
    pub const fn connect_account(&self) -> &MerchantConnectAccount {
        &self.connect_account
    }

    /// Existing `PaymentIntent`.
    #[must_use]
    pub const fn payment_intent_id(&self) -> &PaymentIntentId {
        &self.payment_intent_id
    }

    /// Latest Charge before capture.
    #[must_use]
    pub const fn latest_charge_id(&self) -> &ChargeId {
        &self.latest_charge_id
    }

    /// Exact Customer.
    #[must_use]
    pub const fn customer_id(&self) -> &CustomerId {
        &self.customer_id
    }

    /// Protected order scope.
    #[must_use]
    pub fn order_scope(&self) -> &str {
        &self.order_scope
    }

    /// Original authorized amount.
    #[must_use]
    pub const fn authorized_amount_minor(&self) -> u64 {
        self.authorized_amount_minor
    }

    /// Capturable amount before capture.
    #[must_use]
    pub const fn amount_capturable_before_minor(&self) -> u64 {
        self.amount_capturable_before_minor
    }

    /// Exact amount to capture.
    #[must_use]
    pub const fn amount_to_capture_minor(&self) -> u64 {
        self.amount_to_capture_minor
    }

    /// Currency.
    #[must_use]
    pub const fn currency(&self) -> &Currency {
        &self.currency
    }

    /// Final-capture-only flag.
    #[must_use]
    pub const fn final_capture(&self) -> bool {
        self.final_capture
    }

    /// Statement descriptor commitment.
    #[must_use]
    pub const fn statement_descriptor_commitment(&self) -> &DigestHex {
        &self.statement_descriptor_commitment
    }

    /// Fixed metadata commitment.
    #[must_use]
    pub const fn fixed_metadata_commitment(&self) -> &DigestHex {
        &self.fixed_metadata_commitment
    }

    /// Linked authorization action digest.
    #[must_use]
    pub const fn authorization_action_digest(&self) -> &DigestHex {
        &self.authorization_action_digest
    }

    /// Linked authorization reservation.
    #[must_use]
    pub const fn authorization_reservation_id(&self) -> &DigestHex {
        &self.authorization_reservation_id
    }

    /// Pinned API version.
    #[must_use]
    pub fn stripe_api_version(&self) -> &str {
        &self.stripe_api_version
    }

    /// Required policy digest.
    #[must_use]
    pub const fn required_policy_digest(&self) -> &DigestHex {
        &self.required_policy_digest
    }

    /// Required evaluator.
    #[must_use]
    pub const fn required_evaluator(&self) -> &MerchantEvaluatorCommitment {
        &self.required_evaluator
    }

    /// Required runtime configuration.
    #[must_use]
    pub const fn required_configuration_digest(&self) -> &DigestHex {
        &self.required_configuration_digest
    }

    /// Exact executor audience.
    #[must_use]
    pub fn executor_audience(&self) -> &str {
        &self.executor_audience
    }

    /// Action expiry.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Fresh replay nonce.
    #[must_use]
    pub const fn nonce(&self) -> &DigestHex {
        &self.nonce
    }
}

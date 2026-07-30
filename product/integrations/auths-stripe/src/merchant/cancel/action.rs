//! Exact cancellation action for one existing Stripe `PaymentIntent`.

use auths_model::Audience;
use serde::{Deserialize, Serialize};

use crate::{
    canonical::{CanonicalError, canonical_digest, canonical_json},
    types::{Currency, CustomerId, DigestHex, PaymentIntentId, StripeAccountId},
};

use super::super::{
    MerchantConnectAccount, MerchantEvaluatorCommitment, MerchantValidationError,
    PAYMENT_CANCEL_PROFILE, valid_api_version, valid_local_id,
};

const MAX_MONEY_MINOR: u64 = 99_999_999;

/// Closed Stripe cancellation-reason vocabulary supported by V1.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentCancellationReason {
    /// The target duplicates another payment.
    Duplicate,
    /// The merchant identified the target as fraudulent.
    Fraudulent,
    /// The customer explicitly requested cancellation.
    RequestedByCustomer,
    /// The payment flow was abandoned.
    Abandoned,
}

impl PaymentCancellationReason {
    /// Exact Stripe wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Duplicate => "duplicate",
            Self::Fraudulent => "fraudulent",
            Self::RequestedByCustomer => "requested_by_customer",
            Self::Abandoned => "abandoned",
        }
    }
}

/// Exact terminal cancellation of one existing `PaymentIntent`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StripeExactPaymentCancelV1 {
    profile: String,
    stripe_account_id: StripeAccountId,
    connect_account: MerchantConnectAccount,
    payment_intent_id: PaymentIntentId,
    customer_id: CustomerId,
    order_scope: String,
    current_status: String,
    amount_minor: u64,
    amount_capturable_minor: u64,
    currency: Currency,
    cancellation_reason: PaymentCancellationReason,
    authorization_action_digest: Option<DigestHex>,
    authorization_reservation_id: Option<DigestHex>,
    stripe_api_version: String,
    required_policy_digest: DigestHex,
    required_evaluator: MerchantEvaluatorCommitment,
    required_configuration_digest: DigestHex,
    executor_audience: String,
    expires_at: u64,
    nonce: DigestHex,
}

/// Inputs for one exact cancellation action.
pub struct StripeExactPaymentCancelInput {
    /// Stripe account.
    pub stripe_account_id: StripeAccountId,
    /// Platform or Connect context.
    pub connect_account: MerchantConnectAccount,
    /// Existing `PaymentIntent`.
    pub payment_intent_id: PaymentIntentId,
    /// Exact Customer.
    pub customer_id: CustomerId,
    /// Protected order scope.
    pub order_scope: String,
    /// Exact provider status authorized for cancellation.
    pub current_status: String,
    /// Original payment amount.
    pub amount_minor: u64,
    /// Exact capturable amount before cancellation.
    pub amount_capturable_minor: u64,
    /// Currency.
    pub currency: Currency,
    /// Closed cancellation reason.
    pub cancellation_reason: PaymentCancellationReason,
    /// Optional linked authorization action.
    pub authorization_action_digest: Option<DigestHex>,
    /// Optional linked authorization reservation.
    pub authorization_reservation_id: Option<DigestHex>,
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

impl StripeExactPaymentCancelV1 {
    /// Builds one exact cancellation action.
    ///
    /// # Errors
    ///
    /// Rejects malformed identifiers, unsafe states, or inconsistent hold links.
    pub fn new(input: StripeExactPaymentCancelInput) -> Result<Self, MerchantValidationError> {
        let value = Self {
            profile: PAYMENT_CANCEL_PROFILE.into(),
            stripe_account_id: input.stripe_account_id,
            connect_account: input.connect_account,
            payment_intent_id: input.payment_intent_id,
            customer_id: input.customer_id,
            order_scope: input.order_scope,
            current_status: input.current_status,
            amount_minor: input.amount_minor,
            amount_capturable_minor: input.amount_capturable_minor,
            currency: input.currency,
            cancellation_reason: input.cancellation_reason,
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

    /// Validates decoded V1 cancellation semantics.
    ///
    /// # Errors
    ///
    /// Rejects values outside the exact cancellation profile.
    pub fn validate(&self) -> Result<(), MerchantValidationError> {
        let cancelable = matches!(
            self.current_status.as_str(),
            "requires_payment_method"
                | "requires_capture"
                | "requires_confirmation"
                | "requires_action"
        );
        let linked_hold = self.authorization_action_digest.is_some()
            && self.authorization_reservation_id.is_some();
        let complete_authorization_link = self.authorization_action_digest.is_some()
            == self.authorization_reservation_id.is_some();
        let hold_shape = if self.current_status == "requires_capture" {
            self.amount_capturable_minor > 0 && linked_hold
        } else {
            self.amount_capturable_minor == 0 && !linked_hold
        };
        if self.profile != PAYMENT_CANCEL_PROFILE
            || !valid_local_id(&self.order_scope)
            || !cancelable
            || self.amount_minor == 0
            || self.amount_minor > MAX_MONEY_MINOR
            || self.amount_capturable_minor > self.amount_minor
            || !complete_authorization_link
            || !hold_shape
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
    /// Returns an error when the action cannot be encoded canonically.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        canonical_json(self)
    }

    /// Exact action digest.
    ///
    /// # Errors
    ///
    /// Returns an error when the action cannot be encoded canonically.
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

    /// Provider state authorized by the action.
    #[must_use]
    pub fn current_status(&self) -> &str {
        &self.current_status
    }

    /// Original payment amount.
    #[must_use]
    pub const fn amount_minor(&self) -> u64 {
        self.amount_minor
    }

    /// Capturable amount before cancellation.
    #[must_use]
    pub const fn amount_capturable_minor(&self) -> u64 {
        self.amount_capturable_minor
    }

    /// Currency.
    #[must_use]
    pub const fn currency(&self) -> &Currency {
        &self.currency
    }

    /// Exact cancellation reason.
    #[must_use]
    pub const fn cancellation_reason(&self) -> PaymentCancellationReason {
        self.cancellation_reason
    }

    /// Linked authorization action, if a hold must be conditionally released.
    #[must_use]
    pub const fn authorization_action_digest(&self) -> Option<&DigestHex> {
        self.authorization_action_digest.as_ref()
    }

    /// Linked authorization reservation, if a hold must be conditionally released.
    #[must_use]
    pub const fn authorization_reservation_id(&self) -> Option<&DigestHex> {
        self.authorization_reservation_id.as_ref()
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

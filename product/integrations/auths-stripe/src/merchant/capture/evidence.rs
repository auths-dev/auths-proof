//! Protected pre-capture Stripe and durable-authorization evidence.

use serde::{Deserialize, Serialize};

use crate::{
    canonical::{CanonicalError, canonical_digest},
    types::{ChargeId, Currency, CustomerId, DigestHex, PaymentIntentId, StripeAccountId},
};

use super::super::{
    MerchantConnectAccount, MerchantReservationState, MerchantValidationError, valid_api_version,
    valid_local_id, valid_workflow_id,
};

/// Fresh evidence for one exact final capture.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentCaptureEvidenceV1 {
    schema: String,
    stripe_account_id: StripeAccountId,
    connect_account: MerchantConnectAccount,
    payment_intent_id: PaymentIntentId,
    latest_charge_id: ChargeId,
    customer_id: CustomerId,
    order_scope: String,
    authorized_amount_minor: u64,
    amount_capturable_minor: u64,
    amount_captured_minor: u64,
    currency: Currency,
    payment_intent_status: String,
    capture_before: u64,
    livemode: bool,
    stripe_api_version: String,
    authorization_workflow_id: String,
    authorization_action_digest: DigestHex,
    authorization_reservation_id: DigestHex,
    authorization_state: MerchantReservationState,
    authorization_created_at: u64,
    observed_at: u64,
    source: String,
    response_commitment: DigestHex,
}

/// Inputs for protected pre-capture evidence.
pub struct PaymentCaptureEvidenceInput {
    /// Stripe account.
    pub stripe_account_id: StripeAccountId,
    /// Platform or Connect context.
    pub connect_account: MerchantConnectAccount,
    /// Existing `PaymentIntent`.
    pub payment_intent_id: PaymentIntentId,
    /// Latest Charge.
    pub latest_charge_id: ChargeId,
    /// Exact Customer.
    pub customer_id: CustomerId,
    /// Protected order scope.
    pub order_scope: String,
    /// Original authorized amount.
    pub authorized_amount_minor: u64,
    /// Current capturable amount.
    pub amount_capturable_minor: u64,
    /// Amount already captured before this V1 action.
    pub amount_captured_minor: u64,
    /// Currency.
    pub currency: Currency,
    /// Current `PaymentIntent` status.
    pub payment_intent_status: String,
    /// Card authorization expiry.
    pub capture_before: u64,
    /// Stripe live-mode bit.
    pub livemode: bool,
    /// Pinned Stripe API version.
    pub stripe_api_version: String,
    /// Linked authorization workflow.
    pub authorization_workflow_id: String,
    /// Linked authorization action.
    pub authorization_action_digest: DigestHex,
    /// Linked authorization reservation.
    pub authorization_reservation_id: DigestHex,
    /// Durable authorization lifecycle.
    pub authorization_state: MerchantReservationState,
    /// Durable authorization creation time.
    pub authorization_created_at: u64,
    /// Observation time.
    pub observed_at: u64,
    /// Closed observation source.
    pub source: String,
    /// Commitment to sanitized Stripe response fields.
    pub response_commitment: DigestHex,
}

impl PaymentCaptureEvidenceV1 {
    /// Constructs exact pre-capture evidence.
    ///
    /// # Errors
    ///
    /// Rejects contradictory Stripe or durable authorization facts.
    pub fn new(input: PaymentCaptureEvidenceInput) -> Result<Self, MerchantValidationError> {
        let value = Self {
            schema: "auths.stripe.payment-capture-evidence/1".into(),
            stripe_account_id: input.stripe_account_id,
            connect_account: input.connect_account,
            payment_intent_id: input.payment_intent_id,
            latest_charge_id: input.latest_charge_id,
            customer_id: input.customer_id,
            order_scope: input.order_scope,
            authorized_amount_minor: input.authorized_amount_minor,
            amount_capturable_minor: input.amount_capturable_minor,
            amount_captured_minor: input.amount_captured_minor,
            currency: input.currency,
            payment_intent_status: input.payment_intent_status,
            capture_before: input.capture_before,
            livemode: input.livemode,
            stripe_api_version: input.stripe_api_version,
            authorization_workflow_id: input.authorization_workflow_id,
            authorization_action_digest: input.authorization_action_digest,
            authorization_reservation_id: input.authorization_reservation_id,
            authorization_state: input.authorization_state,
            authorization_created_at: input.authorization_created_at,
            observed_at: input.observed_at,
            source: input.source,
            response_commitment: input.response_commitment,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validates exact V1 pre-capture evidence.
    ///
    /// # Errors
    ///
    /// Rejects stale-looking structure or non-capturable lifecycle facts.
    pub fn validate(&self) -> Result<(), MerchantValidationError> {
        if self.schema != "auths.stripe.payment-capture-evidence/1"
            || !valid_local_id(&self.order_scope)
            || self.authorized_amount_minor == 0
            || self.amount_capturable_minor > self.authorized_amount_minor
            || self.amount_captured_minor > self.authorized_amount_minor
            || self
                .amount_capturable_minor
                .checked_add(self.amount_captured_minor)
                .is_none_or(|amount| amount > self.authorized_amount_minor)
            || !matches!(
                self.payment_intent_status.as_str(),
                "requires_capture" | "succeeded" | "canceled"
            )
            || !valid_api_version(&self.stripe_api_version)
            || !valid_workflow_id(&self.authorization_workflow_id)
            || !matches!(
                self.authorization_state,
                MerchantReservationState::Authorized
                    | MerchantReservationState::ReconciledAuthorized
            )
            || self.authorization_created_at > self.observed_at
            || (self.payment_intent_status == "requires_capture"
                && self.capture_before <= self.observed_at)
            || !matches!(
                self.source.as_str(),
                "stripe-api-and-auths-store" | "retrieve"
            )
        {
            return Err(MerchantValidationError::InvalidEvidence);
        }
        Ok(())
    }

    /// Canonical evidence digest.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization failure.
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
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

    /// Latest Charge.
    #[must_use]
    pub const fn latest_charge_id(&self) -> &ChargeId {
        &self.latest_charge_id
    }

    /// Customer.
    #[must_use]
    pub const fn customer_id(&self) -> &CustomerId {
        &self.customer_id
    }

    /// Order scope.
    #[must_use]
    pub fn order_scope(&self) -> &str {
        &self.order_scope
    }

    /// Original authorized amount.
    #[must_use]
    pub const fn authorized_amount_minor(&self) -> u64 {
        self.authorized_amount_minor
    }

    /// Current capturable amount.
    #[must_use]
    pub const fn amount_capturable_minor(&self) -> u64 {
        self.amount_capturable_minor
    }

    /// Amount captured before this action.
    #[must_use]
    pub const fn amount_captured_minor(&self) -> u64 {
        self.amount_captured_minor
    }

    /// Currency.
    #[must_use]
    pub const fn currency(&self) -> &Currency {
        &self.currency
    }

    /// `PaymentIntent` status.
    #[must_use]
    pub fn payment_intent_status(&self) -> &str {
        &self.payment_intent_status
    }

    /// Authorization expiry.
    #[must_use]
    pub const fn capture_before(&self) -> u64 {
        self.capture_before
    }

    /// Stripe live-mode bit.
    #[must_use]
    pub const fn livemode(&self) -> bool {
        self.livemode
    }

    /// Pinned API version.
    #[must_use]
    pub fn stripe_api_version(&self) -> &str {
        &self.stripe_api_version
    }

    /// Linked authorization workflow.
    #[must_use]
    pub fn authorization_workflow_id(&self) -> &str {
        &self.authorization_workflow_id
    }

    /// Linked authorization action.
    #[must_use]
    pub const fn authorization_action_digest(&self) -> &DigestHex {
        &self.authorization_action_digest
    }

    /// Linked authorization reservation.
    #[must_use]
    pub const fn authorization_reservation_id(&self) -> &DigestHex {
        &self.authorization_reservation_id
    }

    /// Durable authorization state.
    #[must_use]
    pub const fn authorization_state(&self) -> MerchantReservationState {
        self.authorization_state
    }

    /// Durable authorization creation time.
    #[must_use]
    pub const fn authorization_created_at(&self) -> u64 {
        self.authorization_created_at
    }

    /// Observation time.
    #[must_use]
    pub const fn observed_at(&self) -> u64 {
        self.observed_at
    }

    /// Sanitized response commitment.
    #[must_use]
    pub const fn response_commitment(&self) -> &DigestHex {
        &self.response_commitment
    }

    /// Compares every effect-critical fact while allowing a fresh observation timestamp.
    #[must_use]
    pub fn critical_scope_matches(&self, fresh: &Self) -> bool {
        self.stripe_account_id == fresh.stripe_account_id
            && self.connect_account == fresh.connect_account
            && self.payment_intent_id == fresh.payment_intent_id
            && self.latest_charge_id == fresh.latest_charge_id
            && self.customer_id == fresh.customer_id
            && self.order_scope == fresh.order_scope
            && self.authorized_amount_minor == fresh.authorized_amount_minor
            && self.amount_capturable_minor == fresh.amount_capturable_minor
            && self.amount_captured_minor == fresh.amount_captured_minor
            && self.currency == fresh.currency
            && self.payment_intent_status == fresh.payment_intent_status
            && self.capture_before == fresh.capture_before
            && self.livemode == fresh.livemode
            && self.stripe_api_version == fresh.stripe_api_version
            && self.authorization_workflow_id == fresh.authorization_workflow_id
            && self.authorization_action_digest == fresh.authorization_action_digest
            && self.authorization_reservation_id == fresh.authorization_reservation_id
            && self.authorization_state == fresh.authorization_state
            && self.authorization_created_at == fresh.authorization_created_at
    }
}

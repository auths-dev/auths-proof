//! Protected Stripe and optional durable-authorization evidence for cancellation.

use serde::{Deserialize, Serialize};

use crate::{
    canonical::{CanonicalError, canonical_digest},
    types::{ChargeId, Currency, CustomerId, DigestHex, PaymentIntentId, StripeAccountId},
};

use super::super::{
    MerchantConnectAccount, MerchantReservationState, MerchantValidationError, valid_api_version,
    valid_local_id, valid_workflow_id,
};

/// Fresh evidence for one exact cancellation target.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentCancelEvidenceV1 {
    schema: String,
    stripe_account_id: StripeAccountId,
    connect_account: MerchantConnectAccount,
    payment_intent_id: PaymentIntentId,
    latest_charge_id: Option<ChargeId>,
    customer_id: CustomerId,
    order_scope: String,
    amount_minor: u64,
    amount_capturable_minor: u64,
    currency: Currency,
    payment_intent_status: String,
    cancellation_eligible: bool,
    livemode: bool,
    stripe_api_version: String,
    authorization_workflow_id: Option<String>,
    authorization_action_digest: Option<DigestHex>,
    authorization_reservation_id: Option<DigestHex>,
    authorization_state: Option<MerchantReservationState>,
    authorization_created_at: Option<u64>,
    observed_at: u64,
    source: String,
    response_commitment: DigestHex,
}

/// Inputs for protected cancellation evidence.
pub struct PaymentCancelEvidenceInput {
    pub stripe_account_id: StripeAccountId,
    pub connect_account: MerchantConnectAccount,
    pub payment_intent_id: PaymentIntentId,
    pub latest_charge_id: Option<ChargeId>,
    pub customer_id: CustomerId,
    pub order_scope: String,
    pub amount_minor: u64,
    pub amount_capturable_minor: u64,
    pub currency: Currency,
    pub payment_intent_status: String,
    pub cancellation_eligible: bool,
    pub livemode: bool,
    pub stripe_api_version: String,
    pub authorization_workflow_id: Option<String>,
    pub authorization_action_digest: Option<DigestHex>,
    pub authorization_reservation_id: Option<DigestHex>,
    pub authorization_state: Option<MerchantReservationState>,
    pub authorization_created_at: Option<u64>,
    pub observed_at: u64,
    pub source: String,
    pub response_commitment: DigestHex,
}

impl PaymentCancelEvidenceV1 {
    /// Constructs exact cancellation evidence.
    ///
    /// # Errors
    ///
    /// Rejects contradictory Stripe or durable hold facts.
    pub fn new(input: PaymentCancelEvidenceInput) -> Result<Self, MerchantValidationError> {
        let value = Self {
            schema: "auths.stripe.payment-cancel-evidence/1".into(),
            stripe_account_id: input.stripe_account_id,
            connect_account: input.connect_account,
            payment_intent_id: input.payment_intent_id,
            latest_charge_id: input.latest_charge_id,
            customer_id: input.customer_id,
            order_scope: input.order_scope,
            amount_minor: input.amount_minor,
            amount_capturable_minor: input.amount_capturable_minor,
            currency: input.currency,
            payment_intent_status: input.payment_intent_status,
            cancellation_eligible: input.cancellation_eligible,
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

    /// Validates exact V1 evidence structure.
    ///
    /// # Errors
    ///
    /// Rejects impossible cancellation or hold shapes.
    pub fn validate(&self) -> Result<(), MerchantValidationError> {
        let cancelable = matches!(
            self.payment_intent_status.as_str(),
            "requires_payment_method"
                | "requires_capture"
                | "requires_confirmation"
                | "requires_action"
        );
        let hold_fields = [
            self.authorization_workflow_id.is_some(),
            self.authorization_action_digest.is_some(),
            self.authorization_reservation_id.is_some(),
            self.authorization_state.is_some(),
            self.authorization_created_at.is_some(),
        ];
        let has_complete_hold = hold_fields.iter().all(|present| *present);
        let has_no_hold = hold_fields.iter().all(|present| !*present);
        let hold_shape = if self.payment_intent_status == "requires_capture" {
            self.amount_capturable_minor > 0
                && has_complete_hold
                && matches!(
                    self.authorization_state,
                    Some(
                        MerchantReservationState::Authorized
                            | MerchantReservationState::ReconciledAuthorized
                    )
                )
                && self
                    .authorization_created_at
                    .is_some_and(|created| created <= self.observed_at)
        } else {
            self.amount_capturable_minor == 0 && has_no_hold
        };
        if self.schema != "auths.stripe.payment-cancel-evidence/1"
            || !valid_local_id(&self.order_scope)
            || self.amount_minor == 0
            || self.amount_capturable_minor > self.amount_minor
            || !cancelable
            || !self.cancellation_eligible
            || !hold_shape
            || !valid_api_version(&self.stripe_api_version)
            || self
                .authorization_workflow_id
                .as_deref()
                .is_some_and(|workflow| !valid_workflow_id(workflow))
            || !matches!(
                self.source.as_str(),
                "stripe-api-and-auths-store" | "stripe-api" | "retrieve"
            )
        {
            return Err(MerchantValidationError::InvalidEvidence);
        }
        Ok(())
    }

    /// Returns the canonical evidence commitment.
    ///
    /// # Errors
    ///
    /// Returns an error when the evidence cannot be encoded canonically.
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }

    #[must_use]
    pub const fn stripe_account_id(&self) -> &StripeAccountId {
        &self.stripe_account_id
    }

    #[must_use]
    pub const fn connect_account(&self) -> &MerchantConnectAccount {
        &self.connect_account
    }

    #[must_use]
    pub const fn payment_intent_id(&self) -> &PaymentIntentId {
        &self.payment_intent_id
    }

    #[must_use]
    pub const fn latest_charge_id(&self) -> Option<&ChargeId> {
        self.latest_charge_id.as_ref()
    }

    #[must_use]
    pub const fn customer_id(&self) -> &CustomerId {
        &self.customer_id
    }

    #[must_use]
    pub fn order_scope(&self) -> &str {
        &self.order_scope
    }

    #[must_use]
    pub const fn amount_minor(&self) -> u64 {
        self.amount_minor
    }

    #[must_use]
    pub const fn amount_capturable_minor(&self) -> u64 {
        self.amount_capturable_minor
    }

    #[must_use]
    pub const fn currency(&self) -> &Currency {
        &self.currency
    }

    #[must_use]
    pub fn payment_intent_status(&self) -> &str {
        &self.payment_intent_status
    }

    #[must_use]
    pub const fn livemode(&self) -> bool {
        self.livemode
    }

    #[must_use]
    pub fn stripe_api_version(&self) -> &str {
        &self.stripe_api_version
    }

    #[must_use]
    pub fn authorization_workflow_id(&self) -> Option<&str> {
        self.authorization_workflow_id.as_deref()
    }

    #[must_use]
    pub const fn authorization_action_digest(&self) -> Option<&DigestHex> {
        self.authorization_action_digest.as_ref()
    }

    #[must_use]
    pub const fn authorization_reservation_id(&self) -> Option<&DigestHex> {
        self.authorization_reservation_id.as_ref()
    }

    #[must_use]
    pub const fn authorization_state(&self) -> Option<MerchantReservationState> {
        self.authorization_state
    }

    #[must_use]
    pub const fn authorization_created_at(&self) -> Option<u64> {
        self.authorization_created_at
    }

    #[must_use]
    pub const fn observed_at(&self) -> u64 {
        self.observed_at
    }

    #[must_use]
    pub const fn response_commitment(&self) -> &DigestHex {
        &self.response_commitment
    }

    /// Compares every effect-critical fact while allowing a fresh timestamp.
    #[must_use]
    pub fn critical_scope_matches(&self, fresh: &Self) -> bool {
        self.stripe_account_id == fresh.stripe_account_id
            && self.connect_account == fresh.connect_account
            && self.payment_intent_id == fresh.payment_intent_id
            && self.latest_charge_id == fresh.latest_charge_id
            && self.customer_id == fresh.customer_id
            && self.order_scope == fresh.order_scope
            && self.amount_minor == fresh.amount_minor
            && self.amount_capturable_minor == fresh.amount_capturable_minor
            && self.currency == fresh.currency
            && self.payment_intent_status == fresh.payment_intent_status
            && self.cancellation_eligible == fresh.cancellation_eligible
            && self.livemode == fresh.livemode
            && self.stripe_api_version == fresh.stripe_api_version
            && self.authorization_workflow_id == fresh.authorization_workflow_id
            && self.authorization_action_digest == fresh.authorization_action_digest
            && self.authorization_reservation_id == fresh.authorization_reservation_id
            && self.authorization_state == fresh.authorization_state
            && self.authorization_created_at == fresh.authorization_created_at
    }
}

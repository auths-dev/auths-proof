//! Bounded protected evidence shared by Stripe collection and authorization evaluators.

use serde::{Deserialize, Serialize};

use super::{
    MerchantConnectAccount, MerchantOperation, MerchantValidationError, valid_api_version,
    valid_local_id, valid_payment_method_type,
};
use crate::{
    canonical::{CanonicalError, canonical_digest},
    types::{Currency, CustomerId, DigestHex, PaymentIntentId, PaymentMethodId, StripeAccountId},
};

const MAX_PRIOR_PAYMENTS: usize = 64;
const MAX_MONEY_MINOR: u64 = 99_999_999;

/// Existing provider outcome for a protected order scope.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PriorMerchantPaymentState {
    /// Automatic collection completed.
    Succeeded,
    /// Manual authorization is active.
    RequiresCapture,
    /// Provider still processes the request.
    Processing,
    /// Delivery may have reached Stripe.
    OutcomeUnknown,
    /// Provider definitively declined or failed before payment.
    Failed,
    /// Provider canceled or expired the intent.
    Canceled,
}

/// One bounded prior `PaymentIntent` projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PriorMerchantPayment {
    payment_intent_id: Option<PaymentIntentId>,
    order_scope: String,
    operation: MerchantOperation,
    state: PriorMerchantPaymentState,
    amount_minor: u64,
    currency: Currency,
    action_digest: Option<DigestHex>,
}

impl PriorMerchantPayment {
    /// Constructs one protected prior-order projection.
    ///
    /// # Errors
    ///
    /// Rejects malformed order, amount, or identifier facts.
    pub fn new(
        payment_intent_id: Option<PaymentIntentId>,
        order_scope: impl Into<String>,
        operation: MerchantOperation,
        state: PriorMerchantPaymentState,
        amount_minor: u64,
        currency: Currency,
        action_digest: Option<DigestHex>,
    ) -> Result<Self, MerchantValidationError> {
        let value = Self {
            payment_intent_id,
            order_scope: order_scope.into(),
            operation,
            state,
            amount_minor,
            currency,
            action_digest,
        };
        if !valid_local_id(&value.order_scope)
            || value.amount_minor == 0
            || value.amount_minor > MAX_MONEY_MINOR
        {
            return Err(MerchantValidationError::InvalidEvidence);
        }
        Ok(value)
    }

    /// `PaymentIntent` when known.
    #[must_use]
    pub const fn payment_intent_id(&self) -> Option<&PaymentIntentId> {
        self.payment_intent_id.as_ref()
    }

    /// Protected order scope.
    #[must_use]
    pub fn order_scope(&self) -> &str {
        &self.order_scope
    }

    /// Exact operation.
    #[must_use]
    pub const fn operation(&self) -> MerchantOperation {
        self.operation
    }

    /// Normalized provider state.
    #[must_use]
    pub const fn state(&self) -> PriorMerchantPaymentState {
        self.state
    }
}

/// Fresh protected Customer, `PaymentMethod`, and order evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MerchantPaymentEvidenceV1 {
    schema: String,
    stripe_account_id: StripeAccountId,
    connect_account: MerchantConnectAccount,
    customer_id: CustomerId,
    payment_method_id: PaymentMethodId,
    payment_method_type: String,
    attached_customer_id: CustomerId,
    livemode: bool,
    stripe_api_version: String,
    order_scope: String,
    consent_order_commitment: DigestHex,
    supports_manual_capture: bool,
    prior_payments: Vec<PriorMerchantPayment>,
    observed_at: u64,
    source: String,
    response_commitment: DigestHex,
}

/// Inputs for normalized protected merchant-payment evidence.
pub struct MerchantPaymentEvidenceInput {
    /// Stripe account.
    pub stripe_account_id: StripeAccountId,
    /// Platform or Connect context.
    pub connect_account: MerchantConnectAccount,
    /// Exact Customer.
    pub customer_id: CustomerId,
    /// Exact attached `PaymentMethod`.
    pub payment_method_id: PaymentMethodId,
    /// `PaymentMethod` type.
    pub payment_method_type: String,
    /// Customer to which the `PaymentMethod` is attached.
    pub attached_customer_id: CustomerId,
    /// Provider test/live bit.
    pub livemode: bool,
    /// Pinned Stripe API version.
    pub stripe_api_version: String,
    /// Protected merchant order scope.
    pub order_scope: String,
    /// Consent/order record commitment.
    pub consent_order_commitment: DigestHex,
    /// Whether the method supports separate authorization/capture.
    pub supports_manual_capture: bool,
    /// Bounded prior relevant `PaymentIntents`.
    pub prior_payments: Vec<PriorMerchantPayment>,
    /// Trusted observation time.
    pub observed_at: u64,
    /// Evidence source.
    pub source: String,
    /// Commitment to the bounded sanitized provider response.
    pub response_commitment: DigestHex,
}

impl MerchantPaymentEvidenceV1 {
    /// Builds internally consistent protected evidence.
    ///
    /// # Errors
    ///
    /// Rejects live mode, attachment mismatch, duplicates, unbounded prior
    /// state, or malformed provider/order facts.
    pub fn new(mut input: MerchantPaymentEvidenceInput) -> Result<Self, MerchantValidationError> {
        input.prior_payments.sort_by(|left, right| {
            (
                left.order_scope(),
                left.operation(),
                left.payment_intent_id(),
            )
                .cmp(&(
                    right.order_scope(),
                    right.operation(),
                    right.payment_intent_id(),
                ))
        });
        let prior_unique = input.prior_payments.windows(2).all(|pair| {
            (
                pair[0].order_scope(),
                pair[0].operation(),
                pair[0].payment_intent_id(),
            ) < (
                pair[1].order_scope(),
                pair[1].operation(),
                pair[1].payment_intent_id(),
            )
        });
        if input.livemode
            || input.customer_id != input.attached_customer_id
            || !valid_payment_method_type(&input.payment_method_type)
            || !valid_api_version(&input.stripe_api_version)
            || !valid_local_id(&input.order_scope)
            || input.prior_payments.len() > MAX_PRIOR_PAYMENTS
            || !prior_unique
            || !matches!(
                input.source.as_str(),
                "stripe-api" | "stripe-api-and-order-store"
            )
            || input
                .prior_payments
                .iter()
                .any(|prior| prior.order_scope() != input.order_scope)
        {
            return Err(MerchantValidationError::InvalidEvidence);
        }
        Ok(Self {
            schema: "auths.stripe.merchant-payment-evidence/1".into(),
            stripe_account_id: input.stripe_account_id,
            connect_account: input.connect_account,
            customer_id: input.customer_id,
            payment_method_id: input.payment_method_id,
            payment_method_type: input.payment_method_type,
            attached_customer_id: input.attached_customer_id,
            livemode: input.livemode,
            stripe_api_version: input.stripe_api_version,
            order_scope: input.order_scope,
            consent_order_commitment: input.consent_order_commitment,
            supports_manual_capture: input.supports_manual_capture,
            prior_payments: input.prior_payments,
            observed_at: input.observed_at,
            source: input.source,
            response_commitment: input.response_commitment,
        })
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

    /// Customer.
    #[must_use]
    pub const fn customer_id(&self) -> &CustomerId {
        &self.customer_id
    }

    /// `PaymentMethod`.
    #[must_use]
    pub const fn payment_method_id(&self) -> &PaymentMethodId {
        &self.payment_method_id
    }

    /// `PaymentMethod` type.
    #[must_use]
    pub fn payment_method_type(&self) -> &str {
        &self.payment_method_type
    }

    /// Test/live bit.
    #[must_use]
    pub const fn livemode(&self) -> bool {
        self.livemode
    }

    /// Pinned API version.
    #[must_use]
    pub fn stripe_api_version(&self) -> &str {
        &self.stripe_api_version
    }

    /// Protected order scope.
    #[must_use]
    pub fn order_scope(&self) -> &str {
        &self.order_scope
    }

    /// Consent/order commitment.
    #[must_use]
    pub const fn consent_order_commitment(&self) -> &DigestHex {
        &self.consent_order_commitment
    }

    /// Whether manual capture is supported.
    #[must_use]
    pub const fn supports_manual_capture(&self) -> bool {
        self.supports_manual_capture
    }

    /// Bounded prior relevant `PaymentIntents`.
    #[must_use]
    pub fn prior_payments(&self) -> &[PriorMerchantPayment] {
        &self.prior_payments
    }

    /// Trusted observation time.
    #[must_use]
    pub const fn observed_at(&self) -> u64 {
        self.observed_at
    }

    /// Evidence source.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Sanitized provider-response commitment.
    #[must_use]
    pub const fn response_commitment(&self) -> &DigestHex {
        &self.response_commitment
    }

    /// Whether two observations bind the same critical execution scope.
    #[must_use]
    pub fn critical_scope_matches(&self, other: &Self) -> bool {
        self.stripe_account_id == other.stripe_account_id
            && self.connect_account == other.connect_account
            && self.customer_id == other.customer_id
            && self.payment_method_id == other.payment_method_id
            && self.payment_method_type == other.payment_method_type
            && self.attached_customer_id == other.attached_customer_id
            && self.livemode == other.livemode
            && self.stripe_api_version == other.stripe_api_version
            && self.order_scope == other.order_scope
            && self.consent_order_commitment == other.consent_order_commitment
            && self.supports_manual_capture == other.supports_manual_capture
            && self.prior_payments == other.prior_payments
    }
}

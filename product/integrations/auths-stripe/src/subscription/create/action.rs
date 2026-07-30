//! Closed exact action for subscription creation.

use auths_model::Audience;
use serde::{Deserialize, Serialize};

use super::SUBSCRIPTION_CREATE_PROFILE;
use crate::{
    canonical::{CanonicalError, canonical_digest, canonical_json},
    subscription::{
        SUBSCRIPTION_EVALUATOR_ID, SubscriptionCollectionMethod, SubscriptionConnectAccount,
        SubscriptionPaymentBehavior, SubscriptionProrationBehavior, SubscriptionValidationError,
        valid_api_version,
    },
    types::{
        Currency, CustomerId, DigestHex, PaymentMethodId, PriceId, ProductId, StripeAccountId,
        TestClockId,
    },
};

/// One exact licensed recurring item.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionCreateItem {
    price_id: PriceId,
    product_id: ProductId,
    quantity: u32,
}

impl SubscriptionCreateItem {
    pub fn new(
        price_id: PriceId,
        product_id: ProductId,
        quantity: u32,
    ) -> Result<Self, SubscriptionValidationError> {
        if quantity == 0 || quantity > 1_000_000 {
            return Err(SubscriptionValidationError::Action);
        }
        Ok(Self {
            price_id,
            product_id,
            quantity,
        })
    }
    pub const fn price_id(&self) -> &PriceId {
        &self.price_id
    }
    pub const fn product_id(&self) -> &ProductId {
        &self.product_id
    }
    pub const fn quantity(&self) -> u32 {
        self.quantity
    }
}

/// Exact bounded subscription creation authorized by Auths.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StripeExactSubscriptionCreateV1 {
    profile: String,
    stripe_account_id: StripeAccountId,
    connect_account: SubscriptionConnectAccount,
    customer_id: CustomerId,
    items: Vec<SubscriptionCreateItem>,
    currency: Currency,
    collection_method: SubscriptionCollectionMethod,
    default_payment_method_id: PaymentMethodId,
    mandate_receipt_digest: DigestHex,
    payment_behavior: SubscriptionPaymentBehavior,
    trial_end: Option<u64>,
    billing_cycle_anchor: u64,
    cancel_at: u64,
    proration_behavior: SubscriptionProrationBehavior,
    automatic_tax: bool,
    discounts: Option<Vec<String>>,
    add_invoice_items: Option<Vec<String>>,
    fixed_metadata_commitment: DigestHex,
    invoice_preview_digest: DigestHex,
    projected_first_invoice_minor: u64,
    projected_recurring_minor: u64,
    projected_cycle_count: u32,
    projected_term_liability_minor: u64,
    test_clock_id: TestClockId,
    stripe_api_version: String,
    required_policy_digest: DigestHex,
    required_evaluator: String,
    required_configuration_digest: DigestHex,
    executor_audience: String,
    expires_at: u64,
    nonce: DigestHex,
}

/// Constructor inputs for the closed action.
pub struct StripeExactSubscriptionCreateInput {
    pub stripe_account_id: StripeAccountId,
    pub connect_account: SubscriptionConnectAccount,
    pub customer_id: CustomerId,
    pub items: Vec<SubscriptionCreateItem>,
    pub currency: Currency,
    pub default_payment_method_id: PaymentMethodId,
    pub mandate_receipt_digest: DigestHex,
    pub payment_behavior: SubscriptionPaymentBehavior,
    pub trial_end: Option<u64>,
    pub billing_cycle_anchor: u64,
    pub cancel_at: u64,
    pub fixed_metadata_commitment: DigestHex,
    pub invoice_preview_digest: DigestHex,
    pub projected_first_invoice_minor: u64,
    pub projected_recurring_minor: u64,
    pub projected_cycle_count: u32,
    pub projected_term_liability_minor: u64,
    pub test_clock_id: TestClockId,
    pub stripe_api_version: String,
    pub required_policy_digest: DigestHex,
    pub required_configuration_digest: DigestHex,
    pub executor_audience: String,
    pub expires_at: u64,
    pub nonce: DigestHex,
}

impl StripeExactSubscriptionCreateV1 {
    pub fn new(
        input: StripeExactSubscriptionCreateInput,
    ) -> Result<Self, SubscriptionValidationError> {
        let mut items = input.items;
        items.sort();
        let action = Self {
            profile: SUBSCRIPTION_CREATE_PROFILE.into(),
            stripe_account_id: input.stripe_account_id,
            connect_account: input.connect_account,
            customer_id: input.customer_id,
            items,
            currency: input.currency,
            collection_method: SubscriptionCollectionMethod::ChargeAutomatically,
            default_payment_method_id: input.default_payment_method_id,
            mandate_receipt_digest: input.mandate_receipt_digest,
            payment_behavior: input.payment_behavior,
            trial_end: input.trial_end,
            billing_cycle_anchor: input.billing_cycle_anchor,
            cancel_at: input.cancel_at,
            proration_behavior: SubscriptionProrationBehavior::None,
            automatic_tax: false,
            discounts: None,
            add_invoice_items: None,
            fixed_metadata_commitment: input.fixed_metadata_commitment,
            invoice_preview_digest: input.invoice_preview_digest,
            projected_first_invoice_minor: input.projected_first_invoice_minor,
            projected_recurring_minor: input.projected_recurring_minor,
            projected_cycle_count: input.projected_cycle_count,
            projected_term_liability_minor: input.projected_term_liability_minor,
            test_clock_id: input.test_clock_id,
            stripe_api_version: input.stripe_api_version,
            required_policy_digest: input.required_policy_digest,
            required_evaluator: SUBSCRIPTION_EVALUATOR_ID.into(),
            required_configuration_digest: input.required_configuration_digest,
            executor_audience: input.executor_audience,
            expires_at: input.expires_at,
            nonce: input.nonce,
        };
        action.validate()?;
        Ok(action)
    }

    pub fn validate(&self) -> Result<(), SubscriptionValidationError> {
        let recomputed = self
            .projected_recurring_minor
            .checked_mul(u64::from(self.projected_cycle_count))
            .ok_or(SubscriptionValidationError::Action)?;
        let valid = self.profile == SUBSCRIPTION_CREATE_PROFILE
            && self.required_evaluator == SUBSCRIPTION_EVALUATOR_ID
            && !self.items.is_empty()
            && self.items.len() <= 32
            && self.items.windows(2).all(|p| p[0] < p[1])
            && self.items.iter().all(|item| item.quantity > 0)
            && self.collection_method == SubscriptionCollectionMethod::ChargeAutomatically
            && self.proration_behavior == SubscriptionProrationBehavior::None
            && !self.automatic_tax
            && self.discounts.is_none()
            && self.add_invoice_items.is_none()
            && self.billing_cycle_anchor < self.cancel_at
            && self
                .trial_end
                .is_none_or(|value| value >= self.billing_cycle_anchor && value < self.cancel_at)
            && self.projected_recurring_minor > 0
            && self.projected_cycle_count > 0
            && recomputed == self.projected_term_liability_minor
            && valid_api_version(&self.stripe_api_version)
            && Audience::parse(&self.executor_audience).is_ok();
        if valid {
            Ok(())
        } else {
            Err(SubscriptionValidationError::Action)
        }
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
    pub const fn connect_account(&self) -> &SubscriptionConnectAccount {
        &self.connect_account
    }
    pub const fn customer_id(&self) -> &CustomerId {
        &self.customer_id
    }
    pub fn items(&self) -> &[SubscriptionCreateItem] {
        &self.items
    }
    pub const fn currency(&self) -> &Currency {
        &self.currency
    }
    pub const fn collection_method(&self) -> SubscriptionCollectionMethod {
        self.collection_method
    }
    pub const fn default_payment_method_id(&self) -> &PaymentMethodId {
        &self.default_payment_method_id
    }
    pub const fn mandate_receipt_digest(&self) -> &DigestHex {
        &self.mandate_receipt_digest
    }
    pub const fn payment_behavior(&self) -> SubscriptionPaymentBehavior {
        self.payment_behavior
    }
    pub const fn trial_end(&self) -> Option<u64> {
        self.trial_end
    }
    pub const fn billing_cycle_anchor(&self) -> u64 {
        self.billing_cycle_anchor
    }
    pub const fn cancel_at(&self) -> u64 {
        self.cancel_at
    }
    pub const fn fixed_metadata_commitment(&self) -> &DigestHex {
        &self.fixed_metadata_commitment
    }
    pub const fn invoice_preview_digest(&self) -> &DigestHex {
        &self.invoice_preview_digest
    }
    pub const fn projected_first_invoice_minor(&self) -> u64 {
        self.projected_first_invoice_minor
    }
    pub const fn projected_recurring_minor(&self) -> u64 {
        self.projected_recurring_minor
    }
    pub const fn projected_cycle_count(&self) -> u32 {
        self.projected_cycle_count
    }
    pub const fn projected_term_liability_minor(&self) -> u64 {
        self.projected_term_liability_minor
    }
    pub const fn test_clock_id(&self) -> &TestClockId {
        &self.test_clock_id
    }
    pub fn stripe_api_version(&self) -> &str {
        &self.stripe_api_version
    }
    pub const fn required_policy_digest(&self) -> &DigestHex {
        &self.required_policy_digest
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

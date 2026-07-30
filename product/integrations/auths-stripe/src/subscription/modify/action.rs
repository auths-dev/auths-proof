//! Closed exact action and protected evidence for subscription modification.

use auths_model::Audience;
use serde::{Deserialize, Serialize};

use super::SUBSCRIPTION_MODIFY_PROFILE;
use crate::{
    canonical::{CanonicalError, canonical_digest, canonical_json},
    subscription::{
        SUBSCRIPTION_EVALUATOR_ID, SubscriptionCatalogItemEvidence, SubscriptionCollectionMethod,
        SubscriptionConnectAccount, SubscriptionPreviewLine, SubscriptionProrationBehavior,
        SubscriptionValidationError, valid_api_version, valid_local,
    },
    types::{
        Currency, CustomerId, DigestHex, InvoiceId, PaymentIntentId, PaymentMethodId, PriceId,
        ProductId, StripeAccountId, SubscriptionId, SubscriptionItemId, TestClockId,
    },
};

/// Closed payment behavior owned by the subscription-modify profile.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionModifyPaymentBehavior {
    PendingIfIncomplete,
}

/// One exact retained Subscription Item before or after modification.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionModifyItem {
    subscription_item_id: SubscriptionItemId,
    price_id: PriceId,
    product_id: ProductId,
    quantity: u32,
}

impl SubscriptionModifyItem {
    pub fn new(
        subscription_item_id: SubscriptionItemId,
        price_id: PriceId,
        product_id: ProductId,
        quantity: u32,
    ) -> Result<Self, SubscriptionValidationError> {
        if quantity == 0 || quantity > 1_000_000 {
            return Err(SubscriptionValidationError::Action);
        }
        Ok(Self {
            subscription_item_id,
            price_id,
            product_id,
            quantity,
        })
    }
    pub const fn subscription_item_id(&self) -> &SubscriptionItemId {
        &self.subscription_item_id
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

/// One exact bounded Subscription update.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StripeExactSubscriptionModifyV1 {
    profile: String,
    stripe_account_id: StripeAccountId,
    connect_account: SubscriptionConnectAccount,
    subscription_id: SubscriptionId,
    customer_id: CustomerId,
    before_subscription_digest: DigestHex,
    before_items: Vec<SubscriptionModifyItem>,
    after_items: Vec<SubscriptionModifyItem>,
    currency: Currency,
    billing_cycle_anchor: u64,
    cancel_at: u64,
    proration_date: u64,
    proration_behavior: SubscriptionProrationBehavior,
    payment_behavior: SubscriptionModifyPaymentBehavior,
    mandate_receipt_digest: DigestHex,
    invoice_preview_digest: DigestHex,
    proration_debit_minor: u64,
    proration_credit_minor: u64,
    before_recurring_minor: u64,
    after_recurring_minor: u64,
    remaining_cycle_count: u32,
    incremental_term_liability_minor: u64,
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
pub struct StripeExactSubscriptionModifyInput {
    pub stripe_account_id: StripeAccountId,
    pub connect_account: SubscriptionConnectAccount,
    pub subscription_id: SubscriptionId,
    pub customer_id: CustomerId,
    pub before_subscription_digest: DigestHex,
    pub before_items: Vec<SubscriptionModifyItem>,
    pub after_items: Vec<SubscriptionModifyItem>,
    pub currency: Currency,
    pub billing_cycle_anchor: u64,
    pub cancel_at: u64,
    pub proration_date: u64,
    pub mandate_receipt_digest: DigestHex,
    pub invoice_preview_digest: DigestHex,
    pub proration_debit_minor: u64,
    pub proration_credit_minor: u64,
    pub before_recurring_minor: u64,
    pub after_recurring_minor: u64,
    pub remaining_cycle_count: u32,
    pub incremental_term_liability_minor: u64,
    pub test_clock_id: TestClockId,
    pub stripe_api_version: String,
    pub required_policy_digest: DigestHex,
    pub required_configuration_digest: DigestHex,
    pub executor_audience: String,
    pub expires_at: u64,
    pub nonce: DigestHex,
}

impl StripeExactSubscriptionModifyV1 {
    pub fn new(
        input: StripeExactSubscriptionModifyInput,
    ) -> Result<Self, SubscriptionValidationError> {
        let mut before_items = input.before_items;
        let mut after_items = input.after_items;
        before_items.sort();
        after_items.sort();
        let value = Self {
            profile: SUBSCRIPTION_MODIFY_PROFILE.into(),
            stripe_account_id: input.stripe_account_id,
            connect_account: input.connect_account,
            subscription_id: input.subscription_id,
            customer_id: input.customer_id,
            before_subscription_digest: input.before_subscription_digest,
            before_items,
            after_items,
            currency: input.currency,
            billing_cycle_anchor: input.billing_cycle_anchor,
            cancel_at: input.cancel_at,
            proration_date: input.proration_date,
            proration_behavior: SubscriptionProrationBehavior::AlwaysInvoice,
            payment_behavior: SubscriptionModifyPaymentBehavior::PendingIfIncomplete,
            mandate_receipt_digest: input.mandate_receipt_digest,
            invoice_preview_digest: input.invoice_preview_digest,
            proration_debit_minor: input.proration_debit_minor,
            proration_credit_minor: input.proration_credit_minor,
            before_recurring_minor: input.before_recurring_minor,
            after_recurring_minor: input.after_recurring_minor,
            remaining_cycle_count: input.remaining_cycle_count,
            incremental_term_liability_minor: input.incremental_term_liability_minor,
            test_clock_id: input.test_clock_id,
            stripe_api_version: input.stripe_api_version,
            required_policy_digest: input.required_policy_digest,
            required_evaluator: SUBSCRIPTION_EVALUATOR_ID.into(),
            required_configuration_digest: input.required_configuration_digest,
            executor_audience: input.executor_audience,
            expires_at: input.expires_at,
            nonce: input.nonce,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), SubscriptionValidationError> {
        let before_term = self
            .before_recurring_minor
            .checked_mul(u64::from(self.remaining_cycle_count))
            .ok_or(SubscriptionValidationError::Action)?;
        let after_term = self
            .after_recurring_minor
            .checked_mul(u64::from(self.remaining_cycle_count))
            .ok_or(SubscriptionValidationError::Action)?;
        let incremental = after_term.saturating_sub(before_term);
        let item_identity_retained = self.before_items.len() == self.after_items.len()
            && self
                .before_items
                .iter()
                .zip(&self.after_items)
                .all(|(before, after)| before.subscription_item_id == after.subscription_item_id);
        let changed = self.before_items != self.after_items;
        let valid = self.profile == SUBSCRIPTION_MODIFY_PROFILE
            && self.required_evaluator == SUBSCRIPTION_EVALUATOR_ID
            && !self.before_items.is_empty()
            && self.before_items.len() <= 32
            && self.before_items.windows(2).all(|pair| pair[0] < pair[1])
            && self.after_items.windows(2).all(|pair| pair[0] < pair[1])
            && item_identity_retained
            && changed
            && self.billing_cycle_anchor < self.cancel_at
            && self.proration_date >= self.billing_cycle_anchor
            && self.proration_date < self.cancel_at
            && self.proration_behavior == SubscriptionProrationBehavior::AlwaysInvoice
            && self.payment_behavior == SubscriptionModifyPaymentBehavior::PendingIfIncomplete
            && self.before_recurring_minor > 0
            && self.after_recurring_minor > 0
            && self.remaining_cycle_count > 0
            && incremental == self.incremental_term_liability_minor
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
    pub const fn subscription_id(&self) -> &SubscriptionId {
        &self.subscription_id
    }
    pub const fn customer_id(&self) -> &CustomerId {
        &self.customer_id
    }
    pub const fn before_subscription_digest(&self) -> &DigestHex {
        &self.before_subscription_digest
    }
    pub fn before_items(&self) -> &[SubscriptionModifyItem] {
        &self.before_items
    }
    pub fn after_items(&self) -> &[SubscriptionModifyItem] {
        &self.after_items
    }
    pub const fn currency(&self) -> &Currency {
        &self.currency
    }
    pub const fn billing_cycle_anchor(&self) -> u64 {
        self.billing_cycle_anchor
    }
    pub const fn cancel_at(&self) -> u64 {
        self.cancel_at
    }
    pub const fn proration_date(&self) -> u64 {
        self.proration_date
    }
    pub const fn proration_behavior(&self) -> SubscriptionProrationBehavior {
        self.proration_behavior
    }
    pub const fn payment_behavior(&self) -> SubscriptionModifyPaymentBehavior {
        self.payment_behavior
    }
    pub const fn mandate_receipt_digest(&self) -> &DigestHex {
        &self.mandate_receipt_digest
    }
    pub const fn invoice_preview_digest(&self) -> &DigestHex {
        &self.invoice_preview_digest
    }
    pub const fn proration_debit_minor(&self) -> u64 {
        self.proration_debit_minor
    }
    pub const fn proration_credit_minor(&self) -> u64 {
        self.proration_credit_minor
    }
    pub const fn before_recurring_minor(&self) -> u64 {
        self.before_recurring_minor
    }
    pub const fn after_recurring_minor(&self) -> u64 {
        self.after_recurring_minor
    }
    pub const fn remaining_cycle_count(&self) -> u32 {
        self.remaining_cycle_count
    }
    pub const fn incremental_term_liability_minor(&self) -> u64 {
        self.incremental_term_liability_minor
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

/// Exact protected Subscription state used for the before-state commitment.
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct SubscriptionBeforeCommitment<'a> {
    subscription_id: &'a SubscriptionId,
    customer_id: &'a CustomerId,
    items: &'a [SubscriptionModifyItem],
    currency: &'a Currency,
    collection_method: SubscriptionCollectionMethod,
    payment_method_id: &'a PaymentMethodId,
    billing_cycle_anchor: u64,
    current_period_start: u64,
    current_period_end: u64,
    cancel_at: u64,
    mandate_receipt_digest: &'a DigestHex,
    test_clock_id: &'a TestClockId,
}

/// Fresh Subscription, catalog, invoice-preview, and payment evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionModifyEvidenceV1 {
    pub schema: String,
    pub stripe_account_id: StripeAccountId,
    pub connect_account: SubscriptionConnectAccount,
    pub subscription_id: SubscriptionId,
    pub customer_id: CustomerId,
    pub current_items: Vec<SubscriptionModifyItem>,
    pub currency: Currency,
    pub collection_method: SubscriptionCollectionMethod,
    pub payment_method_id: PaymentMethodId,
    pub billing_cycle_anchor: u64,
    pub current_period_start: u64,
    pub current_period_end: u64,
    pub cancel_at: u64,
    pub mandate_receipt_digest: DigestHex,
    pub test_clock_id: TestClockId,
    pub before_subscription_digest: DigestHex,
    pub pending_update_digest: Option<DigestHex>,
    pub catalog: Vec<SubscriptionCatalogItemEvidence>,
    pub preview_lines: Vec<SubscriptionPreviewLine>,
    pub preview_digest: DigestHex,
    pub proration_date: u64,
    pub proration_debit_minor: u64,
    pub proration_credit_minor: u64,
    pub before_recurring_minor: u64,
    pub after_recurring_minor: u64,
    pub remaining_cycle_count: u32,
    pub latest_invoice_id: Option<InvoiceId>,
    pub latest_payment_intent_id: Option<PaymentIntentId>,
    pub invoice_status: Option<String>,
    pub payment_status: Option<String>,
    pub preview_valid_until: u64,
    pub livemode: bool,
    pub stripe_api_version: String,
    pub observed_at: u64,
    pub response_digest: DigestHex,
    pub source: String,
}

impl SubscriptionModifyEvidenceV1 {
    pub fn before_digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(&SubscriptionBeforeCommitment {
            subscription_id: &self.subscription_id,
            customer_id: &self.customer_id,
            items: &self.current_items,
            currency: &self.currency,
            collection_method: self.collection_method,
            payment_method_id: &self.payment_method_id,
            billing_cycle_anchor: self.billing_cycle_anchor,
            current_period_start: self.current_period_start,
            current_period_end: self.current_period_end,
            cancel_at: self.cancel_at,
            mandate_receipt_digest: &self.mandate_receipt_digest,
            test_clock_id: &self.test_clock_id,
        })
    }

    pub fn validate(&self) -> Result<(), SubscriptionValidationError> {
        let valid = self.schema == "auths.stripe.subscription-modify-evidence/1"
            && !self.current_items.is_empty()
            && self.current_items.len() <= 32
            && self.current_items.windows(2).all(|pair| pair[0] < pair[1])
            && !self.catalog.is_empty()
            && self.catalog.len() <= 32
            && self.catalog.windows(2).all(|pair| pair[0] < pair[1])
            && self.preview_lines.len() <= 64
            && self.preview_lines.windows(2).all(|pair| pair[0] < pair[1])
            && self.current_period_start < self.current_period_end
            && self.billing_cycle_anchor <= self.current_period_start
            && self.current_period_end <= self.cancel_at
            && self.proration_date >= self.current_period_start
            && self.proration_date < self.current_period_end
            && self.remaining_cycle_count > 0
            && !self.livemode
            && valid_api_version(&self.stripe_api_version)
            && valid_local(&self.source)
            && self.before_digest().ok().as_ref() == Some(&self.before_subscription_digest);
        if valid {
            Ok(())
        } else {
            Err(SubscriptionValidationError::Evidence)
        }
    }
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

/// Sanitized result of an exact update or later reconciliation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionModifyProviderProjection {
    pub subscription_id: SubscriptionId,
    pub customer_id: CustomerId,
    pub items: Vec<SubscriptionModifyItem>,
    pub item_set_digest: DigestHex,
    pub pending_update_digest: Option<DigestHex>,
    pub latest_invoice_id: Option<InvoiceId>,
    pub payment_intent_id: Option<PaymentIntentId>,
    pub invoice_status: Option<String>,
    pub payment_status: Option<String>,
    pub applied: bool,
    pub payment_incomplete: bool,
    pub amount_paid_minor: u64,
    pub billing_cycle_anchor: u64,
    pub cancel_at: u64,
    pub livemode: bool,
    pub stripe_request_id: Option<String>,
    pub response_digest: DigestHex,
    pub observed_at: u64,
    pub source: String,
}

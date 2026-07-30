//! Immutable subscription policy and protected provider evidence.

use std::collections::BTreeMap;

use auths_model::Audience;
use serde::{Deserialize, Serialize};

use super::{
    SUBSCRIPTION_CANONICALIZATION, SUBSCRIPTION_EVALUATOR_ID, SUBSCRIPTION_LIABILITY_SCHEMA,
    SUBSCRIPTION_POLICY_TYPE, SubscriptionValidationError, sorted_unique_nonempty,
    valid_api_version, valid_local,
};
use crate::{
    canonical::{CanonicalError, canonical_digest},
    mandate::{
        MandateInterval, PaymentMandateCapabilityRecord, PaymentMandateCapabilityState,
        PaymentMandateReceipt, StripeExactPaymentMandateV1,
    },
    types::{
        Currency, CustomerId, DigestHex, InvoiceId, PaymentIntentId, PaymentMethodId, PriceId,
        ProductId, StripeAccountId, SubscriptionId, TestClockId,
    },
};

/// Platform versus one exact connected account.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "account")]
pub enum SubscriptionConnectAccount {
    Platform,
    Connected(StripeAccountId),
}

/// Licensed recurring interval.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionInterval {
    Week,
    Month,
    Year,
}

impl SubscriptionInterval {
    pub const fn mandate_interval(self) -> MandateInterval {
        match self {
            Self::Week => MandateInterval::Weekly,
            Self::Month => MandateInterval::Monthly,
            Self::Year => MandateInterval::Yearly,
        }
    }
}

/// V1 collection method.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionCollectionMethod {
    ChargeAutomatically,
}

/// Closed creation payment behavior.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionPaymentBehavior {
    DefaultIncomplete,
    ErrorIfIncomplete,
}

/// Closed proration behavior.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionProrationBehavior {
    None,
    CreateProrations,
    AlwaysInvoice,
}

/// Closed cancellation mode shared with the later cancellation profile.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionCancelMode {
    AtPeriodEnd,
    Immediate,
}

/// Policy operation. It is policy data and never dispatches execution.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionOperation {
    Create,
    Modify,
    Cancel,
}

/// One interval-aware recurring ceiling.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionRecurringLimit {
    pub currency: Currency,
    pub interval: SubscriptionInterval,
    pub limit_minor: u64,
}

/// One finite-term aggregate recurring budget.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AggregateRecurringBudget {
    pub budget_id: String,
    pub customer_id: CustomerId,
    pub currency: Currency,
    pub interval: SubscriptionInterval,
    pub limit_minor: u64,
}

/// One immediate-debit budget.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AggregateImmediateBudget {
    pub budget_id: String,
    pub currency: Currency,
    pub limit_minor: u64,
    pub starts_at: u64,
    pub ends_at: u64,
}

/// Closed policy shared by create/modify/cancel, without shared execution.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StripeBoundedSubscriptionPolicyV1 {
    policy_type: String,
    canonicalization: String,
    evaluator_semantic_id: String,
    evaluator_semantic_version: u16,
    policy_id: String,
    valid_from: u64,
    expires_at: u64,
    allowed_operations: Vec<SubscriptionOperation>,
    allowed_test_account_ids: Vec<StripeAccountId>,
    allowed_customer_ids: Vec<CustomerId>,
    allowed_product_ids: Vec<ProductId>,
    allowed_price_ids: Vec<PriceId>,
    allowed_payment_method_ids: Vec<PaymentMethodId>,
    allowed_mandate_receipt_digests: Vec<DigestHex>,
    allowed_currencies: Vec<Currency>,
    allowed_intervals: Vec<SubscriptionInterval>,
    allowed_collection_methods: Vec<SubscriptionCollectionMethod>,
    allowed_payment_behaviors: Vec<SubscriptionPaymentBehavior>,
    allowed_proration_behaviors: Vec<SubscriptionProrationBehavior>,
    allowed_cancel_modes: Vec<SubscriptionCancelMode>,
    maximum_quantity_by_price: BTreeMap<PriceId, u32>,
    maximum_recurring_minor_by_currency_and_interval: Vec<SubscriptionRecurringLimit>,
    maximum_first_invoice_minor_by_currency: BTreeMap<Currency, u64>,
    maximum_proration_debit_minor_by_currency: BTreeMap<Currency, u64>,
    maximum_term_seconds: u64,
    maximum_billing_cycles: u32,
    maximum_active_subscriptions_per_customer: u32,
    aggregate_recurring_budgets: Vec<AggregateRecurringBudget>,
    aggregate_immediate_budgets: Vec<AggregateImmediateBudget>,
    minimum_preview_validity_seconds: u64,
    maximum_evidence_age_seconds: u64,
    maximum_action_lifetime_seconds: u64,
    allowed_api_versions: Vec<String>,
    require_fixed_term: bool,
    require_livemode: bool,
}

/// Explicit policy input.
pub struct StripeBoundedSubscriptionPolicyInput {
    pub policy_id: String,
    pub valid_from: u64,
    pub expires_at: u64,
    pub allowed_operations: Vec<SubscriptionOperation>,
    pub allowed_test_account_ids: Vec<StripeAccountId>,
    pub allowed_customer_ids: Vec<CustomerId>,
    pub allowed_product_ids: Vec<ProductId>,
    pub allowed_price_ids: Vec<PriceId>,
    pub allowed_payment_method_ids: Vec<PaymentMethodId>,
    pub allowed_mandate_receipt_digests: Vec<DigestHex>,
    pub allowed_currencies: Vec<Currency>,
    pub allowed_intervals: Vec<SubscriptionInterval>,
    pub allowed_payment_behaviors: Vec<SubscriptionPaymentBehavior>,
    pub maximum_quantity_by_price: BTreeMap<PriceId, u32>,
    pub maximum_recurring_minor_by_currency_and_interval: Vec<SubscriptionRecurringLimit>,
    pub maximum_first_invoice_minor_by_currency: BTreeMap<Currency, u64>,
    pub maximum_term_seconds: u64,
    pub maximum_billing_cycles: u32,
    pub maximum_active_subscriptions_per_customer: u32,
    pub aggregate_recurring_budgets: Vec<AggregateRecurringBudget>,
    pub aggregate_immediate_budgets: Vec<AggregateImmediateBudget>,
    pub minimum_preview_validity_seconds: u64,
    pub maximum_evidence_age_seconds: u64,
    pub maximum_action_lifetime_seconds: u64,
    pub allowed_api_versions: Vec<String>,
}

impl StripeBoundedSubscriptionPolicyV1 {
    pub fn new(
        mut input: StripeBoundedSubscriptionPolicyInput,
    ) -> Result<Self, SubscriptionValidationError> {
        input.allowed_operations.sort();
        input.allowed_test_account_ids.sort();
        input.allowed_customer_ids.sort();
        input.allowed_product_ids.sort();
        input.allowed_price_ids.sort();
        input.allowed_payment_method_ids.sort();
        input.allowed_mandate_receipt_digests.sort();
        input.allowed_currencies.sort();
        input.allowed_intervals.sort();
        input.allowed_payment_behaviors.sort();
        input
            .maximum_recurring_minor_by_currency_and_interval
            .sort();
        input.aggregate_recurring_budgets.sort();
        input.aggregate_immediate_budgets.sort();
        input.allowed_api_versions.sort();
        let policy = Self {
            policy_type: SUBSCRIPTION_POLICY_TYPE.into(),
            canonicalization: SUBSCRIPTION_CANONICALIZATION.into(),
            evaluator_semantic_id: SUBSCRIPTION_EVALUATOR_ID.into(),
            evaluator_semantic_version: 1,
            policy_id: input.policy_id,
            valid_from: input.valid_from,
            expires_at: input.expires_at,
            allowed_operations: input.allowed_operations,
            allowed_test_account_ids: input.allowed_test_account_ids,
            allowed_customer_ids: input.allowed_customer_ids,
            allowed_product_ids: input.allowed_product_ids,
            allowed_price_ids: input.allowed_price_ids,
            allowed_payment_method_ids: input.allowed_payment_method_ids,
            allowed_mandate_receipt_digests: input.allowed_mandate_receipt_digests,
            allowed_currencies: input.allowed_currencies,
            allowed_intervals: input.allowed_intervals,
            allowed_collection_methods: vec![SubscriptionCollectionMethod::ChargeAutomatically],
            allowed_payment_behaviors: input.allowed_payment_behaviors,
            allowed_proration_behaviors: vec![SubscriptionProrationBehavior::None],
            allowed_cancel_modes: vec![
                SubscriptionCancelMode::AtPeriodEnd,
                SubscriptionCancelMode::Immediate,
            ],
            maximum_quantity_by_price: input.maximum_quantity_by_price,
            maximum_recurring_minor_by_currency_and_interval: input
                .maximum_recurring_minor_by_currency_and_interval,
            maximum_first_invoice_minor_by_currency: input.maximum_first_invoice_minor_by_currency,
            maximum_proration_debit_minor_by_currency: BTreeMap::new(),
            maximum_term_seconds: input.maximum_term_seconds,
            maximum_billing_cycles: input.maximum_billing_cycles,
            maximum_active_subscriptions_per_customer: input
                .maximum_active_subscriptions_per_customer,
            aggregate_recurring_budgets: input.aggregate_recurring_budgets,
            aggregate_immediate_budgets: input.aggregate_immediate_budgets,
            minimum_preview_validity_seconds: input.minimum_preview_validity_seconds,
            maximum_evidence_age_seconds: input.maximum_evidence_age_seconds,
            maximum_action_lifetime_seconds: input.maximum_action_lifetime_seconds,
            allowed_api_versions: input.allowed_api_versions,
            require_fixed_term: true,
            require_livemode: false,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Enables the closed modify semantics without changing creation defaults.
    pub fn with_modify_limits(
        mut self,
        maximum_proration_debit_minor_by_currency: BTreeMap<Currency, u64>,
    ) -> Result<Self, SubscriptionValidationError> {
        self.allowed_operations.push(SubscriptionOperation::Modify);
        self.allowed_operations.sort();
        self.allowed_operations.dedup();
        self.allowed_proration_behaviors = vec![
            SubscriptionProrationBehavior::None,
            SubscriptionProrationBehavior::AlwaysInvoice,
        ];
        self.maximum_proration_debit_minor_by_currency = maximum_proration_debit_minor_by_currency;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), SubscriptionValidationError> {
        let valid = self.policy_type == SUBSCRIPTION_POLICY_TYPE
            && self.canonicalization == SUBSCRIPTION_CANONICALIZATION
            && self.evaluator_semantic_id == SUBSCRIPTION_EVALUATOR_ID
            && self.evaluator_semantic_version == 1
            && valid_local(&self.policy_id)
            && self.valid_from < self.expires_at
            && sorted_unique_nonempty(&self.allowed_operations)
            && sorted_unique_nonempty(&self.allowed_test_account_ids)
            && sorted_unique_nonempty(&self.allowed_customer_ids)
            && sorted_unique_nonempty(&self.allowed_product_ids)
            && sorted_unique_nonempty(&self.allowed_price_ids)
            && sorted_unique_nonempty(&self.allowed_payment_method_ids)
            && sorted_unique_nonempty(&self.allowed_mandate_receipt_digests)
            && sorted_unique_nonempty(&self.allowed_currencies)
            && sorted_unique_nonempty(&self.allowed_intervals)
            && self.allowed_collection_methods
                == [SubscriptionCollectionMethod::ChargeAutomatically]
            && sorted_unique_nonempty(&self.allowed_payment_behaviors)
            && sorted_unique_nonempty(&self.allowed_proration_behaviors)
            && self
                .allowed_proration_behaviors
                .binary_search(&SubscriptionProrationBehavior::None)
                .is_ok()
            && (!self
                .allowed_operations
                .contains(&SubscriptionOperation::Modify)
                || (self
                    .allowed_proration_behaviors
                    .binary_search(&SubscriptionProrationBehavior::AlwaysInvoice)
                    .is_ok()
                    && !self.maximum_proration_debit_minor_by_currency.is_empty()))
            && self
                .maximum_proration_debit_minor_by_currency
                .iter()
                .all(|(currency, amount)| {
                    *amount > 0 && self.allowed_currencies.binary_search(currency).is_ok()
                })
            && !self.maximum_quantity_by_price.is_empty()
            && self
                .maximum_quantity_by_price
                .iter()
                .all(|(price, quantity)| {
                    self.allowed_price_ids.binary_search(price).is_ok() && *quantity > 0
                })
            && sorted_unique_nonempty(&self.maximum_recurring_minor_by_currency_and_interval)
            && self
                .maximum_recurring_minor_by_currency_and_interval
                .iter()
                .all(|limit| {
                    limit.limit_minor > 0
                        && self
                            .allowed_currencies
                            .binary_search(&limit.currency)
                            .is_ok()
                        && self
                            .allowed_intervals
                            .binary_search(&limit.interval)
                            .is_ok()
                })
            && !self.maximum_first_invoice_minor_by_currency.is_empty()
            && self.maximum_term_seconds > 0
            && self.maximum_billing_cycles > 0
            && self.maximum_active_subscriptions_per_customer > 0
            && self.minimum_preview_validity_seconds > 0
            && self.maximum_evidence_age_seconds > 0
            && self.maximum_action_lifetime_seconds > 0
            && sorted_unique_nonempty(&self.allowed_api_versions)
            && self
                .allowed_api_versions
                .iter()
                .all(|value| valid_api_version(value))
            && self.require_fixed_term
            && !self.require_livemode;
        if valid {
            Ok(())
        } else {
            Err(SubscriptionValidationError::Policy)
        }
    }

    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
    pub const fn valid_from(&self) -> u64 {
        self.valid_from
    }
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
    pub fn allowed_operations(&self) -> &[SubscriptionOperation] {
        &self.allowed_operations
    }
    pub fn allowed_test_account_ids(&self) -> &[StripeAccountId] {
        &self.allowed_test_account_ids
    }
    pub fn allowed_customer_ids(&self) -> &[CustomerId] {
        &self.allowed_customer_ids
    }
    pub fn allowed_product_ids(&self) -> &[ProductId] {
        &self.allowed_product_ids
    }
    pub fn allowed_price_ids(&self) -> &[PriceId] {
        &self.allowed_price_ids
    }
    pub fn allowed_payment_method_ids(&self) -> &[PaymentMethodId] {
        &self.allowed_payment_method_ids
    }
    pub fn allowed_mandate_receipt_digests(&self) -> &[DigestHex] {
        &self.allowed_mandate_receipt_digests
    }
    pub fn allowed_currencies(&self) -> &[Currency] {
        &self.allowed_currencies
    }
    pub fn allowed_intervals(&self) -> &[SubscriptionInterval] {
        &self.allowed_intervals
    }
    pub fn allowed_payment_behaviors(&self) -> &[SubscriptionPaymentBehavior] {
        &self.allowed_payment_behaviors
    }
    pub fn allowed_proration_behaviors(&self) -> &[SubscriptionProrationBehavior] {
        &self.allowed_proration_behaviors
    }
    pub fn allowed_cancel_modes(&self) -> &[SubscriptionCancelMode] {
        &self.allowed_cancel_modes
    }
    pub fn maximum_quantity_by_price(&self) -> &BTreeMap<PriceId, u32> {
        &self.maximum_quantity_by_price
    }
    pub fn recurring_limits(&self) -> &[SubscriptionRecurringLimit] {
        &self.maximum_recurring_minor_by_currency_and_interval
    }
    pub fn first_invoice_limits(&self) -> &BTreeMap<Currency, u64> {
        &self.maximum_first_invoice_minor_by_currency
    }
    pub fn proration_debit_limits(&self) -> &BTreeMap<Currency, u64> {
        &self.maximum_proration_debit_minor_by_currency
    }
    pub const fn maximum_term_seconds(&self) -> u64 {
        self.maximum_term_seconds
    }
    pub const fn maximum_billing_cycles(&self) -> u32 {
        self.maximum_billing_cycles
    }
    pub const fn maximum_active_subscriptions_per_customer(&self) -> u32 {
        self.maximum_active_subscriptions_per_customer
    }
    pub fn aggregate_recurring_budgets(&self) -> &[AggregateRecurringBudget] {
        &self.aggregate_recurring_budgets
    }
    pub fn aggregate_immediate_budgets(&self) -> &[AggregateImmediateBudget] {
        &self.aggregate_immediate_budgets
    }
    pub const fn minimum_preview_validity_seconds(&self) -> u64 {
        self.minimum_preview_validity_seconds
    }
    pub const fn maximum_evidence_age_seconds(&self) -> u64 {
        self.maximum_evidence_age_seconds
    }
    pub const fn maximum_action_lifetime_seconds(&self) -> u64 {
        self.maximum_action_lifetime_seconds
    }
    pub fn allowed_api_versions(&self) -> &[String] {
        &self.allowed_api_versions
    }
}

/// Runtime identity required to equal the action commitment literally.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StripeSubscriptionConfigurationV1 {
    profile: String,
    evaluator_id: String,
    implementation_id: String,
    canonicalization: String,
    policy_digest: DigestHex,
    stripe_account_id: StripeAccountId,
    connect_account: SubscriptionConnectAccount,
    test_clock_id: TestClockId,
    stripe_api_version: String,
    liability_schema: String,
    receipt_schema: String,
    executor_audience: String,
    maximum_action_bytes: u32,
    maximum_items: u32,
    maximum_preview_lines: u32,
    maximum_evidence_objects: u32,
    maximum_reservations: u32,
    maximum_cycles: u32,
    maximum_work_units: u32,
}

impl StripeSubscriptionConfigurationV1 {
    #[allow(
        clippy::too_many_arguments,
        reason = "all trust anchors remain explicit"
    )]
    pub fn new(
        profile: &str,
        receipt_schema: &str,
        policy: &StripeBoundedSubscriptionPolicyV1,
        stripe_account_id: StripeAccountId,
        connect_account: SubscriptionConnectAccount,
        test_clock_id: TestClockId,
        stripe_api_version: String,
        executor_audience: String,
    ) -> Result<Self, SubscriptionValidationError> {
        let value = Self {
            profile: profile.into(),
            evaluator_id: SUBSCRIPTION_EVALUATOR_ID.into(),
            implementation_id: "auths-stripe-subscription-rust/1".into(),
            canonicalization: SUBSCRIPTION_CANONICALIZATION.into(),
            policy_digest: policy
                .digest()
                .map_err(|_| SubscriptionValidationError::Configuration)?,
            stripe_account_id,
            connect_account,
            test_clock_id,
            stripe_api_version,
            liability_schema: SUBSCRIPTION_LIABILITY_SCHEMA.into(),
            receipt_schema: receipt_schema.into(),
            executor_audience,
            maximum_action_bytes: 65_536,
            maximum_items: 32,
            maximum_preview_lines: 64,
            maximum_evidence_objects: 128,
            maximum_reservations: 64,
            maximum_cycles: policy.maximum_billing_cycles(),
            maximum_work_units: 4_096,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), SubscriptionValidationError> {
        let valid = self.evaluator_id == SUBSCRIPTION_EVALUATOR_ID
            && self.implementation_id == "auths-stripe-subscription-rust/1"
            && self.canonicalization == SUBSCRIPTION_CANONICALIZATION
            && valid_local(&self.profile)
            && valid_local(&self.receipt_schema)
            && valid_api_version(&self.stripe_api_version)
            && Audience::parse(&self.executor_audience).is_ok()
            && self.liability_schema == SUBSCRIPTION_LIABILITY_SCHEMA
            && self.maximum_action_bytes == 65_536
            && self.maximum_items == 32
            && self.maximum_preview_lines == 64
            && self.maximum_evidence_objects == 128
            && self.maximum_reservations == 64
            && self.maximum_cycles > 0
            && self.maximum_work_units == 4_096;
        if valid {
            Ok(())
        } else {
            Err(SubscriptionValidationError::Configuration)
        }
    }
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
    pub const fn policy_digest(&self) -> &DigestHex {
        &self.policy_digest
    }
    pub const fn stripe_account_id(&self) -> &StripeAccountId {
        &self.stripe_account_id
    }
    pub const fn connect_account(&self) -> &SubscriptionConnectAccount {
        &self.connect_account
    }
    pub const fn test_clock_id(&self) -> &TestClockId {
        &self.test_clock_id
    }
    pub fn stripe_api_version(&self) -> &str {
        &self.stripe_api_version
    }
    pub fn executor_audience(&self) -> &str {
        &self.executor_audience
    }
}

/// Immutable Stripe Price/Product evidence.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionCatalogItemEvidence {
    pub price_id: PriceId,
    pub product_id: ProductId,
    pub currency: Currency,
    pub unit_amount_minor: u64,
    pub interval: SubscriptionInterval,
    pub interval_count: u32,
    pub licensed: bool,
    pub active: bool,
}

/// One normalized invoice preview line.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionPreviewLine {
    pub price_id: PriceId,
    pub quantity: u32,
    pub amount_minor: i64,
    pub proration: bool,
}

/// Protected evidence for create. It carries the exact mandate action and its
/// committed capability record instead of a boolean consent flag.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionCreateEvidenceV1 {
    pub schema: String,
    pub stripe_account_id: StripeAccountId,
    pub connect_account: SubscriptionConnectAccount,
    pub customer_id: CustomerId,
    pub payment_method_id: PaymentMethodId,
    pub test_clock_id: TestClockId,
    pub mandate_action: StripeExactPaymentMandateV1,
    pub mandate_capability: PaymentMandateCapabilityRecord,
    pub mandate_receipt: PaymentMandateReceipt,
    pub mandate_receipt_digest: DigestHex,
    pub catalog: Vec<SubscriptionCatalogItemEvidence>,
    pub preview_lines: Vec<SubscriptionPreviewLine>,
    pub preview_digest: DigestHex,
    pub preview_amount_due_minor: i64,
    pub preview_valid_until: u64,
    pub cycle_anchors: Vec<u64>,
    pub active_subscriptions: u32,
    pub livemode: bool,
    pub stripe_api_version: String,
    pub observed_at: u64,
    pub response_digest: DigestHex,
    pub source: String,
}

impl SubscriptionCreateEvidenceV1 {
    pub fn validate(&self) -> Result<(), SubscriptionValidationError> {
        let valid = self.schema == "auths.stripe.subscription-create-evidence/1"
            && self.stripe_account_id == *self.mandate_capability.stripe_account_id()
            && self.customer_id == *self.mandate_capability.customer_id()
            && self.payment_method_id == *self.mandate_capability.payment_method_id()
            && self.mandate_capability.state() == PaymentMandateCapabilityState::Committed
            && self.mandate_action.stripe_account_id() == &self.stripe_account_id
            && self.mandate_action.customer_id() == &self.customer_id
            && self.mandate_action.payment_method_id() == &self.payment_method_id
            && matches!(
                (&self.mandate_receipt, self.mandate_capability.provider()),
                (PaymentMandateReceipt::Observation(value), Some(provider))
                    if value.capability_id == *self.mandate_capability.capability_id()
                        && value.provider.setup_intent_id == provider.setup_intent_id
            )
            && canonical_digest(&self.mandate_receipt).ok().as_ref()
                == Some(&self.mandate_receipt_digest)
            && !self.catalog.is_empty()
            && self.catalog.len() <= 32
            && self.catalog.windows(2).all(|p| p[0] < p[1])
            && self.preview_lines.len() <= 64
            && self.preview_lines.windows(2).all(|p| p[0] < p[1])
            && !self.cycle_anchors.is_empty()
            && self.cycle_anchors.windows(2).all(|p| p[0] < p[1])
            && !self.livemode
            && valid_api_version(&self.stripe_api_version)
            && valid_local(&self.source);
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

/// Sanitized provider projection, never a credential or client secret.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionProviderProjection {
    pub subscription_id: SubscriptionId,
    pub latest_invoice_id: Option<InvoiceId>,
    pub payment_intent_id: Option<PaymentIntentId>,
    pub customer_id: CustomerId,
    pub test_clock_id: TestClockId,
    pub status: String,
    pub invoice_status: Option<String>,
    pub amount_paid_minor: u64,
    pub current_period_end: u64,
    pub cancel_at: u64,
    pub ended_at: Option<u64>,
    pub livemode: bool,
    pub stripe_request_id: Option<String>,
    pub response_digest: DigestHex,
    pub observed_at: u64,
    pub source: String,
}

//! Closed Stripe-local bounded merchant-payment policy and configuration.

use std::collections::BTreeMap;

use auths_model::Audience;
use serde::{Deserialize, Serialize};

use super::{
    MerchantAggregateBudget, MerchantValidationError, valid_api_version, valid_local_id,
    valid_nonempty_sorted, valid_payment_method_type,
};
use crate::{
    bounded::CONFIGURED_POLICY_PROVENANCE,
    canonical::{CanonicalError, canonical_digest},
    types::{Currency, CustomerId, DigestHex, PaymentMethodId, StripeAccountId},
};

/// Immutable merchant-payment policy type.
pub const MERCHANT_POLICY_TYPE: &str = "auths.stripe.bounded-merchant-payment-policy";
/// Initial merchant-payment policy version.
pub const MERCHANT_POLICY_VERSION: u16 = 1;
/// Merchant-payment canonicalization semantics.
pub const MERCHANT_CANONICALIZATION: &str = "rfc8785-sha256-v1";
/// Merchant-payment evaluator semantic identifier.
pub const MERCHANT_EVALUATOR_ID: &str = "auths.stripe.bounded-merchant-payment-evaluator";
/// Merchant-payment evaluator semantic version.
pub const MERCHANT_EVALUATOR_VERSION: u16 = 1;
/// Exact automatic-capture collection profile.
pub const PAYMENT_COLLECT_PROFILE: &str = "auths.stripe.exact-payment-collect/1";
/// Exact manual-capture authorization profile.
pub const PAYMENT_AUTHORIZE_PROFILE: &str = "auths.stripe.exact-payment-authorize/1";
/// Protected statement descriptor suffix used by V1.
pub const PAYMENT_STATEMENT_DESCRIPTOR: &str = "AUTHS DEMO";
/// Receipt policy provenance until the protocol carries a signer commitment.
pub const MERCHANT_POLICY_PROVENANCE: &str = CONFIGURED_POLICY_PROVENANCE;

const MAX_AGGREGATE_BUDGETS: usize = 16;
const MAX_POLICY_LIFETIME_SECONDS: u64 = 366 * 24 * 60 * 60;
const MAX_ACTION_LIFETIME_SECONDS: u64 = 60 * 60;
const MAX_EVIDENCE_AGE_SECONDS: u64 = 15 * 60;
const MAX_MONEY_MINOR: u64 = 99_999_999;

/// Closed operation family governed by the merchant-payment policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MerchantOperation {
    /// Create and confirm an automatic-capture `PaymentIntent`.
    Collect,
    /// Create and confirm a manual-capture `PaymentIntent`.
    Authorize,
    /// Capture an existing exact authorization.
    Capture,
    /// Cancel an existing `PaymentIntent`.
    Cancel,
}

impl MerchantOperation {
    pub(super) const fn has_money_amount(self) -> bool {
        !matches!(self, Self::Cancel)
    }

    pub(super) const fn creates_payment_method_effect(self) -> bool {
        matches!(self, Self::Collect | Self::Authorize)
    }

    pub(super) const fn uses_authorization_window(self) -> bool {
        matches!(self, Self::Authorize | Self::Capture)
    }
}

/// Exact Stripe Connect context.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum MerchantConnectAccount {
    /// Direct/platform account with no `Stripe-Account` header.
    Platform,
    /// One exact connected account.
    Connected {
        /// Connected-account identifier.
        account_id: StripeAccountId,
    },
}

impl MerchantConnectAccount {
    /// Returns the connected account header value, if any.
    #[must_use]
    pub const fn connected_account_id(&self) -> Option<&StripeAccountId> {
        match self {
            Self::Platform => None,
            Self::Connected { account_id } => Some(account_id),
        }
    }
}

/// Immutable configured Stripe merchant-payment policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StripeBoundedMerchantPaymentPolicyV1 {
    policy_type: String,
    policy_version: u16,
    canonicalization: String,
    evaluator_semantic_id: String,
    evaluator_semantic_version: u16,
    policy_id: String,
    valid_from: u64,
    expires_at: u64,
    allowed_operations: Vec<MerchantOperation>,
    allowed_test_account_ids: Vec<StripeAccountId>,
    allowed_connect_accounts: Vec<MerchantConnectAccount>,
    allowed_customer_ids: Vec<CustomerId>,
    allowed_payment_method_ids: Vec<PaymentMethodId>,
    allowed_payment_method_types: Vec<String>,
    allowed_currencies: Vec<Currency>,
    allowed_order_scopes: Vec<String>,
    allowed_cancellation_reasons: Vec<String>,
    per_operation_absolute_minor_by_currency: BTreeMap<MerchantOperation, BTreeMap<Currency, u64>>,
    per_customer_minor_by_currency: BTreeMap<Currency, u64>,
    per_order_minor_by_currency: BTreeMap<Currency, u64>,
    aggregate_budgets: Vec<MerchantAggregateBudget>,
    maximum_authorization_age_seconds: u64,
    minimum_capture_window_seconds: u64,
    maximum_evidence_age_seconds: u64,
    maximum_action_lifetime_seconds: u64,
    allowed_api_versions: Vec<String>,
    require_livemode: bool,
    require_manual_confirmation: bool,
    allow_customer_action: bool,
}

/// Inputs whose immutable identity fields are supplied by the implementation.
pub struct StripeBoundedMerchantPaymentPolicyInput {
    /// Stable local policy identifier.
    pub policy_id: String,
    /// Inclusive policy start.
    pub valid_from: u64,
    /// Inclusive policy expiry.
    pub expires_at: u64,
    /// Closed set of allowed merchant operations.
    pub allowed_operations: Vec<MerchantOperation>,
    /// Allowed Stripe test accounts.
    pub allowed_test_account_ids: Vec<StripeAccountId>,
    /// Allowed platform or Connect contexts.
    pub allowed_connect_accounts: Vec<MerchantConnectAccount>,
    /// Allowed Customers.
    pub allowed_customer_ids: Vec<CustomerId>,
    /// Allowed reusable `PaymentMethod` references.
    pub allowed_payment_method_ids: Vec<PaymentMethodId>,
    /// Allowed `PaymentMethod` types.
    pub allowed_payment_method_types: Vec<String>,
    /// Allowed currencies for money-bearing operations.
    pub allowed_currencies: Vec<Currency>,
    /// Allowed protected order scopes.
    pub allowed_order_scopes: Vec<String>,
    /// Allowed cancellation reasons; empty unless cancel is enabled.
    pub allowed_cancellation_reasons: Vec<String>,
    /// Per-money-operation absolute ceilings.
    pub per_operation_absolute_minor_by_currency:
        BTreeMap<MerchantOperation, BTreeMap<Currency, u64>>,
    /// Per-customer ceilings for money-bearing operations.
    pub per_customer_minor_by_currency: BTreeMap<Currency, u64>,
    /// Per-order ceilings for money-bearing operations.
    pub per_order_minor_by_currency: BTreeMap<Currency, u64>,
    /// Aggregate fixed or rolling budgets.
    pub aggregate_budgets: Vec<MerchantAggregateBudget>,
    /// Maximum permitted active authorization age; zero when unused.
    pub maximum_authorization_age_seconds: u64,
    /// Minimum remaining capture window; zero when unused.
    pub minimum_capture_window_seconds: u64,
    /// Maximum evidence age.
    pub maximum_evidence_age_seconds: u64,
    /// Maximum exact-action lifetime.
    pub maximum_action_lifetime_seconds: u64,
    /// Allowed pinned Stripe API versions.
    pub allowed_api_versions: Vec<String>,
}

impl StripeBoundedMerchantPaymentPolicyV1 {
    /// Builds one canonical immutable configured policy.
    ///
    /// # Errors
    ///
    /// Rejects defaults, duplicates, irrelevant operation constraints,
    /// missing constraints, unsafe modes, and unbounded financial values.
    pub fn new(
        mut input: StripeBoundedMerchantPaymentPolicyInput,
    ) -> Result<Self, MerchantValidationError> {
        input.allowed_operations.sort();
        input.allowed_test_account_ids.sort();
        input.allowed_connect_accounts.sort();
        input.allowed_customer_ids.sort();
        input.allowed_payment_method_ids.sort();
        input.allowed_payment_method_types.sort();
        input.allowed_currencies.sort();
        input.allowed_order_scopes.sort();
        input.allowed_cancellation_reasons.sort();
        input.allowed_api_versions.sort();
        input.aggregate_budgets.sort_by(|left, right| {
            (left.operation(), left.budget_id(), left.currency()).cmp(&(
                right.operation(),
                right.budget_id(),
                right.currency(),
            ))
        });
        let value = Self {
            policy_type: MERCHANT_POLICY_TYPE.into(),
            policy_version: MERCHANT_POLICY_VERSION,
            canonicalization: MERCHANT_CANONICALIZATION.into(),
            evaluator_semantic_id: MERCHANT_EVALUATOR_ID.into(),
            evaluator_semantic_version: MERCHANT_EVALUATOR_VERSION,
            policy_id: input.policy_id,
            valid_from: input.valid_from,
            expires_at: input.expires_at,
            allowed_operations: input.allowed_operations,
            allowed_test_account_ids: input.allowed_test_account_ids,
            allowed_connect_accounts: input.allowed_connect_accounts,
            allowed_customer_ids: input.allowed_customer_ids,
            allowed_payment_method_ids: input.allowed_payment_method_ids,
            allowed_payment_method_types: input.allowed_payment_method_types,
            allowed_currencies: input.allowed_currencies,
            allowed_order_scopes: input.allowed_order_scopes,
            allowed_cancellation_reasons: input.allowed_cancellation_reasons,
            per_operation_absolute_minor_by_currency: input
                .per_operation_absolute_minor_by_currency,
            per_customer_minor_by_currency: input.per_customer_minor_by_currency,
            per_order_minor_by_currency: input.per_order_minor_by_currency,
            aggregate_budgets: input.aggregate_budgets,
            maximum_authorization_age_seconds: input.maximum_authorization_age_seconds,
            minimum_capture_window_seconds: input.minimum_capture_window_seconds,
            maximum_evidence_age_seconds: input.maximum_evidence_age_seconds,
            maximum_action_lifetime_seconds: input.maximum_action_lifetime_seconds,
            allowed_api_versions: input.allowed_api_versions,
            require_livemode: false,
            require_manual_confirmation: true,
            allow_customer_action: false,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validates exact V1 and operation-conditional semantics.
    ///
    /// # Errors
    ///
    /// Rejects unknown, contradictory, irrelevant, or unsafe values.
    #[allow(
        clippy::too_many_lines,
        reason = "closed policy validation stays explicit"
    )]
    pub fn validate(&self) -> Result<(), MerchantValidationError> {
        let has_cancel = self.allowed_operations.contains(&MerchantOperation::Cancel);
        let uses_authorization = self
            .allowed_operations
            .iter()
            .any(|operation| operation.uses_authorization_window());
        let creates_payment_method_effect = self
            .allowed_operations
            .iter()
            .any(|operation| operation.creates_payment_method_effect());
        let money_operations: Vec<_> = self
            .allowed_operations
            .iter()
            .copied()
            .filter(|operation| operation.has_money_amount())
            .collect();
        let currencies_match = |map: &BTreeMap<Currency, u64>| {
            map.len() == self.allowed_currencies.len()
                && self
                    .allowed_currencies
                    .iter()
                    .all(|currency| matches!(map.get(currency), Some(1..=MAX_MONEY_MINOR)))
        };
        let operation_limits_valid = money_operations.iter().all(|operation| {
            self.per_operation_absolute_minor_by_currency
                .get(operation)
                .is_some_and(&currencies_match)
        }) && self.per_operation_absolute_minor_by_currency.len()
            == money_operations.len();
        let cancel_reasons_valid = if has_cancel {
            valid_nonempty_sorted(&self.allowed_cancellation_reasons)
                && self.allowed_cancellation_reasons.iter().all(|value| {
                    matches!(
                        value.as_str(),
                        "abandoned" | "duplicate" | "fraudulent" | "requested_by_customer"
                    )
                })
        } else {
            self.allowed_cancellation_reasons.is_empty()
        };
        let authorization_constraints_valid = if uses_authorization {
            (1..=31 * 24 * 60 * 60).contains(&self.maximum_authorization_age_seconds)
                && (1..=31 * 24 * 60 * 60).contains(&self.minimum_capture_window_seconds)
        } else {
            self.maximum_authorization_age_seconds == 0 && self.minimum_capture_window_seconds == 0
        };
        let payment_method_constraints_valid = if creates_payment_method_effect {
            valid_nonempty_sorted(&self.allowed_payment_method_ids)
                && valid_nonempty_sorted(&self.allowed_payment_method_types)
                && self
                    .allowed_payment_method_types
                    .iter()
                    .all(|value| valid_payment_method_type(value))
        } else {
            self.allowed_payment_method_ids.is_empty()
                && self.allowed_payment_method_types.is_empty()
        };
        let money_constraints_valid = if money_operations.is_empty() {
            self.allowed_currencies.is_empty()
                && self.per_operation_absolute_minor_by_currency.is_empty()
                && self.per_customer_minor_by_currency.is_empty()
                && self.per_order_minor_by_currency.is_empty()
                && self.aggregate_budgets.is_empty()
        } else {
            valid_nonempty_sorted(&self.allowed_currencies)
                && operation_limits_valid
                && currencies_match(&self.per_customer_minor_by_currency)
                && currencies_match(&self.per_order_minor_by_currency)
                && !self.aggregate_budgets.is_empty()
                && self.aggregate_budgets.len() <= MAX_AGGREGATE_BUDGETS
                && self.aggregate_budgets.windows(2).all(|pair| {
                    (pair[0].operation(), pair[0].budget_id(), pair[0].currency())
                        < (pair[1].operation(), pair[1].budget_id(), pair[1].currency())
                })
                && self.aggregate_budgets.iter().all(|budget| {
                    money_operations.contains(&budget.operation())
                        && self.allowed_currencies.contains(budget.currency())
                        && budget.validate(self.valid_from).is_ok()
                })
                && money_operations.iter().all(|operation| {
                    self.aggregate_budgets
                        .iter()
                        .any(|budget| budget.operation() == *operation)
                })
        };
        if self.policy_type != MERCHANT_POLICY_TYPE
            || self.policy_version != MERCHANT_POLICY_VERSION
            || self.canonicalization != MERCHANT_CANONICALIZATION
            || self.evaluator_semantic_id != MERCHANT_EVALUATOR_ID
            || self.evaluator_semantic_version != MERCHANT_EVALUATOR_VERSION
            || !valid_local_id(&self.policy_id)
            || self.valid_from >= self.expires_at
            || self.expires_at.saturating_sub(self.valid_from) > MAX_POLICY_LIFETIME_SECONDS
            || !valid_nonempty_sorted(&self.allowed_operations)
            || !valid_nonempty_sorted(&self.allowed_test_account_ids)
            || !valid_nonempty_sorted(&self.allowed_connect_accounts)
            || !valid_nonempty_sorted(&self.allowed_customer_ids)
            || !valid_nonempty_sorted(&self.allowed_order_scopes)
            || !valid_nonempty_sorted(&self.allowed_api_versions)
            || self
                .allowed_order_scopes
                .iter()
                .any(|value| !valid_local_id(value))
            || self
                .allowed_api_versions
                .iter()
                .any(|value| !valid_api_version(value))
            || !cancel_reasons_valid
            || !authorization_constraints_valid
            || !payment_method_constraints_valid
            || !money_constraints_valid
            || self.maximum_evidence_age_seconds == 0
            || self.maximum_evidence_age_seconds > MAX_EVIDENCE_AGE_SECONDS
            || self.maximum_action_lifetime_seconds == 0
            || self.maximum_action_lifetime_seconds > MAX_ACTION_LIFETIME_SECONDS
            || self.require_livemode
            || !self.require_manual_confirmation
            || self.allow_customer_action
        {
            return Err(MerchantValidationError::InvalidPolicy);
        }
        Ok(())
    }

    /// Canonical policy digest.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization failure.
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }

    /// Stable local identifier.
    #[must_use]
    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }

    /// Inclusive validity start.
    #[must_use]
    pub const fn valid_from(&self) -> u64 {
        self.valid_from
    }

    /// Inclusive validity end.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Closed enabled operations.
    #[must_use]
    pub fn allowed_operations(&self) -> &[MerchantOperation] {
        &self.allowed_operations
    }

    /// Allowed Stripe test accounts.
    #[must_use]
    pub fn allowed_test_account_ids(&self) -> &[StripeAccountId] {
        &self.allowed_test_account_ids
    }

    /// Allowed Connect contexts.
    #[must_use]
    pub fn allowed_connect_accounts(&self) -> &[MerchantConnectAccount] {
        &self.allowed_connect_accounts
    }

    /// Allowed Customers.
    #[must_use]
    pub fn allowed_customer_ids(&self) -> &[CustomerId] {
        &self.allowed_customer_ids
    }

    /// Allowed `PaymentMethod` identifiers.
    #[must_use]
    pub fn allowed_payment_method_ids(&self) -> &[PaymentMethodId] {
        &self.allowed_payment_method_ids
    }

    /// Allowed `PaymentMethod` types.
    #[must_use]
    pub fn allowed_payment_method_types(&self) -> &[String] {
        &self.allowed_payment_method_types
    }

    /// Allowed currencies.
    #[must_use]
    pub fn allowed_currencies(&self) -> &[Currency] {
        &self.allowed_currencies
    }

    /// Allowed order scopes.
    #[must_use]
    pub fn allowed_order_scopes(&self) -> &[String] {
        &self.allowed_order_scopes
    }

    /// Allowed pinned Stripe API versions.
    #[must_use]
    pub fn allowed_api_versions(&self) -> &[String] {
        &self.allowed_api_versions
    }

    /// Aggregate budgets.
    #[must_use]
    pub fn aggregate_budgets(&self) -> &[MerchantAggregateBudget] {
        &self.aggregate_budgets
    }

    /// Evidence freshness bound.
    #[must_use]
    pub const fn maximum_evidence_age_seconds(&self) -> u64 {
        self.maximum_evidence_age_seconds
    }

    /// Maximum exact-action lifetime.
    #[must_use]
    pub const fn maximum_action_lifetime_seconds(&self) -> u64 {
        self.maximum_action_lifetime_seconds
    }

    /// Minimum manual-capture window.
    #[must_use]
    pub const fn minimum_capture_window_seconds(&self) -> u64 {
        self.minimum_capture_window_seconds
    }

    /// Maximum active authorization age.
    #[must_use]
    pub const fn maximum_authorization_age_seconds(&self) -> u64 {
        self.maximum_authorization_age_seconds
    }

    /// Returns the operation ceiling for one currency.
    #[must_use]
    pub fn operation_limit_minor(
        &self,
        operation: MerchantOperation,
        currency: &Currency,
    ) -> Option<u64> {
        self.per_operation_absolute_minor_by_currency
            .get(&operation)
            .and_then(|limits| limits.get(currency))
            .copied()
    }

    /// Returns the customer ceiling for one currency.
    #[must_use]
    pub fn customer_limit_minor(&self, currency: &Currency) -> Option<u64> {
        self.per_customer_minor_by_currency.get(currency).copied()
    }

    /// Returns the order ceiling for one currency.
    #[must_use]
    pub fn order_limit_minor(&self, currency: &Currency) -> Option<u64> {
        self.per_order_minor_by_currency.get(currency).copied()
    }
}

/// Required/executed evaluator and runtime configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StripeMerchantEvaluatorConfigurationV1 {
    schema: String,
    policy_digest: DigestHex,
    policy_type: String,
    policy_version: u16,
    canonicalization: String,
    evaluator_semantic_id: String,
    evaluator_semantic_version: u16,
    evaluator_implementation_id: String,
    exact_action_profile: String,
    stripe_account_id: StripeAccountId,
    connect_account: MerchantConnectAccount,
    stripe_api_version: String,
    reservation_schema: String,
    claim_schema: String,
    receipt_schema: String,
    executor_audience: String,
    maximum_action_bytes: u32,
    maximum_policy_items: u16,
    maximum_evidence_objects: u16,
    maximum_reservations: u32,
    maximum_evaluator_work: u32,
}

impl StripeMerchantEvaluatorConfigurationV1 {
    /// Constructs exact collection runtime configuration.
    ///
    /// # Errors
    ///
    /// Rejects malformed or inconsistent configuration commitments.
    pub fn for_collect_policy(
        policy: &StripeBoundedMerchantPaymentPolicyV1,
        evaluator_implementation_id: impl Into<String>,
        stripe_account_id: StripeAccountId,
        connect_account: MerchantConnectAccount,
        stripe_api_version: impl Into<String>,
        executor_audience: impl Into<String>,
    ) -> Result<Self, MerchantValidationError> {
        Self::for_profile(
            policy,
            evaluator_implementation_id,
            PAYMENT_COLLECT_PROFILE,
            stripe_account_id,
            connect_account,
            stripe_api_version,
            executor_audience,
        )
    }

    /// Constructs exact authorization runtime configuration.
    ///
    /// # Errors
    ///
    /// Rejects malformed or inconsistent configuration commitments.
    pub fn for_authorize_policy(
        policy: &StripeBoundedMerchantPaymentPolicyV1,
        evaluator_implementation_id: impl Into<String>,
        stripe_account_id: StripeAccountId,
        connect_account: MerchantConnectAccount,
        stripe_api_version: impl Into<String>,
        executor_audience: impl Into<String>,
    ) -> Result<Self, MerchantValidationError> {
        Self::for_profile(
            policy,
            evaluator_implementation_id,
            PAYMENT_AUTHORIZE_PROFILE,
            stripe_account_id,
            connect_account,
            stripe_api_version,
            executor_audience,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn for_profile(
        policy: &StripeBoundedMerchantPaymentPolicyV1,
        evaluator_implementation_id: impl Into<String>,
        exact_action_profile: impl Into<String>,
        stripe_account_id: StripeAccountId,
        connect_account: MerchantConnectAccount,
        stripe_api_version: impl Into<String>,
        executor_audience: impl Into<String>,
    ) -> Result<Self, MerchantValidationError> {
        let value = Self {
            schema: "auths.stripe.merchant-evaluator-configuration/1".into(),
            policy_digest: policy
                .digest()
                .map_err(|_| MerchantValidationError::Canonicalization)?,
            policy_type: MERCHANT_POLICY_TYPE.into(),
            policy_version: MERCHANT_POLICY_VERSION,
            canonicalization: MERCHANT_CANONICALIZATION.into(),
            evaluator_semantic_id: MERCHANT_EVALUATOR_ID.into(),
            evaluator_semantic_version: MERCHANT_EVALUATOR_VERSION,
            evaluator_implementation_id: evaluator_implementation_id.into(),
            exact_action_profile: exact_action_profile.into(),
            stripe_account_id,
            connect_account,
            stripe_api_version: stripe_api_version.into(),
            reservation_schema: "auths.stripe.merchant-reservation/1".into(),
            claim_schema: "auths.stripe.merchant-claim/1".into(),
            receipt_schema: "auths.stripe.merchant-receipt/1".into(),
            executor_audience: executor_audience.into(),
            maximum_action_bytes: 64 * 1024,
            maximum_policy_items: 64,
            maximum_evidence_objects: 64,
            maximum_reservations: 100_000,
            maximum_evaluator_work: 4_096,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validates exact V1 runtime semantics.
    ///
    /// # Errors
    ///
    /// Rejects any noncanonical or inconsistent runtime field.
    pub fn validate(&self) -> Result<(), MerchantValidationError> {
        if self.schema != "auths.stripe.merchant-evaluator-configuration/1"
            || self.policy_type != MERCHANT_POLICY_TYPE
            || self.policy_version != MERCHANT_POLICY_VERSION
            || self.canonicalization != MERCHANT_CANONICALIZATION
            || self.evaluator_semantic_id != MERCHANT_EVALUATOR_ID
            || self.evaluator_semantic_version != MERCHANT_EVALUATOR_VERSION
            || !valid_local_id(&self.evaluator_implementation_id)
            || !matches!(
                self.exact_action_profile.as_str(),
                PAYMENT_COLLECT_PROFILE | PAYMENT_AUTHORIZE_PROFILE
            )
            || !valid_api_version(&self.stripe_api_version)
            || self.reservation_schema != "auths.stripe.merchant-reservation/1"
            || self.claim_schema != "auths.stripe.merchant-claim/1"
            || self.receipt_schema != "auths.stripe.merchant-receipt/1"
            || Audience::parse(&self.executor_audience).is_err()
            || self.maximum_action_bytes != 64 * 1024
            || self.maximum_policy_items != 64
            || self.maximum_evidence_objects != 64
            || self.maximum_reservations == 0
            || self.maximum_reservations > 100_000
            || self.maximum_evaluator_work != 4_096
        {
            return Err(MerchantValidationError::InvalidConfiguration);
        }
        Ok(())
    }

    /// Canonical configuration digest.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization failure.
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }

    /// Configured policy digest.
    #[must_use]
    pub const fn policy_digest(&self) -> &DigestHex {
        &self.policy_digest
    }

    /// Exact action profile.
    #[must_use]
    pub fn exact_action_profile(&self) -> &str {
        &self.exact_action_profile
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

    /// Pinned Stripe API version.
    #[must_use]
    pub fn stripe_api_version(&self) -> &str {
        &self.stripe_api_version
    }

    /// Executor audience.
    #[must_use]
    pub fn executor_audience(&self) -> &str {
        &self.executor_audience
    }
}

/// Exact evaluator semantic commitment embedded in an action.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MerchantEvaluatorCommitment {
    semantic_id: String,
    semantic_version: u16,
}

impl MerchantEvaluatorCommitment {
    /// Returns the V1 merchant evaluator commitment.
    #[must_use]
    pub fn v1() -> Self {
        Self {
            semantic_id: MERCHANT_EVALUATOR_ID.into(),
            semantic_version: MERCHANT_EVALUATOR_VERSION,
        }
    }
}
